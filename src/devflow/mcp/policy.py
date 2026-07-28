"""Default-deny MCP authorization, context propagation, and audit evidence."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml
from pydantic import BaseModel, Field

from devflow.exceptions import ConfigError, MCPAuthorizationError
from devflow.mcp.approval import ApprovalVerifier
from devflow.mcp.context_auth import ContextSigner
from devflow.mcp.contracts import MCPCallContext
from devflow.models.patch import Patch
from devflow.security.secrets import contains_secret

_PROTECTED_BRANCHES = {"main", "master"}
class RawMCPTransport(Protocol):
    """Untrusted transport invoked only after policy authorization."""

    async def call_tool(
        self, server: str, tool: str, arguments: dict[str, Any]
    ) -> Any: ...


@dataclass(frozen=True)
class ToolGrant:
    """One explicit Agent/Skill capability grant."""

    server: str
    tool: str
    allowed_agents: frozenset[str]
    allowed_skills: frozenset[str]
    readonly: bool
    requires_confirmation: bool
    propagate_context: bool


class MCPAuditRecord(BaseModel):
    """Secret-free evidence for one authorized or denied call."""

    timestamp: datetime
    run_id: str
    task_id: str
    issue_id: int
    agent: str
    skill: str
    server: str
    tool: str
    readonly: bool
    outcome: str = Field(pattern=r"^(denied|authorized|succeeded|failed)$")
    arguments_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    detail: str | None = Field(default=None, max_length=300)


class AuditSink(Protocol):
    """Destination for MCP boundary audit records."""

    async def record(self, entry: MCPAuditRecord) -> None: ...


class MemoryAuditSink:
    """Test and local-development audit sink."""

    def __init__(self) -> None:
        self.records: list[MCPAuditRecord] = []

    async def record(self, entry: MCPAuditRecord) -> None:
        self.records.append(entry)


class HashChainAuditLog:
    """Append-only JSONL sink whose entries form a tamper-evident hash chain."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = asyncio.Lock()
        self._previous_hash = self._load_previous_hash()

    def _load_previous_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return "0" * 64
        try:
            return _verify_audit_chain(self.path)
        except (OSError, IndexError, KeyError, json.JSONDecodeError, ValueError):
            pass
        raise ConfigError(f"Audit chain is unreadable or invalid: {self.path}")

    async def record(self, entry: MCPAuditRecord) -> None:
        async with self._lock:
            payload = entry.model_dump(mode="json")
            payload["previous_hash"] = self._previous_hash
            serialized = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            entry_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            payload["entry_hash"] = entry_hash
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._previous_hash = entry_hash


class MCPPolicy:
    """Compiled default-deny policy loaded from ``mcp_servers.yaml``."""

    def __init__(
        self,
        grants: Mapping[tuple[str, str], ToolGrant],
        *,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> None:
        self._grants = dict(grants)
        self._approval_verifier = approval_verifier

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        approval_verifier: ApprovalVerifier | None = None,
    ) -> MCPPolicy:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        servers = raw.get("servers")
        if not isinstance(servers, dict):
            raise ConfigError("MCP policy requires a servers mapping")
        grants: dict[tuple[str, str], ToolGrant] = {}
        for server_name, server in servers.items():
            if not isinstance(server, dict) or not server.get("enabled", False):
                continue
            tools = server.get("tools", [])
            if not isinstance(tools, list):
                raise ConfigError(f"MCP server {server_name} tools must be a list")
            for item in tools:
                if not isinstance(item, dict):
                    raise ConfigError(f"MCP server {server_name} has an invalid tool")
                name = str(item.get("name", ""))
                agents = frozenset(str(value) for value in item.get("allowed_agents", []))
                skills = frozenset(str(value) for value in item.get("allowed_skills", []))
                if not name or not agents or not skills:
                    raise ConfigError(
                        f"{server_name}:{name or '<unnamed>'} needs Agent and Skill grants"
                    )
                key = (str(server_name), name)
                if key in grants:
                    raise ConfigError(f"duplicate MCP tool grant: {server_name}:{name}")
                grants[key] = ToolGrant(
                    server=str(server_name),
                    tool=name,
                    allowed_agents=agents,
                    allowed_skills=skills,
                    readonly=bool(item.get("readonly", False)),
                    requires_confirmation=bool(item.get("requires_confirmation", False)),
                    propagate_context=bool(server.get("propagate_context", False)),
                )
        return cls(grants, approval_verifier=approval_verifier)

    def authorize(
        self,
        context: MCPCallContext,
        server: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> ToolGrant:
        grant = self._grants.get((server, tool))
        if grant is None:
            raise MCPAuthorizationError(f"MCP tool is not registered: {server}:{tool}")
        if context.agent not in grant.allowed_agents:
            raise MCPAuthorizationError(
                f"Agent {context.agent} is not allowed to call {server}:{tool}"
            )
        if context.skill not in grant.allowed_skills:
            raise MCPAuthorizationError(
                f"Skill {context.skill} is not allowed to call {server}:{tool}"
            )
        if _contains_secret(arguments):
            raise MCPAuthorizationError("MCP arguments contain secret-shaped content")
        if grant.requires_confirmation:
            approval = context.approval
            expected_action = f"{server}:{tool}"
            if approval is None:
                raise MCPAuthorizationError(
                    f"{server}:{tool} requires action-bound approval evidence"
                )
            verifier = self._approval_verifier
            if verifier is None:
                raise MCPAuthorizationError("approval verifier is unavailable")
            digest = arguments_digest(arguments)
            target = _approval_target(server, tool, arguments)
            if not verifier.verify(
                approval,
                action=expected_action,
                target=target,
                artifact_digest=digest,
            ):
                raise MCPAuthorizationError(
                    "approval signature, scope, target, digest, or expiry is invalid"
                )
        self._validate_tool_arguments(server, tool, arguments)
        return grant

    @staticmethod
    def _validate_tool_arguments(
        server: str, tool: str, arguments: dict[str, Any]
    ) -> None:
        if server == "github" and tool == "get_file_contents":
            _require_safe_path(arguments.get("path"))
        elif server == "github" and tool == "create_pull_request":
            _require_safe_branch(arguments.get("branch") or arguments.get("head"))
        elif server == "cicd" and tool == "run_tests":
            try:
                Patch.model_validate(arguments.get("patch"))
            except Exception as exc:
                raise MCPAuthorizationError(f"run_tests requires a valid Patch: {exc}") from exc
        elif server == "cicd" and tool == "trigger_pipeline":
            _require_safe_branch(arguments.get("branch"))
            if arguments.get("suite") not in {"full", "affected", "smoke"}:
                raise MCPAuthorizationError("pipeline suite is unsupported")
        elif server == "cicd" and tool in {"get_test_results", "get_coverage"}:
            pipeline_id = arguments.get("pipeline_id")
            if not isinstance(pipeline_id, str) or not re.fullmatch(
                r"[a-f0-9]{32}", pipeline_id
            ):
                raise MCPAuthorizationError("pipeline id is invalid")


class PolicyEnforcedMCPClient:
    """MCP client that cannot reach a transport without policy authorization."""

    def __init__(
        self,
        transport: RawMCPTransport,
        policy: MCPPolicy,
        audit: AuditSink,
        context_signer: ContextSigner | None = None,
    ) -> None:
        self._transport = transport
        self._policy = policy
        self._audit = audit
        self._context_signer = context_signer

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        *,
        context: MCPCallContext,
    ) -> Any:
        digest = arguments_digest(arguments)
        try:
            grant = self._policy.authorize(context, server, tool, arguments)
        except MCPAuthorizationError as exc:
            await self._record(context, server, tool, False, "denied", digest, str(exc))
            raise
        outbound = dict(arguments)
        if grant.propagate_context:
            if self._context_signer is None:
                detail = "internal MCP context signer is unavailable"
                await self._record(
                    context, server, tool, grant.readonly, "denied", digest, detail
                )
                raise MCPAuthorizationError(detail)
            signed_context = self._context_signer.sign(context)
            outbound["devflow_context"] = signed_context.model_dump(mode="json")
        await self._record(context, server, tool, grant.readonly, "authorized", digest)
        try:
            result = await self._transport.call_tool(server, tool, outbound)
        except Exception as exc:
            await self._record(
                context,
                server,
                tool,
                grant.readonly,
                "failed",
                digest,
                type(exc).__name__,
            )
            raise
        await self._record(context, server, tool, grant.readonly, "succeeded", digest)
        return result

    async def _record(
        self,
        context: MCPCallContext,
        server: str,
        tool: str,
        readonly: bool,
        outcome: str,
        digest: str,
        detail: str | None = None,
    ) -> None:
        await self._audit.record(
            MCPAuditRecord(
                timestamp=datetime.now(timezone.utc),
                run_id=context.run_id,
                task_id=context.task_id,
                issue_id=context.issue_id,
                agent=context.agent,
                skill=context.skill,
                server=server,
                tool=tool,
                readonly=readonly,
                outcome=outcome,
                arguments_sha256=digest,
                detail=detail,
            )
        )


def arguments_digest(arguments: dict[str, Any]) -> str:
    serialized = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _verify_audit_chain(path: Path) -> str:
    previous = "0" * 64
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parsed = json.loads(line)
        claimed = parsed.pop("entry_hash")
        if parsed.get("previous_hash") != previous:
            raise ValueError(f"audit chain link mismatch at line {line_number}")
        serialized = json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        actual = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        if not isinstance(claimed, str) or not hmac.compare_digest(claimed, actual):
            raise ValueError(f"audit chain digest mismatch at line {line_number}")
        previous = claimed
    return previous


def verify_audit_chain(path: Path) -> bool:
    """Verify every entry digest and link in an audit JSONL file."""

    try:
        _verify_audit_chain(path)
        return True
    except (OSError, IndexError, KeyError, json.JSONDecodeError, ValueError):
        return False


def _contains_secret(value: Any) -> bool:
    return contains_secret(value)


def _require_safe_branch(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MCPAuthorizationError("a non-empty branch is required")
    branch = value.strip()
    if branch in _PROTECTED_BRANCHES or branch.startswith("refs/heads/main"):
        raise MCPAuthorizationError("write operations cannot target a protected branch")
    if ".." in branch or branch.startswith(('/', '-')) or branch.endswith(('/', '.')):
        raise MCPAuthorizationError("unsafe branch name")
    return branch


def _require_safe_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MCPAuthorizationError("a repository-relative path is required")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        raise MCPAuthorizationError("path escapes repository boundary")
    return path.as_posix()


def _approval_target(server: str, tool: str, arguments: dict[str, Any]) -> str:
    """Build the canonical target string a trusted approval must sign."""

    if server == "cicd" and tool == "rollback_deployment":
        environment = arguments.get("environment")
        release = arguments.get("target_release") or "previous-good"
        if environment not in {"staging", "production"}:
            raise MCPAuthorizationError("rollback requires a valid environment")
        if not isinstance(release, str) or not release.strip():
            raise MCPAuthorizationError("rollback requires a valid target release")
        return f"{environment}:{release.strip()}"
    raise MCPAuthorizationError(
        f"dangerous MCP tool has no approval target adapter: {server}:{tool}"
    )


__all__ = [
    "HashChainAuditLog",
    "MCPAuditRecord",
    "MCPPolicy",
    "MemoryAuditSink",
    "PolicyEnforcedMCPClient",
    "RawMCPTransport",
    "ToolGrant",
    "arguments_digest",
    "verify_audit_chain",
]

"""Portable FastMCP adapter for the single policy-bound test action."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from devflow.exceptions import MCPAuthorizationError
from devflow.mcp.cicd import PORTABLE_CICD_SERVER, IsolatedTestService
from devflow.mcp.context_auth import HMACContextAuthority
from devflow.mcp.contracts import MCPCallContext
from devflow.mcp.policy import (
    HashChainAuditLog,
    MCPAuditRecord,
    MCPPolicy,
    arguments_digest,
)
from devflow.models.patch import Patch
from devflow.observability import (
    configure_otlp_tracing,
    metrics,
    start_prometheus_server,
    tracer,
)


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _json_argv(name: str, default: tuple[str, ...] | None = None) -> tuple[str, ...] | None:
    raw = os.getenv(name)
    if not raw:
        return default
    parsed = json.loads(raw)
    if (
        not isinstance(parsed, list)
        or not parsed
        or not all(isinstance(item, str) and item for item in parsed)
    ):
        raise ValueError(f"{name} must be a non-empty JSON argv list")
    return tuple(parsed)


def _test_commands() -> tuple[tuple[str, ...], tuple[str, ...]]:
    focused = _json_argv(
        "CICD_FOCUSED_TEST_COMMAND_JSON",
        (sys.executable, "-m", "pytest", "-q", "--maxfail=1"),
    )
    full = _json_argv(
        "CICD_FULL_TEST_COMMAND_JSON",
        (sys.executable, "-m", "pytest", "-q"),
    )
    if focused is None or full is None:
        raise ValueError("portable CI requires focused and full server-owned argv")
    return focused, full


def _loopback_host() -> str:
    host = os.getenv("MCP_CICD_HOST", "127.0.0.1")
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if not is_loopback:
        raise ValueError("CI/CD MCP server must bind to a loopback address")
    return host


def _path_from_env(name: str, default: str) -> Path:
    value = Path(os.getenv(name, default))
    return value if value.is_absolute() else _project_root() / value


def _require_portable_context(
    context: MCPCallContext,
    arguments: dict[str, Any],
) -> None:
    """Bind the portable request to its authenticated local task context."""

    if context.issue_id != arguments.get("issue_id"):
        raise MCPAuthorizationError(
            "portable CI issue_id does not match signed MCP context"
        )
    if context.risk_tier is None:
        raise MCPAuthorizationError(
            "portable CI requires risk_tier in signed MCP context"
        )


def build_server() -> Any:
    """Build the optional FastMCP server without importing MCP at module load."""

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError('Install DevFlow with the "mcp" extra to run this server') from exc

    load_dotenv(_project_root() / ".env")
    host = _loopback_host()
    port = int(os.getenv("MCP_CICD_PORT", "8766"))
    if not 1 <= port <= 65535:
        raise ValueError("MCP_CICD_PORT must be between 1 and 65535")
    server = FastMCP(PORTABLE_CICD_SERVER, host=host, port=port)
    policy = MCPPolicy.from_file(
        _project_root() / "config" / "mcp_servers.portable.yaml"
    )
    context_authority = HMACContextAuthority(
        os.environ["DEVFLOW_MCP_CONTEXT_HMAC_KEY"].encode("utf-8")
    )
    audit = HashChainAuditLog(_path_from_env("AUDIT_LOG_PATH", "logs/mcp-audit.jsonl"))
    focused_command, full_command = _test_commands()
    test_service = IsolatedTestService(
        Path(os.environ["DEVFLOW_REPOSITORY_ROOT"]),
        focused_command,
        full_command,
        timeout_seconds=int(os.getenv("CICD_TEST_TIMEOUT_SECONDS", "600")),
    )

    async def invoke(
        tool: str,
        arguments: dict[str, Any],
        raw_context: dict[str, Any],
        operation: Callable[[MCPCallContext], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        started = time.perf_counter()
        outcome = "failed"
        with tracer.start_as_current_span("devflow.mcp.cicd.invoke") as span:
            span.set_attribute("devflow.mcp.server", PORTABLE_CICD_SERVER)
            span.set_attribute("devflow.mcp.tool", tool)
            try:
                context = MCPCallContext.model_validate(raw_context)
                span.set_attribute("devflow.agent", context.agent)
                span.set_attribute("devflow.skill", context.skill)
                if not context_authority.verify(context):
                    outcome = "denied"
                    raise MCPAuthorizationError("internal MCP context signature is invalid")
                digest = arguments_digest(arguments)
                try:
                    _require_portable_context(context, arguments)
                except MCPAuthorizationError as exc:
                    outcome = "denied"
                    await _audit(audit, context, tool, False, "denied", digest, str(exc))
                    raise
                try:
                    grant = policy.authorize(
                        context, PORTABLE_CICD_SERVER, tool, arguments
                    )
                except MCPAuthorizationError as exc:
                    outcome = "denied"
                    await _audit(audit, context, tool, False, "denied", digest, str(exc))
                    raise
                if grant.requires_confirmation:
                    outcome = "denied"
                    raise MCPAuthorizationError(
                        f"{PORTABLE_CICD_SERVER} exposes no destructive confirmation surface"
                    )
                await _audit(audit, context, tool, grant.readonly, "authorized", digest)
                try:
                    result = await operation(context)
                except Exception as exc:
                    await _audit(
                        audit,
                        context,
                        tool,
                        grant.readonly,
                        "failed",
                        digest,
                        type(exc).__name__,
                    )
                    raise
                await _audit(audit, context, tool, grant.readonly, "succeeded", digest)
                outcome = "succeeded"
                return result
            finally:
                span.set_attribute("devflow.mcp.outcome", outcome)
                metrics.counter("devflow_mcp_tool_calls_total").inc(
                    labels={"server": PORTABLE_CICD_SERVER, "tool": tool, "status": outcome}
                )
                metrics.histogram("devflow_mcp_tool_duration_seconds").observe(
                    time.perf_counter() - started,
                    labels={"server": PORTABLE_CICD_SERVER, "tool": tool, "status": outcome},
                )

    @server.tool()
    async def run_tests(
        issue_id: int,
        patch: dict[str, Any],
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run in disposable process-level copies; this is not an OS sandbox."""

        arguments = {"issue_id": issue_id, "patch": patch}

        async def operation(context: MCPCallContext) -> dict[str, Any]:
            assert context.risk_tier is not None
            result = await test_service.run_tests(
                Patch.model_validate(patch), risk_tier=context.risk_tier
            )
            return result.model_dump(mode="json")

        return await invoke("run_tests", arguments, devflow_context, operation)

    return server


async def _audit(
    sink: HashChainAuditLog,
    context: MCPCallContext,
    tool: str,
    readonly: bool,
    outcome: str,
    digest: str,
    detail: str | None = None,
) -> None:
    await sink.record(
        MCPAuditRecord(
            timestamp=datetime.now(timezone.utc),
            run_id=context.run_id,
            task_id=context.task_id,
            issue_id=context.issue_id,
            agent=context.agent,
            skill=context.skill,
            server=PORTABLE_CICD_SERVER,
            tool=tool,
            readonly=readonly,
            outcome=outcome,
            arguments_sha256=digest,
            detail=detail,
        )
    )


def main() -> None:
    """Start loopback MCP, Prometheus metrics, and OTLP trace export."""

    load_dotenv(_project_root() / ".env")
    provider = None
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if endpoint:
        provider = configure_otlp_tracing(endpoint)
    metrics_server = start_prometheus_server(
        host=os.getenv("DEVFLOW_METRICS_HOST", "127.0.0.1"),
        port=int(os.getenv("DEVFLOW_METRICS_PORT", "9090")),
    )
    try:
        build_server().run(transport="streamable-http")
    finally:
        metrics_server.close()
        if provider is not None:
            provider.shutdown()


if __name__ == "__main__":
    main()

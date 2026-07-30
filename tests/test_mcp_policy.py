"""Executable least-privilege and isolation tests for the MCP boundary."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from devflow.exceptions import ConfigError, MCPAuthorizationError, MCPError
from devflow.mcp.approval import HMACApprovalAuthority
from devflow.mcp.cicd import IsolatedTestService
from devflow.mcp.context_auth import HMACContextAuthority
from devflow.mcp.contracts import ApprovalEvidence, MCPCallContext
from devflow.mcp.policy import (
    HashChainAuditLog,
    MCPPolicy,
    MemoryAuditSink,
    PolicyEnforcedMCPClient,
    verify_audit_chain,
)
from devflow.models.patch import ChangeType, FileChange, Patch

ROOT = Path(__file__).resolve().parents[1]


class RecordingTransport:
    """Raw transport proving denied calls never cross the policy boundary."""

    def __init__(self, response: Any = None) -> None:
        self.response = response if response is not None else {"ok": True}
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call_tool(self, server: str, tool: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((server, tool, arguments))
        return self.response


def _context(
    *,
    agent: str = "LocatorAgent",
    skill: str = "github-evidence",
    approval: ApprovalEvidence | None = None,
) -> MCPCallContext:
    return MCPCallContext(
        run_id="issue-42",
        issue_id=42,
        task_id="42-locator",
        agent=agent,
        skill=skill,
        trace_id="issue-42:42-locator",
        idempotency_key="issue-42:42-locator:github:get-file",
        risk_tier="T2",
        approval=approval,
    )


def _patch(original: str = "def add(a, b):\n    return a - b\n") -> Patch:
    return Patch(
        branch_name="devflow/fix-add",
        changes=[
            FileChange(
                file_path="calculator.py",
                change_type=ChangeType.MODIFY,
                original_content=original,
                new_content="def add(a, b):\n    return a + b\n",
                diff="--- a/calculator.py\n+++ b/calculator.py\n",
            )
        ],
        commit_message="fix: add operands",
        description="Correct the arithmetic operator.",
    )


@pytest.fixture
def policy() -> MCPPolicy:
    return MCPPolicy.from_file(ROOT / "config" / "mcp_servers.portable.yaml")


@pytest.mark.asyncio
async def test_policy_allows_exact_agent_skill_pair_and_audits(policy: MCPPolicy) -> None:
    transport = RecordingTransport({"content": "safe"})
    audit = MemoryAuditSink()
    client = PolicyEnforcedMCPClient(transport, policy, audit)

    result = await client.call_tool(
        "github",
        "get_file_contents",
        {"owner": "example", "repo": "repo", "path": "src/app.py"},
        context=_context(),
    )

    assert result == {"content": "safe"}
    assert len(transport.calls) == 1
    assert [record.outcome for record in audit.records] == ["authorized", "succeeded"]
    assert all(record.arguments_sha256 for record in audit.records)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("agent", "skill"),
    [
        ("ReviewerAgent", "code-root-cause"),
        ("LocatorAgent", "pr-reviewer"),
    ],
)
async def test_policy_denies_wrong_agent_or_skill_before_transport(
    policy: MCPPolicy, agent: str, skill: str
) -> None:
    transport = RecordingTransport()
    audit = MemoryAuditSink()
    client = PolicyEnforcedMCPClient(transport, policy, audit)

    with pytest.raises(MCPAuthorizationError):
        await client.call_tool(
            "github",
            "get_file_contents",
            {"owner": "example", "repo": "repo", "path": "src/app.py"},
            context=_context(agent=agent, skill=skill),
        )

    assert transport.calls == []
    assert [record.outcome for record in audit.records] == ["denied"]


def test_policy_exposes_no_github_write_and_denies_repository_escape(
    policy: MCPPolicy,
) -> None:
    reviewer = _context(agent="ReviewerAgent", skill="pr-reviewer")

    with pytest.raises(MCPAuthorizationError, match="not registered"):
        policy.authorize(
            reviewer,
            "github",
            "create_pull_request",
            {"branch": "main", "title": "unsafe", "body": "unsafe"},
        )
    with pytest.raises(MCPAuthorizationError, match="escapes repository"):
        policy.authorize(
            _context(),
            "github",
            "get_file_contents",
            {"owner": "example", "repo": "repo", "path": "../secret"},
        )


def _rollback_policy(
    tmp_path: Path,
    authority: HMACApprovalAuthority | None,
) -> MCPPolicy:
    path = tmp_path / "test-only-rollback-policy.yaml"
    path.write_text(
        """
servers:
  cicd:
    enabled: true
    tools:
      - name: rollback_deployment
        allowed_agents: [TeamLeader]
        allowed_skills: [test-only-approval-engine]
        readonly: false
        requires_confirmation: true
""".lstrip(),
        encoding="utf-8",
    )
    return MCPPolicy.from_file(path, approval_verifier=authority)


def test_approval_engine_requires_signed_target_and_digest_bound_evidence(
    tmp_path: Path,
) -> None:
    authority = HMACApprovalAuthority(b"test-only-approval-signing-key-32-bytes")
    policy = _rollback_policy(tmp_path, authority)
    arguments = {"environment": "production", "target_release": "v1.2.3"}
    serialized = json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    leader = _context(agent="TeamLeader", skill="test-only-approval-engine")

    with pytest.raises(MCPAuthorizationError, match="approval evidence"):
        policy.authorize(leader, "cicd", "rollback_deployment", arguments)

    evidence = authority.issue(
        action="cicd:rollback_deployment",
        target="production:v1.2.3",
        artifact_digest=digest,
        approved_by="human:reviewer",
    )
    approved = leader.model_copy(update={"approval": evidence})
    assert policy.authorize(
        approved, "cicd", "rollback_deployment", arguments
    ).requires_confirmation

    tampered = evidence.model_copy(update={"target": "staging:v1.2.3"})
    with pytest.raises(MCPAuthorizationError, match="signature, scope, target"):
        policy.authorize(
            leader.model_copy(update={"approval": tampered}),
            "cicd",
            "rollback_deployment",
            arguments,
        )


def test_approval_engine_denies_expired_or_unverifiable_evidence(
    tmp_path: Path,
) -> None:
    authority = HMACApprovalAuthority(b"test-only-approval-signing-key-32-bytes")
    arguments = {"environment": "production", "target_release": None}
    digest = hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    expired = authority.issue(
        action="cicd:rollback_deployment",
        target="production:previous-good",
        artifact_digest=digest,
        approved_by="human:reviewer",
        approved_at=datetime.now(timezone.utc) - timedelta(days=2),
    )
    context = _context(
        agent="TeamLeader",
        skill="test-only-approval-engine",
        approval=expired,
    )
    policy = _rollback_policy(tmp_path, authority)
    with pytest.raises(MCPAuthorizationError, match="expiry"):
        policy.authorize(context, "cicd", "rollback_deployment", arguments)

    no_verifier = _rollback_policy(tmp_path, None)
    with pytest.raises(MCPAuthorizationError, match="verifier is unavailable"):
        no_verifier.authorize(context, "cicd", "rollback_deployment", arguments)


@pytest.mark.asyncio
async def test_internal_cicd_receives_verified_context(policy: MCPPolicy) -> None:
    transport = RecordingTransport({"passed": 1})
    authority = HMACContextAuthority(b"test-only-context-signing-key-32-bytes")
    client = PolicyEnforcedMCPClient(transport, policy, MemoryAuditSink(), context_signer=authority)
    tester = _context(agent="TesterAgent", skill="test-runner")

    await client.call_tool(
        "devflow-cicd-portable",
        "run_tests",
        {"issue_id": 42, "patch": _patch().model_dump(mode="json")},
        context=tester,
    )

    outbound = transport.calls[0][2]
    assert outbound["devflow_context"]["agent"] == "TesterAgent"
    assert outbound["devflow_context"]["skill"] == "test-runner"
    signed = MCPCallContext.model_validate(outbound["devflow_context"])
    assert authority.verify(signed)
    assert not authority.verify(signed.model_copy(update={"agent": "ReviewerAgent"}))


@pytest.mark.asyncio
async def test_internal_cicd_denies_when_context_signer_is_unavailable(
    policy: MCPPolicy,
) -> None:
    transport = RecordingTransport()
    audit = MemoryAuditSink()
    client = PolicyEnforcedMCPClient(transport, policy, audit)

    with pytest.raises(MCPAuthorizationError, match="context signer"):
        await client.call_tool(
            "devflow-cicd-portable",
            "run_tests",
            {"issue_id": 42, "patch": _patch().model_dump(mode="json")},
            context=_context(agent="TesterAgent", skill="test-runner"),
        )

    assert transport.calls == []
    assert [entry.outcome for entry in audit.records] == ["denied"]


def test_portable_cicd_rejects_caller_selected_suite(policy: MCPPolicy) -> None:
    arguments = {
        "issue_id": 42,
        "patch": _patch().model_dump(mode="json"),
        "full_suite": False,
    }

    with pytest.raises(MCPAuthorizationError, match="only issue_id and patch"):
        policy.authorize(
            _context(agent="TesterAgent", skill="test-runner"),
            "devflow-cicd-portable",
            "run_tests",
            arguments,
        )


def test_canonical_agentteams_cicd_accepts_only_assignment_binding() -> None:
    policy = MCPPolicy.from_file(ROOT / "config" / "mcp_servers.yaml")
    context = _context(agent="TesterAgent", skill="test-runner")
    arguments = {
        "taskId": "task-42",
        "revision": "a" * 40,
        "workspaceBinding": "b" * 64,
    }

    grant = policy.authorize(context, "devflow-cicd", "run_tests", arguments)

    assert grant.server == "devflow-cicd"
    with pytest.raises(MCPAuthorizationError, match="accepts only"):
        policy.authorize(
            context,
            "devflow-cicd",
            "run_tests",
            {**arguments, "patch": _patch().model_dump(mode="json")},
        )


@pytest.mark.asyncio
async def test_hash_chain_audit_log_links_entries(tmp_path: Path) -> None:
    sink = HashChainAuditLog(tmp_path / "audit.jsonl")
    record = {
        "timestamp": datetime.now(timezone.utc),
        "run_id": "issue-42",
        "task_id": "task-1",
        "issue_id": 42,
        "agent": "LocatorAgent",
        "skill": "code-root-cause",
        "server": "github",
        "tool": "get_file_contents",
        "readonly": True,
        "outcome": "succeeded",
        "arguments_sha256": "a" * 64,
    }
    from devflow.mcp.policy import MCPAuditRecord

    await sink.record(MCPAuditRecord.model_validate(record))
    await sink.record(MCPAuditRecord.model_validate(record))
    lines = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]

    assert lines[0]["previous_hash"] == "0" * 64
    assert lines[1]["previous_hash"] == lines[0]["entry_hash"]
    assert lines[0]["entry_hash"] != lines[1]["entry_hash"]
    assert verify_audit_chain(tmp_path / "audit.jsonl")

    lines[0]["agent"] = "TamperedAgent"
    (tmp_path / "audit.jsonl").write_text(
        "\n".join(json.dumps(line) for line in lines) + "\n", encoding="utf-8"
    )
    assert not verify_audit_chain(tmp_path / "audit.jsonl")


@pytest.mark.asyncio
async def test_hash_chain_serializes_independent_concurrent_appenders(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    first = HashChainAuditLog(path)
    second = HashChainAuditLog(path)
    from devflow.mcp.policy import MCPAuditRecord

    def record(index: int) -> MCPAuditRecord:
        return MCPAuditRecord(
            timestamp=datetime.now(timezone.utc),
            run_id="run",
            task_id=f"task-{index}",
            issue_id=42,
            agent="TesterAgent",
            skill="test-runner",
            server="cicd",
            tool="run_tests",
            readonly=False,
            outcome="succeeded",
            arguments_sha256=hashlib.sha256(str(index).encode()).hexdigest(),
        )

    await asyncio.gather(
        *[(first if index % 2 else second).record(record(index)) for index in range(12)]
    )

    assert verify_audit_chain(path)
    assert len(path.read_text(encoding="utf-8").splitlines()) == 12


@pytest.mark.asyncio
async def test_hash_chain_refuses_to_append_after_external_tampering(
    tmp_path: Path,
) -> None:
    path = tmp_path / "audit.jsonl"
    sink = HashChainAuditLog(path)
    from devflow.mcp.policy import MCPAuditRecord

    record = MCPAuditRecord(
        timestamp=datetime.now(timezone.utc),
        run_id="run",
        task_id="task",
        issue_id=42,
        agent="TesterAgent",
        skill="test-runner",
        server="cicd",
        tool="run_tests",
        readonly=False,
        outcome="succeeded",
        arguments_sha256="a" * 64,
    )
    await sink.record(record)
    parsed = json.loads(path.read_text(encoding="utf-8"))
    parsed["outcome"] = "failed"
    path.write_text(json.dumps(parsed) + "\n", encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(ConfigError, match="invalid"):
        await sink.record(record)

    assert path.read_bytes() == before


@pytest.mark.asyncio
async def test_isolated_test_service_never_mutates_canonical_repo(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    original = "def add(a, b):\n    return a - b\n"
    (repo / "calculator.py").write_text(original, encoding="utf-8")
    (repo / "test_calculator.py").write_text(
        "import unittest\nfrom calculator import add\n"
        "class T(unittest.TestCase):\n"
        "    def test_add(self): self.assertEqual(add(2, 3), 5)\n",
        encoding="utf-8",
    )
    service = IsolatedTestService(
        repo,
        (sys.executable, "-m", "unittest", "discover", "-v"),
        (sys.executable, "-m", "unittest", "discover", "-v"),
        timeout_seconds=30,
    )

    result = await service.run_tests(_patch(original), risk_tier="T3")

    assert result.passed == 1
    assert result.baseline_comparison is not None
    assert result.baseline_comparison.baseline_passed == 0
    assert result.baseline_comparison.fixed_tests
    assert (repo / "calculator.py").read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_isolated_test_service_rejects_stale_candidate(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "calculator.py").write_text("current\n", encoding="utf-8")
    command = (sys.executable, "-c", "print('ok')")
    service = IsolatedTestService(repo, command, command)

    with pytest.raises(MCPError, match="stale original content"):
        await service.run_tests(_patch("stale\n"), risk_tier="T2")

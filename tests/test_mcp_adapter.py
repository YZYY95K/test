"""Production adapter checks for the optional FastMCP server."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from devflow.exceptions import MCPAuthorizationError  # noqa: E402
from devflow.mcp.cicd_server import _require_portable_context, build_server  # noqa: E402
from devflow.mcp.contracts import MCPCallContext  # noqa: E402


def _configure(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    monkeypatch.setenv("DEVFLOW_REPOSITORY_ROOT", str(repository))
    monkeypatch.setenv(
        "CICD_FOCUSED_TEST_COMMAND_JSON",
        json.dumps([sys.executable, "-m", "pytest", "-q", "--maxfail=1"]),
    )
    monkeypatch.setenv(
        "CICD_FULL_TEST_COMMAND_JSON",
        json.dumps([sys.executable, "-m", "pytest", "-q"]),
    )
    monkeypatch.setenv("DEVFLOW_MCP_CONTEXT_HMAC_KEY", "test-only-context-signing-key-32-bytes")
    monkeypatch.setenv("DEVFLOW_APPROVAL_HMAC_KEY", "test-only-approval-signing-key-32-bytes")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(repository / "mcp-audit.jsonl"))
    monkeypatch.setenv("CICD_REPLAY_STATE_PATH", str(repository / "mcp-replay.sqlite3"))
    monkeypatch.setenv("CICD_RELEASE_STATE_PATH", str(repository / "releases.json"))
    monkeypatch.setenv("MCP_CICD_PORT", "8766")


def test_fastmcp_adapter_builds_on_loopback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure(monkeypatch, tmp_path)
    monkeypatch.setenv("MCP_CICD_HOST", "127.0.0.1")

    server = build_server()

    assert type(server).__name__ == "FastMCP"
    tools = asyncio.run(server.list_tools())
    assert {tool.name for tool in tools} == {"run_tests"}
    schema = tools[0].inputSchema
    assert set(schema["properties"]) == {"issue_id", "patch", "devflow_context"}
    assert "full_suite" not in schema["properties"]


def test_fastmcp_adapter_rejects_public_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure(monkeypatch, tmp_path)
    monkeypatch.setenv("MCP_CICD_HOST", "0.0.0.0")

    with pytest.raises(ValueError, match="loopback"):
        build_server()


def test_portable_context_binds_issue_and_requires_risk_tier() -> None:
    context = MCPCallContext(
        run_id="run-42",
        issue_id=42,
        task_id="task-42",
        agent="TesterAgent",
        skill="test-runner",
        trace_id="run-42:task-42",
        idempotency_key="run-42:task-42:portable",
        risk_tier="T2",
    )

    _require_portable_context(context, {"issue_id": 42, "patch": {}})
    with pytest.raises(MCPAuthorizationError, match="does not match"):
        _require_portable_context(context, {"issue_id": 43, "patch": {}})
    with pytest.raises(MCPAuthorizationError, match="requires risk_tier"):
        _require_portable_context(
            context.model_copy(update={"risk_tier": None}),
            {"issue_id": 42, "patch": {}},
        )

"""Production adapter checks for the optional FastMCP server."""

from __future__ import annotations

import asyncio
import json
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

from devflow.mcp.approval import HMACApprovalAuthority  # noqa: E402
from devflow.mcp.cicd_server import build_server  # noqa: E402
from devflow.mcp.context_auth import HMACContextAuthority  # noqa: E402
from devflow.mcp.contracts import MCPCallContext  # noqa: E402
from devflow.mcp.policy import arguments_digest, verify_audit_chain  # noqa: E402
from devflow.observability import metrics  # noqa: E402


@contextmanager
def _healthy_endpoint() -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/health"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _configure(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    monkeypatch.setenv("DEVFLOW_REPOSITORY_ROOT", str(repository))
    monkeypatch.setenv("CICD_TEST_COMMAND_JSON", json.dumps([sys.executable, "-m", "pytest", "-q"]))
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
    assert {tool.name for tool in asyncio.run(server.list_tools())} == {
        "run_tests",
        "trigger_pipeline",
        "get_test_results",
        "get_coverage",
        "rollback_deployment",
    }


def test_fastmcp_adapter_rejects_public_bind(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure(monkeypatch, tmp_path)
    monkeypatch.setenv("MCP_CICD_HOST", "0.0.0.0")

    with pytest.raises(ValueError, match="loopback"):
        build_server()


@pytest.mark.asyncio
async def test_fastmcp_rollback_closes_policy_credential_health_and_audit_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _configure(monkeypatch, tmp_path)
    state_path = tmp_path / "releases.json"
    state_path.write_text(
        json.dumps({"production": {"current": "v2", "previous": "v1"}}),
        encoding="utf-8",
    )
    sentinel = "provider-sentinel-not-a-real-credential"
    monkeypatch.setenv("DEVFLOW_CREDENTIAL_BROKER_HMAC_KEY", "broker-key-32-bytes-test-only-value")
    monkeypatch.setenv("CICD_ROLLBACK_CREDENTIAL_SOURCE", "TEST_PROVIDER_SOURCE")
    monkeypatch.setenv("CICD_ROLLBACK_CREDENTIAL_ENV", "PROVIDER_AUTH")
    monkeypatch.setenv("TEST_PROVIDER_SOURCE", sentinel)
    monkeypatch.setenv(
        "CICD_ROLLBACK_COMMAND_JSON",
        json.dumps(
            [
                sys.executable,
                "-c",
                "import os,sys; sys.exit(0 if "
                f"os.environ.get('PROVIDER_AUTH') == {sentinel!r} and "
                "os.environ.get('DEVFLOW_TARGET_RELEASE') == 'v1' else 9)",
            ]
        ),
    )
    arguments = {"environment": "production", "target_release": "v1"}
    approval_authority = HMACApprovalAuthority(b"test-only-approval-signing-key-32-bytes")
    approval = approval_authority.issue(
        action="cicd:rollback_deployment",
        target="production:v1",
        artifact_digest=arguments_digest(arguments),
        approved_by="human:release-manager",
    )
    context = MCPCallContext(
        run_id="run-rollback-1",
        issue_id=42,
        task_id="task-rollback-1",
        agent="TeamLeader",
        skill="team-orchestration",
        trace_id="trace-rollback-1",
        idempotency_key="rollback-production-v1",
        risk_tier="T4",
        approval=approval,
    )
    signed = HMACContextAuthority(b"test-only-context-signing-key-32-bytes").sign(context)

    with _healthy_endpoint() as health_url:
        monkeypatch.setenv("HEALTH_CHECK_URL", health_url)
        server = build_server()
        payload = {**arguments, "devflow_context": signed.model_dump(mode="json")}
        await server.call_tool("rollback_deployment", payload)
        restarted_server = build_server()
        with pytest.raises(ToolError, match="already consumed"):
            await restarted_server.call_tool("rollback_deployment", payload)

    state = json.loads(state_path.read_text(encoding="utf-8"))
    audit_path = tmp_path / "mcp-audit.jsonl"
    audit_text = audit_path.read_text(encoding="utf-8")
    assert state["production"]["current"] == "v1"
    assert verify_audit_chain(audit_path)
    assert [json.loads(line)["outcome"] for line in audit_text.splitlines()] == [
        "authorized",
        "succeeded",
        "denied",
    ]
    assert sentinel not in audit_text
    exposition = metrics.render_prometheus()
    assert "devflow_mcp_tool_calls_total" in exposition
    assert "devflow_mcp_tool_duration_seconds_bucket" in exposition

"""Production adapter checks for the optional FastMCP server."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from devflow.mcp.cicd_server import build_server  # noqa: E402


def _configure(monkeypatch: pytest.MonkeyPatch, repository: Path) -> None:
    monkeypatch.setenv("DEVFLOW_REPOSITORY_ROOT", str(repository))
    monkeypatch.setenv(
        "CICD_TEST_COMMAND_JSON", json.dumps([sys.executable, "-m", "pytest", "-q"])
    )
    monkeypatch.setenv(
        "DEVFLOW_MCP_CONTEXT_HMAC_KEY", "test-only-context-signing-key-32-bytes"
    )
    monkeypatch.setenv(
        "DEVFLOW_APPROVAL_HMAC_KEY", "test-only-approval-signing-key-32-bytes"
    )
    monkeypatch.setenv("AUDIT_LOG_PATH", str(repository / "mcp-audit.jsonl"))
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

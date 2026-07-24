"""FastMCP adapter for the policy-bound isolated CI/CD service."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any

from devflow.exceptions import MCPAuthorizationError
from devflow.mcp.cicd import IsolatedTestService
from devflow.mcp.context_auth import HMACContextAuthority
from devflow.mcp.contracts import MCPCallContext
from devflow.mcp.policy import MCPPolicy
from devflow.models.patch import Patch


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _test_command() -> tuple[str, ...]:
    raw = os.getenv("CICD_TEST_COMMAND_JSON")
    if not raw:
        return (sys.executable, "-m", "pytest", "-q")
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or not all(isinstance(item, str) and item for item in parsed):
        raise ValueError("CICD_TEST_COMMAND_JSON must be a non-empty JSON argv list")
    return tuple(parsed)


def build_server() -> Any:
    """Build the optional FastMCP server without importing MCP at module load."""

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError('Install DevFlow with the "mcp" extra to run this server') from exc

    host = os.getenv("MCP_CICD_HOST", "127.0.0.1")
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host == "localhost"
    if not is_loopback:
        raise ValueError("CI/CD MCP server must bind to a loopback address")
    port = int(os.getenv("MCP_CICD_PORT", "8766"))
    if not 1 <= port <= 65535:
        raise ValueError("MCP_CICD_PORT must be between 1 and 65535")
    server = FastMCP("devflow-cicd", host=host, port=port)
    policy = MCPPolicy.from_file(_project_root() / "config" / "mcp_servers.yaml")
    context_key = os.environ["DEVFLOW_MCP_CONTEXT_HMAC_KEY"].encode("utf-8")
    context_authority = HMACContextAuthority(context_key)
    service = IsolatedTestService(
        Path(os.environ["DEVFLOW_REPOSITORY_ROOT"]),
        _test_command(),
        timeout_seconds=int(os.getenv("CICD_TEST_TIMEOUT_SECONDS", "600")),
    )

    @server.tool()
    async def run_tests(
        issue_id: int,
        patch: dict[str, Any],
        full_suite: bool,
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run the server-owned test adapter in disposable isolation."""

        context = MCPCallContext.model_validate(devflow_context)
        if not context_authority.verify(context):
            raise MCPAuthorizationError("internal MCP context signature is invalid")
        arguments = {"issue_id": issue_id, "patch": patch, "full_suite": full_suite}
        policy.authorize(context, "cicd", "run_tests", arguments)
        result = await service.run_tests(Patch.model_validate(patch), full_suite=full_suite)
        return result.model_dump(mode="json")

    return server


def main() -> None:
    """Start the loopback-only streamable HTTP MCP server."""

    build_server().run(transport="streamable-http")


if __name__ == "__main__":
    main()

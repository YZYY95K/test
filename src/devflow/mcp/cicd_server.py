"""FastMCP adapter for policy-bound CI, coverage, and rollback services."""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from devflow.exceptions import MCPAuthorizationError, MCPError
from devflow.mcp.approval import HMACApprovalAuthority
from devflow.mcp.cicd import IsolatedTestService
from devflow.mcp.context_auth import HMACContextAuthority
from devflow.mcp.contracts import MCPCallContext
from devflow.mcp.pipeline import PipelineService, RollbackService
from devflow.mcp.policy import (
    HashChainAuditLog,
    MCPAuditRecord,
    MCPPolicy,
    arguments_digest,
)
from devflow.models.patch import Patch
from devflow.observability import configure_otlp_tracing, start_prometheus_server


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _json_argv(name: str, default: tuple[str, ...] | None = None) -> tuple[str, ...] | None:
    raw = os.getenv(name)
    if not raw:
        return default
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or not parsed or not all(
        isinstance(item, str) and item for item in parsed
    ):
        raise ValueError(f"{name} must be a non-empty JSON argv list")
    return tuple(parsed)


def _test_command() -> tuple[str, ...]:
    return _json_argv(
        "CICD_TEST_COMMAND_JSON", (sys.executable, "-m", "pytest", "-q")
    ) or (sys.executable, "-m", "pytest", "-q")


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
    server = FastMCP("devflow-cicd", host=host, port=port)
    approval_authority = HMACApprovalAuthority(
        os.environ["DEVFLOW_APPROVAL_HMAC_KEY"].encode("utf-8")
    )
    policy = MCPPolicy.from_file(
        _project_root() / "config" / "mcp_servers.yaml",
        approval_verifier=approval_authority,
    )
    context_authority = HMACContextAuthority(
        os.environ["DEVFLOW_MCP_CONTEXT_HMAC_KEY"].encode("utf-8")
    )
    audit = HashChainAuditLog(_path_from_env("AUDIT_LOG_PATH", "logs/mcp-audit.jsonl"))
    test_service = IsolatedTestService(
        Path(os.environ["DEVFLOW_REPOSITORY_ROOT"]),
        _test_command(),
        timeout_seconds=int(os.getenv("CICD_TEST_TIMEOUT_SECONDS", "600")),
    )
    pipelines = PipelineService(test_service)
    rollback = RollbackService(
        _path_from_env("CICD_RELEASE_STATE_PATH", ".devflow/releases.json"),
        command=_json_argv("CICD_ROLLBACK_COMMAND_JSON"),
        health_check_url=os.getenv("HEALTH_CHECK_URL") or None,
        timeout_seconds=int(os.getenv("CICD_ROLLBACK_TIMEOUT_SECONDS", "120")),
    )

    async def invoke(
        tool: str,
        arguments: dict[str, Any],
        raw_context: dict[str, Any],
        operation: Callable[[], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        context = MCPCallContext.model_validate(raw_context)
        if not context_authority.verify(context):
            raise MCPAuthorizationError("internal MCP context signature is invalid")
        digest = arguments_digest(arguments)
        try:
            grant = policy.authorize(context, "cicd", tool, arguments)
        except MCPAuthorizationError as exc:
            await _audit(audit, context, tool, False, "denied", digest, str(exc))
            raise
        await _audit(audit, context, tool, grant.readonly, "authorized", digest)
        try:
            result = await operation()
        except Exception as exc:
            await _audit(
                audit, context, tool, grant.readonly, "failed", digest, type(exc).__name__
            )
            raise
        await _audit(audit, context, tool, grant.readonly, "succeeded", digest)
        return result

    @server.tool()
    async def run_tests(
        issue_id: int,
        patch: dict[str, Any],
        full_suite: bool,
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run the server-owned test adapter in disposable isolation."""

        arguments = {"issue_id": issue_id, "patch": patch, "full_suite": full_suite}

        async def operation() -> dict[str, Any]:
            result = await test_service.run_tests(
                Patch.model_validate(patch), full_suite=full_suite
            )
            return result.model_dump(mode="json")

        return await invoke("run_tests", arguments, devflow_context, operation)

    @server.tool()
    async def trigger_pipeline(
        branch: str,
        suite: str,
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Run a server-owned CI command in a disposable checkout."""

        arguments = {"branch": branch, "suite": suite}

        async def operation() -> dict[str, Any]:
            return (await pipelines.trigger(branch=branch, suite=suite)).model_dump(
                mode="json"
            )

        return await invoke("trigger_pipeline", arguments, devflow_context, operation)

    @server.tool()
    async def get_test_results(
        pipeline_id: str,
        wait_seconds: int,
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Return the immutable result for a known pipeline id."""

        if not 0 <= wait_seconds <= 120:
            raise MCPError("wait_seconds must be between 0 and 120")
        arguments = {"pipeline_id": pipeline_id, "wait_seconds": wait_seconds}

        async def operation() -> dict[str, Any]:
            return (await pipelines.get(pipeline_id)).model_dump(mode="json")

        return await invoke("get_test_results", arguments, devflow_context, operation)

    @server.tool()
    async def get_coverage(
        pipeline_id: str,
        baseline_ref: str,
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Return coverage captured from the pipeline's disposable checkout."""

        arguments = {"pipeline_id": pipeline_id, "baseline_ref": baseline_ref}

        async def operation() -> dict[str, Any]:
            return (await pipelines.coverage(pipeline_id)).model_dump(mode="json")

        return await invoke("get_coverage", arguments, devflow_context, operation)

    @server.tool()
    async def rollback_deployment(
        environment: str,
        target_release: str | None,
        devflow_context: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute a signed, server-owned rollback provider adapter."""

        arguments = {"environment": environment, "target_release": target_release}

        async def operation() -> dict[str, Any]:
            return (
                await rollback.rollback(
                    environment=environment, target_release=target_release
                )
            ).model_dump(mode="json")

        return await invoke("rollback_deployment", arguments, devflow_context, operation)

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
            server="cicd",
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

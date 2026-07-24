"""Integration tests for executable infrastructure that config alone cannot prove."""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path
from urllib.request import urlopen

import pytest

from devflow.exceptions import MCPAuthorizationError
from devflow.mcp.cicd import IsolatedTestService
from devflow.mcp.pipeline import PipelineService, RollbackService
from devflow.observability import Metrics, start_prometheus_server
from devflow.security.credentials import CredentialBroker


@pytest.mark.asyncio
async def test_pipeline_runs_in_disposable_copy_and_captures_coverage(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "canonical.txt").write_text("unchanged", encoding="utf-8")
    command = (
        sys.executable,
        "-c",
        "import json,pathlib; "
        "pathlib.Path('coverage.json').write_text(json.dumps({'totals': {"
        "'percent_covered': 82.5, 'percent_covered_branches': 75.0}})); "
        "pathlib.Path('canonical.txt').write_text('candidate-only')",
    )
    service = PipelineService(IsolatedTestService(repository, command))

    record = await service.trigger(branch="devflow/benchmark", suite="full")
    fetched = await service.get(record.pipeline_id)
    coverage = await service.coverage(record.pipeline_id)

    assert fetched.status == "passed"
    assert coverage.line_percent == 82.5
    assert coverage.branch_percent == 75.0
    assert (repository / "canonical.txt").read_text(encoding="utf-8") == "unchanged"


@pytest.mark.asyncio
async def test_rollback_uses_server_owned_command_and_updates_registry(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "releases.json"
    state_path.write_text(
        json.dumps({"production": {"current": "v2", "previous": "v1"}}),
        encoding="utf-8",
    )
    command = (
        sys.executable,
        "-c",
        "import os,sys; sys.exit(0 if "
        "os.environ['DEVFLOW_DEPLOYMENT_ENVIRONMENT']=='production' and "
        "os.environ['DEVFLOW_TARGET_RELEASE']=='v1' else 2)",
    )
    service = RollbackService(state_path, command=command)

    result = await service.rollback(environment="production", target_release=None)
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert result.restored_release == "v1"
    assert result.health_verified is True
    assert state["production"]["current"] == "v1"
    assert state["production"]["previous"] == "v2"


def test_credential_broker_never_places_secret_in_agent_handle() -> None:
    broker = CredentialBroker(
        b"test-only-credential-broker-key-32-bytes",
        agent_capabilities={"LocatorAgent": {"github:read_file"}},
        capability_secrets={"github:read_file": "TEST_GITHUB_TOKEN"},
        environment={"TEST_GITHUB_TOKEN": "provider-secret-value"},
    )
    handle = broker.issue(agent="LocatorAgent", capability="github:read_file")

    assert "provider-secret-value" not in handle.model_dump_json()
    assert (
        broker.resolve(
            handle,
            expected_agent="LocatorAgent",
            expected_capability="github:read_file",
        )
        == "provider-secret-value"
    )
    with pytest.raises(MCPAuthorizationError, match="scope"):
        broker.resolve(
            handle,
            expected_agent="ReviewerAgent",
            expected_capability="github:read_file",
        )

    expired = handle.model_copy(
        update={"expires_at": handle.expires_at - timedelta(hours=2)}
    )
    with pytest.raises(MCPAuthorizationError, match="signature"):
        broker.resolve(
            expired,
            expected_agent="LocatorAgent",
            expected_capability="github:read_file",
        )


def test_prometheus_endpoint_exposes_metrics_on_loopback() -> None:
    registry = Metrics()
    registry.counter("devflow_test_events_total").inc(labels={"result": "ok"})
    registry.histogram("devflow_test_duration_seconds").observe(0.25)
    server = start_prometheus_server(port=0, registry=registry)
    try:
        with urlopen(f"http://127.0.0.1:{server.port}/metrics", timeout=5) as response:
            payload = response.read().decode("utf-8")
    finally:
        server.close()

    assert "devflow_test_events_total{result=\"ok\"} 1.0" in payload
    assert "devflow_test_duration_seconds_count 1" in payload


def test_prometheus_endpoint_rejects_public_bind() -> None:
    with pytest.raises(ValueError, match="loopback"):
        start_prometheus_server(host="0.0.0.0", port=0)

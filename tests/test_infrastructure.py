"""Integration tests for executable infrastructure that config alone cannot prove."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Iterator
from concurrent import futures
from contextlib import contextmanager
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.request import urlopen

import pytest

from devflow.exceptions import MCPAuthorizationError, MCPError
from devflow.mcp.cicd import IsolatedTestService
from devflow.mcp.pipeline import PipelineService, RollbackService
from devflow.observability import (
    Metrics,
    configure_otlp_tracing,
    start_prometheus_server,
)
from devflow.security.credentials import CredentialBroker, CredentialEnvironmentProxy


def _git(repository: Path, *arguments: str) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    assert process.returncode == 0, process.stderr
    return process.stdout.strip()


def _commit_repository(repository: Path) -> tuple[str, str]:
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.name", "DevFlow Test")
    _git(repository, "config", "user.email", "devflow-test@example.invalid")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "fixture")
    _git(repository, "branch", "devflow/benchmark")
    return _git(repository, "rev-parse", "HEAD"), _git(repository, "rev-parse", "HEAD^{tree}")


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


@pytest.mark.asyncio
async def test_pipeline_runs_in_disposable_copy_and_captures_coverage(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "canonical.txt").write_text("committed", encoding="utf-8")
    command = (
        sys.executable,
        "-c",
        "import json,pathlib,sys; "
        "source=pathlib.Path('canonical.txt').read_text(); "
        "pathlib.Path('coverage.json').write_text(json.dumps({'totals': {"
        "'percent_covered': 82.5, 'percent_covered_branches': 75.0}})); "
        "pathlib.Path('canonical.txt').write_text('candidate-only'); "
        "sys.exit(0 if source == 'committed' else 3)",
    )
    commit_sha, tree_sha = _commit_repository(repository)
    (repository / "canonical.txt").write_text("dirty-working-tree", encoding="utf-8")
    service = PipelineService(IsolatedTestService(repository, command, command))

    record = await service.trigger(branch="devflow/benchmark", suite="full")
    assert record.status == "queued"
    fetched = await service.get(record.pipeline_id, wait_seconds=10)
    coverage = await service.coverage(record.pipeline_id)

    assert fetched.status == "passed"
    assert fetched.commit_sha == commit_sha
    assert fetched.tree_sha == tree_sha
    assert coverage.line_percent == 82.5
    assert coverage.branch_percent == 75.0
    assert (repository / "canonical.txt").read_text(encoding="utf-8") == "dirty-working-tree"


@pytest.mark.asyncio
async def test_pipeline_rejects_unknown_ref_and_unconfigured_suite(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "tracked.txt").write_text("tracked", encoding="utf-8")
    _commit_repository(repository)
    service = PipelineService(
        IsolatedTestService(
            repository,
            (sys.executable, "-c", "raise SystemExit(0)"),
            (sys.executable, "-c", "raise SystemExit(0)"),
        )
    )

    with pytest.raises(MCPError, match="ref is unavailable"):
        await service.trigger(branch="missing/ref", suite="full")
    with pytest.raises(MCPError, match="no server-owned command"):
        await service.trigger(branch="main", suite="smoke")


def test_test_command_environment_is_allowlisted_and_output_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    sentinel = "".join(("ghp_", "A1b2C3d4E5f6G7h8I9j0", "K1l2M3n4O5p6Q7r8S9t0"))
    monkeypatch.setenv("UNRELATED_PROVIDER_TOKEN", sentinel)
    command = (
        sys.executable,
        "-c",
        "import os; print(os.getenv('UNRELATED_PROVIDER_TOKEN', 'not-inherited')); "
        f"print({sentinel!r})",
    )
    service = IsolatedTestService(tmp_path, command, command)

    outcome = service.execute(tmp_path)

    assert outcome.returncode == 0
    assert "not-inherited" in outcome.output
    assert sentinel not in outcome.output
    assert "[REDACTED]" in outcome.output


@pytest.mark.asyncio
async def test_rollback_uses_server_owned_command_and_updates_registry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "releases.json"
    state_path.write_text(
        json.dumps({"production": {"current": "v2", "previous": "v1"}}),
        encoding="utf-8",
    )
    provider_sentinel = "provider-sentinel-not-a-real-credential"
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-cross-provider-boundary")
    command = (
        sys.executable,
        "-c",
        "import os,sys; sys.exit(0 if "
        "os.environ['DEVFLOW_DEPLOYMENT_ENVIRONMENT']=='production' and "
        "os.environ['DEVFLOW_TARGET_RELEASE']=='v1' and "
        f"os.environ['PROVIDER_AUTH']=={provider_sentinel!r} and "
        "'UNRELATED_SECRET' not in os.environ else 2)",
    )
    with _healthy_endpoint() as health_url:
        service = RollbackService(
            state_path,
            command=command,
            health_check_url=health_url,
        )
        result = await service.rollback(
            environment="production",
            target_release=None,
            provider_environment={"PROVIDER_AUTH": provider_sentinel},
        )
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert result.restored_release == "v1"
    assert result.health_verified is True
    assert state["production"]["current"] == "v1"
    assert state["production"]["previous"] == "v2"


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["command", "health"])
async def test_rollback_fails_closed_when_provider_boundary_is_incomplete(
    tmp_path: Path,
    missing: str,
) -> None:
    state_path = tmp_path / "releases.json"
    original = {"production": {"current": "v2", "previous": "v1"}}
    state_path.write_text(json.dumps(original), encoding="utf-8")
    command = None if missing == "command" else (sys.executable, "-c", "pass")
    health_url = None if missing == "health" else "http://127.0.0.1:1/health"
    service = RollbackService(
        state_path,
        command=command,
        health_check_url=health_url,
    )

    with pytest.raises(MCPError, match=f"{missing}.*not configured"):
        await service.rollback(environment="production", target_release=None)

    assert json.loads(state_path.read_text(encoding="utf-8")) == original


@pytest.mark.asyncio
async def test_rollback_rejects_target_not_registered_as_known_good(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "releases.json"
    original = {"production": {"current": "v3", "previous": "v2", "known_good": ["v1"]}}
    state_path.write_text(json.dumps(original), encoding="utf-8")
    with _healthy_endpoint() as health_url:
        service = RollbackService(
            state_path,
            command=(sys.executable, "-c", "pass"),
            health_check_url=health_url,
        )
        with pytest.raises(MCPError, match="known-good"):
            await service.rollback(environment="production", target_release="v0")

    assert json.loads(state_path.read_text(encoding="utf-8")) == original


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

    expired = handle.model_copy(update={"expires_at": handle.expires_at - timedelta(hours=2)})
    with pytest.raises(MCPAuthorizationError, match="signature"):
        broker.resolve(
            expired,
            expected_agent="LocatorAgent",
            expected_capability="github:read_file",
        )


def test_credential_proxy_resolves_only_exact_agent_capability_and_variable() -> None:
    sentinel = "provider-sentinel-not-a-real-credential"
    broker = CredentialBroker(
        b"test-only-credential-broker-key-32-bytes",
        agent_capabilities={"TeamLeader": {"cicd:rollback"}},
        capability_secrets={"cicd:rollback": "TEST_ROLLBACK_CREDENTIAL"},
        environment={"TEST_ROLLBACK_CREDENTIAL": sentinel},
    )
    proxy = CredentialEnvironmentProxy(
        broker,
        capability="cicd:rollback",
        provider_variable="PROVIDER_AUTH",
    )

    assert proxy.resolve_for_provider(agent="TeamLeader") == {"PROVIDER_AUTH": sentinel}
    with pytest.raises(MCPAuthorizationError, match="not granted"):
        proxy.resolve_for_provider(agent="TesterAgent")
    with pytest.raises(ValueError, match="environment name"):
        CredentialEnvironmentProxy(
            broker,
            capability="cicd:rollback",
            provider_variable="INVALID-NAME",
        )
    with pytest.raises(ValueError, match="bootstrap"):
        CredentialEnvironmentProxy(
            broker,
            capability="cicd:rollback",
            provider_variable="PATH",
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

    assert 'devflow_test_events_total{result="ok"} 1.0' in payload
    assert "# TYPE devflow_test_duration_seconds histogram" in payload
    assert 'devflow_test_duration_seconds_bucket{le="0.25"} 1' in payload
    assert 'devflow_test_duration_seconds_bucket{le="+Inf"} 1' in payload
    assert "devflow_test_duration_seconds_count 1" in payload


def test_prometheus_endpoint_rejects_public_bind() -> None:
    with pytest.raises(ValueError, match="loopback"):
        start_prometheus_server(host="0.0.0.0", port=0)


def test_prometheus_histogram_rejects_bucket_definition_drift() -> None:
    registry = Metrics()
    registry.histogram("devflow_duration_seconds", buckets=(0.1, 1.0))

    with pytest.raises(ValueError, match="cannot change"):
        registry.histogram("devflow_duration_seconds", buckets=(0.1, 2.0))
    with pytest.raises(ValueError, match="increasing"):
        registry.histogram("devflow_invalid_seconds", buckets=(1.0, 0.1))


def test_trace_provider_exports_spans_through_sdk_batch_pipeline() -> None:
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = configure_otlp_tracing(
        "offline.invalid:4317",
        service_name="devflow-offline-verification",
        span_exporter=exporter,
        set_global=False,
    )
    try:
        with provider.get_tracer("devflow-test").start_as_current_span(
            "devflow.mcp.cicd.invoke"
        ) as span:
            span.set_attribute("devflow.mcp.tool", "trigger_pipeline")
        assert provider.force_flush(timeout_millis=5000)
        exported = exporter.get_finished_spans()
    finally:
        provider.shutdown()

    assert len(exported) == 1
    assert exported[0].name == "devflow.mcp.cicd.invoke"
    assert exported[0].attributes is not None
    assert exported[0].attributes["devflow.mcp.tool"] == "trigger_pipeline"
    assert exported[0].resource.attributes["service.name"] == ("devflow-offline-verification")


def test_trace_provider_reaches_a_real_otlp_grpc_collector() -> None:
    """Prove the production exporter reaches an actual OTLP/gRPC receiver."""

    import grpc
    from opentelemetry.proto.collector.trace.v1 import (
        trace_service_pb2,
        trace_service_pb2_grpc,
    )

    received: list[Any] = []
    receipt = threading.Event()

    class Collector(trace_service_pb2_grpc.TraceServiceServicer):
        def Export(self, request: Any, _context: Any) -> Any:  # noqa: N802
            received.append(request)
            receipt.set()
            return trace_service_pb2.ExportTraceServiceResponse()

    collector = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    trace_service_pb2_grpc.add_TraceServiceServicer_to_server(  # type: ignore[no-untyped-call]
        Collector(), collector
    )
    port = collector.add_insecure_port("127.0.0.1:0")
    assert port > 0
    collector.start()
    provider = configure_otlp_tracing(
        f"127.0.0.1:{port}",
        service_name="devflow-network-verification",
        insecure=True,
        set_global=False,
    )
    try:
        with provider.get_tracer("devflow-network-test").start_as_current_span(
            "devflow.mcp.cicd.network-receipt"
        ) as span:
            span.set_attribute("devflow.mcp.tool", "trigger_pipeline")
        assert provider.force_flush(timeout_millis=5000)
        assert receipt.wait(timeout=5)
    finally:
        provider.shutdown()
        collector.stop(grace=1).wait(timeout=5)

    assert len(received) == 1
    request = received[0]
    resource_spans = request.resource_spans
    assert len(resource_spans) == 1
    attributes = {
        item.key: item.value.string_value for item in resource_spans[0].resource.attributes
    }
    assert attributes["service.name"] == "devflow-network-verification"
    spans = resource_spans[0].scope_spans[0].spans
    assert [span.name for span in spans] == ["devflow.mcp.cicd.network-receipt"]

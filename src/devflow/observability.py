"""Structured logging, OTLP tracing, and a loopback Prometheus endpoint."""

from __future__ import annotations

import logging
import math
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import structlog
from opentelemetry import trace

_DEFAULT_HISTOGRAM_BUCKETS = (
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
    1200.0,
)


def _configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        cache_logger_on_first_use=True,
    )


_configure_logging()
logger = structlog.get_logger("devflow")
tracer = trace.get_tracer("devflow")


def _label_key(labels: dict[str, Any] | None) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((str(key), str(value)) for key, value in (labels or {}).items()))


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels_text(key: tuple[tuple[str, str], ...]) -> str:
    if not key:
        return ""
    body = ",".join(f'{name}="{_escape_label(value)}"' for name, value in key)
    return "{" + body + "}"


@dataclass
class _Counter:
    values: dict[tuple[tuple[str, str], ...], float] = field(
        default_factory=lambda: defaultdict(float)
    )
    lock: threading.RLock = field(default_factory=threading.RLock)

    def inc(self, amount: float = 1.0, *, labels: dict[str, Any] | None = None) -> None:
        if not math.isfinite(amount) or amount < 0:
            raise ValueError("counter increments must be finite and non-negative")
        with self.lock:
            self.values[_label_key(labels)] += amount


@dataclass
class _Histogram:
    buckets: tuple[float, ...] = _DEFAULT_HISTOGRAM_BUCKETS
    values: dict[tuple[tuple[str, str], ...], list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )
    lock: threading.RLock = field(default_factory=threading.RLock)

    def observe(self, value: float, *, labels: dict[str, Any] | None = None) -> None:
        if not math.isfinite(value):
            raise ValueError("histogram observations must be finite")
        with self.lock:
            self.values[_label_key(labels)].append(float(value))


@dataclass
class _Gauge:
    values: dict[tuple[tuple[str, str], ...], float] = field(
        default_factory=lambda: defaultdict(float)
    )
    lock: threading.RLock = field(default_factory=threading.RLock)

    def set(self, value: float, *, labels: dict[str, Any] | None = None) -> None:
        if not math.isfinite(value):
            raise ValueError("gauge values must be finite")
        with self.lock:
            self.values[_label_key(labels)] = float(value)

    def inc(self, amount: float = 1.0, *, labels: dict[str, Any] | None = None) -> None:
        with self.lock:
            self.values[_label_key(labels)] += amount

    def dec(self, amount: float = 1.0, *, labels: dict[str, Any] | None = None) -> None:
        self.inc(-amount, labels=labels)


class Metrics:
    """Thread-safe metric facade with native Prometheus text exposition."""

    def __init__(self) -> None:
        self._counters: dict[str, _Counter] = {}
        self._histograms: dict[str, _Histogram] = {}
        self._gauges: dict[str, _Gauge] = {}

    def counter(self, name: str) -> _Counter:
        return self._counters.setdefault(name, _Counter())

    def histogram(
        self,
        name: str,
        *,
        buckets: tuple[float, ...] | None = None,
    ) -> _Histogram:
        selected = buckets or _DEFAULT_HISTOGRAM_BUCKETS
        if (
            not selected
            or tuple(sorted(set(selected))) != selected
            or any(not math.isfinite(value) or value <= 0 for value in selected)
        ):
            raise ValueError("histogram buckets must be finite, positive, and increasing")
        existing = self._histograms.get(name)
        if existing is not None:
            if existing.buckets != selected:
                raise ValueError("histogram bucket definition cannot change")
            return existing
        metric = _Histogram(buckets=selected)
        self._histograms[name] = metric
        return metric

    def gauge(self, name: str) -> _Gauge:
        return self._gauges.setdefault(name, _Gauge())

    def record(
        self,
        *,
        name: str,
        value: float,
        unit: str,
        tags: dict[str, str] | None = None,
    ) -> None:
        self.histogram(name).observe(value, labels={"unit": unit, **(tags or {})})

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": {
                name: {str(key): value for key, value in metric.values.items()}
                for name, metric in self._counters.items()
            },
            "histograms": {
                name: {str(key): values for key, values in metric.values.items()}
                for name, metric in self._histograms.items()
            },
            "gauges": {
                name: {str(key): value for key, value in metric.values.items()}
                for name, metric in self._gauges.items()
            },
        }

    def render_prometheus(self) -> str:
        """Render valid Prometheus 0.0.4 text without exposing raw event data."""

        lines: list[str] = []
        for name, counter_metric in sorted(self._counters.items()):
            lines.extend((f"# TYPE {name} counter",))
            with counter_metric.lock:
                lines.extend(
                    f"{name}{_labels_text(key)} {value}"
                    for key, value in sorted(counter_metric.values.items())
                )
        for name, gauge_metric in sorted(self._gauges.items()):
            lines.extend((f"# TYPE {name} gauge",))
            with gauge_metric.lock:
                lines.extend(
                    f"{name}{_labels_text(key)} {value}"
                    for key, value in sorted(gauge_metric.values.items())
                )
        for name, histogram_metric in sorted(self._histograms.items()):
            lines.extend((f"# TYPE {name} histogram",))
            with histogram_metric.lock:
                for key, values in sorted(histogram_metric.values.items()):
                    labels = _labels_text(key)
                    for boundary in histogram_metric.buckets:
                        bucket_labels = _labels_text(tuple(sorted((*key, ("le", str(boundary))))))
                        count = sum(value <= boundary for value in values)
                        lines.append(f"{name}_bucket{bucket_labels} {count}")
                    infinite_labels = _labels_text(tuple(sorted((*key, ("le", "+Inf")))))
                    lines.append(f"{name}_bucket{infinite_labels} {len(values)}")
                    lines.append(f"{name}_count{labels} {len(values)}")
                    lines.append(f"{name}_sum{labels} {sum(values)}")
        return "\n".join(lines) + "\n"


class PrometheusServer:
    """Lifecycle handle for a loopback metrics HTTP server."""

    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread) -> None:
        self.server = server
        self.thread = thread

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def start_prometheus_server(
    *, host: str = "127.0.0.1", port: int = 9090, registry: Metrics | None = None
) -> PrometheusServer:
    """Expose metrics on loopback; public binds are rejected."""

    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("Prometheus metrics must bind to loopback")
    selected = registry or metrics

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib HTTP hook
            if self.path != "/metrics":
                self.send_error(404)
                return
            payload = selected.render_prometheus().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, _format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return PrometheusServer(server, thread)


def configure_otlp_tracing(
    endpoint: str,
    *,
    service_name: str = "devflow",
    insecure: bool = True,
    span_exporter: Any | None = None,
    set_global: bool = True,
) -> Any:
    """Build a batched trace provider and optionally install it globally.

    Production callers omit ``span_exporter`` and receive the real OTLP/gRPC
    exporter.  Tests may inject an in-memory SDK exporter to verify the batch
    pipeline without a network collector.
    """

    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    if not endpoint.strip():
        raise ValueError("OTLP endpoint must be non-empty")
    if span_exporter is None:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=insecure)
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(span_exporter))
    if set_global:
        trace.set_tracer_provider(provider)
    return provider


metrics = Metrics()


__all__ = [
    "Metrics",
    "PrometheusServer",
    "configure_otlp_tracing",
    "logger",
    "metrics",
    "start_prometheus_server",
    "tracer",
]

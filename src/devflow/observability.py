"""Dependency-light structured logging, tracing, and in-memory metrics."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog
from opentelemetry import trace


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


@dataclass
class _Counter:
    values: dict[tuple[tuple[str, str], ...], float] = field(
        default_factory=lambda: defaultdict(float)
    )

    def inc(
        self, amount: float = 1.0, *, labels: dict[str, Any] | None = None
    ) -> None:
        key = tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))
        self.values[key] += amount


@dataclass
class _Histogram:
    values: dict[tuple[tuple[str, str], ...], list[float]] = field(
        default_factory=lambda: defaultdict(list)
    )

    def observe(
        self, value: float, *, labels: dict[str, Any] | None = None
    ) -> None:
        key = tuple(sorted((str(k), str(v)) for k, v in (labels or {}).items()))
        self.values[key].append(float(value))


class Metrics:
    """Minimal metric facade matching the calls made by agents."""

    def __init__(self) -> None:
        self._counters: dict[str, _Counter] = {}
        self._histograms: dict[str, _Histogram] = {}

    def counter(self, name: str) -> _Counter:
        return self._counters.setdefault(name, _Counter())

    def histogram(self, name: str) -> _Histogram:
        return self._histograms.setdefault(name, _Histogram())

    def record(
        self,
        *,
        name: str,
        value: float,
        unit: str,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a point measurement using the histogram backend."""

        labels = {"unit": unit, **(tags or {})}
        self.histogram(name).observe(value, labels=labels)

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
        }


metrics = Metrics()

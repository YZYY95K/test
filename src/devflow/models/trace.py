"""Observability trace models for DevFlow.

Defines structures for distributed tracing, structured agent logging, and
metric recording to provide full observability into the multi-agent execution
pipeline.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

#: JSON-serializable value type for trace attributes and log metadata.
AttributeValue = str | int | float | bool | None


class SpanStatus(str, Enum):
    """Outcome status of a trace span."""

    SUCCESS = "success"
    FAILURE = "failure"


class LogLevel(str, Enum):
    """Severity level for an agent log entry."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class TraceSpan(BaseModel):
    """A single span within a distributed trace."""

    span_id: str = Field(
        ..., min_length=1, description="Unique identifier of the span"
    )
    parent_id: str | None = Field(
        default=None, description="Identifier of the parent span, if any"
    )
    agent_name: str = Field(
        ..., min_length=1, description="Name of the agent that produced the span"
    )
    skill_name: str = Field(
        ..., min_length=1, description="Name of the skill executed within the span"
    )
    start_time: datetime = Field(
        ..., description="Start timestamp of the span"
    )
    end_time: datetime = Field(
        ..., description="End timestamp of the span"
    )
    duration_ms: int = Field(
        ..., ge=0, description="Span duration in milliseconds"
    )
    status: SpanStatus = Field(
        ..., description="Outcome status of the span"
    )
    attributes: dict[str, AttributeValue] = Field(
        default_factory=dict,
        description="Additional structured attributes attached to the span",
    )
    events: list[str] = Field(
        default_factory=list,
        description="Ordered list of event descriptions recorded during the span",
    )


class TraceContext(BaseModel):
    """Context representing a full distributed trace."""

    trace_id: str = Field(
        ..., min_length=1, description="Unique identifier of the trace"
    )
    spans: list[TraceSpan] = Field(
        default_factory=list,
        description="Ordered list of spans belonging to the trace",
    )
    total_duration_ms: int = Field(
        ..., ge=0, description="Total trace duration in milliseconds"
    )
    agent_sequence: list[str] = Field(
        default_factory=list,
        description="Ordered list of agent names involved in the trace",
    )


class AgentLog(BaseModel):
    """A structured log entry produced by an agent."""

    timestamp: datetime = Field(
        ..., description="Time at which the log entry was produced"
    )
    agent_name: str = Field(
        ..., min_length=1, description="Name of the agent that produced the log"
    )
    level: LogLevel = Field(
        ..., description="Severity level of the log entry"
    )
    message: str = Field(
        ..., min_length=1, description="Log message content"
    )
    metadata: dict[str, AttributeValue] = Field(
        default_factory=dict,
        description="Additional structured metadata attached to the log entry",
    )


class MetricRecord(BaseModel):
    """A single metric measurement with optional tags."""

    name: str = Field(
        ..., min_length=1, description="Name of the metric"
    )
    value: float = Field(
        ..., description="Numeric value of the metric"
    )
    unit: str = Field(
        ..., min_length=1, description="Unit of the metric value (e.g. 'ms', 'count')"
    )
    tags: dict[str, str] = Field(
        default_factory=dict,
        description="String tags used for filtering and grouping the metric",
    )
    timestamp: datetime = Field(
        ..., description="Time at which the metric was recorded"
    )

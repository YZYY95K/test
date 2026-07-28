"""Strict collaboration events for auditable Agent execution failures."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERROR_TYPE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
FailureRetryDomain = Literal["execution", "generation"]
FailureErrorCode = Literal[
    "AGENT_EXECUTION_FAILED",
    "CANDIDATE_INVALID",
    "CODER_GENERATION_FAILED",
]


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_error_type(error: BaseException) -> str:
    candidate = type(error).__name__
    return candidate if _ERROR_TYPE.fullmatch(candidate) is not None else "Exception"


def _error_digest(error: BaseException, error_type: str) -> str:
    try:
        message = str(error)
    except Exception:  # noqa: BLE001 - hostile exception formatter
        message = "<unprintable>"
    return hashlib.sha256(
        f"{error_type}\0{message}".encode("utf-8", errors="replace")
    ).hexdigest()


class AgentFailureEvent(BaseModel):
    """Fail-closed event separating execution retries from semantic retries.

    Correlation is trusted only when all fields were recovered from one
    integrity-valid :class:`HandoffEnvelope`. A malformed or direct input is
    still auditable, but every routable identifier must remain absent.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["devflow.agent-failure/v2"] = (
        "devflow.agent-failure/v2"
    )
    agent: str = Field(min_length=1, max_length=128)
    retry_domain: FailureRetryDomain
    execution_retry_eligible: StrictBool
    correlation_trusted: StrictBool
    issue_id: StrictInt | None = Field(default=None, ge=1)
    run_id: str | None = Field(default=None, min_length=1, max_length=512)
    task_id: str | None = Field(default=None, min_length=1, max_length=512)
    trace_id: str | None = Field(default=None, min_length=1, max_length=1024)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=1024)
    execution_attempt: StrictInt | None = Field(default=None, ge=1, le=100)
    handoff_sha256: str | None = None
    error_code: FailureErrorCode
    error_type: str
    error_digest: str
    consecutive_failures: StrictInt = Field(ge=1)
    timestamp: str
    failure_id: str

    @field_validator(
        "agent",
        "run_id",
        "task_id",
        "trace_id",
        "idempotency_key",
    )
    @classmethod
    def _validate_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or _CONTROL.search(value) is not None:
            raise ValueError("event correlation text is not canonical")
        return value

    @field_validator("error_type")
    @classmethod
    def _validate_error_type(cls, value: str) -> str:
        if _ERROR_TYPE.fullmatch(value) is None:
            raise ValueError("error type is not canonical")
        return value

    @field_validator("error_digest", "failure_id")
    @classmethod
    def _validate_digest(cls, value: str) -> str:
        if _DIGEST.fullmatch(value) is None:
            raise ValueError("event digest is malformed")
        return value

    @field_validator("handoff_sha256")
    @classmethod
    def _validate_optional_digest(cls, value: str | None) -> str | None:
        if value is not None and _DIGEST.fullmatch(value) is None:
            raise ValueError("handoff digest is malformed")
        return value

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, value: str) -> str:
        if value != value.strip() or len(value) > 64:
            raise ValueError("failure timestamp is malformed")
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("failure timestamp is malformed") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("failure timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def _validate_correlation_and_identity(self) -> AgentFailureEvent:
        correlation = (
            self.issue_id,
            self.run_id,
            self.task_id,
            self.trace_id,
            self.idempotency_key,
            self.execution_attempt,
            self.handoff_sha256,
        )
        if self.correlation_trusted:
            if any(value is None for value in correlation):
                raise ValueError("trusted failure correlation is incomplete")
            assert self.run_id is not None
            assert self.task_id is not None
            assert self.trace_id is not None
            if self.trace_id != f"{self.run_id}:{self.task_id}":
                raise ValueError("trusted trace does not match run and task")
        elif any(value is not None for value in correlation):
            raise ValueError("untrusted failure must not carry routable identifiers")
        if self.execution_retry_eligible and (
            not self.correlation_trusted or self.retry_domain != "execution"
        ):
            raise ValueError(
                "execution retry eligibility requires trusted execution correlation"
            )
        if self.retry_domain == "execution":
            if self.error_code != "AGENT_EXECUTION_FAILED":
                raise ValueError("execution failures require the execution error code")
        elif self.error_code not in {
            "CANDIDATE_INVALID",
            "CODER_GENERATION_FAILED",
        }:
            raise ValueError("generation failures require a generation error code")

        unsigned = self.model_dump(exclude={"failure_id"}, mode="json")
        if _canonical_digest(unsigned) != self.failure_id:
            raise ValueError("failure id does not match the canonical event")
        return self

    @classmethod
    def from_error(
        cls,
        *,
        agent: str,
        error: BaseException,
        consecutive_failures: int,
        issue_id: int | None = None,
        run_id: str | None = None,
        task_id: str | None = None,
        trace_id: str | None = None,
        idempotency_key: str | None = None,
        execution_attempt: int | None = None,
        handoff_sha256: str | None = None,
        retry_domain: FailureRetryDomain = "execution",
        error_code: FailureErrorCode = "AGENT_EXECUTION_FAILED",
        execution_retry_eligible: bool = True,
        timestamp: datetime | None = None,
    ) -> AgentFailureEvent:
        """Create an event without ever serializing the raw exception message."""

        correlation = (
            issue_id,
            run_id,
            task_id,
            trace_id,
            idempotency_key,
            execution_attempt,
            handoff_sha256,
        )
        trusted = all(value is not None for value in correlation)
        if not trusted:
            issue_id = None
            run_id = None
            task_id = None
            trace_id = None
            idempotency_key = None
            execution_attempt = None
            handoff_sha256 = None
        eligible = bool(
            execution_retry_eligible
            and trusted
            and retry_domain == "execution"
        )
        error_type = _safe_error_type(error)
        error_digest = _error_digest(error, error_type)
        occurred_at = (timestamp or datetime.now(timezone.utc)).isoformat()
        data = {
            "schema_version": "devflow.agent-failure/v2",
            "agent": agent,
            "retry_domain": retry_domain,
            "execution_retry_eligible": eligible,
            "correlation_trusted": trusted,
            "issue_id": issue_id,
            "run_id": run_id,
            "task_id": task_id,
            "trace_id": trace_id,
            "idempotency_key": idempotency_key,
            "execution_attempt": execution_attempt,
            "handoff_sha256": handoff_sha256,
            "error_code": error_code,
            "error_type": error_type,
            "error_digest": error_digest,
            "consecutive_failures": consecutive_failures,
            "timestamp": occurred_at,
        }
        return cls.model_validate({**data, "failure_id": _canonical_digest(data)})


__all__ = [
    "AgentFailureEvent",
    "FailureErrorCode",
    "FailureRetryDomain",
]

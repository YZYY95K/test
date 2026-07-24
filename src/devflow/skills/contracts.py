"""Machine-checkable contracts for Skill collaboration and hand-offs."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class ArtifactContract(BaseModel):
    """A versioned artifact crossing a Skill boundary."""

    type: str = Field(min_length=1)
    schema_version: str = Field(pattern=r"^\d+\.\d+$")
    required_fields: list[str] = Field(min_length=1)


class HandoffRule(BaseModel):
    """One explicit collaboration edge."""

    on: Literal["success", "failure", "blocked"]
    consumer: str = Field(min_length=1)
    artifact_type: str = Field(min_length=1)
    event: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")


class FailureRule(BaseModel):
    """Bounded, deterministic recovery policy."""

    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    retryable: bool
    max_attempts: int = Field(ge=0, le=5)
    action: str = Field(min_length=1)
    route_to: str = Field(min_length=1)
    event: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")


class VerificationRule(BaseModel):
    """Evidence required before an output may be handed off."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]+$")
    requirement: str = Field(min_length=1)
    evidence: str = Field(min_length=1)


class ReleasePolicy(BaseModel):
    """Compatibility and rollback requirements for a Skill release."""

    compatibility: str = Field(min_length=1)
    change_policy: str = Field(min_length=1)
    rollback: str = Field(min_length=1)


class SkillContract(BaseModel):
    """Portable contract stored in ``references/contract.yaml``."""

    schema_version: Literal["1.0"]
    name: str = Field(pattern=r"^[a-z0-9-]+$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    owner: str = Field(min_length=1)
    intent: str = Field(min_length=1)
    invoke_when: list[str] = Field(min_length=1)
    refuse_when: list[str] = Field(min_length=1)
    input: ArtifactContract
    output: ArtifactContract
    dependencies: list[str] = Field(min_length=1)
    mcp_tools: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(min_length=1)
    forbidden_actions: list[str] = Field(min_length=3)
    handoffs: list[HandoffRule] = Field(min_length=1)
    failures: list[FailureRule] = Field(min_length=2)
    verification: list[VerificationRule] = Field(min_length=2)
    release: ReleasePolicy
    examples_ref: str = Field(pattern=r"^references/[^/]+$")

    @model_validator(mode="after")
    def _validate_recovery_bounds(self) -> SkillContract:
        for failure in self.failures:
            if not failure.retryable and failure.max_attempts != 0:
                raise ValueError(
                    f"{failure.code}: non-retryable failures need max_attempts=0"
                )
        return self

    @field_validator("mcp_tools")
    @classmethod
    def _validate_mcp_tools(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("mcp_tools must be unique")
        for item in value:
            if not re.fullmatch(r"[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*", item):
                raise ValueError(f"invalid MCP tool identifier: {item}")
        return value


class HandoffStatus(str, Enum):
    """State of an inter-agent hand-off."""

    READY = "ready"
    RETRY = "retry"
    BLOCKED = "blocked"
    FAILED = "failed"


class HandoffArtifact(BaseModel):
    """Inline or referenced hand-off payload with integrity metadata."""

    type: str = Field(min_length=1)
    schema_version: str = Field(pattern=r"^\d+\.\d+$")
    inline: dict[str, Any] | None = None
    ref: str | None = None
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _require_one_payload(self) -> HandoffArtifact:
        if (self.inline is None) == (self.ref is None):
            raise ValueError("exactly one of inline or ref is required")
        return self

    @staticmethod
    def digest(payload: dict[str, Any]) -> str:
        serialized = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @classmethod
    def from_inline(
        cls, *, artifact_type: str, schema_version: str, payload: dict[str, Any]
    ) -> HandoffArtifact:
        return cls(
            type=artifact_type,
            schema_version=schema_version,
            inline=payload,
            sha256=cls.digest(payload),
        )

    def verify_integrity(self) -> bool:
        return self.inline is None or self.sha256 == self.digest(self.inline)


class HandoffEnvelope(BaseModel):
    """Auditable transport envelope shared by all agents."""

    envelope_version: Literal["1.0"] = "1.0"
    run_id: str = Field(min_length=1)
    issue_id: int = Field(ge=1)
    task_id: str = Field(min_length=1)
    producer: str = Field(min_length=1)
    consumer: str = Field(min_length=1)
    skill: str = Field(pattern=r"^[a-z0-9-]+$")
    trace_id: str = Field(min_length=1)
    idempotency_key: str = Field(min_length=1)
    created_at: datetime
    status: HandoffStatus
    artifact: HandoffArtifact

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        issue_id: int,
        task_id: str,
        producer: str,
        consumer: str,
        skill: str,
        artifact_type: str,
        payload: dict[str, Any],
        status: HandoffStatus = HandoffStatus.READY,
    ) -> HandoffEnvelope:
        return cls(
            run_id=run_id,
            issue_id=issue_id,
            task_id=task_id,
            producer=producer,
            consumer=consumer,
            skill=skill,
            trace_id=f"{run_id}:{task_id}",
            idempotency_key=f"{run_id}:{task_id}:{consumer}:{skill}",
            created_at=datetime.now(timezone.utc),
            status=status,
            artifact=HandoffArtifact.from_inline(
                artifact_type=artifact_type,
                schema_version="1.0",
                payload=payload,
            ),
        )


__all__ = [
    "ArtifactContract",
    "FailureRule",
    "HandoffArtifact",
    "HandoffEnvelope",
    "HandoffRule",
    "HandoffStatus",
    "ReleasePolicy",
    "SkillContract",
    "VerificationRule",
]

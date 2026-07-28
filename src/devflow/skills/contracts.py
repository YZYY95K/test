"""Machine-checkable contracts for Skill collaboration and hand-offs."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictContractModel(BaseModel):
    """Reject contract vocabulary the runtime does not understand."""

    model_config = ConfigDict(extra="forbid")


class ArtifactContract(StrictContractModel):
    """A versioned artifact crossing a Skill boundary."""

    type: str = Field(min_length=1)
    schema_version: str = Field(pattern=r"^\d+\.\d+$")
    required_fields: list[str] = Field(min_length=1)


class HandoffRule(StrictContractModel):
    """One explicit collaboration edge."""

    on: Literal["success", "failure", "blocked"]
    consumer: str = Field(min_length=1)
    artifact_type: str = Field(min_length=1)
    event: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")


class FailureRule(StrictContractModel):
    """Bounded, deterministic recovery policy."""

    code: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    retryable: bool
    max_attempts: int = Field(ge=0, le=5)
    action: str = Field(min_length=1)
    route_to: str = Field(min_length=1)
    event: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")


class VerificationRule(StrictContractModel):
    """Evidence required before an output may be handed off."""

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]+$")
    requirement: str = Field(min_length=1)
    evidence: str = Field(min_length=1)


class ReleasePolicy(StrictContractModel):
    """Compatibility and rollback requirements for a Skill release."""

    compatibility: str = Field(min_length=1)
    change_policy: str = Field(min_length=1)
    rollback: str = Field(min_length=1)


class FailureEvidenceBounds(StrictContractModel):
    """Hard caps for evidence that may cross the Tester boundary."""

    failing_tests: int = Field(ge=1, le=1024)
    new_failures: int = Field(ge=1, le=1024)
    diagnostics: int = Field(ge=1, le=256)
    test_name_chars: int = Field(ge=1, le=4096)
    error_message_chars: int = Field(ge=1, le=16384)
    traceback_chars: int = Field(ge=1, le=32768)


class FailureEvidenceIntegrity(StrictContractModel):
    """Digest meanings published by the test-runner Skill."""

    candidate_digest: str = Field(min_length=1)
    test_result_digest: str = Field(min_length=1)
    derivation: str = Field(min_length=1)


class FailureEvidencePrivacy(StrictContractModel):
    """Privacy boundary for failure evidence."""

    redaction_marker: Literal["[REDACTED]"]
    rule: str = Field(min_length=1)
    local_only: str = Field(min_length=1)
    model_boundary: str = Field(min_length=1)


class FailureEvidenceContract(StrictContractModel):
    """Typed TestFailureEvidence extension for test-runner."""

    type: Literal["TestFailureEvidence"]
    schema_version: Literal["1.2"]
    required_fields: list[str] = Field(min_length=1)
    bounds: FailureEvidenceBounds
    integrity: FailureEvidenceIntegrity
    privacy: FailureEvidencePrivacy


class FailureHandoffContract(StrictContractModel):
    """Exact Tester-to-TeamLeader semantic-failure edge."""

    artifact_type: Literal["TestEvidence"]
    producer: Literal["TesterAgent"]
    consumer: Literal["TeamLeader"]
    skill: Literal["test-runner"]
    event: Literal["test.failed"]
    status: Literal["retry"]
    required_payload_fields: list[str] = Field(min_length=1)
    verifier_boundary: str = Field(min_length=1)
    coder_boundary: str = Field(min_length=1)


class RetryEndpoint(StrictContractModel):
    """One typed endpoint in the mediated semantic-retry route."""

    producer: str = Field(min_length=1)
    consumer: str = Field(min_length=1)
    event: str = Field(pattern=r"^[a-z][a-z0-9_.-]+$")
    artifact_type: str = Field(min_length=1)


class PatchAttemptBounds(StrictContractModel):
    """Global semantic patch-generation budget."""

    first_retry: Literal[2]
    maximum_total: Literal[3]


class RetryProtocolContract(StrictContractModel):
    """TeamLeader-mediated Tester-to-Coder retry protocol."""

    mediator: Literal["TeamLeader"]
    ingress: RetryEndpoint
    egress: RetryEndpoint
    idempotency_subject: list[str] = Field(min_length=1)
    duplicate_policy: str = Field(min_length=1)
    patch_attempts: PatchAttemptBounds


class RetryAttemptBounds(StrictContractModel):
    """Allowed attempt numbers on a patch retry invocation."""

    minimum: Literal[2]
    maximum: Literal[3]
    maximum_total: Literal[3]


class RetryIntegrityContract(StrictContractModel):
    """Integrity statements enforced for a retry handoff."""

    prior_candidate: str = Field(min_length=1)
    envelope: str = Field(min_length=1)
    result: str = Field(min_length=1)


class RetryIdempotencyContract(StrictContractModel):
    """Stable identity of a semantic retry."""

    subject: list[str] = Field(min_length=1)
    duplicate_policy: str = Field(min_length=1)


class RetryTrustContract(StrictContractModel):
    """Untrusted fields and redaction policy at the Coder boundary."""

    untrusted_fields: list[str] = Field(min_length=1)
    rule: str = Field(min_length=1)
    redaction: str = Field(min_length=1)


class RetryHandoffContract(StrictContractModel):
    """Typed TeamLeader-to-Coder retry invocation extension."""

    type: Literal["SkillInvocation"]
    schema_version: Literal["1.0"]
    producer: Literal["TeamLeader"]
    consumer: Literal["CoderAgent"]
    skill: Literal["patch-generator"]
    status: Literal["retry"]
    required_input_fields: list[str] = Field(min_length=1)
    attempt_bounds: RetryAttemptBounds
    integrity: RetryIntegrityContract
    idempotency: RetryIdempotencyContract
    trust: RetryTrustContract


class SkillContract(StrictContractModel):
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
    failure_evidence: FailureEvidenceContract | None = None
    failure_handoff: FailureHandoffContract | None = None
    retry_protocol: RetryProtocolContract | None = None
    retry_handoff: RetryHandoffContract | None = None

    @model_validator(mode="after")
    def _validate_recovery_bounds(self) -> SkillContract:
        for failure in self.failures:
            if not failure.retryable and failure.max_attempts != 0:
                raise ValueError(f"{failure.code}: non-retryable failures need max_attempts=0")
        if self.name == "test-runner":
            if not all(
                (
                    self.failure_evidence,
                    self.failure_handoff,
                    self.retry_protocol,
                )
            ):
                raise ValueError(
                    "test-runner requires failure_evidence, failure_handoff, and retry_protocol"
                )
            assert self.failure_handoff is not None
            assert self.retry_protocol is not None
            failure_edges = {
                (item.consumer, item.artifact_type, item.event)
                for item in self.handoffs
                if item.on == "failure"
            }
            expected_edge = (
                self.failure_handoff.consumer,
                self.failure_handoff.artifact_type,
                self.failure_handoff.event,
            )
            if expected_edge not in failure_edges:
                raise ValueError("failure_handoff must match a declared failure handoff")
            ingress = self.retry_protocol.ingress
            if (
                ingress.producer != self.failure_handoff.producer
                or ingress.consumer != self.failure_handoff.consumer
                or ingress.event != self.failure_handoff.event
                or ingress.artifact_type != self.failure_handoff.artifact_type
            ):
                raise ValueError("retry ingress must match failure_handoff")
            egress = self.retry_protocol.egress
            if (
                egress.producer != "TeamLeader"
                or egress.consumer != "CoderAgent"
                or egress.event != "task.route.coderagent"
                or egress.artifact_type != "SkillInvocation"
            ):
                raise ValueError("retry egress must be TeamLeader to CoderAgent")
            regression_rules = [item for item in self.failures if item.code == "TEST_REGRESSION"]
            if len(regression_rules) != 1 or regression_rules[0].route_to != "TeamLeader":
                raise ValueError("TEST_REGRESSION must route through TeamLeader")
        elif any((self.failure_evidence, self.failure_handoff, self.retry_protocol)):
            raise ValueError("failure retry extensions are reserved for test-runner")

        if self.name == "patch-generator":
            if self.retry_handoff is None:
                raise ValueError("patch-generator requires retry_handoff")
        elif self.retry_handoff is not None:
            raise ValueError("retry_handoff is reserved for patch-generator")
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


class HandoffArtifact(StrictContractModel):
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


class HandoffEnvelope(StrictContractModel):
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
        artifact_schema_version: str = "1.0",
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
                schema_version=artifact_schema_version,
                payload=payload,
            ),
        )


__all__ = [
    "ArtifactContract",
    "FailureEvidenceContract",
    "FailureHandoffContract",
    "FailureRule",
    "HandoffArtifact",
    "HandoffEnvelope",
    "HandoffRule",
    "HandoffStatus",
    "ReleasePolicy",
    "RetryHandoffContract",
    "RetryProtocolContract",
    "SkillContract",
    "VerificationRule",
]

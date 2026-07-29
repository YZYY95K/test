"""Versioned output model for the experience-distiller Skill."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from devflow.mcp.contracts import ApprovalEvidence
from devflow.models.patch import Patch
from devflow.models.review import ReviewDecision, ReviewResult
from devflow.models.test_result import TestRunResult, canonical_artifact_digest


class VerifiedTerminalReceipt(BaseModel):
    """Leader-issued proof that only clean, approved evidence may be distilled."""

    schema_version: Literal["1.0"] = "1.0"
    issuer: Literal["TeamLeader"] = "TeamLeader"
    run_id: str = Field(min_length=1)
    issue_id: int = Field(ge=1)
    repository_revision: str = Field(min_length=1)
    terminal_state: Literal["review_approved", "human_approved"]
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    test_result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    approval_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    receipt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        issue_id: int,
        repository_revision: str,
        patch: Patch,
        test_result: TestRunResult,
        review: ReviewResult,
        approval: ApprovalEvidence | None = None,
    ) -> VerifiedTerminalReceipt:
        comparison = test_result.baseline_comparison
        attestation = test_result.integrity_attestation
        if (
            test_result.failed
            or test_result.errors
            or comparison is None
            or comparison.regression
            or comparison.new_failures
            or attestation is None
            or not attestation.verified
        ):
            raise ValueError("terminal receipt requires a clean regression gate")
        if review.decision is not ReviewDecision.APPROVED or review.requires_human_approval:
            raise ValueError("terminal receipt requires an approved review decision")
        terminal_state: Literal["review_approved", "human_approved"] = (
            "human_approved" if approval is not None else "review_approved"
        )
        values = {
            "schema_version": "1.0",
            "issuer": "TeamLeader",
            "run_id": run_id,
            "issue_id": issue_id,
            "repository_revision": repository_revision,
            "terminal_state": terminal_state,
            "candidate_digest": canonical_artifact_digest(patch),
            "test_result_digest": canonical_artifact_digest(test_result),
            "review_digest": canonical_artifact_digest(review),
            "approval_digest": (
                canonical_artifact_digest(approval) if approval is not None else None
            ),
        }
        return cls(
            run_id=run_id,
            issue_id=issue_id,
            repository_revision=repository_revision,
            candidate_digest=str(values["candidate_digest"]),
            test_result_digest=str(values["test_result_digest"]),
            review_digest=str(values["review_digest"]),
            terminal_state=terminal_state,
            approval_digest=(
                str(values["approval_digest"]) if values["approval_digest"] is not None else None
            ),
            receipt_sha256=cls._digest(values),
        )

    @staticmethod
    def _digest(values: dict[str, object]) -> str:
        encoded = json.dumps(
            values,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @model_validator(mode="after")
    def _verify_receipt_digest(self) -> VerifiedTerminalReceipt:
        if (self.terminal_state == "human_approved") != (self.approval_digest is not None):
            raise ValueError("terminal receipt approval provenance is incomplete")
        values = self.model_dump(mode="json", exclude={"receipt_sha256"})
        if self.receipt_sha256 != self._digest(values):
            raise ValueError("terminal receipt digest does not match")
        return self

    def verifies(
        self,
        *,
        issue_id: int,
        repository_revision: str,
        patch: Patch,
        test_result: TestRunResult,
        review: ReviewResult,
        approval: ApprovalEvidence | None = None,
    ) -> bool:
        comparison = test_result.baseline_comparison
        attestation = test_result.integrity_attestation
        return bool(
            self.issue_id == issue_id
            and self.repository_revision == repository_revision
            and self.candidate_digest == canonical_artifact_digest(patch)
            and self.test_result_digest == canonical_artifact_digest(test_result)
            and self.review_digest == canonical_artifact_digest(review)
            and self.approval_digest
            == (canonical_artifact_digest(approval) if approval is not None else None)
            and self.terminal_state
            == ("human_approved" if approval is not None else "review_approved")
            and test_result.failed == 0
            and test_result.errors == 0
            and comparison is not None
            and not comparison.regression
            and not comparison.new_failures
            and attestation is not None
            and attestation.verified
            and review.decision is ReviewDecision.APPROVED
            and not review.requires_human_approval
        )


class ExperienceProvenance(BaseModel):
    """Immutable links supporting a distilled claim."""

    trace_id: str = Field(min_length=1)
    issue_id: int = Field(ge=1)
    repository_revision: str = Field(min_length=1)
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    terminal_receipt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class RedactionEvidence(BaseModel):
    """Evidence that storage content passed privacy gates."""

    policy_version: str = Field(min_length=1)
    secret_scan_passed: bool
    pii_scan_passed: bool


class ExperiencePattern(BaseModel):
    """Safe, reusable result of a terminal reviewed run."""

    pattern_id: str = Field(pattern=r"^exp-[a-zA-Z0-9-]+$")
    schema_version: Literal["1.0"] = "1.0"
    outcome: str = Field(pattern=r"^(approved|changes_requested|human_approval_required)$")
    summary: str = Field(min_length=1)
    reusable_lesson: str = Field(min_length=1)
    provenance: ExperienceProvenance
    redaction: RedactionEvidence
    stored: bool


__all__ = [
    "ExperiencePattern",
    "ExperienceProvenance",
    "RedactionEvidence",
    "VerifiedTerminalReceipt",
]

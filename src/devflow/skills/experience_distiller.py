"""Executable experience-distiller Skill used by the local and production loop."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Protocol

from devflow.event_bus import publish
from devflow.mcp.contracts import ApprovalEvidence
from devflow.models.experience import (
    ExperiencePattern,
    ExperienceProvenance,
    RedactionEvidence,
    VerifiedTerminalReceipt,
)
from devflow.models.issue import IssueData
from devflow.models.patch import Patch
from devflow.models.review import ReviewResult
from devflow.models.test_result import TestRunResult
from devflow.security.secrets import contains_secret
from devflow.skills.base import BaseSkill, SkillSpec


class ExperienceWriter(Protocol):
    """Minimal persistence port; ChromaDB and tests can both implement it."""

    async def store(self, pattern_id: str, summary: str, metadata: dict[str, Any]) -> None: ...


class ExperienceDistillerSkill(BaseSkill):
    """Distill terminal reviewed evidence without copying source content."""

    spec = SkillSpec(
        name="experience-distiller",
        description="Distill terminal reviewed evidence into safe reusable memory.",
        input_schema={
            "required": [
                "issue",
                "repository_revision",
                "located_context",
                "patch",
                "test_result",
                "review",
                "trace_id",
                "terminal_receipt",
            ]
        },
        output_schema={
            "required": [
                "pattern_id",
                "schema_version",
                "outcome",
                "summary",
                "reusable_lesson",
                "provenance",
                "redaction",
                "stored",
            ]
        },
        invocation_conditions=["A reviewed run has reached a terminal outcome."],
        dependencies={"data": ["experience_store", "audit_evidence"]},
        failure_handling={"store_unavailable": "retry twice, then report degraded"},
        security_boundary=[
            "Never store raw secrets or full private files.",
            "Never distill an active or unreviewed run.",
        ],
    )
    _EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def __init__(self, store: ExperienceWriter | None = None) -> None:
        self._store = store

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        required = list(self.spec.input_schema["required"])
        self._validate_input(kwargs, required)

        issue = IssueData.model_validate(kwargs["issue"])
        patch = Patch.model_validate(kwargs["patch"])
        tests = TestRunResult.model_validate(kwargs["test_result"])
        review = ReviewResult.model_validate(kwargs["review"])
        human_approval = (
            ApprovalEvidence.model_validate(kwargs["human_approval"])
            if kwargs.get("human_approval") is not None
            else None
        )
        receipt = VerifiedTerminalReceipt.model_validate(kwargs["terminal_receipt"])
        located = kwargs["located_context"]
        if not isinstance(located, dict):
            raise ValueError("located_context must be a mapping")
        root_cause = located.get("root_cause")
        if not isinstance(root_cause, dict) or not root_cause.get("summary"):
            raise ValueError("located_context requires a supported root_cause")
        repository_revision = str(kwargs["repository_revision"])
        if not receipt.verifies(
            issue_id=issue.issue_number,
            repository_revision=repository_revision,
            patch=patch,
            test_result=tests,
            review=review,
            approval=human_approval,
        ):
            raise ValueError("terminal receipt does not verify the reviewed run evidence")

        candidate_digest = self._digest(patch.model_dump(mode="json"))
        review_digest = self._digest(review.model_dump(mode="json"))
        pattern_id = f"exp-{issue.issue_number}-{candidate_digest[:12]}"
        outcome = review.decision.value
        issue_title = self._redact_pii(issue.title)
        root_summary = self._redact_pii(str(root_cause["summary"]))
        patch_description = self._redact_pii(patch.description)
        summary = (
            f"{issue_title}. Root cause: {root_summary} "
            f"Resolution: {patch_description} "
            f"Validation: {tests.passed}/{tests.total} tests passed; "
            f"review outcome {outcome}."
        )
        lesson = (
            "Bind the smallest evidence-backed change to its source revision, "
            "then compare isolated candidate tests with the trusted baseline."
        )
        secret_scan_passed = not contains_secret(summary) and not contains_secret(lesson)
        pii_scan_passed = self._EMAIL.search(summary) is None
        if not secret_scan_passed or not pii_scan_passed:
            raise ValueError("distilled memory did not pass redaction gates")
        pattern = ExperiencePattern(
            pattern_id=pattern_id,
            outcome=outcome,
            summary=summary,
            reusable_lesson=lesson,
            provenance=ExperienceProvenance(
                trace_id=str(kwargs["trace_id"]),
                issue_id=issue.issue_number,
                repository_revision=repository_revision,
                candidate_digest=candidate_digest,
                review_digest=review_digest,
                terminal_receipt_sha256=receipt.receipt_sha256,
            ),
            redaction=RedactionEvidence(
                policy_version="1.0",
                secret_scan_passed=secret_scan_passed,
                pii_scan_passed=pii_scan_passed,
            ),
            stored=False,
        )
        # Check the exact persistence payload before any external write. The
        # BaseSkill lifecycle checks again after execute for defense in depth.
        self._check_security(pattern.model_dump(mode="json"))

        if self._store is not None:
            await self._store.store(
                pattern.pattern_id,
                pattern.summary,
                {
                    "issue_number": issue.issue_number,
                    "tier": str(kwargs.get("tier", "unknown")),
                    "root_cause_file": str(root_cause.get("file", "")),
                    "trace_id": pattern.provenance.trace_id,
                    "candidate_digest": candidate_digest,
                    "schema_version": pattern.schema_version,
                    "outcome": outcome,
                    "terminal_receipt_sha256": receipt.receipt_sha256,
                    "human_approval_digest": receipt.approval_digest or "none",
                },
            )
            pattern.stored = True

        await publish(
            "experience.stored" if pattern.stored else "experience.degraded",
            {
                "issue_id": issue.issue_number,
                "pattern_id": pattern.pattern_id,
                "stored": pattern.stored,
                "trace_id": pattern.provenance.trace_id,
            },
        )
        return pattern.model_dump(mode="json")

    @staticmethod
    def _digest(payload: dict[str, Any]) -> str:
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    @classmethod
    def _redact_pii(cls, text: str) -> str:
        return cls._EMAIL.sub("[REDACTED_EMAIL]", text)


__all__ = ["ExperienceDistillerSkill", "ExperienceWriter"]

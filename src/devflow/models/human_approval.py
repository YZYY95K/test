"""Digest-bound target for a T4/T5 human resume decision."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class HumanApprovalTarget(BaseModel):
    """Non-secret evidence a trusted approval authority must sign exactly."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["devflow.human-approval-target/v1"] = "devflow.human-approval-target/v1"
    action: Literal["devflow:resume"] = "devflow:resume"
    run_id: str = Field(min_length=1, max_length=200)
    issue_id: int = Field(ge=1)
    tier: Literal["T4", "T5"]
    repository_revision: str = Field(min_length=1, max_length=200)
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    test_result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_task_id: str = Field(min_length=1, max_length=200)
    target_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @classmethod
    def create(
        cls,
        *,
        run_id: str,
        issue_id: int,
        tier: Literal["T4", "T5"],
        repository_revision: str,
        candidate_digest: str,
        test_result_digest: str,
        review_digest: str,
        source_task_id: str,
    ) -> HumanApprovalTarget:
        body = {
            "schema_version": "devflow.human-approval-target/v1",
            "action": "devflow:resume",
            "run_id": run_id,
            "issue_id": issue_id,
            "tier": tier,
            "repository_revision": repository_revision,
            "candidate_digest": candidate_digest,
            "test_result_digest": test_result_digest,
            "review_digest": review_digest,
            "source_task_id": source_task_id,
        }
        return cls(
            run_id=run_id,
            issue_id=issue_id,
            tier=tier,
            repository_revision=repository_revision,
            candidate_digest=candidate_digest,
            test_result_digest=test_result_digest,
            review_digest=review_digest,
            source_task_id=source_task_id,
            target_sha256=cls._digest(body),
        )

    @staticmethod
    def _digest(value: dict[str, object]) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @model_validator(mode="after")
    def _verify_target_digest(self) -> HumanApprovalTarget:
        body = self.model_dump(mode="json", exclude={"target_sha256"})
        if self.target_sha256 != self._digest(body):
            raise ValueError("human approval target digest does not match")
        return self


__all__ = ["HumanApprovalTarget"]

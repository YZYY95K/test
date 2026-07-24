"""Review and approval models for the final DevFlow gate."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class ReviewDecision(str, Enum):
    """Outcome of automated review."""

    APPROVED = "approved"
    CHANGES_REQUESTED = "changes_requested"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"


class ReviewFinding(BaseModel):
    """One actionable review or security finding."""

    severity: str = Field(..., pattern="^(info|low|medium|high|critical)$")
    category: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    file_path: str | None = None


class ReviewResult(BaseModel):
    """Structured result emitted by ReviewerAgent."""

    decision: ReviewDecision
    findings: list[ReviewFinding] = Field(default_factory=list)
    summary: str = Field(..., min_length=1)
    pr_url: str | None = None
    requires_human_approval: bool = False


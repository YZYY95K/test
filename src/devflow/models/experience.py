"""Versioned output model for the experience-distiller Skill."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ExperienceProvenance(BaseModel):
    """Immutable links supporting a distilled claim."""

    trace_id: str = Field(min_length=1)
    issue_id: int = Field(ge=1)
    repository_revision: str = Field(min_length=1)
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


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


__all__ = ["ExperiencePattern", "ExperienceProvenance", "RedactionEvidence"]

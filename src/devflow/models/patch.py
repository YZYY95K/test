"""Code patch models for DevFlow.

Defines structures for representing file changes, patches, and impact analysis
used during code generation, review, and application.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def canonical_patch_digest(value: BaseModel | dict[str, object]) -> str:
    """Return the canonical digest used by PatchCandidate boundaries."""

    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_repository_path(value: str) -> str:
    """Return one canonical repository-relative POSIX path or fail closed."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("repository path must be non-empty canonical text")
    normalized_input = value.replace("\\", "/")
    path = PurePosixPath(normalized_input)
    normalized = path.as_posix()
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or normalized in {"", "."}
        or re.match(r"^[A-Za-z]:", normalized) is not None
        or normalized_input.startswith("//")
        or normalized != normalized_input
    ):
        raise ValueError("repository path escapes or aliases the repository boundary")
    return normalized


def is_test_path(value: str) -> bool:
    """Return whether a canonical path names a conventional test artifact."""

    path = PurePosixPath(canonical_repository_path(value))
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name
    lowered = name.lower()
    stem = name.rsplit(".", 1)[0]
    lowered_stem = stem.lower()
    return bool(
        parts.intersection({"test", "tests", "__tests__", "spec", "specs"})
        or lowered_stem in {"test", "tests", "spec", "specs"}
        or lowered_stem.startswith(("test_", "test-"))
        or lowered_stem.endswith(
            ("_test", "-test", ".test", "_spec", "-spec", ".spec", ".tests", ".specs")
        )
        or stem.endswith(("Test", "Tests", "Spec", "Specs"))
        or ".test." in lowered
        or ".spec." in lowered
    )


class ChangeType(str, Enum):
    """Type of change applied to a file."""

    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"


class RiskLevel(str, Enum):
    """Risk level associated with applying a patch."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FileChange(BaseModel):
    """Represents a single file change within a patch."""

    file_path: str = Field(..., min_length=1, description="Repository-relative path of the file")
    change_type: ChangeType = Field(..., description="Type of change applied to the file")
    original_content: str | None = Field(
        default=None, description="Original file content before the change"
    )
    new_content: str | None = Field(default=None, description="New file content after the change")
    diff: str = Field(..., min_length=1, description="Unified diff describing the change")


class Patch(BaseModel):
    """Represents a code patch containing one or more file changes."""

    branch_name: str = Field(
        ..., min_length=1, max_length=255, description="Name of the Git branch for the patch"
    )
    changes: list[FileChange] = Field(
        ..., min_length=1, description="List of file changes included in the patch"
    )
    commit_message: str = Field(..., min_length=1, description="Git commit message for the patch")
    description: str = Field(
        ..., min_length=1, description="Human-readable description of the patch"
    )


class EvidenceBoundary(BaseModel):
    """Minimal, digest-bound Locator scope carried with a candidate patch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    located_context_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    allowed_files: list[str] = Field(min_length=1, max_length=256)
    scope_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @classmethod
    def create(
        cls,
        *,
        located_context_digest: str,
        allowed_files: list[str] | tuple[str, ...] | frozenset[str],
    ) -> EvidenceBoundary:
        """Build the canonical scope derived from one LocatedContext."""

        normalized = sorted(canonical_repository_path(path) for path in allowed_files)
        body: dict[str, object] = {
            "schema_version": "1.0",
            "located_context_digest": located_context_digest,
            "allowed_files": normalized,
        }
        return cls(
            schema_version="1.0",
            located_context_digest=located_context_digest,
            allowed_files=normalized,
            scope_digest=canonical_patch_digest(body),
        )

    @model_validator(mode="after")
    def _validate_scope(self) -> EvidenceBoundary:
        if _DIGEST.fullmatch(self.located_context_digest) is None:
            raise ValueError("located_context_digest is malformed")
        normalized = [canonical_repository_path(path) for path in self.allowed_files]
        if normalized != sorted(set(normalized)):
            raise ValueError("allowed_files must be sorted, unique, and canonical")
        body: dict[str, object] = {
            "schema_version": self.schema_version,
            "located_context_digest": self.located_context_digest,
            "allowed_files": normalized,
        }
        if canonical_patch_digest(body) != self.scope_digest:
            raise ValueError("scope_digest does not bind the exact evidence boundary")
        return self


class PatchCandidate(BaseModel):
    """Versioned Coder-to-Tester artifact with an explicit evidence scope."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.2"]
    issue_id: StrictInt = Field(ge=1)
    tier: Literal["T1", "T2", "T3", "T4", "T5"]
    patch: Patch
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    evidence_boundary: EvidenceBoundary
    model_call_attempt: StrictInt = Field(ge=1, le=3)
    retry_attempt: StrictInt = Field(ge=1, le=3)
    revision_of: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _validate_candidate(self) -> PatchCandidate:
        if self.candidate_digest != canonical_patch_digest(self.patch):
            raise ValueError("candidate_digest does not bind the exact patch")
        if self.model_call_attempt < self.retry_attempt:
            raise ValueError("model_call_attempt cannot precede retry_attempt")
        if self.retry_attempt == 1 and self.revision_of is not None:
            raise ValueError("initial PatchCandidate cannot declare revision_of")
        if self.retry_attempt > 1 and self.revision_of is None:
            raise ValueError("revised PatchCandidate requires revision_of")
        allowed = frozenset(self.evidence_boundary.allowed_files)
        for change in self.patch.changes:
            path = canonical_repository_path(change.file_path)
            if path not in allowed:
                raise ValueError("patch changes a file outside the located evidence boundary")
            if change.change_type is ChangeType.DELETE and is_test_path(path):
                raise ValueError("patch cannot delete a test file")
        return self


class ImpactAnalysis(BaseModel):
    """Analysis of the potential impact of applying a patch."""

    affected_files: list[str] = Field(
        default_factory=list,
        description="List of repository-relative file paths affected by the patch",
    )
    affected_modules: list[str] = Field(
        default_factory=list,
        description="List of module names affected by the patch",
    )
    risk_level: RiskLevel = Field(..., description="Overall risk level of applying the patch")
    breaking_changes: bool = Field(
        default=False,
        description="Whether the patch introduces breaking changes",
    )
    test_files_needed: list[str] = Field(
        default_factory=list,
        description="List of test files that should be created or updated",
    )

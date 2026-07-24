"""Code patch models for DevFlow.

Defines structures for representing file changes, patches, and impact analysis
used during code generation, review, and application.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


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

    file_path: str = Field(
        ..., min_length=1, description="Repository-relative path of the file"
    )
    change_type: ChangeType = Field(
        ..., description="Type of change applied to the file"
    )
    original_content: str | None = Field(
        default=None, description="Original file content before the change"
    )
    new_content: str | None = Field(
        default=None, description="New file content after the change"
    )
    diff: str = Field(
        ..., min_length=1, description="Unified diff describing the change"
    )


class Patch(BaseModel):
    """Represents a code patch containing one or more file changes."""

    branch_name: str = Field(
        ..., min_length=1, max_length=255, description="Name of the Git branch for the patch"
    )
    changes: list[FileChange] = Field(
        ..., min_length=1, description="List of file changes included in the patch"
    )
    commit_message: str = Field(
        ..., min_length=1, description="Git commit message for the patch"
    )
    description: str = Field(
        ..., min_length=1, description="Human-readable description of the patch"
    )


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
    risk_level: RiskLevel = Field(
        ..., description="Overall risk level of applying the patch"
    )
    breaking_changes: bool = Field(
        default=False,
        description="Whether the patch introduces breaking changes",
    )
    test_files_needed: list[str] = Field(
        default_factory=list,
        description="List of test files that should be created or updated",
    )

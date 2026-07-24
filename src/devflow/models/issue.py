"""GitHub Issue data models for DevFlow.

This module defines the data structures representing GitHub issues and their
classification, including complexity assessment, categorization, and
prioritization produced by the issue-classification agent.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class ComplexityLevel(str, Enum):
    """Complexity tier of an issue, from T1 (trivial) to T5 (architectural)."""

    T1 = "T1"  # Trivial - lint fix, typo
    T2 = "T2"  # Simple bug fix
    T3 = "T3"  # Moderate bug fix
    T4 = "T4"  # Complex feature
    T5 = "T5"  # Architectural change


class IssueCategory(str, Enum):
    """Functional category of an issue."""

    BUG = "bug"
    FEATURE = "feature"
    DOCS = "docs"
    REFACTOR = "refactor"


class IssuePriority(str, Enum):
    """Priority level of an issue."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IssueData(BaseModel):
    """Represents a GitHub issue with its core metadata."""

    issue_number: int = Field(
        ..., ge=1, description="GitHub issue number, must be positive"
    )
    title: str = Field(
        ..., min_length=1, max_length=512, description="Issue title"
    )
    body: str | None = Field(
        default=None, description="Issue body content in Markdown"
    )
    labels: list[str] = Field(
        default_factory=list, description="List of label names attached to the issue"
    )
    state: str = Field(
        default="open", description="Issue state (e.g. 'open' or 'closed')"
    )
    author: str = Field(
        ..., min_length=1, description="GitHub username of the issue author"
    )
    created_at: datetime = Field(
        ..., description="Timestamp when the issue was created"
    )
    repo_owner: str = Field(
        ..., min_length=1, description="Owner (user or org) of the repository"
    )
    repo_name: str = Field(
        ..., min_length=1, description="Name of the repository"
    )


class IssueClassification(BaseModel):
    """Classification result for a GitHub issue.

    Produced by the classification agent to guide downstream processing such as
    routing, effort estimation, and duplicate detection.
    """

    complexity_level: ComplexityLevel = Field(
        ..., description="Complexity tier from T1 (trivial) to T5 (architectural)"
    )
    category: IssueCategory = Field(
        ..., description="Functional category of the issue"
    )
    priority: IssuePriority = Field(
        ..., description="Priority of the issue"
    )
    duplicate_of: int | None = Field(
        default=None,
        ge=1,
        description="Issue number this issue is a duplicate of, if any",
    )
    estimated_effort_hours: float = Field(
        ...,
        ge=0.0,
        description="Estimated effort in hours required to resolve the issue",
    )

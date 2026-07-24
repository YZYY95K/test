"""Contract and gate tests for the DevFlow agents."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from devflow.agents.coder_agent import CoderAgent
from devflow.agents.reviewer_agent import ReviewerAgent
from devflow.agents.team_leader import TeamLeader
from devflow.exceptions import AgentError
from devflow.models.issue import (
    ComplexityLevel,
    IssueCategory,
    IssueClassification,
    IssueData,
    IssuePriority,
)
from devflow.models.patch import ChangeType, FileChange, Patch
from devflow.models.review import ReviewDecision
from devflow.models.test_result import TestRunResult as RunResult


def _issue() -> IssueData:
    return IssueData(
        issue_number=42,
        title="Fix an edge case",
        body="A focused bug report.",
        labels=["bug"],
        author="tester",
        created_at=datetime.now(timezone.utc),
        repo_owner="example",
        repo_name="repo",
    )


def _patch(path: str = "src/fix.py", content: str = "fixed = True\n") -> Patch:
    return Patch(
        branch_name="devflow/fix-42",
        changes=[
            FileChange(
                file_path=path,
                change_type=ChangeType.MODIFY,
                original_content="fixed = False\n",
                new_content=content,
                diff="--- a/src/fix.py\n+++ b/src/fix.py\n",
            )
        ],
        commit_message="fix: handle edge case",
        description="Focused correction.",
    )


@pytest.mark.asyncio
async def test_team_leader_builds_ordered_five_stage_plan() -> None:
    classification = IssueClassification(
        complexity_level=ComplexityLevel.T2,
        category=IssueCategory.BUG,
        priority=IssuePriority.MEDIUM,
        estimated_effort_hours=2,
    )
    tasks = await TeamLeader().decompose_task(_issue(), classification)

    assert [task.agent for task in tasks] == [
        "TriageAgent",
        "LocatorAgent",
        "CoderAgent",
        "TesterAgent",
        "ReviewerAgent",
    ]
    assert tasks[0].depends_on == []
    assert tasks[-1].depends_on == [tasks[-2].task_id]


def test_coder_rejects_repository_escape() -> None:
    with pytest.raises(AgentError, match="escapes the repository"):
        CoderAgent._validate_patch(_patch("../../outside.py"))


def test_coder_rejects_dangerous_execution() -> None:
    with pytest.raises(AgentError, match="blocked code patterns"):
        CoderAgent._validate_patch(_patch(content="eval(user_input)\n"))


@pytest.mark.asyncio
async def test_reviewer_requires_human_for_t4() -> None:
    tests = RunResult(
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        duration_ms=10,
    )
    result = await ReviewerAgent().run(
        {
            "issue_id": 42,
            "tier": "T4",
            "patch": _patch(),
            "test_result": tests,
            "create_pr": False,
        }
    )

    assert result.decision is ReviewDecision.HUMAN_APPROVAL_REQUIRED
    assert result.requires_human_approval is True

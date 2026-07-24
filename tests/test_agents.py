"""Contract and gate tests for the DevFlow agents."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from devflow.agents.coder_agent import CoderAgent
from devflow.agents.reviewer_agent import ReviewerAgent
from devflow.agents.team_leader import Conflict, IssueLifecycle, TeamLeader
from devflow.event_bus import event_bus
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


@pytest.mark.asyncio
async def test_team_leader_t1_skips_locator_and_routes_integral_envelope() -> None:
    event_bus.clear()
    classification = IssueClassification(
        complexity_level=ComplexityLevel.T1,
        category=IssueCategory.DOCS,
        priority=IssuePriority.LOW,
        estimated_effort_hours=0.25,
    )
    leader = TeamLeader()
    tasks = await leader.decompose_task(_issue(), classification)
    assert "LocatorAgent" not in [task.agent for task in tasks]

    await leader.route_task(tasks[0])
    routed = event_bus.history()[-1]
    assert routed.event_type == "task.route.triageagent"
    assert routed.payload["consumer"] == "TriageAgent"
    assert routed.payload["skill"] == "issue-classifier"
    assert routed.payload["artifact"]["sha256"]
    event_bus.clear()


class ArbitrationLLM:
    async def complete(self, *_args: object, **_kwargs: object) -> str:
        return "RESOLUTION: retry focused suite\nNEXT_AGENT: TesterAgent"


@pytest.mark.asyncio
async def test_team_leader_arbitrates_security_and_model_conflicts() -> None:
    event_bus.clear()
    leader = TeamLeader(llm_client=ArbitrationLLM())
    security = await leader.arbitrate(
        Conflict(
            issue_id=42,
            description="Reviewer found a security issue despite passing tests",
            parties=["TesterAgent", "ReviewerAgent"],
            positions={"ReviewerAgent": "unsafe deserialization"},
        )
    )
    assert security.resolution == "security_overrides_pass"
    assert security.next_agent == "CoderAgent"

    ordinary = await leader.arbitrate(
        Conflict(
            issue_id=42,
            description="Focused and full suites disagree",
            parties=["TesterAgent", "ReviewerAgent"],
        )
    )
    assert ordinary.resolution == "retry focused suite"
    assert ordinary.next_agent == "TesterAgent"
    assert event_bus.history()[-1].event_type == "arbitration.resolved"
    event_bus.clear()


@pytest.mark.asyncio
async def test_team_leader_failure_retry_escalation_and_approval_pause() -> None:
    event_bus.clear()
    leader = TeamLeader()
    retry = await leader.handle_failure(42, "TesterAgent", "timeout", attempt=1)
    assert retry.next_action == "retry"
    assert retry.payload["attempt"] == 2

    escalated = await leader.handle_failure(42, "TesterAgent", "timeout", attempt=3)
    assert escalated.next_action == "escalate_human"
    assert leader.get_lifecycle(42) is IssueLifecycle.REJECTED

    await leader._on_approval_required({"issue_id": 42, "tier": "T4"})
    assert leader._issue_context[42]["approval_required"] is True
    assert event_bus.history()[-1].event_type == "pipeline.paused"
    assert await leader.run(42) == {"issue_id": 42, "lifecycle": "rejected"}
    assert "42" in (await leader.run(None))["tracked_issues"]
    event_bus.clear()


@pytest.mark.asyncio
async def test_team_leader_event_handlers_advance_and_reverse_lifecycle() -> None:
    event_bus.clear()
    leader = TeamLeader()
    await leader._on_issue_created({"issue": _issue().model_dump(mode="json")})
    assert event_bus.history()[-1].event_type == "task.route.triageagent"

    await leader._on_agent_completed({"issue_id": 42, "agent": "TriageAgent"})
    assert leader.get_lifecycle(42) is IssueLifecycle.TRIAGED
    await leader._on_agent_completed({"issue_id": 42, "agent": "LocatorAgent"})
    assert leader.get_lifecycle(42) is IssueLifecycle.LOCATING

    await leader._on_review_rejected(
        {"issue_id": 42, "feedback": "narrow the patch", "findings": ["scope"]}
    )
    assert leader.get_lifecycle(42) is IssueLifecycle.CODING
    assert event_bus.history()[-1].payload["reason"] == "review_rejected"

    await leader._on_test_failed(
        {"issue_id": 42, "failing_tests": ["test_edge"], "test_output": "failed"}
    )
    assert event_bus.history()[-1].payload["reason"] == "test_failed"
    event_bus.clear()

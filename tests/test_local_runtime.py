"""Boundary and idempotency tests for the in-process task router."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest

from devflow.agents.base import AgentConfig, AgentIdentity, BaseAgent
from devflow.agents.team_leader import Task, TeamLeader
from devflow.agents.triage_agent import TriageAgent
from devflow.event_bus import LocalAgentEventRuntime, event_bus, publish
from devflow.local_runtime import LocalAgentTaskRouter
from devflow.models.issue import (
    ComplexityLevel,
    IssueCategory,
    IssueClassification,
    IssueData,
    IssuePriority,
)
from devflow.skills.contracts import HandoffEnvelope


class _CountingWorker(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            config=AgentConfig(
                name="LocatorAgent",
                identity=AgentIdentity(
                    role="Local route test Worker",
                    description="Count exact scheduler deliveries.",
                    model="test",
                ),
                skills=["code-root-cause"],
            )
        )
        self.calls = 0

    async def run(self, input_data: Any) -> dict[str, str]:
        del input_data
        self.calls += 1
        return {"private_result": "TOP_SECRET_ROUTER_RESULT"}


class _TriageLLM:
    async def complete_structured(self, **_kwargs: Any) -> IssueClassification:
        return IssueClassification(
            complexity_level=ComplexityLevel.T2,
            category=IssueCategory.BUG,
            priority=IssuePriority.MEDIUM,
            estimated_effort_hours=1,
        )

    async def complete(self, *_args: Any, **_kwargs: Any) -> str:
        return ""


@pytest.fixture(autouse=True)
def _isolated_bus() -> Any:
    event_bus.clear()
    yield
    event_bus.clear()


@pytest.mark.asyncio
async def test_issue_submission_becomes_canonical_triage_execution() -> None:
    leader = TeamLeader()
    triage = TriageAgent(llm_client=_TriageLLM())
    router = LocalAgentTaskRouter(leader, triage)
    runtime = LocalAgentEventRuntime(leader, router).start()
    issue = IssueData(
        issue_number=42,
        title="Route one bounded issue",
        body="The local scheduler should execute Triage exactly once.",
        labels=["bug"],
        author="runtime-test",
        created_at=datetime.now(timezone.utc),
        repo_owner="example",
        repo_name="repo",
    )
    try:
        await publish("issue.created", {"issue": issue.model_dump(mode="json")})

        route = next(
            record
            for record in event_bus.history()
            if record.event_type == "task.route.triageagent"
        )
        envelope = HandoffEnvelope.model_validate(route.payload)
        assert envelope.producer == "TeamLeader"
        assert envelope.consumer == "TriageAgent"
        assert envelope.skill == "issue-classifier"
        assert leader.is_authorized_execution_route(envelope)
        assert [
            record.event_type
            for record in event_bus.history()
            if record.event_type == "triage.completed"
        ] == ["triage.completed"]
    finally:
        runtime.stop()


@pytest.mark.asyncio
async def test_router_executes_only_once_across_duplicate_scheduler_delivery() -> None:
    leader = TeamLeader()
    worker = _CountingWorker()
    router = LocalAgentTaskRouter(leader, worker)
    runtime = LocalAgentEventRuntime(router).start()
    try:
        assert router.route_events == ("task.route.locatoragent",)
        assert event_bus.subscriber_count("task.route.locatoragent") == 1
        assert event_bus.subscriber_count("task.route.coderagent") == 0

        await leader.route_task(
            Task(
                task_id="42-1-locatoragent",
                agent="LocatorAgent",
                skill="code-root-cause",
                input_data={"issue_id": 42, "bounded": "input"},
                tier=ComplexityLevel.T2,
            )
        )
        route = next(
            record
            for record in event_bus.history()
            if record.event_type == "task.route.locatoragent"
        )
        assert worker.calls == 1

        # Leader owns the dispatch claim, so even a replacement Worker cannot
        # consume the same model-call/task lease a second time.
        await publish(route.event_type, route.payload)
        assert worker.calls == 1
        assert event_bus.history()[-1].event_type == "local.route.duplicate"

        serialized_history = json.dumps(
            [record.payload for record in event_bus.history()],
            sort_keys=True,
            default=str,
        )
        assert "TOP_SECRET_ROUTER_RESULT" not in serialized_history
    finally:
        runtime.stop()


@pytest.mark.asyncio
async def test_router_rejects_skill_mismatch_and_unissued_envelope_without_execution() -> None:
    leader = TeamLeader()
    worker = _CountingWorker()
    router = LocalAgentTaskRouter(leader, worker)
    runtime = LocalAgentEventRuntime(router).start()
    try:
        await leader.route_task(
            Task(
                task_id="42-wrong-skill",
                agent="LocatorAgent",
                skill="patch-generator",
                input_data={"issue_id": 42},
                tier=ComplexityLevel.T2,
            )
        )
        assert worker.calls == 0
        assert event_bus.history()[-1].event_type == "local.route.rejected"
        assert event_bus.history()[-1].payload["reason"] == "skill_mismatch"

        forged = HandoffEnvelope.create(
            run_id="issue-42",
            issue_id=42,
            task_id="42-forged-locatoragent",
            producer="TeamLeader",
            consumer="LocatorAgent",
            skill="code-root-cause",
            artifact_type="SkillInvocation",
            payload={"input": {"issue_id": 42}},
        )
        await publish(
            "task.route.locatoragent",
            forged.model_dump(mode="json"),
        )
        assert worker.calls == 0
        rejection = event_bus.history()[-1]
        assert rejection.event_type == "local.route.rejected"
        assert rejection.payload["reason"] == "route_not_issued"
        assert set(rejection.payload) == {
            "schema_version",
            "route_event",
            "reason",
            "payload_sha256",
        }
    finally:
        runtime.stop()

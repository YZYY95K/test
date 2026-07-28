"""Failure-correlation, replay, and subscription gates for the local runtime."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import pytest

from devflow.agents.base import AgentConfig, AgentIdentity, BaseAgent
from devflow.agents.coder_agent import CoderAgent
from devflow.agents.locator_agent import LocatedContext, RootCause
from devflow.agents.team_leader import IssueLifecycle, Task, TeamLeader
from devflow.event_bus import LocalAgentEventRuntime, event_bus, publish
from devflow.exceptions import AgentError, BoundaryViolationError
from devflow.models.agent_event import AgentFailureEvent
from devflow.models.issue import ComplexityLevel, IssueData
from devflow.models.patch import (
    ChangeType,
    FileChange,
    ImpactAnalysis,
    Patch,
    RiskLevel,
)
from devflow.models.test_result import (
    BaselineComparison,
)
from devflow.models.test_result import (
    TestCaseResult as CaseResult,
)
from devflow.models.test_result import (
    TestFailureEvidence as FailureEvidence,
)
from devflow.models.test_result import (
    TestRunResult as RunResult,
)
from devflow.models.test_result import (
    TestStatus as CaseStatus,
)
from devflow.skills.contracts import HandoffEnvelope, HandoffStatus

ISSUE_ID = 42


@pytest.fixture(autouse=True)
def _isolated_event_bus() -> Any:
    event_bus.clear()
    yield
    event_bus.clear()


class FailingWorker(BaseAgent):
    """Deterministic worker whose public name is supplied by AgentConfig."""

    def __init__(self, *, name: str, skill: str, message: str) -> None:
        super().__init__(
            config=AgentConfig(
                name=name,
                identity=AgentIdentity(
                    role="Failure test worker",
                    description="Raises a deterministic bounded exception.",
                    model="test",
                ),
                skills=[skill],
                max_consecutive_failures=3,
            )
        )
        self._message = message

    async def run(self, input_data: Any) -> Any:
        del input_data
        raise RuntimeError(self._message)


class SuccessfulWorker(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            config=AgentConfig(
                name="LocatorAgent",
                identity=AgentIdentity(
                    role="Success test worker",
                    description="Returns its validated input.",
                    model="test",
                ),
                skills=["code-root-cause"],
            )
        )
        self.calls = 0

    async def run(self, input_data: Any) -> Any:
        self.calls += 1
        return input_data


class BlockingSuccessfulWorker(SuccessfulWorker):
    """Expose the in-flight window for deterministic duplicate delivery."""

    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self, input_data: Any) -> Any:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return input_data


class InvalidCandidateLLM:
    """Count generation calls while returning a structurally invalid Patch."""

    def __init__(self) -> None:
        self.calls = 0

    async def complete_structured(
        self,
        *,
        prompt: str,
        response_model: type[Any],
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> Any:
        del prompt, response_model, model, temperature, system
        self.calls += 1
        return {"invalid": "candidate"}

    async def complete(
        self,
        prompt: str,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        system: str | None = None,
    ) -> str:
        del prompt, model, temperature, system
        return ""


def _issue() -> IssueData:
    return IssueData(
        issue_number=ISSUE_ID,
        title="Bounded recovery fixture",
        body="Exercise failure recovery without external effects.",
        labels=["bug"],
        author="fixture",
        created_at=datetime.now(timezone.utc),
        repo_owner="example",
        repo_name="repo",
    )


def _patch(content: str = "fixed = False\n") -> Patch:
    return Patch(
        branch_name="devflow/fix-42",
        changes=[
            FileChange(
                file_path="src/fix.py",
                change_type=ChangeType.MODIFY,
                original_content="fixed = False\n",
                new_content=content,
                diff="--- a/src/fix.py\n+++ b/src/fix.py\n",
            )
        ],
        commit_message="fix: bounded recovery fixture",
        description="A deterministic candidate patch.",
    )


def _located() -> LocatedContext:
    return LocatedContext(
        root_cause=RootCause(
            summary="The state remains false.",
            file="src/fix.py",
            start_line=1,
            end_line=1,
            confidence=0.99,
        ),
        context_payload="src/fix.py:1 fixed = False",
        related_tests=["tests/test_fix.py"],
        impact_analysis=ImpactAnalysis(
            affected_files=["src/fix.py"],
            affected_modules=["fix"],
            risk_level=RiskLevel.LOW,
            breaking_changes=False,
            test_files_needed=[],
        ),
    )


def _failed_test_result() -> RunResult:
    return RunResult(
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        duration_ms=5,
        results=[
            CaseResult(
                name="test_fix",
                status=CaseStatus.FAILED,
                duration_ms=5,
                error_message="assertion failed",
                traceback="bounded traceback",
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=0,
            new_failures=["test_fix"],
            fixed_tests=[],
            regression=True,
        ),
    )


def _coder_input(attempt: int) -> dict[str, Any]:
    issue = _issue()
    payload: dict[str, Any] = {
        "issue_id": ISSUE_ID,
        "issue": issue.model_dump(mode="json"),
        "tier": "T2",
        "located_context": _located().model_dump(mode="json"),
    }
    if attempt > 1:
        candidate = _patch()
        evidence = FailureEvidence.from_test_result(
            issue_id=ISSUE_ID,
            candidate=candidate,
            result=_failed_test_result(),
        )
        payload.update(
            {
                "previous_patch": candidate.model_dump(mode="json"),
                "test_failure_evidence": evidence.model_dump(mode="json"),
                "retry_attempt": attempt,
            }
        )
    return payload


def _tester_failure_handoff(candidate: Patch) -> HandoffEnvelope:
    result = _failed_test_result()
    evidence = FailureEvidence.from_test_result(
        issue_id=ISSUE_ID,
        candidate=candidate,
        result=result,
    )
    return HandoffEnvelope.create(
        run_id=f"issue-{ISSUE_ID}",
        issue_id=ISSUE_ID,
        task_id=f"{ISSUE_ID}-testeragent-test-runner",
        producer="TesterAgent",
        consumer="TeamLeader",
        skill="test-runner",
        artifact_type="TestEvidence",
        status=HandoffStatus.RETRY,
        payload={
            "issue_id": ISSUE_ID,
            "candidate_digest": evidence.candidate_digest,
            "test_result": result.model_dump(mode="json"),
            "failing_tests": evidence.failing_tests,
            "failure_evidence": evidence.model_dump(mode="json"),
        },
    )


def _routes(event_type: str) -> list[HandoffEnvelope]:
    return [
        HandoffEnvelope.model_validate(record.payload)
        for record in event_bus.history()
        if record.event_type == event_type
    ]


def _execution_failure(
    route: HandoffEnvelope,
    error: BaseException,
) -> AgentFailureEvent:
    return AgentFailureEvent.from_error(
        agent=route.consumer,
        error=error,
        consecutive_failures=1,
        issue_id=route.issue_id,
        run_id=route.run_id,
        task_id=route.task_id,
        trace_id=route.trace_id,
        idempotency_key=route.idempotency_key,
        execution_attempt=1,
        handoff_sha256=TeamLeader._handoff_sha256(route),
    )


@pytest.mark.asyncio
async def test_verified_failure_routes_real_retry_and_is_idempotent() -> None:
    secret = "gh" + "p_" + "A" * 40
    leader = TeamLeader()
    worker = FailingWorker(
        name="LocatorAgent",
        skill="code-root-cause",
        message=f"credential={secret}",
    )
    runtime = LocalAgentEventRuntime(leader).start()
    task = Task(
        task_id="42-2-locatoragent",
        agent="LocatorAgent",
        skill="code-root-cause",
        input_data={
            "issue_id": ISSUE_ID,
            "tier": "T2",
            "retry_attempt": 2,
            "bounded": True,
        },
        tier=ComplexityLevel.T2,
    )
    await leader.route_task(task)
    initial = _routes("task.route.locatoragent")[-1]

    with pytest.raises(RuntimeError):
        await worker.execute(initial.model_dump(mode="json"))

    failure_record = next(
        record for record in event_bus.history() if record.event_type == "agent.failed"
    )
    failure = AgentFailureEvent.model_validate(failure_record.payload)
    assert failure.correlation_trusted is True
    assert failure.issue_id == ISSUE_ID
    assert failure.execution_attempt == 1
    assert failure.trace_id == f"{failure.run_id}:{failure.task_id}"
    assert failure.retry_domain == "execution"
    assert secret not in json.dumps(
        [record.payload for record in event_bus.history()],
        sort_keys=True,
        default=str,
    )

    routes = _routes("task.route.locatoragent")
    assert len(routes) == 2
    retry = routes[-1]
    assert retry.status is HandoffStatus.RETRY
    assert retry.artifact.inline is not None
    assert retry.artifact.inline["input"]["retry_attempt"] == 2
    assert retry.artifact.inline["execution_retry"]["attempt"] == 2

    await publish("agent.failed", failure_record.payload)
    assert len(_routes("task.route.locatoragent")) == 2
    outcomes = [
        record.payload
        for record in event_bus.history()
        if record.event_type == "failure.handled"
    ]
    assert outcomes[-1]["idempotent"] is True
    assert outcomes[-1]["resolution"] == "retry_routed"
    runtime.stop()


@pytest.mark.asyncio
async def test_concurrent_distinct_failures_claim_one_route_and_both_are_audited() -> None:
    leader = TeamLeader()
    runtime = LocalAgentEventRuntime(leader).start()
    await leader.route_task(
        Task(
            task_id="42-concurrent-locator",
            agent="LocatorAgent",
            skill="code-root-cause",
            input_data={"issue_id": ISSUE_ID, "tier": "T2"},
            tier=ComplexityLevel.T2,
        )
    )
    route = _routes("task.route.locatoragent")[-1]
    first = _execution_failure(route, RuntimeError("first transient failure"))
    second = _execution_failure(route, RuntimeError("second transient failure"))
    assert first.failure_id != second.failure_id

    await asyncio.gather(
        publish("agent.failed", first.model_dump(mode="json")),
        publish("agent.failed", second.model_dump(mode="json")),
    )

    assert len(_routes("task.route.locatoragent")) == 2
    outcomes = [
        record.payload
        for record in event_bus.history()
        if record.event_type == "failure.handled"
        and record.payload["failure_id"] in {first.failure_id, second.failure_id}
    ]
    assert len(outcomes) == 2
    assert {outcome["resolution"] for outcome in outcomes} == {
        "retry_routed",
        "duplicate",
    }
    assert outcomes[0]["route_claim"] == outcomes[1]["route_claim"] == {
        "handoff_sha256": first.handoff_sha256,
        "execution_attempt": 1,
    }
    duplicate = next(
        outcome for outcome in outcomes if outcome["resolution"] == "duplicate"
    )
    assert duplicate["reason"] == "route_attempt_failure_conflict"
    assert duplicate["idempotent"] is True
    runtime.stop()


@pytest.mark.asyncio
async def test_retry_route_conflict_is_audited_instead_of_swallowed() -> None:
    leader = TeamLeader()
    runtime = LocalAgentEventRuntime(leader).start()
    await leader.route_task(
        Task(
            task_id="42-conflict-locator",
            agent="LocatorAgent",
            skill="code-root-cause",
            input_data={"issue_id": ISSUE_ID, "tier": "T2"},
            tier=ComplexityLevel.T2,
        )
    )
    route = _routes("task.route.locatoragent")[-1]
    conflicting_retry = HandoffEnvelope.create(
        run_id=route.run_id,
        issue_id=route.issue_id,
        task_id=f"{route.task_id}-exec-2",
        producer="TeamLeader",
        consumer="LocatorAgent",
        skill="code-root-cause",
        artifact_type="SkillInvocation",
        status=HandoffStatus.RETRY,
        payload={"input": {"conflicting": True}},
    )
    leader._remember_execution_route(conflicting_retry)

    failure = _execution_failure(route, RuntimeError("transient failure"))
    await publish("agent.failed", failure.model_dump(mode="json"))

    assert len(_routes("task.route.locatoragent")) == 1
    outcome = next(
        record.payload
        for record in event_bus.history()
        if record.event_type == "failure.handled"
        and record.payload["failure_id"] == failure.failure_id
    )
    assert outcome["resolution"] == "escalated"
    assert outcome["reason"] == "execution_retry_route_conflict"
    runtime.stop()


@pytest.mark.asyncio
async def test_third_execution_failure_escalates_without_fourth_route() -> None:
    secret = "sk-" + "B" * 24
    leader = TeamLeader()
    worker = FailingWorker(
        name="LocatorAgent",
        skill="code-root-cause",
        message=f"upstream={secret}",
    )
    runtime = LocalAgentEventRuntime(leader).start()
    await leader.route_task(
        Task(
            task_id="42-1-locatoragent",
            agent="LocatorAgent",
            skill="code-root-cause",
            input_data={"issue_id": ISSUE_ID, "tier": "T2"},
            tier=ComplexityLevel.T2,
        )
    )

    for expected_attempt in (1, 2, 3):
        route = _routes("task.route.locatoragent")[-1]
        with pytest.raises(RuntimeError):
            await worker.execute(route.model_dump(mode="json"))
        failure = AgentFailureEvent.model_validate(
            [
                record.payload
                for record in event_bus.history()
                if record.event_type == "agent.failed"
            ][-1]
        )
        assert failure.execution_attempt == expected_attempt

    assert len(_routes("task.route.locatoragent")) == 3
    outcome = [
        record.payload
        for record in event_bus.history()
        if record.event_type == "failure.handled"
    ][-1]
    assert outcome["resolution"] == "escalated"
    assert outcome["reason"] == "execution_retry_budget_exhausted"
    assert leader.get_lifecycle(ISSUE_ID) is IssueLifecycle.REJECTED
    assert secret not in json.dumps(
        [record.payload for record in event_bus.history()],
        sort_keys=True,
        default=str,
    )
    runtime.stop()


@pytest.mark.asyncio
async def test_coder_candidate_failures_never_multiply_generation_budget() -> None:
    leader = TeamLeader()
    llm = InvalidCandidateLLM()
    coder = CoderAgent(llm_client=llm)
    runtime = LocalAgentEventRuntime(leader).start()
    await leader.route_task(
        Task(
            task_id="42-coder-generation-1",
            agent="CoderAgent",
            skill="patch-generator",
            input_data=_coder_input(1),
            tier=ComplexityLevel.T2,
        )
    )
    routes: list[HandoffEnvelope] = []
    for expected_attempt in range(1, 4):
        route = _routes("task.route.coderagent")[-1]
        routes.append(route)
        assert route.artifact.inline is not None
        assert route.artifact.inline["input"]["model_call_attempt"] == expected_attempt
        with pytest.raises(AgentError, match="global model-call budget"):
            await coder.execute(route.model_dump(mode="json"))
        assert llm.calls == expected_attempt
        assert len(_routes("task.route.coderagent")) == min(
            expected_attempt + 1,
            3,
        )

    assert len({route.task_id for route in routes}) == 3
    assert len(_routes("coder.candidate_rejected")) == 2
    exhausted = _routes("coder.exhausted")
    assert len(exhausted) == 1
    assert exhausted[0].consumer == "TeamLeader"
    assert exhausted[0].status is HandoffStatus.FAILED
    assert exhausted[0].artifact.inline == {
        "schema_version": "devflow.skill-failure/v1",
        "issue_id": ISSUE_ID,
        "code": "CANDIDATE_INVALID",
        "semantic_patch_attempt": 1,
        "model_call_attempt": 3,
        "max_model_calls": 3,
        "rejection_code": "STRUCTURE_INVALID",
    }
    failures = [
        AgentFailureEvent.model_validate(record.payload)
        for record in event_bus.history()
        if record.event_type == "agent.failed"
        and record.payload.get("agent") == "CoderAgent"
    ]
    assert len(failures) == 3
    assert all(failure.error_code == "CANDIDATE_INVALID" for failure in failures)
    assert all(failure.retry_domain == "generation" for failure in failures)
    assert all(not failure.execution_retry_eligible for failure in failures)

    outcomes = [
        record.payload
        for record in event_bus.history()
        if record.event_type == "failure.handled"
        and record.payload.get("failed_agent") == "CoderAgent"
    ]
    assert len(outcomes) == 3
    assert [outcome["resolution"] for outcome in outcomes] == [
        "retry_routed",
        "retry_routed",
        "escalated",
    ]
    assert outcomes[-1]["reason"] == "generation_retry_budget_exhausted"
    assert outcomes[-1]["generation_attempt"] == 3
    assert leader.get_lifecycle(ISSUE_ID) is IssueLifecycle.REJECTED

    with pytest.raises(
        BoundaryViolationError,
        match="generation attempt was already claimed",
    ):
        await coder.execute(routes[-1].model_dump(mode="json"))
    assert llm.calls == 3
    assert len(_routes("task.route.coderagent")) == 3
    runtime.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["trace_id", "idempotency_key"])
async def test_forged_handoff_correlation_is_audited_but_not_trusted(
    field: str,
) -> None:
    worker = FailingWorker(
        name="LocatorAgent",
        skill="code-root-cause",
        message="must not run",
    )
    envelope = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=ISSUE_ID,
        task_id="42-1-locatoragent",
        producer="TeamLeader",
        consumer="LocatorAgent",
        skill="code-root-cause",
        artifact_type="SkillInvocation",
        payload={"input": {"issue_id": ISSUE_ID}},
    ).model_dump(mode="json")
    envelope[field] = "forged-correlation"

    with pytest.raises(BoundaryViolationError):
        await worker.execute(envelope)

    failure = AgentFailureEvent.model_validate(
        next(
            record.payload
            for record in event_bus.history()
            if record.event_type == "agent.failed"
        )
    )
    assert failure.correlation_trusted is False
    assert failure.issue_id is None
    assert failure.run_id is None
    assert failure.task_id is None
    assert failure.trace_id is None
    assert failure.idempotency_key is None
    assert failure.execution_attempt is None


@pytest.mark.asyncio
async def test_malformed_handoff_is_audited_without_forged_identifiers() -> None:
    worker = FailingWorker(
        name="LocatorAgent",
        skill="code-root-cause",
        message="must not run",
    )
    malformed = {
        "envelope_version": "1.0",
        "issue_id": 999,
        "run_id": "forged-run",
        "task_id": "forged-task",
        "trace_id": "forged-trace",
    }
    with pytest.raises(BoundaryViolationError):
        await worker.execute(malformed)
    failure = AgentFailureEvent.model_validate(
        next(
            record.payload
            for record in event_bus.history()
            if record.event_type == "agent.failed"
        )
    )
    assert failure.correlation_trusted is False
    assert all(
        value is None
        for value in (
            failure.issue_id,
            failure.run_id,
            failure.task_id,
            failure.trace_id,
            failure.idempotency_key,
            failure.execution_attempt,
            failure.handoff_sha256,
        )
    )


@pytest.mark.asyncio
async def test_success_completion_declares_execution_outcome() -> None:
    worker = SuccessfulWorker()
    envelope = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=ISSUE_ID,
        task_id="42-1-locatoragent",
        producer="TeamLeader",
        consumer="LocatorAgent",
        skill="code-root-cause",
        artifact_type="SkillInvocation",
        payload={"input": {"issue_id": ISSUE_ID}},
    )
    assert await worker.execute(envelope.model_dump(mode="json")) == {
        "issue_id": ISSUE_ID
    }
    completed = next(
        record.payload
        for record in event_bus.history()
        if record.event_type == "agent.completed"
    )
    assert completed["outcome"] == "execution_succeeded"
    assert completed["execution_attempt"] == 1
    assert completed["trace_id"] == envelope.trace_id


@pytest.mark.asyncio
async def test_successful_handoff_redelivery_is_cached_and_never_routes_retry() -> None:
    leader = TeamLeader()
    worker = BlockingSuccessfulWorker()
    runtime = LocalAgentEventRuntime(leader).start()
    await leader.route_task(
        Task(
            task_id="42-idempotent-locator",
            agent="LocatorAgent",
            skill="code-root-cause",
            input_data={
                "issue_id": ISSUE_ID,
                "tier": "T2",
                "private_marker": "must-not-enter-duplicate-audit",
            },
            tier=ComplexityLevel.T2,
        )
    )
    route = _routes("task.route.locatoragent")[-1]
    envelope = route.model_dump(mode="json")

    first = asyncio.create_task(worker.execute(envelope))
    await worker.started.wait()
    concurrent_redelivery = asyncio.create_task(worker.execute(envelope))
    await asyncio.sleep(0)
    worker.release.set()

    first_result, concurrent_result = await asyncio.gather(
        first,
        concurrent_redelivery,
    )
    completed_redelivery = await worker.execute(envelope)

    assert first_result == concurrent_result == completed_redelivery
    assert worker.calls == 1
    assert len(_routes("task.route.locatoragent")) == 1
    assert not [
        record
        for record in event_bus.history()
        if record.event_type in {"agent.failed", "failure.handled"}
    ]
    assert len(
        [
            record
            for record in event_bus.history()
            if record.event_type == "agent.completed"
        ]
    ) == 1
    duplicates = [
        record.payload
        for record in event_bus.history()
        if record.event_type == "agent.execution.duplicate"
    ]
    assert len(duplicates) == 2
    assert all(
        duplicate == {
            "agent": "LocatorAgent",
            "schema_version": "devflow.execution-duplicate/v1",
            "outcome": "cached_success",
            "idempotent": True,
            "issue_id": ISSUE_ID,
            "execution_attempt": 1,
            "handoff_sha256": TeamLeader._handoff_sha256(route),
            "timestamp": duplicate["timestamp"],
        }
        for duplicate in duplicates
    )
    assert "must-not-enter-duplicate-audit" not in json.dumps(duplicates)
    runtime.stop()


def test_explicit_runtime_subscription_is_idempotent_and_reversible() -> None:
    leader = TeamLeader()
    runtime = LocalAgentEventRuntime(leader)
    assert event_bus.subscriber_count("agent.failed") == 0
    runtime.start()
    runtime.start()
    leader.subscribe_events()
    assert event_bus.subscriber_count("agent.failed") == 1
    assert event_bus.subscriber_count("test.failed") == 1
    runtime.stop()
    runtime.stop()
    assert event_bus.subscriber_count("agent.failed") == 0
    assert event_bus.subscriber_count("test.failed") == 0


@pytest.mark.asyncio
async def test_untrusted_direct_failure_escalates_without_claiming_retry() -> None:
    leader = TeamLeader()
    worker = FailingWorker(
        name="CoderAgent",
        skill="patch-generator",
        message="direct invocation failed",
    )
    runtime = LocalAgentEventRuntime(leader).start()
    with pytest.raises(RuntimeError):
        await worker.execute({"issue_id": ISSUE_ID, "retry_attempt": 2})
    assert _routes("task.route.coderagent") == []
    outcome = next(
        record.payload
        for record in event_bus.history()
        if record.event_type == "failure.handled"
    )
    assert outcome["resolution"] == "escalated"
    assert outcome["reason"] == "untrusted_execution_context"
    assert "issue_id" not in outcome
    runtime.stop()


@pytest.mark.asyncio
async def test_tester_completion_cannot_overwrite_pending_semantic_retry() -> None:
    leader = TeamLeader()
    leader._issue_context[ISSUE_ID] = {
        "pending_test_retry": {"bounded": True},
        "semantic_test_failure": {"bounded": True},
        "patch_attempt": 1,
    }
    leader._set_lifecycle(ISSUE_ID, IssueLifecycle.CODING)
    runtime = LocalAgentEventRuntime(leader).start()
    await publish(
        "agent.completed",
        {
            "agent": "TesterAgent",
            "issue_id": ISSUE_ID,
            "outcome": "execution_succeeded",
        },
    )
    assert leader.get_lifecycle(ISSUE_ID) is IssueLifecycle.CODING
    assert event_bus.history()[-1].event_type == "agent.completion.ignored"
    runtime.stop()


@pytest.mark.asyncio
async def test_tester_execution_completion_never_substitutes_for_gate_outcome() -> None:
    leader = TeamLeader()
    leader._set_lifecycle(ISSUE_ID, IssueLifecycle.CODING)
    runtime = LocalAgentEventRuntime(leader).start()

    await publish(
        "agent.completed",
        {
            "agent": "TesterAgent",
            "issue_id": ISSUE_ID,
            "outcome": "execution_succeeded",
        },
    )

    assert leader.get_lifecycle(ISSUE_ID) is IssueLifecycle.CODING
    decision = event_bus.history()[-1]
    assert decision.event_type == "agent.completion.ignored"
    assert decision.payload["reason"] == "semantic_test_outcome_required"
    runtime.stop()


def test_next_patch_attempt_clears_only_semantic_retry_state() -> None:
    leader = TeamLeader()
    issue = _issue()
    located = _located()
    leader.record_retry_context(
        ISSUE_ID,
        issue=issue,
        tier=ComplexityLevel.T2,
        located_context=located,
        previous_patch=_patch(),
        patch_attempt=1,
    )
    context = leader._issue_context[ISSUE_ID]
    context["pending_test_retry"] = {"bounded": True}
    context["semantic_test_failure"] = {"bounded": True}
    context["execution_attempt"] = 3
    leader.record_retry_context(
        ISSUE_ID,
        issue=issue,
        tier=ComplexityLevel.T2,
        located_context=located,
        previous_patch=_patch("fixed = True\n"),
        patch_attempt=2,
        model_call_attempt=2,
    )
    assert context["patch_attempt"] == 2
    assert "pending_test_retry" not in context
    assert "semantic_test_failure" not in context
    assert context["execution_attempt"] == 3


@pytest.mark.asyncio
async def test_invalid_tester_failure_has_no_sticky_state_side_effect() -> None:
    leader = TeamLeader()
    handoff = _tester_failure_handoff(_patch())
    with pytest.raises(AgentError, match="Canonical retry context is incomplete"):
        await leader._on_test_failed(handoff.model_dump(mode="json"))
    assert ISSUE_ID not in leader._issue_context


@pytest.mark.asyncio
async def test_conflicting_pending_test_retry_has_no_sticky_failure_marker() -> None:
    leader = TeamLeader()
    candidate = _patch()
    leader.record_retry_context(
        ISSUE_ID,
        issue=_issue(),
        tier=ComplexityLevel.T2,
        located_context=_located(),
        previous_patch=candidate,
        patch_attempt=1,
    )
    context = leader._issue_context[ISSUE_ID]
    context["pending_test_retry"] = {"test_result_digest": "0" * 64}
    with pytest.raises(AgentError, match="different test retry"):
        await leader._on_test_failed(
            _tester_failure_handoff(candidate).model_dump(mode="json")
        )
    assert "semantic_test_failure" not in context


@pytest.mark.asyncio
async def test_legacy_untyped_test_failure_is_rejected_by_default() -> None:
    leader = TeamLeader()
    with pytest.raises(AgentError, match="typed Tester hand-off required"):
        await leader._on_test_failed({"issue_id": ISSUE_ID})
    assert ISSUE_ID not in leader._issue_context

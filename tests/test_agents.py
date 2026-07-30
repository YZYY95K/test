"""Contract and gate tests for the DevFlow agents."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from devflow.agents.base import LLMClient
from devflow.agents.coder_agent import CoderAgent
from devflow.agents.locator_agent import LocatedContext, RootCause
from devflow.agents.reviewer_agent import ReviewerAgent
from devflow.agents.team_leader import Conflict, IssueLifecycle, Task, TeamLeader
from devflow.agents.tester_agent import TesterAgent as DevFlowTesterAgent
from devflow.event_bus import LocalAgentEventRuntime, event_bus
from devflow.exceptions import AgentError
from devflow.local_runtime import LocalAgentTaskRouter
from devflow.mcp.cicd import PORTABLE_CICD_SERVER, IsolatedTestService
from devflow.mcp.contracts import MCPCallContext
from devflow.models.issue import (
    ComplexityLevel,
    IssueCategory,
    IssueClassification,
    IssueData,
    IssuePriority,
)
from devflow.models.patch import (
    ChangeType,
    FileChange,
    ImpactAnalysis,
    Patch,
    RiskLevel,
)
from devflow.models.review import ReviewDecision, ReviewResult
from devflow.models.test_integrity import (
    TEST_INTEGRITY_POLICY,
    TEST_INTEGRITY_POLICY_DIGEST,
    TEST_ISOLATION_BOUNDARY,
)
from devflow.models.test_integrity import (
    TestIntegrityAttestation as IntegrityAttestation,
)
from devflow.models.test_result import (
    BaselineComparison,
    canonical_artifact_digest,
)
from devflow.models.test_result import (
    TestCaseResult as CaseResult,
)
from devflow.models.test_result import (
    TestFailureEvidence as FailureEvidence,
)
from devflow.models.test_result import (
    TestFailureReason as FailureReason,
)
from devflow.models.test_result import (
    TestRunResult as RunResult,
)
from devflow.models.test_result import (
    TestStatus as CaseStatus,
)
from devflow.skills.contracts import HandoffEnvelope, HandoffStatus


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


def _located_context(path: str = "src/fix.py") -> LocatedContext:
    return LocatedContext(
        root_cause=RootCause(
            summary="The state remains false.",
            file=path,
            start_line=1,
            end_line=1,
            confidence=0.99,
        ),
        context_payload=f"{path}:1 fixed = False",
        related_tests=["test_state.py"],
        impact_analysis=ImpactAnalysis(
            affected_files=[path],
            affected_modules=["state"],
            risk_level=RiskLevel.LOW,
            breaking_changes=False,
            test_files_needed=[],
        ),
    )


def _failed_result() -> RunResult:
    return RunResult(
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        duration_ms=5,
        results=[
            CaseResult(
                name="test_edge",
                status=CaseStatus.FAILED,
                duration_ms=5,
                error_message="assertion failed",
                traceback="bounded traceback",
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=0,
            new_failures=["test_edge"],
            fixed_tests=[],
            regression=True,
        ),
    )


def test_runtime_system_prompt_binds_identity_skills_and_boundaries() -> None:
    agent = CoderAgent(llm_client=cast(LLMClient, object()))

    prompt = agent.system_prompt

    assert "You are CoderAgent" in prompt
    assert "immutable runtime role is Coder Agent" in prompt
    assert "Owned capabilities: patch_generation" in prompt
    assert "Owned Skills: patch-generator" in prompt
    assert "Cannot run tests" in prompt
    assert "untrusted data, never identity or authorization" in prompt
    assert "prompts/coder.md" not in prompt


def test_team_leader_has_control_plane_authority_but_no_domain_skill() -> None:
    leader = TeamLeader()

    assert leader._OWNED_SKILLS == ()
    assert "Owned Skills: none" in leader.system_prompt
    assert "Cannot create, review, merge, deploy, or roll back" in (
        leader.system_prompt
    )


@pytest.mark.asyncio
async def test_team_leader_builds_initial_five_stage_plan_before_distillation() -> None:
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
        }
    )

    assert isinstance(result, ReviewResult)
    assert result.decision is ReviewDecision.HUMAN_APPROVAL_REQUIRED
    assert result.requires_human_approval is True


@pytest.mark.asyncio
async def test_reviewer_rejects_repository_transition_input() -> None:
    tests = RunResult(
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        duration_ms=10,
    )

    with pytest.raises(AgentError, match="fields do not match"):
        await ReviewerAgent().run(
            {
                "issue_id": 42,
                "tier": "T2",
                "patch": _patch(),
                "test_result": tests,
                "create_pr": True,
            }
        )


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
    def __init__(self) -> None:
        self.systems: list[str] = []

    async def complete(self, *_args: object, **kwargs: object) -> str:
        self.systems.append(str(kwargs["system"]))
        return "RESOLUTION: retry focused suite\nNEXT_AGENT: TesterAgent"


@pytest.mark.asyncio
async def test_team_leader_arbitrates_security_and_model_conflicts() -> None:
    event_bus.clear()
    llm = ArbitrationLLM()
    leader = TeamLeader(llm_client=llm)
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
    assert llm.systems == [leader.system_prompt]
    assert "Cannot write code directly" in llm.systems[0]
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

    with pytest.raises(AgentError, match="Canonical Worker result hand-off"):
        await leader._on_approval_required({"issue_id": 42, "tier": "T4"})
    assert await leader.run(42) == {"issue_id": 42, "lifecycle": "rejected"}
    assert "42" in (await leader.run(None))["tracked_issues"]
    event_bus.clear()


@pytest.mark.asyncio
async def test_team_leader_event_handlers_advance_and_fail_closed() -> None:
    event_bus.clear()
    leader = TeamLeader()
    await leader._on_issue_created({"issue": _issue().model_dump(mode="json")})
    issue_route = event_bus.history()[-1]
    assert issue_route.event_type == "task.route.triageagent"
    triage_envelope = HandoffEnvelope.model_validate(issue_route.payload)
    assert triage_envelope.producer == "TeamLeader"
    assert triage_envelope.consumer == "TriageAgent"
    assert triage_envelope.skill == "issue-classifier"
    assert leader.is_authorized_execution_route(triage_envelope)

    await leader._on_agent_completed({"issue_id": 42, "agent": "TriageAgent"})
    assert leader.get_lifecycle(42) is IssueLifecycle.TRIAGED
    await leader._on_agent_completed({"issue_id": 42, "agent": "LocatorAgent"})
    assert leader.get_lifecycle(42) is IssueLifecycle.LOCATING

    review = ReviewResult(
        decision=ReviewDecision.CHANGES_REQUESTED,
        findings=[],
        summary="Candidate needs a revision.",
    )
    rejected = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=42,
        task_id="42-revieweragent-pr-reviewer-rejected",
        producer="ReviewerAgent",
        consumer="TeamLeader",
        skill="pr-reviewer",
        artifact_type="ReviewDecision",
        status=HandoffStatus.RETRY,
        payload={
            "issue_id": 42,
            "tier": "T2",
            "review": review.model_dump(mode="json"),
        },
    )
    await leader._on_review_rejected(rejected.model_dump(mode="json"))
    assert leader.get_lifecycle(42) is IssueLifecycle.REJECTED
    assert event_bus.history()[-1].event_type == "review.remediation_blocked"
    assert event_bus.history()[-1].payload["requires_human_replan"] is True
    assert not [
        record for record in event_bus.history() if record.event_type == "task.route.coderagent"
    ]

    failed_result = _failed_result()
    failure_evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=_patch(),
        result=failed_result,
    )
    event_count = len(event_bus.history())
    with pytest.raises(AgentError, match="Canonical Worker result hand-off"):
        await leader._on_test_failed(
            {
                "issue_id": 42,
                "candidate_digest": failure_evidence.candidate_digest,
                "test_result": failed_result.model_dump(mode="json"),
                "failing_tests": failure_evidence.failing_tests,
                "failure_evidence": failure_evidence.model_dump(mode="json"),
            }
        )
    assert len(event_bus.history()) == event_count
    event_bus.clear()


class IsolatedServiceMCP:
    def __init__(self, service: IsolatedTestService) -> None:
        self.service = service

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert (server, tool) == (PORTABLE_CICD_SERVER, "run_tests")
        assert set(arguments) == {"issue_id", "patch"}
        context = cast(MCPCallContext, _kwargs["context"])
        assert context.risk_tier is not None
        result = await self.service.run_tests(
            Patch.model_validate(arguments["patch"]),
            risk_tier=context.risk_tier,
        )
        return result.model_dump(mode="json")


class StaticResultMCP:
    def __init__(self, result: RunResult, *, attest: bool = True) -> None:
        self.result = result
        self.attest = attest

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert (server, tool) == (PORTABLE_CICD_SERVER, "run_tests")
        assert arguments["issue_id"] == 42
        assert set(arguments) == {"issue_id", "patch"}
        if not self.attest:
            return self.result.model_dump(mode="json")
        context = cast(MCPCallContext, _kwargs["context"])
        assert context.risk_tier is not None
        attested = self.result.model_copy(
            update={
                "integrity_attestation": IntegrityAttestation(
                    policy=TEST_INTEGRITY_POLICY,
                    policy_digest=TEST_INTEGRITY_POLICY_DIGEST,
                    command_digest="a" * 64,
                    baseline_manifest_digest="b" * 64,
                    candidate_baseline_manifest_digest="b" * 64,
                    candidate_pre_run_manifest_digest="c" * 64,
                    candidate_post_run_manifest_digest="c" * 64,
                    added_tests_manifest_digest="d" * 64,
                    baseline_protected_file_count=1,
                    added_test_file_count=0,
                    full_suite=context.risk_tier in {"T3", "T4", "T5"},
                    verified=True,
                    isolation_boundary=TEST_ISOLATION_BOUNDARY,
                )
            }
        )
        return attested.model_dump(mode="json")


class RevisionLLM:
    def __init__(self, patch: Patch) -> None:
        self.patch = patch
        self.prompts: list[str] = []

    async def complete_structured(self, **kwargs: Any) -> Patch:
        self.prompts.append(str(kwargs["prompt"]))
        return self.patch

    async def complete(self, prompt: str, **_kwargs: Any) -> str:
        self.prompts.append(prompt)
        return ""


class SequentialRevisionLLM:
    """Return one deterministic value for each issue-global model call."""

    def __init__(self, patches: list[Any]) -> None:
        self._patches = list(patches)
        self.prompts: list[str] = []

    async def complete_structured(self, **kwargs: Any) -> Any:
        self.prompts.append(str(kwargs["prompt"]))
        return self._patches[len(self.prompts) - 1]

    async def complete(self, prompt: str, **_kwargs: Any) -> str:
        self.prompts.append(prompt)
        return ""


def _state_patch(value: str) -> Patch:
    original = "fixed = False\n"
    updated = f"fixed = {value}\n"
    return Patch(
        branch_name="devflow/fix-state",
        changes=[
            FileChange(
                file_path="state.py",
                change_type=ChangeType.MODIFY,
                original_content=original,
                new_content=updated,
                diff=(
                    "--- a/state.py\n"
                    "+++ b/state.py\n"
                    "@@ -1 +1 @@\n"
                    "-fixed = False\n"
                    f"+fixed = {value}\n"
                ),
            )
        ],
        commit_message="fix: set the state",
        description="Set the state to the expected value.",
    )


@pytest.mark.asyncio
async def test_unrouted_coder_candidate_cannot_seed_retry_context() -> None:
    event_bus.clear()
    candidate = _state_patch("None")
    await CoderAgent(llm_client=RevisionLLM(candidate)).execute(
        {
            "issue_id": 42,
            "issue": _issue().model_dump(mode="json"),
            "tier": "T2",
            "located_context": _located_context("state.py").model_dump(mode="json"),
        }
    )
    candidate_event = next(
        record.payload for record in event_bus.history() if record.event_type == "coder.patch_ready"
    )
    leader = TeamLeader()

    with pytest.raises(AgentError, match="source route binding"):
        await leader._on_coder_patch_ready(candidate_event)

    assert 42 not in leader._issue_context
    event_bus.clear()


@pytest.mark.asyncio
async def test_tester_failure_routes_digest_bound_coder_retry_then_passes(
    tmp_path: Path,
) -> None:
    event_bus.clear()
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "state.py").write_text("fixed = False\n", encoding="utf-8")
    (repository / "test_state.py").write_text(
        "import unittest\n"
        "from state import fixed\n\n"
        "class StateTests(unittest.TestCase):\n"
        "    def test_fixed(self):\n"
        "        self.assertTrue(fixed)\n",
        encoding="utf-8",
    )
    service = IsolatedTestService(
        repository,
        (sys.executable, "-m", "unittest", "discover", "-v"),
        (sys.executable, "-m", "unittest", "discover", "-v"),
        timeout_seconds=30,
    )
    tester = DevFlowTesterAgent(mcp_client=IsolatedServiceMCP(service))
    candidate_one = _state_patch("None")
    candidate_two = _state_patch("True")
    located = _located_context("state.py")
    leader = TeamLeader()
    runtime = LocalAgentEventRuntime(leader).start()
    try:
        initial_llm = RevisionLLM(candidate_one)
        initial_coder = CoderAgent(llm_client=initial_llm)
        await leader.route_task(
            Task(
                task_id="42-1-coderagent",
                agent="CoderAgent",
                skill="patch-generator",
                input_data={
                    "issue_id": 42,
                    "issue": _issue().model_dump(mode="json"),
                    "tier": "T2",
                    "located_context": located.model_dump(mode="json"),
                },
                tier=ComplexityLevel.T2,
            )
        )
        initial_envelope = HandoffEnvelope.model_validate(
            next(
                record.payload
                for record in event_bus.history()
                if record.event_type == "task.route.coderagent"
            )
        )
        assert leader.claim_execution_route(initial_envelope) is True
        generated = await initial_coder.execute(initial_envelope.model_dump(mode="json"))
        assert generated == candidate_one
        initial_candidate = HandoffEnvelope.model_validate(
            [
                record.payload
                for record in event_bus.history()
                if record.event_type == "coder.patch_ready"
            ][-1]
        )
        assert initial_candidate.artifact.inline is not None
        assert leader._issue_context[42]["patch_attempt"] == 1
        assert leader._issue_context[42]["previous_patch_digest"] == (
            canonical_artifact_digest(candidate_one)
        )

        first_tester_route = HandoffEnvelope.model_validate(
            [
                record.payload
                for record in event_bus.history()
                if record.event_type == "task.route.testeragent"
            ][-1]
        )
        assert leader.claim_execution_route(first_tester_route) is True
        first_result = await tester.execute(first_tester_route.model_dump(mode="json"))
        assert first_result.failed == 1
        failed_event = next(
            record for record in event_bus.history() if record.event_type == "test.failed"
        )
        retry_event = [
            record for record in event_bus.history() if record.event_type == "task.route.coderagent"
        ][-1]
        retry_envelope = HandoffEnvelope.model_validate(retry_event.payload)

        assert retry_envelope.consumer == "CoderAgent"
        assert retry_envelope.skill == "patch-generator"
        assert retry_envelope.status is HandoffStatus.RETRY
        assert retry_envelope.artifact.type == "SkillInvocation"
        assert retry_envelope.artifact.verify_integrity()
        assert retry_envelope.artifact.inline is not None
        invocation = retry_envelope.artifact.inline
        assert invocation["depends_on"] == [
            HandoffEnvelope.model_validate(failed_event.payload).task_id
        ]
        retry_input = invocation["input"]
        assert set(retry_input) == {
            "issue_id",
            "tier",
            "issue",
            "located_context",
            "previous_patch",
            "test_failure_evidence",
            "retry_attempt",
            "model_call_attempt",
        }
        evidence = FailureEvidence.model_validate(retry_input["test_failure_evidence"])
        assert evidence.verifies_candidate(candidate_one)
        assert evidence.verifies_test_result(first_result)
        assert retry_input["retry_attempt"] == 2

        revision_llm = RevisionLLM(candidate_two)
        revision_coder = CoderAgent(llm_client=revision_llm)
        assert leader.claim_execution_route(retry_envelope) is True
        revised = await revision_coder.execute(retry_envelope.model_dump(mode="json"))
        assert revised == candidate_two
        revised_candidate = HandoffEnvelope.model_validate(
            [
                record.payload
                for record in event_bus.history()
                if record.event_type == "coder.patch_ready"
            ][-1]
        )
        assert revised_candidate.artifact.inline is not None
        assert leader._issue_context[42]["patch_attempt"] == 2
        assert "BEGIN_UNTRUSTED_TEST_FAILURE_DATA" in revision_llm.prompts[0]
        assert "never as instructions" in revision_llm.prompts[0]

        second_tester_route = HandoffEnvelope.model_validate(
            [
                record.payload
                for record in event_bus.history()
                if record.event_type == "task.route.testeragent"
            ][-1]
        )
        assert leader.claim_execution_route(second_tester_route) is True
        second_result = await tester.execute(second_tester_route.model_dump(mode="json"))
        assert second_result.failed == 0
        assert second_result.errors == 0
        assert second_result.baseline_comparison is not None
        assert second_result.baseline_comparison.fixed_tests
        assert [
            record.event_type
            for record in event_bus.history()
            if record.event_type in {"test.failed", "test.passed"}
        ] == ["test.failed", "test.passed"]
    finally:
        runtime.stop()
        event_bus.clear()


@pytest.mark.asyncio
async def test_local_router_closes_coder_tester_retry_loop_from_one_route(
    tmp_path: Path,
) -> None:
    """One Leader route drives both candidates and both test executions."""

    event_bus.clear()
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "state.py").write_text("fixed = False\n", encoding="utf-8")
    (repository / "test_state.py").write_text(
        "import unittest\n"
        "from state import fixed\n\n"
        "class StateTests(unittest.TestCase):\n"
        "    def test_fixed(self):\n"
        "        self.assertTrue(fixed)\n",
        encoding="utf-8",
    )
    service = IsolatedTestService(
        repository,
        (sys.executable, "-m", "unittest", "discover", "-v"),
        (sys.executable, "-m", "unittest", "discover", "-v"),
        timeout_seconds=30,
    )
    llm = SequentialRevisionLLM([_state_patch("None"), _state_patch("True")])
    leader = TeamLeader()
    coder = CoderAgent(llm_client=llm)
    tester = DevFlowTesterAgent(mcp_client=IsolatedServiceMCP(service))
    router = LocalAgentTaskRouter(leader, coder, tester)
    runtime = LocalAgentEventRuntime(leader, router).start()
    try:
        await leader.route_task(
            Task(
                task_id="42-1-coderagent",
                agent="CoderAgent",
                skill="patch-generator",
                input_data={
                    "issue_id": 42,
                    "issue": _issue().model_dump(mode="json"),
                    "tier": "T2",
                    "located_context": _located_context("state.py").model_dump(mode="json"),
                },
                tier=ComplexityLevel.T2,
            )
        )

        routed = [
            HandoffEnvelope.model_validate(record.payload)
            for record in event_bus.history()
            if record.event_type in {"task.route.coderagent", "task.route.testeragent"}
        ]
        assert [(envelope.consumer, envelope.skill, envelope.status) for envelope in routed] == [
            ("CoderAgent", "patch-generator", HandoffStatus.READY),
            ("TesterAgent", "test-runner", HandoffStatus.READY),
            ("CoderAgent", "patch-generator", HandoffStatus.RETRY),
            ("TesterAgent", "test-runner", HandoffStatus.READY),
        ]
        assert all(envelope.producer == "TeamLeader" for envelope in routed)
        assert all(envelope.artifact.verify_integrity() for envelope in routed)
        assert len(llm.prompts) == 2
        assert "BEGIN_UNTRUSTED_TEST_FAILURE_DATA" in llm.prompts[1]
        assert leader._issue_context[42]["patch_attempt"] == 2
        assert [
            record.event_type
            for record in event_bus.history()
            if record.event_type in {"test.failed", "test.passed"}
        ] == ["test.failed", "test.passed"]
        assert not [
            record for record in event_bus.history() if record.event_type == "local.route.rejected"
        ]
    finally:
        runtime.stop()
        event_bus.clear()


@pytest.mark.asyncio
async def test_global_model_call_budget_spans_validation_and_test_failure() -> None:
    """Two invalid candidates plus one tested candidate consume all three calls."""

    event_bus.clear()
    llm = SequentialRevisionLLM(
        [
            {"invalid": "candidate-one"},
            {"invalid": "candidate-two"},
            _state_patch("True"),
        ]
    )
    leader = TeamLeader()
    coder = CoderAgent(llm_client=llm)
    tester = DevFlowTesterAgent(mcp_client=StaticResultMCP(_failed_result()))
    router = LocalAgentTaskRouter(leader, coder, tester)
    runtime = LocalAgentEventRuntime(leader, router).start()
    try:
        await leader.route_task(
            Task(
                task_id="42-global-budget-coderagent",
                agent="CoderAgent",
                skill="patch-generator",
                input_data={
                    "issue_id": 42,
                    "issue": _issue().model_dump(mode="json"),
                    "tier": "T2",
                    "located_context": _located_context("state.py").model_dump(mode="json"),
                },
                tier=ComplexityLevel.T2,
            )
        )

        coder_routes = [
            HandoffEnvelope.model_validate(record.payload)
            for record in event_bus.history()
            if record.event_type == "task.route.coderagent"
        ]
        assert len(coder_routes) == 3
        assert [
            route.artifact.inline["input"]["model_call_attempt"]
            for route in coder_routes
            if route.artifact.inline is not None
        ] == [1, 2, 3]
        assert len(llm.prompts) == 3
        assert "Trusted deterministic validator feedback" not in llm.prompts[0]
        assert "rejection_code: CANDIDATE_INVALID" in llm.prompts[1]
        assert "rejection_code: CANDIDATE_INVALID" in llm.prompts[2]

        candidate = HandoffEnvelope.model_validate(
            [
                record.payload
                for record in event_bus.history()
                if record.event_type == "coder.patch_ready"
            ][-1]
        )
        assert candidate.artifact.inline is not None
        assert candidate.artifact.inline["model_call_attempt"] == 3
        assert candidate.artifact.inline["retry_attempt"] == 1
        assert (
            len([record for record in event_bus.history() if record.event_type == "test.failed"])
            == 1
        )
        assert (
            len(
                [
                    record
                    for record in event_bus.history()
                    if record.event_type == "generation.budget_exhausted"
                ]
            )
            == 1
        )
        assert leader.get_lifecycle(42) is IssueLifecycle.REJECTED
    finally:
        runtime.stop()
        event_bus.clear()


@pytest.mark.asyncio
async def test_global_budget_caps_mixed_test_and_validation_retries() -> None:
    """Semantic and validator retries share one three-call issue budget."""

    event_bus.clear()
    llm = SequentialRevisionLLM(
        [
            _state_patch("None"),
            {"invalid": "candidate-two"},
            _state_patch("True"),
        ]
    )
    leader = TeamLeader()
    coder = CoderAgent(llm_client=llm)
    tester = DevFlowTesterAgent(mcp_client=StaticResultMCP(_failed_result()))
    router = LocalAgentTaskRouter(leader, coder, tester)
    runtime = LocalAgentEventRuntime(leader, router).start()
    try:
        await leader.route_task(
            Task(
                task_id="42-mixed-budget-coderagent",
                agent="CoderAgent",
                skill="patch-generator",
                input_data={
                    "issue_id": 42,
                    "issue": _issue().model_dump(mode="json"),
                    "tier": "T2",
                    "located_context": _located_context("state.py").model_dump(mode="json"),
                },
                tier=ComplexityLevel.T2,
            )
        )

        coder_routes = [
            HandoffEnvelope.model_validate(record.payload)
            for record in event_bus.history()
            if record.event_type == "task.route.coderagent"
        ]
        assert len(coder_routes) == 3
        routed_inputs = [
            route.artifact.inline["input"]
            for route in coder_routes
            if route.artifact.inline is not None
        ]
        assert [
            (
                request["model_call_attempt"],
                request.get("retry_attempt", 1),
            )
            for request in routed_inputs
        ] == [(1, 1), (2, 2), (3, 2)]
        assert routed_inputs[2]["validator_feedback_code"] == "CANDIDATE_INVALID"
        assert len(llm.prompts) == 3
        assert (
            len(
                [
                    record
                    for record in event_bus.history()
                    if record.event_type == "coder.patch_ready"
                ]
            )
            == 2
        )
        assert (
            len([record for record in event_bus.history() if record.event_type == "test.failed"])
            == 2
        )
        assert (
            len(
                [
                    record
                    for record in event_bus.history()
                    if record.event_type == "generation.budget_exhausted"
                ]
            )
            == 1
        )
        assert leader._issue_context[42]["patch_attempt"] == 2
        assert leader._issue_context[42]["model_call_attempt"] == 3
        assert leader.get_lifecycle(42) is IssueLifecycle.REJECTED
    finally:
        runtime.stop()
        event_bus.clear()


@pytest.mark.asyncio
async def test_tester_never_passes_without_clean_baseline_comparison() -> None:
    candidate = _patch()
    missing_baseline = RunResult(
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        duration_ms=1,
        results=[
            CaseResult(
                name="test_edge",
                status=CaseStatus.PASSED,
                duration_ms=1,
            )
        ],
    )
    regression = missing_baseline.model_copy(
        update={
            "baseline_comparison": BaselineComparison(
                baseline_passed=1,
                current_passed=1,
                new_failures=["test_regression"],
                fixed_tests=[],
                regression=True,
            )
        }
    )

    for result, expected_reason in (
        (missing_baseline, FailureReason.BASELINE_MISSING),
        (regression, FailureReason.REGRESSION),
    ):
        event_bus.clear()
        await DevFlowTesterAgent(mcp_client=StaticResultMCP(result)).execute(
            CoderAgent.build_patch_candidate(
                issue_id=42,
                tier="T2",
                patch=candidate,
                located=_located_context(),
            ).model_dump(mode="json", exclude_none=True)
        )
        gate_events = [
            record
            for record in event_bus.history()
            if record.event_type in {"test.failed", "test.passed"}
        ]
        assert [record.event_type for record in gate_events] == ["test.failed"]
        envelope = HandoffEnvelope.model_validate(gate_events[0].payload)
        assert envelope.artifact.inline is not None
        evidence = FailureEvidence.model_validate(envelope.artifact.inline["failure_evidence"])
        assert expected_reason in evidence.reasons
    event_bus.clear()


@pytest.mark.asyncio
async def test_tester_rejects_clean_result_without_server_integrity_attestation() -> None:
    clean = RunResult(
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        duration_ms=1,
        results=[
            CaseResult(
                name="test_edge",
                status=CaseStatus.PASSED,
                duration_ms=1,
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=1,
            new_failures=[],
            fixed_tests=[],
            regression=False,
        ),
    )
    candidate = CoderAgent.build_patch_candidate(
        issue_id=42,
        tier="T2",
        patch=_patch(),
        located=_located_context(),
    )

    with pytest.raises(AgentError, match="did not attest"):
        await DevFlowTesterAgent(mcp_client=StaticResultMCP(clean, attest=False)).execute(
            candidate.model_dump(mode="json", exclude_none=True)
        )

    assert not [
        record
        for record in event_bus.history()
        if record.event_type in {"test.passed", "test.failed"}
    ]
    event_bus.clear()


def test_coder_rejects_failure_evidence_for_a_different_candidate() -> None:
    candidate = _patch()
    result = _failed_result()
    evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=candidate,
        result=result,
    )
    tampered = evidence.model_copy(update={"candidate_digest": "0" * 64})

    with pytest.raises(AgentError, match="candidate digest does not match"):
        CoderAgent()._parse_input(
            {
                "issue_id": 42,
                "issue": _issue().model_dump(mode="json"),
                "tier": "T2",
                "located_context": _located_context().model_dump(mode="json"),
                "previous_patch": candidate.model_dump(mode="json"),
                "test_failure_evidence": tampered.model_dump(mode="json"),
                "retry_attempt": 2,
            }
        )
    assert canonical_artifact_digest(candidate) == evidence.candidate_digest

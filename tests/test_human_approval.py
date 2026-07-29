"""End-to-end T4 pause, external approval, replay, and resume tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from devflow.agents.locator_agent import LocatedContext, RootCause
from devflow.agents.reviewer_agent import ReviewerAgent
from devflow.agents.team_leader import IssueLifecycle, Task, TeamLeader
from devflow.collaboration.ledger import DurableRouteLedger
from devflow.event_bus import LocalAgentEventRuntime, event_bus
from devflow.exceptions import AgentError
from devflow.local_runtime import LocalAgentTaskRouter
from devflow.mcp.approval import HMACApprovalAuthority
from devflow.models.experience import VerifiedTerminalReceipt
from devflow.models.human_approval import HumanApprovalTarget
from devflow.models.issue import ComplexityLevel, IssueData
from devflow.models.patch import (
    ChangeType,
    FileChange,
    ImpactAnalysis,
    Patch,
    RiskLevel,
)
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
    TestRunResult as RunResult,
)
from devflow.models.test_result import (
    TestStatus as CaseStatus,
)
from devflow.skills.contracts import HandoffEnvelope


class _ExperienceStore:
    def __init__(self) -> None:
        self.records: dict[str, dict[str, Any]] = {}

    async def store(
        self,
        pattern_id: str,
        summary: str,
        metadata: dict[str, Any],
    ) -> None:
        self.records[pattern_id] = {"summary": summary, "metadata": metadata}


def _issue() -> IssueData:
    return IssueData(
        issue_number=42,
        title="High-risk production fix",
        body="The candidate touches a production release path.",
        labels=["production", "bug"],
        author="review-fixture",
        created_at=datetime.now(timezone.utc),
        repo_owner="example",
        repo_name="service",
    )


def _patch() -> Patch:
    return Patch(
        branch_name="devflow/fix-42",
        changes=[
            FileChange(
                file_path="src/release.py",
                change_type=ChangeType.MODIFY,
                original_content="ready = False\n",
                new_content="ready = True\n",
                diff=(
                    "--- a/src/release.py\n"
                    "+++ b/src/release.py\n"
                    "@@ -1 +1 @@\n"
                    "-ready = False\n"
                    "+ready = True\n"
                ),
            )
        ],
        commit_message="fix: restore release readiness",
        description="Change only the reviewed readiness condition.",
    )


def _located() -> LocatedContext:
    return LocatedContext(
        root_cause=RootCause(
            summary="The readiness flag remains false after validation.",
            file="src/release.py",
            start_line=1,
            end_line=1,
            confidence=0.99,
        ),
        context_payload="src/release.py:1 ready = False",
        related_tests=["tests/test_release.py"],
        impact_analysis=ImpactAnalysis(
            affected_files=["src/release.py"],
            affected_modules=["release"],
            risk_level=RiskLevel.HIGH,
            breaking_changes=False,
            test_files_needed=[],
        ),
    )


def _passing_tests() -> RunResult:
    return RunResult(
        total=1,
        passed=1,
        failed=0,
        errors=0,
        skipped=0,
        duration_ms=10,
        results=[
            CaseResult(
                name="tests/test_release.py::test_ready",
                status=CaseStatus.PASSED,
                duration_ms=10,
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=1,
            new_failures=[],
            fixed_tests=[],
            regression=False,
        ),
        integrity_attestation=IntegrityAttestation(
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
            full_suite=True,
            verified=True,
            isolation_boundary=TEST_ISOLATION_BOUNDARY,
        ),
    )


@pytest.fixture(autouse=True)
def _clear_events() -> Any:
    event_bus.clear()
    yield
    event_bus.clear()


@pytest.mark.asyncio
async def test_t4_requires_exact_external_approval_and_resumes_once(
    tmp_path: Path,
) -> None:
    authority = HMACApprovalAuthority(b"human-approval-test-key-material-32-bytes")
    ledger = DurableRouteLedger(tmp_path / "routes.sqlite3", owner_id="leader-test")
    leader = TeamLeader(
        execution_ledger=ledger,
        approval_verifier=authority,
    )
    store = _ExperienceStore()
    reviewer = ReviewerAgent(experience_store=store)
    router = LocalAgentTaskRouter(leader, reviewer)
    runtime = LocalAgentEventRuntime(leader, router).start()
    issue = _issue()
    patch = _patch()
    tests = _passing_tests()
    leader._issue_context[issue.issue_number] = {
        "issue": issue.model_dump(mode="json"),
        "tier": ComplexityLevel.T4.value,
        "repository_revision": "a" * 40,
        "located_context": _located().model_dump(mode="json"),
        "previous_patch": patch.model_dump(mode="json"),
        "previous_patch_digest": canonical_artifact_digest(patch),
        "test_result": tests.model_dump(mode="json"),
        "test_result_digest": canonical_artifact_digest(tests),
    }
    leader._set_lifecycle(issue.issue_number, IssueLifecycle.REVIEWING)

    try:
        await leader.route_task(
            Task(
                task_id="42-5-revieweragent-t4",
                agent="ReviewerAgent",
                skill="pr-reviewer",
                input_data={
                    "issue_id": issue.issue_number,
                    "tier": "T4",
                    "patch": patch.model_dump(mode="json"),
                    "test_result": tests.model_dump(mode="json"),
                    "create_pr": False,
                },
                tier=ComplexityLevel.T4,
            )
        )

        assert leader.get_lifecycle(issue.issue_number) is IssueLifecycle.PAUSED
        pause = next(
            record
            for record in reversed(event_bus.history())
            if record.event_type == "pipeline.paused"
        )
        target = HumanApprovalTarget.model_validate(pause.payload["approval_target"])
        review_event = next(
            record for record in event_bus.history() if record.event_type == "approval.required"
        )
        review_handoff = HandoffEnvelope.model_validate(review_event.payload)
        assert review_handoff.consumer == "TeamLeader"
        assert review_handoff.parent_task_id == "42-5-revieweragent-t4"

        wrong = authority.issue(
            action=target.action,
            target=f"issue:{issue.issue_number}",
            artifact_digest="0" * 64,
            approved_by="human-reviewer",
        )
        with pytest.raises(AgentError, match="scope, or freshness"):
            await leader.resume_with_approval(issue.issue_number, wrong)
        assert leader.get_lifecycle(issue.issue_number) is IssueLifecycle.PAUSED
        assert not store.records

        approval = authority.issue(
            action=target.action,
            target=f"issue:{issue.issue_number}",
            artifact_digest=target.target_sha256,
            approved_by="human-reviewer",
        )
        await leader.resume_with_approval(issue.issue_number, approval)

        assert leader.get_lifecycle(issue.issue_number) is IssueLifecycle.VERIFIED
        snapshot = leader.issue_snapshot(issue.issue_number)
        receipt = VerifiedTerminalReceipt.model_validate(snapshot["terminal_receipt"])
        assert receipt.terminal_state == "human_approved"
        assert receipt.approval_digest == canonical_artifact_digest(approval)
        assert snapshot["human_approval_digest"] == receipt.approval_digest
        assert ledger.approval_consumed(approval.approval_id)
        assert ledger.verify_audit_chain().valid is True
        assert len(store.records) == 1

        with pytest.raises(AgentError, match="not paused"):
            await leader.resume_with_approval(issue.issue_number, approval)
    finally:
        runtime.stop()


def test_durable_approval_consumption_is_one_shot_across_processes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "routes.sqlite3"
    first = DurableRouteLedger(path, owner_id="leader-a")
    second = DurableRouteLedger(path, owner_id="leader-b")

    assert first.consume_approval(
        approval_id="a" * 32,
        issue_id=42,
        target_sha256="b" * 64,
        evidence_sha256="c" * 64,
    )
    assert not second.consume_approval(
        approval_id="a" * 32,
        issue_id=42,
        target_sha256="b" * 64,
        evidence_sha256="c" * 64,
    )
    assert second.approval_consumed("a" * 32)

"""Secret-boundary tests for Tester-to-Coder retry evidence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from devflow.agents.coder_agent import CoderAgent
from devflow.agents.locator_agent import LocatedContext, RootCause
from devflow.agents.team_leader import Task, TeamLeader
from devflow.agents.tester_agent import TesterAgent as DevFlowTesterAgent
from devflow.event_bus import event_bus
from devflow.exceptions import AgentError, BoundaryViolationError
from devflow.mcp.contracts import MCPCallContext
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
    redact_test_result_for_handoff,
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
from devflow.skills.contracts import HandoffEnvelope

_GITHUB_TOKEN = "GHP_" + "A" * 30
_FINE_GITHUB_TOKEN = "GitHub_Pat_" + "B" * 30
_OPENAI_PROJECT_KEY = "SK-ProJ-" + "C" * 24
_OPENAI_SERVICE_KEY = "sk-SvcAcct-" + "D" * 24
_AWS_ACCESS_KEY = "akia" + "e" * 16
_AWS_SESSION_KEY = "AsIa" + "F" * 16
_BEARER_TOKEN = "bEaReR AbCdEf0123456789._~+/=-"
_PEM_KEY = (
    "-----BEGIN " + "RSA PRIVATE KEY-----\n"
    "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=\n"
    "-----END RSA PRIVATE KEY-----"
)
_RAW_SECRETS = (
    _GITHUB_TOKEN,
    _FINE_GITHUB_TOKEN,
    _OPENAI_PROJECT_KEY,
    _OPENAI_SERVICE_KEY,
    _AWS_ACCESS_KEY,
    _AWS_SESSION_KEY,
    _BEARER_TOKEN,
    _PEM_KEY,
)


class _StaticResultMCP:
    def __init__(self, result: RunResult) -> None:
        self.result = result

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        **_kwargs: Any,
    ) -> dict[str, Any]:
        assert (server, tool) == ("cicd", "run_tests")
        assert arguments["issue_id"] == 42
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
                    full_suite=bool(arguments["full_suite"]),
                    verified=True,
                    isolation_boundary=TEST_ISOLATION_BOUNDARY,
                )
            }
        )
        return attested.model_dump(mode="json")


class _RawResultMCP:
    def __init__(self, result: dict[str, Any]) -> None:
        self.result = result

    async def call_tool(
        self,
        server: str,
        tool: str,
        arguments: dict[str, Any],
        *,
        context: MCPCallContext,
    ) -> dict[str, Any]:
        del server, tool, arguments, context
        return self.result


def _patch() -> Patch:
    return Patch(
        branch_name="devflow/retry-redaction",
        changes=[
            FileChange(
                file_path="src/fix.py",
                change_type=ChangeType.MODIFY,
                original_content="fixed = False\n",
                new_content="fixed = True\n",
                diff="--- a/src/fix.py\n+++ b/src/fix.py\n",
            )
        ],
        commit_message="fix: retry safely",
        description="A bounded candidate.",
    )


def _issue() -> IssueData:
    return IssueData(
        issue_number=42,
        title="Fix retry behavior",
        body="Keep retry diagnostics bounded.",
        labels=["bug"],
        author="tester",
        created_at=datetime.now(timezone.utc),
        repo_owner="example",
        repo_name="repo",
    )


def _located_context() -> LocatedContext:
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


def _secret_result() -> RunResult:
    return RunResult(
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        duration_ms=7,
        results=[
            CaseResult(
                name=f"test_provider_{_GITHUB_TOKEN}_{_FINE_GITHUB_TOKEN}",
                status=CaseStatus.FAILED,
                duration_ms=7,
                error_message=(
                    f"provider rejected {_AWS_ACCESS_KEY} {_AWS_SESSION_KEY} "
                    f"authorization {_BEARER_TOKEN}"
                ),
                traceback=f"trace starts\n{_PEM_KEY}\ntrace ends",
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=0,
            new_failures=[
                f"test_remote_{_OPENAI_PROJECT_KEY}",
                f"test_service_{_OPENAI_SERVICE_KEY}",
            ],
            fixed_tests=[],
            regression=True,
        ),
    )


@pytest.mark.asyncio
async def test_failure_handoff_and_coder_prompt_never_contain_raw_secrets() -> None:
    event_bus.clear()
    result = _secret_result()
    patch = _patch()
    candidate = CoderAgent.build_patch_candidate(
        issue_id=42,
        tier="T2",
        patch=patch,
        located=_located_context(),
    )

    returned = await DevFlowTesterAgent(mcp_client=_StaticResultMCP(result)).execute(
        candidate.model_dump(mode="json", exclude_none=True)
    )
    assert returned != result
    for secret in _RAW_SECRETS:
        assert secret not in returned.model_dump_json()

    failed_event = next(
        record for record in event_bus.history() if record.event_type == "test.failed"
    )
    envelope = HandoffEnvelope.model_validate(failed_event.payload)
    serialized_handoff = envelope.model_dump_json()
    for secret in _RAW_SECRETS:
        assert secret not in serialized_handoff
    assert "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=" not in serialized_handoff
    assert "[REDACTED]" in serialized_handoff

    assert envelope.artifact.inline is not None
    payload = envelope.artifact.inline
    evidence = FailureEvidence.model_validate(payload["failure_evidence"])
    sanitized_result = RunResult.model_validate(payload["test_result"])
    raw_digest = canonical_artifact_digest(result)
    sanitized_digest = canonical_artifact_digest(sanitized_result)
    assert payload["test_result_redacted"] is True
    assert evidence.redacted is True
    assert raw_digest != sanitized_digest
    assert evidence.test_result_digest == sanitized_digest
    assert not evidence.verifies_test_result(result)
    assert evidence.verifies_test_result(sanitized_result)
    assert raw_digest not in serialized_handoff

    leader = TeamLeader()
    await leader.route_task(
        Task(
            task_id="42-redaction-coderagent",
            agent="CoderAgent",
            skill="patch-generator",
            input_data={
                "issue_id": 42,
                "issue": _issue().model_dump(mode="json"),
                "tier": "T2",
                "located_context": _located_context().model_dump(mode="json"),
            },
            tier=ComplexityLevel.T2,
        )
    )
    leader.record_retry_context(
        42,
        issue=_issue(),
        tier=ComplexityLevel.T2,
        located_context=_located_context(),
        previous_patch=patch,
    )
    await leader.route_task(
        Task(
            task_id="42-redaction-testeragent",
            agent="TesterAgent",
            skill="test-runner",
            input_data={
                "issue_id": 42,
                **candidate.model_dump(mode="json", exclude_none=True),
            },
            tier=ComplexityLevel.T2,
        )
    )
    parent = HandoffEnvelope.model_validate(event_bus.history()[-1].payload)
    assert leader.claim_execution_route(parent)
    correlated = envelope.model_copy(
        update={
            "parent_task_id": parent.task_id,
            "parent_handoff_sha256": TeamLeader._handoff_sha256(parent),
        }
    )
    await leader._on_test_failed(correlated.model_dump(mode="json"))
    routed = event_bus.history()[-1]
    assert routed.event_type == "task.route.coderagent"
    retry_envelope = HandoffEnvelope.model_validate(routed.payload)
    assert retry_envelope.artifact.verify_integrity()
    serialized_history = json.dumps(
        [record.payload for record in event_bus.history()],
        sort_keys=True,
    )
    assert raw_digest not in serialized_history
    for secret in _RAW_SECRETS:
        assert secret not in serialized_history

    prompt = CoderAgent._build_prompt(
        _issue(),
        ComplexityLevel.T2,
        _located_context(),
        previous_patch=patch,
        failure_evidence=evidence,
    )
    for secret in _RAW_SECRETS:
        assert secret not in prompt
    assert "cHJpdmF0ZS1rZXktbWF0ZXJpYWw=" not in prompt
    assert '"redacted":true' in prompt
    assert "[REDACTED]" in prompt
    assert raw_digest not in prompt
    event_bus.clear()


@pytest.mark.asyncio
async def test_tester_redacts_named_credential_from_diagnostic_handoff() -> None:
    event_bus.clear()
    credential = "".join(("Mw9_", "Kx8-", "Qv7.", "Ls6+", "Rp5/", "Hg4="))
    result = RunResult(
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        duration_ms=1,
        results=[
            CaseResult(
                name="test_provider_auth",
                status=CaseStatus.FAILED,
                duration_ms=1,
                error_message=f"api_key={credential}",
                traceback=f'password: "{credential}"',
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=0,
            new_failures=["test_provider_auth"],
            fixed_tests=[],
            regression=True,
        ),
    )
    candidate = CoderAgent.build_patch_candidate(
        issue_id=42,
        tier="T2",
        patch=_patch(),
        located=_located_context(),
    )

    returned = await DevFlowTesterAgent(mcp_client=_StaticResultMCP(result)).execute(
        candidate.model_dump(mode="json", exclude_none=True)
    )

    serialized_history = json.dumps(
        [record.payload for record in event_bus.history()],
        sort_keys=True,
    )
    assert credential not in returned.model_dump_json()
    assert credential not in serialized_history
    assert "[REDACTED]" in serialized_history
    event_bus.clear()


def test_failure_evidence_rebuild_is_deterministic_and_rejects_tampering() -> None:
    result = _secret_result()
    patch = _patch()
    sanitized_result, was_redacted = redact_test_result_for_handoff(result)
    evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=patch,
        result=result,
    )
    rebuilt = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=patch,
        result=result,
    )

    assert was_redacted is True
    assert rebuilt == evidence
    assert not evidence.verifies_test_result(result)
    assert evidence.verifies_test_result(sanitized_result)

    false_redaction_attestation = evidence.model_copy(update={"redacted": False})
    assert not false_redaction_attestation.verifies_test_result(result)
    assert not false_redaction_attestation.verifies_test_result(sanitized_result)

    digest_tamper = evidence.model_copy(update={"test_result_digest": "0" * 64})
    assert not digest_tamper.verifies_test_result(result)
    assert not digest_tamper.verifies_test_result(sanitized_result)

    raw_digest_tamper = evidence.model_copy(
        update={"test_result_digest": canonical_artifact_digest(result)}
    )
    assert not raw_digest_tamper.verifies_test_result(result)
    assert not raw_digest_tamper.verifies_test_result(sanitized_result)

    payload = evidence.model_dump(mode="json")
    payload["diagnostics"][0]["error_message"] = _BEARER_TOKEN
    with pytest.raises(ValidationError, match="unredacted secret-shaped"):
        FailureEvidence.model_validate(payload)

    payload = evidence.model_dump(mode="json")
    payload["diagnostics"][0]["error_message"] = "forged diagnostic"
    diagnostic_tamper = FailureEvidence.model_validate(payload)
    assert not diagnostic_tamper.verifies_test_result(result)
    assert not diagnostic_tamper.verifies_test_result(sanitized_result)


def test_existing_redaction_marker_is_reported_without_rewriting_input() -> None:
    result = RunResult(
        total=1,
        passed=0,
        failed=1,
        errors=0,
        skipped=0,
        duration_ms=1,
        results=[
            CaseResult(
                name="test_already_scrubbed",
                status=CaseStatus.FAILED,
                duration_ms=1,
                error_message="provider returned [REDACTED]",
            )
        ],
        baseline_comparison=BaselineComparison(
            baseline_passed=1,
            current_passed=0,
            new_failures=["test_already_scrubbed"],
            fixed_tests=[],
            regression=True,
        ),
    )

    sanitized, was_redacted = redact_test_result_for_handoff(result)
    evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=_patch(),
        result=result,
    )

    assert sanitized == result
    assert was_redacted is True
    assert evidence.redacted is True
    assert evidence.test_result_digest == canonical_artifact_digest(result)
    assert evidence.verifies_test_result(result)


def test_truncated_private_key_block_redacts_the_remaining_traceback() -> None:
    result = _secret_result().model_copy(
        update={
            "results": [
                CaseResult(
                    name="test_truncated_key",
                    status=CaseStatus.FAILED,
                    duration_ms=1,
                    traceback=(
                        "trace starts\n"
                        "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
                        "sensitive-body-without-a-footer\n"
                        "untrusted trailing text"
                    ),
                )
            ],
            "baseline_comparison": BaselineComparison(
                baseline_passed=1,
                current_passed=0,
                new_failures=["test_truncated_key"],
                fixed_tests=[],
                regression=True,
            ),
        }
    )

    sanitized, was_redacted = redact_test_result_for_handoff(result)
    assert was_redacted is True
    assert sanitized.results[0].traceback == "trace starts\n[REDACTED]"
    assert "sensitive-body" not in sanitized.model_dump_json()


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "total": 2,
                "passed": 1,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "results": [],
                "baseline_comparison": None,
            },
            "totals do not add up",
        ),
        (
            {
                "total": 1,
                "passed": 1,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "results": [
                    CaseResult(
                        name="test_hidden_failure",
                        status=CaseStatus.FAILED,
                        duration_ms=1,
                    )
                ],
                "baseline_comparison": None,
            },
            "statuses do not match aggregates",
        ),
        (
            {
                "total": 1,
                "passed": 1,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "results": [],
                "baseline_comparison": BaselineComparison(
                    baseline_passed=1,
                    current_passed=0,
                    new_failures=[],
                    fixed_tests=[],
                    regression=False,
                ),
            },
            "current_passed does not match passed",
        ),
    ],
)
def test_test_result_rejects_inconsistent_aggregates(
    overrides: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        RunResult.model_validate({"duration_ms": 1, **overrides})


def test_coder_rejects_raw_test_result_and_mismatched_issue_id() -> None:
    raw_result = _secret_result()
    sanitized_result, _ = redact_test_result_for_handoff(raw_result)
    patch = _patch()
    evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=patch,
        result=sanitized_result,
    )
    retry_input = {
        "issue_id": 42,
        "tier": "T2",
        "issue": _issue().model_dump(mode="json"),
        "located_context": _located_context().model_dump(mode="json"),
        "previous_patch": patch.model_dump(mode="json"),
        "test_failure_evidence": evidence.model_dump(mode="json"),
        "retry_attempt": 2,
    }

    with pytest.raises(AgentError, match="fields do not match"):
        CoderAgent._parse_input({**retry_input, "test_result": raw_result.model_dump(mode="json")})
    with pytest.raises(AgentError, match="issue_id does not match"):
        CoderAgent._parse_input({**retry_input, "issue_id": 43})


@pytest.mark.asyncio
async def test_invalid_tool_result_fails_without_leaking_raw_diagnostics() -> None:
    event_bus.clear()
    raw_result = _secret_result().model_dump(mode="json")
    raw_result["failed"] = 0
    raw_result_digest = canonical_artifact_digest(raw_result)

    with pytest.raises(AgentError, match="invalid TestRunResult"):
        await DevFlowTesterAgent(mcp_client=_RawResultMCP(raw_result)).execute(
            CoderAgent.build_patch_candidate(
                issue_id=42,
                tier="T2",
                patch=_patch(),
                located=_located_context(),
            ).model_dump(mode="json", exclude_none=True)
        )

    serialized_history = json.dumps(
        [record.payload for record in event_bus.history()],
        sort_keys=True,
    )
    assert raw_result_digest not in serialized_history
    for secret in _RAW_SECRETS:
        assert secret not in serialized_history
    event_bus.clear()


@pytest.mark.asyncio
async def test_coder_rejects_unauthorized_patch_generator_producer() -> None:
    forged = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=42,
        task_id="42-forged-coder-route",
        producer="TesterAgent",
        consumer="CoderAgent",
        skill="patch-generator",
        artifact_type="SkillInvocation",
        payload={"input": {}},
    )

    with pytest.raises(BoundaryViolationError, match="producer is not authorized"):
        await CoderAgent().execute(forged.model_dump(mode="json"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("name", "n" * 513),
        ("error_message", "e" * 2_049),
        ("traceback", "t" * 4_001),
    ],
)
def test_case_result_rejects_oversized_boundary_strings(
    field: str,
    value: str,
) -> None:
    payload: dict[str, Any] = {
        "name": "test_bounded",
        "status": "failed",
        "duration_ms": 1,
        "error_message": "bounded",
        "traceback": "bounded",
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        CaseResult.model_validate(payload)


def test_run_result_rejects_oversized_result_and_baseline_lists() -> None:
    case = {
        "name": "test_bounded",
        "status": "passed",
        "duration_ms": 1,
    }
    with pytest.raises(ValidationError):
        RunResult.model_validate(
            {
                "total": 10_001,
                "passed": 10_001,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "duration_ms": 1,
                "results": [case] * 10_001,
            }
        )

    with pytest.raises(ValidationError):
        BaselineComparison.model_validate(
            {
                "baseline_passed": 0,
                "current_passed": 0,
                "new_failures": ["test_bounded"] * 10_001,
                "fixed_tests": [],
                "regression": True,
            }
        )


def test_run_result_rejects_unbounded_counts_and_duration() -> None:
    with pytest.raises(ValidationError):
        RunResult.model_validate(
            {
                "total": 1_000_001,
                "passed": 1_000_001,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "duration_ms": 1,
            }
        )
    with pytest.raises(ValidationError):
        RunResult.model_validate(
            {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "errors": 0,
                "skipped": 0,
                "duration_ms": 604_800_001,
            }
        )

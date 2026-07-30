"""TesterAgent — execute a candidate patch through the isolated CI/CD tool."""

from __future__ import annotations

from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.exceptions import AgentError
from devflow.mcp.cicd import PORTABLE_CICD_SERVER
from devflow.models.issue import ComplexityLevel
from devflow.models.patch import PatchCandidate
from devflow.models.test_result import (
    TestFailureEvidence,
    TestRunResult,
    canonical_artifact_digest,
    redact_test_result_for_handoff,
)
from devflow.observability import logger
from devflow.skills.contracts import HandoffStatus


class TesterAgent(BaseAgent):
    """Run tests and turn tool output into a regression-aware gate result."""

    _IDENTITY = AgentIdentity(
        role="Tester Agent",
        description="Execute isolated tests and report evidence without editing code.",
        model="glm-5.2",
        temperature=0.1,
    )
    _CAPABILITIES = (
        "test_execution",
        "baseline_comparison",
        "integrity_validation",
        "regression_detection",
    )
    _BOUNDARIES = (
        "Cannot modify source code",
        "Cannot modify test files",
        "Cannot approve a patch",
        "Must run the full suite for T3+ issues",
    )
    _WATCHES: tuple[str, ...] = ()
    _OWNED_SKILLS = ("test-runner",)
    # Coder owns the typed PatchCandidate result.  TeamLeader may re-issue that
    # already-validated candidate as a scheduler route; no other producer may
    # invoke this Skill through an envelope.
    _HANDOFF_PRODUCERS = {"test-runner": frozenset({"TeamLeader"})}
    _FORBIDDEN_ACTIONS = {
        "modify_source": "Cannot modify source code",
        "modify_tests": "Cannot modify test files",
        "approve_patch": "Cannot approve a patch",
    }

    async def run(self, input_data: Any) -> TestRunResult:
        if not isinstance(input_data, dict):
            raise AgentError("TesterAgent expects a mapping input.")
        try:
            candidate_payload = dict(input_data)
            candidate_payload.pop("execution_retry", None)
            candidate = PatchCandidate.model_validate(candidate_payload)
            patch = candidate.patch
            tier = ComplexityLevel(candidate.tier)
            issue_id = candidate.issue_id
        except (TypeError, ValueError) as exc:
            raise AgentError("Invalid PatchCandidate for TesterAgent.") from exc

        full_suite = tier in {
            ComplexityLevel.T3,
            ComplexityLevel.T4,
            ComplexityLevel.T5,
        }
        async with self._trace_span(
            "test-runner", issue_id=issue_id, tier=tier.value, full_suite=full_suite
        ):
            raw = await self._call_mcp(
                PORTABLE_CICD_SERVER,
                "run_tests",
                {
                    "issue_id": issue_id,
                    "patch": patch.model_dump(mode="json"),
                },
                skill="test-runner",
                issue_id=issue_id,
                risk_tier=tier.value,
            )
            try:
                result_payload = (
                    raw.model_dump(mode="json") if isinstance(raw, TestRunResult) else raw
                )
                result = TestRunResult.model_validate(result_payload)
            except (TypeError, ValueError) as exc:
                raise AgentError("CI/CD returned an invalid TestRunResult.") from exc
            attestation = result.integrity_attestation
            if (
                attestation is None
                or not attestation.verified
                or attestation.full_suite is not full_suite
            ):
                raise AgentError("CI/CD did not attest the requested immutable-test execution.")
            passed = self._passes_gate(result)
            event = "test.passed" if passed else "test.failed"
            candidate_digest = canonical_artifact_digest(patch)
            handoff_result, result_redacted = redact_test_result_for_handoff(result)
            failure_evidence = (
                None
                if passed
                else TestFailureEvidence.from_test_result(
                    issue_id=issue_id,
                    candidate=patch,
                    result=handoff_result,
                )
            )
            logger.info(
                event,
                issue_id=issue_id,
                total=result.total,
                passed=result.passed,
                failed=result.failed,
                errors=result.errors,
            )
            await self._emit_handoff(
                event,
                issue_id=issue_id,
                consumer="TeamLeader",
                skill="test-runner",
                artifact_type="TestEvidence",
                status=(HandoffStatus.READY if event == "test.passed" else HandoffStatus.RETRY),
                payload={
                    "issue_id": issue_id,
                    "candidate_digest": candidate_digest,
                    "test_result": handoff_result.model_dump(mode="json"),
                    "test_result_redacted": result_redacted,
                    "failing_tests": (
                        failure_evidence.failing_tests if failure_evidence is not None else []
                    ),
                    **(
                        {"failure_evidence": failure_evidence.model_dump(mode="json")}
                        if failure_evidence is not None
                        else {}
                    ),
                },
                task_id=(f"{issue_id}-testeragent-test-runner-{candidate_digest[:12]}"),
            )
            # Raw CI strings are Tester-local.  Even the direct Python return
            # follows the same redacted boundary as the inter-Agent hand-off.
            return handoff_result

    @staticmethod
    def _passes_gate(result: TestRunResult) -> bool:
        comparison = result.baseline_comparison
        attestation = result.integrity_attestation
        return bool(
            attestation is not None
            and attestation.verified
            and comparison is not None
            and result.failed == 0
            and result.errors == 0
            and not comparison.regression
            and not comparison.new_failures
        )


__all__ = ["TesterAgent"]

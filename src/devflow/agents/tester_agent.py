"""TesterAgent — execute a candidate patch through the isolated CI/CD tool."""

from __future__ import annotations

from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.exceptions import AgentError
from devflow.models.issue import ComplexityLevel
from devflow.models.patch import Patch
from devflow.models.test_result import TestRunResult
from devflow.observability import logger
from devflow.skills.contracts import HandoffStatus


class TesterAgent(BaseAgent):
    """Run tests and turn tool output into a regression-aware gate result."""

    _IDENTITY = AgentIdentity(
        role="Tester Agent",
        description="Execute isolated tests and report evidence without editing code.",
        model="glm-5.2",
        temperature=0.1,
        system_prompt_ref="prompts/tester.md",
    )
    _CAPABILITIES = (
        "test_execution",
        "baseline_comparison",
        "coverage_analysis",
        "regression_detection",
    )
    _BOUNDARIES = (
        "Cannot modify source code",
        "Cannot modify test files",
        "Cannot approve a patch",
        "Must run the full suite for T3+ issues",
    )
    _WATCHES = ("coder.patch_ready", "pipeline.completed")
    _OWNED_SKILLS = ("test-runner",)
    _FORBIDDEN_ACTIONS = {
        "modify_source": "Cannot modify source code",
        "modify_tests": "Cannot modify test files",
        "approve_patch": "Cannot approve a patch",
    }

    async def run(self, input_data: Any) -> TestRunResult:
        if not isinstance(input_data, dict):
            raise AgentError("TesterAgent expects a mapping input.")
        try:
            patch_raw = input_data["patch"]
            patch = (
                patch_raw
                if isinstance(patch_raw, Patch)
                else Patch.model_validate(patch_raw)
            )
            tier_raw = input_data.get("tier", ComplexityLevel.T3)
            tier = (
                tier_raw
                if isinstance(tier_raw, ComplexityLevel)
                else ComplexityLevel(tier_raw)
            )
            issue_id = int(input_data["issue_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(f"Invalid TesterAgent input: {exc}") from exc

        full_suite = tier in {
            ComplexityLevel.T3,
            ComplexityLevel.T4,
            ComplexityLevel.T5,
        }
        async with self._trace_span(
            "test-runner", issue_id=issue_id, tier=tier.value, full_suite=full_suite
        ):
            raw = await self._call_mcp(
                "cicd",
                "run_tests",
                {
                    "issue_id": issue_id,
                    "patch": patch.model_dump(mode="json"),
                    "full_suite": full_suite,
                },
                skill="test-runner",
                issue_id=issue_id,
                risk_tier=tier.value,
            )
            result = (
                raw if isinstance(raw, TestRunResult) else TestRunResult.model_validate(raw)
            )
            event = (
                "test.passed"
                if result.failed == 0 and result.errors == 0
                else "test.failed"
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
                consumer=("ReviewerAgent" if event == "test.passed" else "CoderAgent"),
                skill="test-runner",
                artifact_type="TestEvidence",
                status=(HandoffStatus.READY if event == "test.passed" else HandoffStatus.RETRY),
                payload={
                    "issue_id": issue_id,
                    "test_result": result.model_dump(mode="json"),
                    "failing_tests": [
                        case.name
                        for case in result.results
                        if case.status.value in {"failed", "error"}
                    ],
                },
            )
            return result


__all__ = ["TesterAgent"]

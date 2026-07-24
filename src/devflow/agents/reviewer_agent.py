"""ReviewerAgent — correctness, security, approval, and optional PR gate."""

from __future__ import annotations

from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.exceptions import AgentError, MCPError
from devflow.models.issue import ComplexityLevel
from devflow.models.patch import Patch
from devflow.models.review import (
    ReviewDecision,
    ReviewFinding,
    ReviewResult,
)
from devflow.models.test_result import TestRunResult
from devflow.observability import logger
from devflow.skills.base import BaseSkill


class ReviewerAgent(BaseAgent):
    """Final autonomous gate; high-risk work always pauses for a human."""

    _IDENTITY = AgentIdentity(
        role="Reviewer Agent",
        description=(
            "Review correctness and security, create PRs, and enforce approval policy."
        ),
        model="glm-5.2",
        temperature=0.3,
        system_prompt_ref="prompts/reviewer.md",
    )
    _CAPABILITIES = (
        "pr_creation",
        "code_review",
        "security_scan",
        "approval_workflow",
        "merge_management",
    )
    _BOUNDARIES = (
        "Cannot auto-merge T4/T5 without human approval",
        "Cannot merge when CI is red",
        "Cannot bypass high or critical security findings",
        "Cannot self-approve a PR it authored",
    )
    _WATCHES = ("test.passed", "review.requested", "security.finding", "human.approved")
    _FORBIDDEN_ACTIONS = {
        "auto_merge_t4_t5": "Cannot auto-merge T4/T5 without human approval",
        "merge_red_ci": "Cannot merge when CI is red",
        "bypass_security": "Cannot bypass high or critical security findings",
        "self_approve": "Cannot self-approve a PR it authored",
    }

    async def run(self, input_data: Any) -> ReviewResult:
        issue_id, tier, patch, tests = self._parse_input(input_data)
        async with self._trace_span(
            "pr-reviewer", issue_id=issue_id, tier=tier.value
        ):
            findings = self._scan_patch(patch)
            if tests.failed or tests.errors:
                findings.append(
                    ReviewFinding(
                        severity="high",
                        category="test",
                        message="Candidate patch does not pass the test gate.",
                    )
                )

            blocked = any(
                finding.severity in {"high", "critical"} for finding in findings
            )
            requires_human = tier in {ComplexityLevel.T4, ComplexityLevel.T5}
            if blocked:
                decision = ReviewDecision.CHANGES_REQUESTED
            elif requires_human:
                decision = ReviewDecision.HUMAN_APPROVAL_REQUIRED
            else:
                decision = ReviewDecision.APPROVED

            pr_url = None
            if not blocked and input_data.get("create_pr", False):
                try:
                    response = await self._call_mcp(
                        "github",
                        "create_pull_request",
                        {
                            "issue_id": issue_id,
                            "branch": patch.branch_name,
                            "title": patch.commit_message,
                            "body": patch.description,
                        },
                    )
                    if isinstance(response, dict):
                        pr_url = response.get("url") or response.get("html_url")
                except MCPError as exc:
                    findings.append(
                        ReviewFinding(
                            severity="medium",
                            category="integration",
                            message=f"PR creation deferred: {exc}",
                        )
                    )

            result = ReviewResult(
                decision=decision,
                findings=findings,
                summary=self._summary(decision, findings),
                pr_url=pr_url,
                requires_human_approval=requires_human,
            )
            await self._emit_event(
                (
                    "approval.required"
                    if decision is ReviewDecision.HUMAN_APPROVAL_REQUIRED
                    else "review.completed"
                ),
                {
                    "issue_id": issue_id,
                    "tier": tier.value,
                    "review": result.model_dump(mode="json"),
                },
            )
            logger.info(
                "review.completed",
                issue_id=issue_id,
                decision=decision.value,
                findings=len(findings),
            )
            return result

    @staticmethod
    def _parse_input(
        input_data: Any,
    ) -> tuple[int, ComplexityLevel, Patch, TestRunResult]:
        if not isinstance(input_data, dict):
            raise AgentError("ReviewerAgent expects a mapping input.")
        try:
            issue_id = int(input_data["issue_id"])
            tier_raw = input_data.get("tier", ComplexityLevel.T3)
            tier = (
                tier_raw
                if isinstance(tier_raw, ComplexityLevel)
                else ComplexityLevel(tier_raw)
            )
            patch_raw = input_data["patch"]
            patch = (
                patch_raw
                if isinstance(patch_raw, Patch)
                else Patch.model_validate(patch_raw)
            )
            tests_raw = input_data["test_result"]
            tests = (
                tests_raw
                if isinstance(tests_raw, TestRunResult)
                else TestRunResult.model_validate(tests_raw)
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(f"Invalid ReviewerAgent input: {exc}") from exc
        return issue_id, tier, patch, tests

    @staticmethod
    def _scan_patch(patch: Patch) -> list[ReviewFinding]:
        findings: list[ReviewFinding] = []
        for change in patch.changes:
            matches = BaseSkill.scan_for_dangerous_patterns(
                change.new_content or change.diff
            )
            for match in matches:
                findings.append(
                    ReviewFinding(
                        severity="critical",
                        category="security",
                        message=f"Blocked dangerous code pattern: {match}",
                        file_path=change.file_path,
                    )
                )
        return findings

    @staticmethod
    def _summary(
        decision: ReviewDecision, findings: list[ReviewFinding]
    ) -> str:
        if decision is ReviewDecision.APPROVED:
            return "Automated review and test gates passed."
        if decision is ReviewDecision.HUMAN_APPROVAL_REQUIRED:
            return "Automated gates passed; risk tier requires recorded human approval."
        return f"Changes requested after {len(findings)} review finding(s)."


__all__ = ["ReviewerAgent"]

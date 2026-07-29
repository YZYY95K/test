"""ReviewerAgent — correctness, security, approval, and optional PR gate."""

from __future__ import annotations

from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.exceptions import AgentError, MCPError
from devflow.models.issue import ComplexityLevel, IssueData
from devflow.models.patch import Patch
from devflow.models.review import (
    ReviewDecision,
    ReviewFinding,
    ReviewResult,
)
from devflow.models.test_result import TestRunResult, canonical_artifact_digest
from devflow.observability import logger
from devflow.skills.base import BaseSkill
from devflow.skills.contracts import HandoffStatus
from devflow.skills.experience_distiller import (
    ExperienceDistillerSkill,
    ExperienceWriter,
)


class ReviewerAgent(BaseAgent):
    """Final autonomous gate; high-risk work always pauses for a human."""

    _IDENTITY = AgentIdentity(
        role="Reviewer Agent",
        description=("Review correctness and security, create PRs, and enforce approval policy."),
        model="glm-5.2",
        temperature=0.3,
    )
    _CAPABILITIES = (
        "pr_creation",
        "code_review",
        "security_scan",
        "approval_workflow",
    )
    _BOUNDARIES = (
        "Cannot merge any PR; may only record review eligibility",
        "Cannot merge when CI is red",
        "Cannot bypass high or critical security findings",
        "Cannot self-approve a PR it authored",
    )
    _WATCHES: tuple[str, ...] = ()
    _OWNED_SKILLS = ("pr-reviewer", "experience-distiller")
    _HANDOFF_PRODUCERS = {
        "pr-reviewer": frozenset({"TeamLeader"}),
        "experience-distiller": frozenset({"TeamLeader"}),
    }
    _FORBIDDEN_ACTIONS = {
        "merge_pr": "Cannot merge any PR; may only record review eligibility",
        "merge_red_ci": "Cannot merge when CI is red",
        "bypass_security": "Cannot bypass high or critical security findings",
        "self_approve": "Cannot self-approve a PR it authored",
    }

    def __init__(
        self,
        *,
        experience_store: ExperienceWriter | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._experience_distiller = ExperienceDistillerSkill(store=experience_store)

    async def run(self, input_data: Any) -> ReviewResult | dict[str, Any]:
        if isinstance(input_data, dict) and input_data.get("operation") == "distill_experience":
            return await self._distill_experience(input_data)
        issue_id, tier, patch, tests = self._parse_input(input_data)
        async with self._trace_span("pr-reviewer", issue_id=issue_id, tier=tier.value):
            findings = self._scan_patch(patch)
            if tests.failed or tests.errors:
                findings.append(
                    ReviewFinding(
                        severity="high",
                        category="test",
                        message="Candidate patch does not pass the test gate.",
                    )
                )

            blocked = any(finding.severity in {"high", "critical"} for finding in findings)
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
                        skill="pr-reviewer",
                        issue_id=issue_id,
                        risk_tier=tier.value,
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
            event = {
                ReviewDecision.APPROVED: "review.approved",
                ReviewDecision.CHANGES_REQUESTED: "review.rejected",
                ReviewDecision.HUMAN_APPROVAL_REQUIRED: "approval.required",
            }[decision]
            consumer = {
                ReviewDecision.APPROVED: "TeamLeader",
                # Reviewer never routes remediation directly. TeamLeader
                # validates the decision and fails closed until feedback is
                # bound to the exact candidate by a formal retry contract.
                ReviewDecision.CHANGES_REQUESTED: "TeamLeader",
                # TeamLeader validates the exact Reviewer route and creates a
                # digest-bound target for the external human authority.
                ReviewDecision.HUMAN_APPROVAL_REQUIRED: "TeamLeader",
            }[decision]
            status = {
                ReviewDecision.APPROVED: HandoffStatus.READY,
                ReviewDecision.CHANGES_REQUESTED: HandoffStatus.RETRY,
                ReviewDecision.HUMAN_APPROVAL_REQUIRED: HandoffStatus.BLOCKED,
            }[decision]
            await self._emit_handoff(
                event,
                issue_id=issue_id,
                consumer=consumer,
                skill="pr-reviewer",
                artifact_type="ReviewDecision",
                status=status,
                payload={
                    "issue_id": issue_id,
                    "tier": tier.value,
                    "review": result.model_dump(mode="json"),
                },
                task_id=(
                    f"{issue_id}-revieweragent-pr-reviewer-{canonical_artifact_digest(patch)[:12]}"
                ),
            )
            logger.info(
                "review.completed",
                issue_id=issue_id,
                decision=decision.value,
                findings=len(findings),
            )
            return result

    async def _distill_experience(
        self,
        input_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute the post-review Skill through a separate Leader route."""

        required = {
            "operation",
            "issue_id",
            "issue",
            "tier",
            "repository_revision",
            "located_context",
            "patch",
            "test_result",
            "review",
            "trace_id",
            "terminal_receipt",
        }
        if set(input_data) not in (required, required | {"human_approval"}):
            raise AgentError("Experience distillation input fields do not match the contract.")
        issue_id_raw = input_data["issue_id"]
        if isinstance(issue_id_raw, bool):
            raise AgentError("Experience distillation issue_id is invalid.")
        issue_id = int(issue_id_raw)
        issue = IssueData.model_validate(input_data["issue"])
        if issue.issue_number != issue_id:
            raise AgentError("Experience distillation issue does not match.")
        result = await self._experience_distiller.run(
            issue=input_data["issue"],
            tier=input_data["tier"],
            repository_revision=input_data["repository_revision"],
            located_context=input_data["located_context"],
            patch=input_data["patch"],
            test_result=input_data["test_result"],
            review=input_data["review"],
            trace_id=input_data["trace_id"],
            terminal_receipt=input_data["terminal_receipt"],
            **(
                {"human_approval": input_data["human_approval"]}
                if "human_approval" in input_data
                else {}
            ),
        )
        await self._emit_handoff(
            "experience.completed",
            issue_id=issue_id,
            consumer="TeamLeader",
            skill="experience-distiller",
            artifact_type="ExperiencePattern",
            payload={
                "issue_id": issue_id,
                "experience": result,
            },
            task_id=(f"{issue_id}-revieweragent-experience-{str(result['pattern_id'])}"),
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
            tier = tier_raw if isinstance(tier_raw, ComplexityLevel) else ComplexityLevel(tier_raw)
            patch_raw = input_data["patch"]
            patch = patch_raw if isinstance(patch_raw, Patch) else Patch.model_validate(patch_raw)
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
            matches = BaseSkill.scan_for_dangerous_patterns(change.new_content or change.diff)
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
    def _summary(decision: ReviewDecision, findings: list[ReviewFinding]) -> str:
        if decision is ReviewDecision.APPROVED:
            return "Automated review and test gates passed."
        if decision is ReviewDecision.HUMAN_APPROVAL_REQUIRED:
            return "Automated gates passed; risk tier requires recorded human approval."
        return f"Changes requested after {len(findings)} review finding(s)."


__all__ = ["ReviewerAgent"]

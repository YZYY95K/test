"""CoderAgent — generate a structured patch without writing repository files."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.agents.locator_agent import LocatedContext
from devflow.exceptions import AgentError
from devflow.models.issue import ComplexityLevel, IssueData
from devflow.models.patch import Patch
from devflow.observability import logger
from devflow.skills.base import BaseSkill


class CoderAgent(BaseAgent):
    """Generate a candidate patch from located code context."""

    _IDENTITY = AgentIdentity(
        role="Coder Agent",
        description=(
            "Generate minimal, repository-aware patches from verified located context."
        ),
        model="glm-5.2",
        temperature=0.2,
        system_prompt_ref="prompts/coder.md",
        model_fallback=("glm-5.2",),
    )
    _CAPABILITIES = (
        "patch_generation",
        "code_context_awareness",
        "multi_file_edit",
        "self_verification",
    )
    _BOUNDARIES = (
        "Cannot push directly to the default branch",
        "Cannot run tests",
        "Cannot approve its own patch",
        "Maximum 3 patch-generation attempts per sub-task before escalation",
    )
    _WATCHES = ("locator.completed", "review.rejected", "test.failed")
    _FORBIDDEN_ACTIONS = {
        "push_default_branch": "Cannot push directly to the default branch",
        "run_tests": "Cannot run tests",
        "approve_patch": "Cannot approve its own patch",
    }

    async def run(self, input_data: Any) -> Patch:
        issue, tier, located = self._parse_input(input_data)
        async with self._trace_span(
            "patch-generator", issue_id=issue.issue_number, tier=tier.value
        ):
            prompt = self._build_prompt(issue, tier, located)
            patch = self._validate_output(
                await self.llm.complete_structured(
                    prompt=prompt,
                    response_model=Patch,
                    model=self.identity.model,
                    temperature=self.identity.temperature,
                    system=self.identity.description,
                ),
                Patch,
            )
            self._validate_patch(patch)
            logger.info(
                "coder.patch_ready",
                issue_id=issue.issue_number,
                files=len(patch.changes),
                branch=patch.branch_name,
            )
            await self._emit_event(
                "coder.patch_ready",
                {
                    "issue_id": issue.issue_number,
                    "tier": tier.value,
                    "patch": patch.model_dump(mode="json"),
                },
            )
            return patch

    @staticmethod
    def _parse_input(
        input_data: Any,
    ) -> tuple[IssueData, ComplexityLevel, LocatedContext]:
        if not isinstance(input_data, dict):
            raise AgentError("CoderAgent expects a mapping input.")
        try:
            issue_raw = input_data["issue"]
            located_raw = input_data["located_context"]
            issue = (
                issue_raw
                if isinstance(issue_raw, IssueData)
                else IssueData.model_validate(issue_raw)
            )
            located = (
                located_raw
                if isinstance(located_raw, LocatedContext)
                else LocatedContext.model_validate(located_raw)
            )
            tier_raw = input_data.get("tier", ComplexityLevel.T3)
            tier = (
                tier_raw
                if isinstance(tier_raw, ComplexityLevel)
                else ComplexityLevel(tier_raw)
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise AgentError(f"Invalid CoderAgent input: {exc}") from exc
        return issue, tier, located

    @staticmethod
    def _build_prompt(
        issue: IssueData, tier: ComplexityLevel, located: LocatedContext
    ) -> str:
        return (
            f"Fix GitHub issue #{issue.issue_number} ({tier.value}).\n"
            f"Title: {issue.title}\nBody: {issue.body or '(empty)'}\n\n"
            f"Located context:\n{located.context_payload}\n\n"
            "Produce the smallest correct patch. Preserve public APIs unless the "
            "issue explicitly requires a breaking change. Include tests when "
            "needed. Return a Patch object with complete new file contents and "
            "a unified diff for every change."
        )

    @staticmethod
    def _validate_patch(patch: Patch) -> None:
        for change in patch.changes:
            normalized = change.file_path.replace("\\", "/")
            path = PurePosixPath(normalized)
            if path.is_absolute() or ".." in path.parts:
                raise AgentError(
                    f"Patch path escapes the repository: {change.file_path}"
                )
            risky = BaseSkill.scan_for_dangerous_patterns(
                change.new_content or change.diff
            )
            if risky:
                raise AgentError(
                    f"Patch contains blocked code patterns in {change.file_path}: "
                    f"{', '.join(risky)}"
                )


__all__ = ["CoderAgent"]

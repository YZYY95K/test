"""TriageAgent — issue intake, classification and deduplication.

The TriageAgent is the first agent to touch an incoming issue. It assigns a
T1-T5 complexity tier (which drives every downstream decision: approval gate,
parallelism, model selection), de-duplicates against the experience store so
recurring issues can be fast-pathed, and assigns priority.

It owns the ``issue-classifier`` skill and emits ``triage.completed`` carrying
an :class:`~devflow.models.issue.IssueClassification`.
"""

from __future__ import annotations

from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.exceptions import AgentError
from devflow.models.issue import (
    ComplexityLevel,
    IssueCategory,
    IssueClassification,
    IssueData,
    IssuePriority,
)
from devflow.observability import logger

#: ChromaDB collection holding historical issue patterns for deduplication.
_EXPERIENCE_COLLECTION = "experience_store"
#: Minimum similarity score (0-1) above which an issue is considered a duplicate.
_DUPLICATE_THRESHOLD = 0.92


class TriageAgent(BaseAgent):
    """Classifies incoming issues into T1-T5 tiers and deduplicates them."""

    _IDENTITY = AgentIdentity(
        role="Triage Agent",
        description=(
            "Classifies incoming issues into T1-T5 complexity tiers, "
            "deduplicates against historical issues, and assigns priority."
        ),
        model="glm-5.2",
        temperature=0.2,  # very low — classification must be deterministic
        system_prompt_ref="prompts/triage.md",
    )
    _CAPABILITIES = (
        "issue_classification",
        "deduplication",
        "priority_assignment",
        "label_assignment",
    )
    _BOUNDARIES = (
        "Cannot modify issue body or title",
        "Cannot assign complexity higher than T5",
        "Cannot skip deduplication step",
    )
    _WATCHES = (
        "issue.created",
        "issue.updated",
    )
    _OWNED_SKILLS = ("issue-classifier",)
    _HANDOFF_PRODUCERS = {"issue-classifier": frozenset({"TeamLeader"})}
    _FORBIDDEN_ACTIONS = {
        "modify_issue_body": "Cannot modify issue body or title",
        "assign_above_t5": "Cannot assign complexity higher than T5",
        "skip_deduplication": "Cannot skip deduplication step",
    }

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.register_event_handler("issue.created", self._on_issue_created)
        self.register_event_handler("issue.updated", self._on_issue_updated)

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #
    async def _on_issue_created(self, payload: dict[str, Any]) -> None:
        issue = self._parse_issue(payload)
        if issue is not None:
            await self.execute(issue)

    async def _on_issue_updated(self, payload: dict[str, Any]) -> None:
        issue = self._parse_issue(payload)
        if issue is not None:
            logger.info(
                "triage.reclassify", issue_id=issue.issue_number, reason="issue_updated"
            )
            await self.execute(issue)

    @staticmethod
    def _parse_issue(payload: dict[str, Any]) -> IssueData | None:
        issue_data = payload.get("issue") or payload
        try:
            if isinstance(issue_data, IssueData):
                return issue_data
            return IssueData(**issue_data)
        except Exception as exc:  # noqa: BLE001 — malformed event
            logger.error("triage.invalid_issue", error=str(exc))
            return None

    # ------------------------------------------------------------------ #
    # Core logic
    # ------------------------------------------------------------------ #
    async def run(self, input_data: Any) -> IssueClassification:
        """Classify an issue and emit ``triage.completed``.

        Args:
            input_data: An :class:`IssueData` instance describing the issue.

        Returns:
            The :class:`IssueClassification` produced for the issue.
        """
        if isinstance(input_data, IssueData):
            issue = input_data
        elif isinstance(input_data, dict):
            issue_raw = input_data.get("issue")
            issue_id_raw = input_data.get("issue_id")
            if issue_raw is None or issue_id_raw is None or set(input_data) != {
                "issue_id",
                "issue",
            }:
                raise AgentError(
                    "TriageAgent routed input requires exact issue_id and issue fields."
                )
            try:
                if isinstance(issue_id_raw, bool):
                    raise TypeError("issue_id must be an integer")
                issue_id = int(issue_id_raw)
                issue = IssueData.model_validate(issue_raw)
            except (TypeError, ValueError) as exc:
                raise AgentError(f"Invalid routed TriageAgent input: {exc}") from exc
            if issue.issue_number != issue_id:
                raise AgentError("Triage issue_id does not match the issue artifact.")
        else:
            raise AgentError("TriageAgent expects IssueData or a routed issue mapping.")

        async with self._trace_span(
            "issue-classifier", issue_id=issue.issue_number
        ):
            # 1. Deduplication against the experience store (boundary: never skip).
            duplicate_of = await self._deduplicate(issue)

            # 2. LLM-backed structured classification.
            classification = await self._classify(issue, duplicate_of)

            # Pydantic's enum validation enforces the T1-T5 ceiling. Boundary
            # checks are invoked only when an action is actually attempted.

            logger.info(
                "triage.classified",
                issue_id=issue.issue_number,
                tier=classification.complexity_level.value,
                category=classification.category.value,
                priority=classification.priority.value,
                duplicate_of=classification.duplicate_of,
            )

            await self._emit_handoff(
                "triage.completed",
                issue_id=issue.issue_number,
                consumer="TeamLeader",
                skill="issue-classifier",
                artifact_type="ClassifiedIssue",
                payload={
                    "issue_id": issue.issue_number,
                    "classification": classification.model_dump(mode="json"),
                    "tier": classification.complexity_level.value,
                    "duplicate_of": classification.duplicate_of,
                },
            )
            return classification

    async def _deduplicate(self, issue: IssueData) -> int | None:
        """Look the issue up in the experience store; return the duplicate id.

        Per ``skills.yaml`` the configured behaviour when dedup is unavailable
        is ``proceed_without_dedup``, so an absent vector store degrades
        gracefully (returns ``None``).
        """
        query = f"{issue.title}\n{issue.body or ''}"
        neighbours = await self._query_vector_store(
            _EXPERIENCE_COLLECTION, query, n_results=3
        )
        for neighbour in neighbours:
            similarity = _as_float(neighbour.get("similarity") or neighbour.get("score"))
            if similarity is not None and similarity >= _DUPLICATE_THRESHOLD:
                dup_id = neighbour.get("issue_id") or neighbour.get("id")
                if isinstance(dup_id, int):
                    logger.info(
                        "triage.duplicate_found",
                        issue_id=issue.issue_number,
                        duplicate_of=dup_id,
                        similarity=similarity,
                    )
                    return dup_id
        return None

    async def _classify(
        self, issue: IssueData, duplicate_of: int | None
    ) -> IssueClassification:
        """Produce a structured classification via the LLM.

        Uses :meth:`complete_structured` so the result is validated against the
        :class:`IssueClassification` schema. On failure the skill's
        ``fallback_tier`` of T3 is applied conservatively.
        """
        prompt = self._build_classification_prompt(issue, duplicate_of)
        try:
            classification = await self.llm.complete_structured(
                prompt=prompt,
                response_model=IssueClassification,
                model=self.identity.model,
                temperature=self.identity.temperature,
                system=self.identity.description,
            )
        except Exception as exc:  # noqa: BLE001 — fall back conservatively
            logger.warning(
                "triage.classification_failed",
                issue_id=issue.issue_number,
                error=str(exc),
                fallback_tier=ComplexityLevel.T3.value,
            )
            classification = IssueClassification(
                complexity_level=ComplexityLevel.T3,
                category=IssueCategory.BUG,
                priority=IssuePriority.MEDIUM,
                duplicate_of=duplicate_of,
                estimated_effort_hours=4.0,
            )
        # Attach the dedup result from the store — it is authoritative over
        # whatever the model may have inferred.
        if duplicate_of is not None:
            classification = classification.model_copy(
                update={"duplicate_of": duplicate_of}
            )
        return self._validate_output(classification, IssueClassification)

    def _build_classification_prompt(
        self, issue: IssueData, duplicate_of: int | None
    ) -> str:
        dup_hint = (
            f"\n\nNote: this issue may be a duplicate of issue #{duplicate_of}."
            if duplicate_of is not None
            else ""
        )
        return (
            "Classify the following GitHub issue.\n\n"
            f"Title: {issue.title}\n"
            f"Body:\n{issue.body or '(empty)'}\n"
            f"Labels: {', '.join(issue.labels) or '(none)'}\n"
            "Assign:\n"
            "- complexity_level: T1 (trivial) .. T5 (architectural)\n"
            "- category: one of bug, feature, docs, refactor\n"
            "- priority: one of critical, high, medium, low\n"
            "- estimated_effort_hours: a non-negative number\n"
            f"{dup_hint}\n"
            "Return the result matching the IssueClassification schema."
        )


def _as_float(value: Any) -> float | None:
    """Coerce a similarity/score value to float, returning ``None`` if invalid."""
    try:
        if value is None:
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


__all__ = ["TriageAgent"]

"""TeamLeader — the central orchestrator of the DevFlow agent team.

The TeamLeader is the *only* agent permitted to decompose issues into
sub-tasks and assign them to workers. It owns the canonical state machine for
an issue's lifecycle and is the final arbiter when agents disagree (for
example when the Tester reports a pass but the Reviewer flags a security
concern).

Responsibilities:

* Receive ``issue.created`` events and kick off decomposition.
* Decompose issues into ordered sub-tasks based on the T1-T5 tier assigned by
  :class:`~devflow.agents.triage_agent.TriageAgent`.
* Route tasks along the pipeline: Triage -> Locator -> Coder -> Tester ->
  Reviewer.
* Handle failures: re-plan, re-assign, or escalate.
* Arbitrate conflicts between agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.models.issue import (
    ComplexityLevel,
    IssueClassification,
    IssueData,
)
from devflow.observability import logger
from devflow.skills.contracts import HandoffEnvelope


class IssueLifecycle(str, Enum):
    """Canonical state machine for a single issue's resolution lifecycle.

    Transitions are driven by agent completion/failure events::

        NEW -> TRIAGED -> LOCATING -> CODING -> TESTING
            -> REVIEWING -> MERGED | REJECTED

    Reversal edges (e.g. ``CODING -> CODING`` on a failed test, or
    ``REVIEWING -> CODING`` on a rejected review) are handled by routing the
    work back to the appropriate agent without leaving the state machine.
    """

    NEW = "new"
    TRIAGED = "triaged"
    LOCATING = "locating"
    CODING = "coding"
    TESTING = "testing"
    REVIEWING = "reviewing"
    MERGED = "merged"
    REJECTED = "rejected"


@dataclass
class Task:
    """A single sub-task dispatched to a worker agent.

    The TeamLeader produces an ordered list of these from a classified issue;
    each task names its target agent and carries the input payload the agent
    consumes.
    """

    task_id: str
    agent: str
    skill: str
    input_data: dict[str, Any]
    depends_on: list[str] = field(default_factory=list)
    #: Tier this task was planned for (drives approval gate & model choice).
    tier: ComplexityLevel = ComplexityLevel.T3


@dataclass
class Decision:
    """The outcome of a conflict arbitration by the TeamLeader."""

    resolution: str
    reasoning: str
    next_agent: str | None = None
    next_action: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class Conflict:
    """A disagreement between two agents that requires arbitration."""

    issue_id: int
    description: str
    parties: list[str]
    positions: dict[str, str] = field(default_factory=dict)
    context: dict[str, Any] = field(default_factory=dict)


#: Ordered pipeline of worker agents for a standard issue resolution flow.
_STANDARD_PIPELINE: tuple[tuple[str, str], ...] = (
    ("TriageAgent", "issue-classifier"),
    ("LocatorAgent", "code-root-cause"),
    ("CoderAgent", "patch-generator"),
    ("TesterAgent", "test-runner"),
    ("ReviewerAgent", "pr-reviewer"),
)


class TeamLeader(BaseAgent):
    """Central orchestrator that decomposes tasks, tracks state and arbitrates."""

    _IDENTITY = AgentIdentity(
        role="Team Leader",
        description=(
            "Central orchestrator that decomposes tasks, tracks state, and "
            "arbitrates conflicts across the agent team."
        ),
        model="glm-4",
        temperature=0.3,
        system_prompt_ref="prompts/team_leader.md",
    )
    _CAPABILITIES = (
        "task_decomposition",
        "state_tracking",
        "conflict_arbitration",
        "worker_management",
        "plan_generation",
    )
    _BOUNDARIES = (
        "Cannot write code directly",
        "Cannot approve PRs without human review for T4/T5 issues",
        "Cannot modify files outside the .devflow/ state directory",
        "Cannot bypass the approval workflow defined in security.yaml",
    )
    _WATCHES = (
        "issue.created",
        "agent.completed",
        "agent.failed",
        "review.rejected",
        "test.failed",
        "approval.required",
    )
    _FORBIDDEN_ACTIONS = {
        "write_code": "Cannot write code directly",
        "approve_t4t5_without_human": (
            "Cannot approve PRs without human review for T4/T5 issues"
        ),
        "modify_outside_devflow": (
            "Cannot modify files outside the .devflow/ state directory"
        ),
        "bypass_approval_workflow": (
            "Cannot bypass the approval workflow defined in security.yaml"
        ),
    }

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        #: Per-issue lifecycle state, keyed by issue number.
        self._lifecycle: dict[int, IssueLifecycle] = {}
        #: Per-issue accumulated context, keyed by issue number.
        self._issue_context: dict[int, dict[str, Any]] = {}
        #: Register handlers for watched events.
        self.register_event_handler("issue.created", self._on_issue_created)
        self.register_event_handler("agent.completed", self._on_agent_completed)
        self.register_event_handler("agent.failed", self._on_agent_failed)
        self.register_event_handler("review.rejected", self._on_review_rejected)
        self.register_event_handler("test.failed", self._on_test_failed)
        self.register_event_handler("approval.required", self._on_approval_required)

    # ------------------------------------------------------------------ #
    # Lifecycle state machine
    # ------------------------------------------------------------------ #
    def get_lifecycle(self, issue_id: int) -> IssueLifecycle:
        """Return the current lifecycle state of an issue (``NEW`` if unknown)."""
        return self._lifecycle.get(issue_id, IssueLifecycle.NEW)

    def _set_lifecycle(self, issue_id: int, state: IssueLifecycle) -> None:
        previous = self.get_lifecycle(issue_id)
        self._lifecycle[issue_id] = state
        logger.info(
            "team_leader.lifecycle_transition",
            issue_id=issue_id,
            previous=previous.value,
            next=state.value,
        )

    def _ensure_context(self, issue_id: int) -> dict[str, Any]:
        return self._issue_context.setdefault(issue_id, {})

    # ------------------------------------------------------------------ #
    # Task decomposition
    # ------------------------------------------------------------------ #
    async def decompose_task(
        self,
        issue: IssueData,
        classification: IssueClassification,
    ) -> list[Task]:
        """Decompose a classified issue into an ordered list of sub-tasks.

        The decomposition is tier-aware: trivial (T1) issues skip the
        localization step, while complex (T4/T5) issues always run the full
        pipeline including the human approval gate.
        """
        async with self._trace_span(
            "decompose_task", issue_id=issue.issue_number, tier=classification.complexity_level.value
        ):
            tier = classification.complexity_level
            issue_id = issue.issue_number
            context = self._ensure_context(issue_id)
            context.update(
                {
                    "issue": issue.model_dump(mode="json"),
                    "classification": classification.model_dump(mode="json"),
                    "tier": tier.value,
                }
            )

            tasks: list[Task] = []
            sequence = _STANDARD_PIPELINE
            # T1 issues are trivial (lint/typo) — localization adds no value
            # and only burns tokens, so skip straight to coding.
            if tier is ComplexityLevel.T1:
                sequence = tuple(
                    step for step in _STANDARD_PIPELINE if step[0] != "LocatorAgent"
                )

            previous_id: str | None = None
            for idx, (agent, skill) in enumerate(sequence):
                task_id = f"{issue_id}-{idx}-{agent.lower()}"
                task_input: dict[str, Any] = {
                    "issue_id": issue_id,
                    "tier": tier.value,
                    "issue": issue.model_dump(mode="json"),
                }
                if classification is not None:
                    task_input["classification"] = classification.model_dump(
                        mode="json"
                    )
                depends_on = [previous_id] if previous_id else []
                tasks.append(
                    Task(
                        task_id=task_id,
                        agent=agent,
                        skill=skill,
                        input_data=task_input,
                        depends_on=depends_on,
                        tier=tier,
                    )
                )
                previous_id = task_id

            self._set_lifecycle(issue_id, IssueLifecycle.TRIAGED)
            logger.info(
                "team_leader.decomposed",
                issue_id=issue_id,
                tier=tier.value,
                task_count=len(tasks),
            )
            return tasks

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #
    async def route_task(self, task: Task) -> None:
        """Dispatch a task to its target agent by emitting a routing event.

        The TeamLeader never invokes worker agents directly; instead it
        publishes a typed event that the scheduler picks up. This keeps the
        agents decoupled and the flow fully event-driven.
        """
        async with self._trace_span("route_task", task_id=task.task_id, agent=task.agent):
            event = f"task.route.{task.agent.lower()}"
            issue_id = int(task.input_data["issue_id"])
            envelope = HandoffEnvelope.create(
                run_id=f"issue-{issue_id}",
                issue_id=issue_id,
                task_id=task.task_id,
                producer=self.name,
                consumer=task.agent,
                skill=task.skill,
                artifact_type="SkillInvocation",
                payload={
                    "tier": task.tier.value,
                    "input": task.input_data,
                    "depends_on": task.depends_on,
                },
            )
            await self._emit_event(
                event,
                envelope.model_dump(mode="json"),
            )

    # ------------------------------------------------------------------ #
    # Conflict arbitration
    # ------------------------------------------------------------------ #
    async def arbitrate(self, conflict: Conflict) -> Decision:
        """Arbitrate a disagreement between agents.

        The TeamLeader uses the LLM to reason over the conflicting positions
        and the issue context, then returns a :class:`Decision` naming the
        next agent/action. Security findings always override a pass verdict —
        safety is non-negotiable.
        """
        async with self._trace_span(
            "arbitrate", issue_id=conflict.issue_id, parties=",".join(conflict.parties)
        ):
            # Deterministic precedence: security concerns override test passes.
            if "ReviewerAgent" in conflict.parties and "security" in conflict.description.lower():
                decision = Decision(
                    resolution="security_overrides_pass",
                    reasoning=(
                        "A security finding overrides a passing test result. "
                        "The patch is routed back to CoderAgent for remediation."
                    ),
                    next_agent="CoderAgent",
                    next_action="regenerate_with_security_feedback",
                    payload={"feedback": conflict.positions.get("ReviewerAgent", "")},
                )
            else:
                prompt = self._build_arbitration_prompt(conflict)
                raw = await self.llm.complete(
                    prompt,
                    model=self.identity.model,
                    temperature=self.identity.temperature,
                    system=self.identity.description,
                )
                decision = self._parse_arbitration(raw, conflict)

            self._ensure_context(conflict.issue_id)["last_decision"] = (
                decision.resolution
            )
            logger.info(
                "team_leader.arbitrated",
                issue_id=conflict.issue_id,
                resolution=decision.resolution,
                next_agent=decision.next_agent,
            )
            await self._emit_event(
                "arbitration.resolved",
                {
                    "issue_id": conflict.issue_id,
                    "resolution": decision.resolution,
                    "next_agent": decision.next_agent,
                    "next_action": decision.next_action,
                },
            )
            return decision

    def _build_arbitration_prompt(self, conflict: Conflict) -> str:
        positions = "\n".join(
            f"- {party}: {position}"
            for party, position in conflict.positions.items()
        )
        return (
            "You are the Team Leader arbitrating a conflict between agents.\n"
            f"Issue #{conflict.issue_id}: {conflict.description}\n\n"
            f"Positions:\n{positions}\n\n"
            "Decide a resolution. Respond with EXACTLY two lines:\n"
            "1) RESOLUTION: <one short phrase>\n"
            "2) NEXT_AGENT: <one of TriageAgent|LocatorAgent|CoderAgent|"
            "TesterAgent|ReviewerAgent|NONE>\n"
        )

    def _parse_arbitration(self, raw: str, conflict: Conflict) -> Decision:
        resolution = "arbitrated"
        next_agent: str | None = None
        for line in raw.splitlines():
            low = line.lower()
            if low.startswith("resolution:"):
                resolution = line.split(":", 1)[1].strip()
            elif low.startswith("next_agent:"):
                value = line.split(":", 1)[1].strip()
                next_agent = value if value.upper() != "NONE" else None
        return Decision(
            resolution=resolution,
            reasoning=raw.strip(),
            next_agent=next_agent,
            next_action="re_dispatch" if next_agent else None,
            payload={"issue_id": conflict.issue_id},
        )

    # ------------------------------------------------------------------ #
    # Failure handling
    # ------------------------------------------------------------------ #
    async def handle_failure(
        self,
        issue_id: int,
        failed_agent: str,
        error: str,
        *,
        attempt: int = 1,
    ) -> Decision:
        """Decide how to recover from a worker agent failure.

        Strategy: re-assign up to a small number of attempts, then escalate.
        The decision is returned so the caller (or the event loop) can act on
        it.
        """
        async with self._trace_span(
            "handle_failure", issue_id=issue_id, failed_agent=failed_agent, attempt=attempt
        ):
            if attempt < self.max_consecutive_failures:
                decision = Decision(
                    resolution="re_assign",
                    reasoning=(
                        f"Agent '{failed_agent}' failed (attempt {attempt}); "
                        "re-assigning the same task."
                    ),
                    next_agent=failed_agent,
                    next_action="retry",
                    payload={"attempt": attempt + 1, "original_error": error},
                )
            else:
                decision = Decision(
                    resolution="escalate",
                    reasoning=(
                        f"Agent '{failed_agent}' exhausted retries "
                        f"({attempt}); escalating to human review."
                    ),
                    next_agent=None,
                    next_action="escalate_human",
                    payload={"attempt": attempt, "original_error": error},
                )
                self._set_lifecycle(issue_id, IssueLifecycle.REJECTED)
            logger.warning(
                "team_leader.failure_decision",
                issue_id=issue_id,
                failed_agent=failed_agent,
                resolution=decision.resolution,
            )
            await self._emit_event(
                "failure.handled",
                {
                    "issue_id": issue_id,
                    "failed_agent": failed_agent,
                    "resolution": decision.resolution,
                    "next_agent": decision.next_agent,
                },
            )
            return decision

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #
    async def _on_issue_created(self, payload: dict[str, Any]) -> None:
        issue_data = payload.get("issue") or payload
        try:
            issue = IssueData(**issue_data) if not isinstance(issue_data, IssueData) else issue_data
        except Exception as exc:  # noqa: BLE001 — malformed event
            logger.error("team_leader.invalid_issue", error=str(exc), payload=payload)
            await self._emit_event(
                "agent.failed",
                {"agent": self.name, "error": f"Invalid issue payload: {exc}"},
            )
            return
        self._ensure_context(issue.issue_number)
        self._set_lifecycle(issue.issue_number, IssueLifecycle.NEW)
        # Kick off triage — classification is the first step of decomposition.
        await self._emit_event(
            "task.route.triageagent",
            {
                "issue_id": issue.issue_number,
                "issue": issue.model_dump(mode="json"),
            },
        )

    async def _on_agent_completed(self, payload: dict[str, Any]) -> None:
        agent = payload.get("agent")
        issue_id = payload.get("issue_id")
        if issue_id is None:
            return
        issue_id = int(issue_id)
        current = self.get_lifecycle(issue_id)
        # Advance the lifecycle based on which agent just completed.
        transitions: dict[IssueLifecycle, tuple[str, IssueLifecycle]] = {
            IssueLifecycle.NEW: ("TriageAgent", IssueLifecycle.TRIAGED),
            IssueLifecycle.TRIAGED: ("LocatorAgent", IssueLifecycle.LOCATING),
            IssueLifecycle.LOCATING: ("CoderAgent", IssueLifecycle.CODING),
            IssueLifecycle.CODING: ("TesterAgent", IssueLifecycle.TESTING),
            IssueLifecycle.TESTING: ("ReviewerAgent", IssueLifecycle.REVIEWING),
        }
        expected = transitions.get(current)
        if expected and expected[0] == agent:
            self._set_lifecycle(issue_id, expected[1])

    async def _on_agent_failed(self, payload: dict[str, Any]) -> None:
        agent = payload.get("agent")
        issue_id = payload.get("issue_id")
        if issue_id is None:
            return
        await self.handle_failure(
            int(issue_id),
            agent or "unknown",
            payload.get("error", "unknown error"),
        )

    async def _on_review_rejected(self, payload: dict[str, Any]) -> None:
        issue_id = payload.get("issue_id")
        if issue_id is None:
            return
        # Route back to the CoderAgent with reviewer feedback.
        self._set_lifecycle(int(issue_id), IssueLifecycle.CODING)
        await self._emit_event(
            "task.route.coderagent",
            {
                "issue_id": issue_id,
                "reason": "review_rejected",
                "feedback": payload.get("feedback", ""),
                "findings": payload.get("findings", []),
            },
        )

    async def _on_test_failed(self, payload: dict[str, Any]) -> None:
        issue_id = payload.get("issue_id")
        if issue_id is None:
            return
        # Route back to the CoderAgent with failing test output.
        self._set_lifecycle(int(issue_id), IssueLifecycle.CODING)
        await self._emit_event(
            "task.route.coderagent",
            {
                "issue_id": issue_id,
                "reason": "test_failed",
                "failing_tests": payload.get("failing_tests", []),
                "test_output": payload.get("test_output", ""),
            },
        )

    async def _on_approval_required(self, payload: dict[str, Any]) -> None:
        issue_id = payload.get("issue_id")
        if issue_id is None:
            return
        self._ensure_context(int(issue_id))["approval_required"] = True
        logger.info(
            "team_leader.approval_required",
            issue_id=issue_id,
            tier=payload.get("tier"),
        )
        # Block until a human approves — the pipeline pauses here.
        await self._emit_event(
            "pipeline.paused",
            {"issue_id": issue_id, "reason": "awaiting_human_approval"},
        )

    # ------------------------------------------------------------------ #
    # BaseAgent.run — the TeamLeader is reactive; running it directly is a
    # no-op that simply reports the current state.
    # ------------------------------------------------------------------ #
    async def run(self, input_data: Any) -> Any:
        """The TeamLeader is event-driven; direct invocation reports state.

        ``input_data`` may be an issue id (``int``) to report that issue's
        lifecycle, or ``None`` to report all tracked issues.
        """
        if isinstance(input_data, int):
            state = self.get_lifecycle(input_data)
            return {"issue_id": input_data, "lifecycle": state.value}
        return {
            "tracked_issues": {
                str(iid): state.value for iid, state in self._lifecycle.items()
            }
        }


__all__ = ["Conflict", "Decision", "IssueLifecycle", "Task", "TeamLeader"]

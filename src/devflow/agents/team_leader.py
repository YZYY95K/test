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

import copy
import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import ValidationError

from devflow.agents.base import AgentIdentity, BaseAgent
from devflow.agents.locator_agent import LocatedContext
from devflow.exceptions import AgentError
from devflow.models.agent_event import AgentFailureEvent
from devflow.models.issue import (
    ComplexityLevel,
    IssueClassification,
    IssueData,
)
from devflow.models.patch import EvidenceBoundary, Patch, PatchCandidate
from devflow.models.review import ReviewDecision, ReviewResult
from devflow.models.test_result import (
    TestFailureEvidence,
    TestRunResult,
    canonical_artifact_digest,
)
from devflow.observability import logger
from devflow.skills.contracts import HandoffEnvelope, HandoffStatus


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
_WORKER_NAMES = frozenset(agent for agent, _skill in _STANDARD_PIPELINE)
_MAX_CODER_GENERATION_ATTEMPTS = 3


class TeamLeader(BaseAgent):
    """Central orchestrator that decomposes tasks, tracks state and arbitrates."""

    _IDENTITY = AgentIdentity(
        role="Team Leader",
        description=(
            "Central orchestrator that decomposes tasks, tracks state, and "
            "arbitrates conflicts across the agent team."
        ),
        model="glm-5.2",
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
        "coder.patch_ready",
        "review.rejected",
        "test.failed",
        "approval.required",
    )
    _OWNED_SKILLS = ("team-orchestration",)
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
        #: Integrity-valid routes retained solely for bounded execution replay.
        self._execution_routes: dict[str, HandoffEnvelope] = {}
        #: Scheduler dispatch claims are owned by Leader rather than a Worker
        #: instance, so replacing a Worker cannot repeat one model-call lease.
        self._dispatched_execution_routes: set[str] = set()
        #: Stable outcomes make duplicate failure delivery idempotent.
        self._handled_execution_failures: dict[str, dict[str, Any]] = {}
        #: One claimant owns the recovery decision for each immutable route
        #: execution. Distinct failure events from duplicate execution cannot
        #: create a second retry.
        self._execution_route_claims: dict[tuple[str, int], str] = {}
        self._execution_route_outcomes: dict[
            tuple[str, int], dict[str, Any]
        ] = {}
        #: TeamLeader is the sole Coder model-call budget authority. Each
        #: issue receives at most three immutable, ordinal-bound routes across
        #: both candidate-validation and semantic test retries.
        self._coder_model_call_routes: dict[tuple[int, int], str] = {}
        #: A validated Coder result is re-issued as exactly one TeamLeader
        #: route to Tester.  The local scheduler consumes only Leader routes,
        #: never arbitrary peer-to-peer result events.
        self._tester_candidate_routes: dict[
            tuple[int, int], HandoffEnvelope
        ] = {}
        #: Register handlers for watched events.
        self.register_event_handler("issue.created", self._on_issue_created)
        self.register_event_handler("agent.completed", self._on_agent_completed)
        self.register_event_handler("agent.failed", self._on_agent_failed)
        self.register_event_handler("coder.patch_ready", self._on_coder_patch_ready)
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

    @staticmethod
    def _handoff_sha256(envelope: HandoffEnvelope) -> str:
        encoded = json.dumps(
            envelope.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _opaque_payload_digest(payload: dict[str, Any]) -> str:
        """Hash an invalid event without echoing any attacker-controlled value."""

        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                default=lambda _value: "<non-json>",
            ).encode("utf-8")
        except (TypeError, ValueError):
            encoded = b"invalid-agent-failure-event"
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _route_execution_attempt(envelope: HandoffEnvelope) -> int:
        inline = envelope.artifact.inline
        if inline is None:
            raise AgentError("Canonical execution route has no inline artifact.")
        retry = inline.get("execution_retry")
        if retry is None:
            return 1
        if (
            not isinstance(retry, dict)
            or retry.get("schema_version") != "devflow.execution-retry/v1"
            or isinstance(retry.get("attempt"), bool)
            or not isinstance(retry.get("attempt"), int)
        ):
            raise AgentError("Canonical execution retry metadata is invalid.")
        return int(retry["attempt"])

    def _coder_model_call_attempt(
        self,
        envelope: HandoffEnvelope,
    ) -> int | None:
        """Return the issue-global Coder model-call ordinal on a route."""

        if (
            envelope.consumer != "CoderAgent"
            or envelope.skill != "patch-generator"
        ):
            return None
        inline = envelope.artifact.inline
        request = inline.get("input") if isinstance(inline, dict) else None
        if not isinstance(request, dict):
            raise AgentError("Coder generation route has no canonical input.")
        raw_attempt = request.get("model_call_attempt")
        if (
            isinstance(raw_attempt, bool)
            or not isinstance(raw_attempt, int)
            or not 1 <= raw_attempt <= _MAX_CODER_GENERATION_ATTEMPTS
        ):
            raise AgentError("Coder model-call attempt is outside the bounded budget.")
        return raw_attempt

    def _remember_execution_route(self, envelope: HandoffEnvelope) -> None:
        """Persist one immutable, integrity-valid replay source in Leader memory."""

        if (
            envelope.producer != self.name
            or envelope.consumer not in _WORKER_NAMES
            or envelope.status not in {HandoffStatus.READY, HandoffStatus.RETRY}
            or envelope.artifact.inline is None
            or not envelope.artifact.verify_integrity()
        ):
            raise AgentError("Execution route is not a canonical Leader hand-off.")
        existing = self._execution_routes.get(envelope.task_id)
        if existing is not None and existing != envelope:
            raise AgentError("Execution route task id conflicts with canonical state.")
        route_digest = self._handoff_sha256(envelope)
        model_call_attempt = self._coder_model_call_attempt(envelope)
        model_call_key = (
            (envelope.issue_id, model_call_attempt)
            if model_call_attempt is not None
            else None
        )
        if model_call_key is not None:
            claimed_route = self._coder_model_call_routes.get(model_call_key)
            if claimed_route is not None and claimed_route != route_digest:
                raise AgentError(
                    "Coder model-call attempt conflicts with canonical state."
                )
            issued = sorted(
                ordinal
                for issue_id, ordinal in self._coder_model_call_routes
                if issue_id == envelope.issue_id
            )
            if claimed_route is None and model_call_attempt != len(issued) + 1:
                raise AgentError(
                    "Coder model-call attempts must be issued sequentially."
                )
        self._execution_routes[envelope.task_id] = envelope.model_copy(deep=True)
        if model_call_key is not None:
            self._coder_model_call_routes[model_call_key] = route_digest

    def is_authorized_execution_route(self, envelope: HandoffEnvelope) -> bool:
        """Verify that this Leader issued the exact immutable Worker route."""

        retained = self._execution_routes.get(envelope.task_id)
        return retained is not None and retained == envelope

    def claim_execution_route(self, envelope: HandoffEnvelope) -> bool:
        """Atomically claim one exact route for scheduler dispatch.

        The mutation is synchronous and process-local. Every retry uses a new
        canonical route, so a duplicate delivery of an old route is never
        needed for recovery and can safely be suppressed across Worker
        instances.
        """

        if not self.is_authorized_execution_route(envelope):
            return False
        route_digest = self._handoff_sha256(envelope)
        if route_digest in self._dispatched_execution_routes:
            return False
        self._dispatched_execution_routes.add(route_digest)
        return True

    def _canonical_coder_model_call_route(
        self,
        issue_id: int,
        model_call_attempt: int,
    ) -> HandoffEnvelope:
        """Resolve a Coder output to its immutable model-call route."""

        route_digest = self._coder_model_call_routes.get(
            (issue_id, model_call_attempt)
        )
        if route_digest is None:
            raise AgentError("Canonical Coder model-call route is unavailable.")
        matches = [
            route
            for route in self._execution_routes.values()
            if route.issue_id == issue_id
            and self._handoff_sha256(route) == route_digest
        ]
        if len(matches) != 1:
            raise AgentError("Canonical Coder generation route is ambiguous.")
        return matches[0]

    async def _record_failure_outcome(
        self,
        *,
        failure_id: str,
        failed_agent: str,
        resolution: str,
        reason: str,
        retry_domain: str = "execution",
        issue_id: int | None = None,
        next_agent: str | None = None,
        execution_attempt: int | None = None,
        generation_attempt: int | None = None,
        route_claim: tuple[str, int] | None = None,
    ) -> None:
        payload: dict[str, Any] = {
            "schema_version": "devflow.failure-outcome/v2",
            "failure_id": failure_id,
            "failed_agent": failed_agent,
            "retry_domain": retry_domain,
            "resolution": resolution,
            "reason": reason,
            "next_agent": next_agent,
            "execution_attempt": execution_attempt,
            "generation_attempt": generation_attempt,
            "idempotent": False,
        }
        if issue_id is not None:
            payload["issue_id"] = issue_id
        if route_claim is not None:
            payload["route_claim"] = {
                "handoff_sha256": route_claim[0],
                "execution_attempt": route_claim[1],
            }
        self._handled_execution_failures[failure_id] = dict(payload)
        if (
            route_claim is not None
            and self._execution_route_claims.get(route_claim) == failure_id
        ):
            self._execution_route_outcomes[route_claim] = dict(payload)
        await self._emit_event("failure.handled", payload)

    async def _repeat_failure_outcome(self, failure_id: str) -> None:
        prior = self._handled_execution_failures[failure_id]
        await self._emit_event(
            "failure.handled",
            {**prior, "idempotent": True},
        )

    async def _record_route_claim_duplicate(
        self,
        *,
        failure: AgentFailureEvent,
        route_claim: tuple[str, int],
        claimed_failure_id: str,
    ) -> None:
        """Audit duplicate execution without mutating the claimant outcome."""

        prior = self._execution_route_outcomes.get(route_claim)
        same_event = claimed_failure_id == failure.failure_id
        payload: dict[str, Any] = {
            "schema_version": "devflow.failure-outcome/v2",
            "failure_id": failure.failure_id,
            "failed_agent": failure.agent,
            "retry_domain": failure.retry_domain,
            "resolution": "duplicate",
            "reason": (
                "route_attempt_duplicate_delivery"
                if same_event
                else "route_attempt_failure_conflict"
            ),
            "next_agent": None,
            "execution_attempt": failure.execution_attempt,
            "generation_attempt": None,
            "idempotent": True,
            "issue_id": failure.issue_id,
            "claimed_failure_id": claimed_failure_id,
            "claimed_resolution": (
                prior.get("resolution") if prior is not None else "pending"
            ),
            "route_claim": {
                "handoff_sha256": route_claim[0],
                "execution_attempt": route_claim[1],
            },
        }
        # A different failure id needs its own stable repeat outcome. For the
        # same in-flight event, the claimant will publish the canonical outcome.
        if not same_event:
            self._handled_execution_failures[failure.failure_id] = dict(payload)
        await self._emit_event("failure.handled", payload)

    def record_retry_context(
        self,
        issue_id: int,
        *,
        issue: IssueData | dict[str, Any],
        tier: ComplexityLevel | str,
        located_context: LocatedContext | dict[str, Any],
        previous_patch: Patch | dict[str, Any],
        patch_attempt: int = 1,
        model_call_attempt: int = 1,
    ) -> None:
        """Record the canonical inputs required for one bounded Coder retry.

        This method is intentionally explicit. Recording context does not
        subscribe agents or execute another stage, so callers retain control
        over when a semantic retry is dispatched.
        """

        try:
            canonical_issue = (
                issue if isinstance(issue, IssueData) else IssueData.model_validate(issue)
            )
            canonical_tier = (
                tier if isinstance(tier, ComplexityLevel) else ComplexityLevel(tier)
            )
            canonical_located = (
                located_context
                if isinstance(located_context, LocatedContext)
                else LocatedContext.model_validate(located_context)
            )
            canonical_patch = (
                previous_patch
                if isinstance(previous_patch, Patch)
                else Patch.model_validate(previous_patch)
            )
            if any(
                isinstance(value, bool)
                for value in (issue_id, patch_attempt, model_call_attempt)
            ):
                raise TypeError("Retry context ordinals must be integers")
            canonical_issue_id = int(issue_id)
            canonical_attempt = int(patch_attempt)
            canonical_model_call_attempt = int(model_call_attempt)
        except (TypeError, ValueError) as exc:
            raise AgentError(f"Invalid retry context: {exc}") from exc
        if canonical_issue_id < 1 or canonical_issue.issue_number != canonical_issue_id:
            raise AgentError("Retry context issue id does not match the canonical issue.")
        if not 1 <= canonical_attempt <= _MAX_CODER_GENERATION_ATTEMPTS:
            raise AgentError("Retry context patch attempt is outside the bounded budget.")
        if (
            not 1
            <= canonical_model_call_attempt
            <= _MAX_CODER_GENERATION_ATTEMPTS
            or canonical_model_call_attempt < canonical_attempt
        ):
            raise AgentError("Retry context model-call attempt is outside the budget.")

        canonical_values = {
            "issue": canonical_issue.model_dump(mode="json"),
            "tier": canonical_tier.value,
            "located_context": canonical_located.model_dump(mode="json"),
        }
        context = self._ensure_context(canonical_issue_id)
        for key, value in canonical_values.items():
            if key in context and context[key] != value:
                raise AgentError(f"Retry context conflicts with canonical {key}.")

        patch_payload = canonical_patch.model_dump(mode="json")
        patch_digest = canonical_artifact_digest(canonical_patch)
        current_attempt = context.get("patch_attempt")
        if current_attempt is None:
            if canonical_attempt != 1:
                raise AgentError("Retry context must start with patch attempt 1.")
        else:
            current_attempt = int(current_attempt)
            if canonical_attempt not in {current_attempt, current_attempt + 1}:
                raise AgentError("Retry context patch attempt is not sequential.")
            if (
                canonical_attempt == current_attempt
                and context.get("previous_patch_digest") != patch_digest
            ):
                raise AgentError("Retry context cannot replace a recorded patch attempt.")

        context.update(canonical_values)
        context.update(
            {
                "previous_patch": patch_payload,
                "previous_patch_digest": patch_digest,
                "patch_attempt": canonical_attempt,
                "model_call_attempt": canonical_model_call_attempt,
            }
        )
        if current_attempt is not None and canonical_attempt == current_attempt + 1:
            context.pop("pending_test_retry", None)
            context.pop("semantic_test_failure", None)

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
            task_input = copy.deepcopy(task.input_data)
            existing = self._execution_routes.get(task.task_id)
            if (
                task.agent == "CoderAgent"
                and task.skill == "patch-generator"
                and "model_call_attempt" not in task_input
            ):
                if existing is not None and existing.artifact.inline is not None:
                    retained_input = existing.artifact.inline.get("input")
                    if isinstance(retained_input, dict):
                        retained_attempt = retained_input.get("model_call_attempt")
                        if isinstance(retained_attempt, int) and not isinstance(
                            retained_attempt, bool
                        ):
                            task_input["model_call_attempt"] = retained_attempt
                if "model_call_attempt" not in task_input:
                    issued = sum(
                        retained_issue_id == issue_id
                        for retained_issue_id, _ordinal in self._coder_model_call_routes
                    )
                    next_attempt = issued + 1
                    if next_attempt > _MAX_CODER_GENERATION_ATTEMPTS:
                        raise AgentError(
                            "Coder model-call budget is exhausted; no route was issued."
                        )
                    task_input["model_call_attempt"] = next_attempt
            route_payload = {
                "tier": task.tier.value,
                "input": task_input,
                "depends_on": task.depends_on,
            }
            if existing is not None:
                if (
                    existing.issue_id != issue_id
                    or existing.consumer != task.agent
                    or existing.skill != task.skill
                    or existing.status is not HandoffStatus.READY
                    or existing.artifact.type != "SkillInvocation"
                    or existing.artifact.inline != route_payload
                ):
                    raise AgentError("Task id conflicts with an existing canonical route.")
                await self._emit_event(event, existing.model_dump(mode="json"))
                return
            envelope = HandoffEnvelope.create(
                run_id=f"issue-{issue_id}",
                issue_id=issue_id,
                task_id=task.task_id,
                producer=self.name,
                consumer=task.agent,
                skill=task.skill,
                artifact_type="SkillInvocation",
                payload=route_payload,
            )
            self._remember_execution_route(envelope)
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
        """Return a legacy caller-owned recovery decision.

        This compatibility helper never claims that a retry was dispatched.
        The strict ``agent.failed`` event path below is the only path that may
        emit a real retry, because it can prove canonical route ownership.
        """
        error_digest = hashlib.sha256(
            error.encode("utf-8", errors="replace")
        ).hexdigest()
        async with self._trace_span(
            "handle_failure", issue_id=issue_id, failed_agent=failed_agent, attempt=attempt
        ):
            if attempt < self.max_consecutive_failures:
                decision = Decision(
                    resolution="retry_proposed",
                    reasoning=(
                        f"Agent '{failed_agent}' failed (attempt {attempt}); "
                        "a caller with canonical route context may retry it."
                    ),
                    next_agent=failed_agent,
                    next_action="retry",
                    payload={"attempt": attempt + 1, "error_digest": error_digest},
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
                    payload={"attempt": attempt, "error_digest": error_digest},
                )
                self._set_lifecycle(issue_id, IssueLifecycle.REJECTED)
            logger.warning(
                "team_leader.failure_decision",
                issue_id=issue_id,
                failed_agent=failed_agent,
                resolution=decision.resolution,
            )
            await self._emit_event(
                "failure.decision",
                {
                    "issue_id": issue_id,
                    "failed_agent": failed_agent,
                    "resolution": decision.resolution,
                    "next_agent": decision.next_agent,
                    "error_digest": error_digest,
                },
            )
            return decision

    # ------------------------------------------------------------------ #
    # Event handlers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _handoff_payload(payload: dict[str, Any]) -> dict[str, Any]:
        """Unpack only integrity-valid collaboration envelopes."""

        if payload.get("envelope_version") != "1.0":
            return payload
        envelope = HandoffEnvelope.model_validate(payload)
        if not envelope.artifact.verify_integrity() or envelope.artifact.inline is None:
            raise AgentError("received a corrupted hand-off artifact")
        return {
            "issue_id": envelope.issue_id,
            "producer": envelope.producer,
            "consumer": envelope.consumer,
            "status": envelope.status.value,
            **envelope.artifact.inline,
        }

    async def _on_issue_created(self, payload: dict[str, Any]) -> None:
        issue_data = payload.get("issue") or payload
        try:
            issue = IssueData(**issue_data) if not isinstance(issue_data, IssueData) else issue_data
        except Exception as exc:  # noqa: BLE001 — malformed event
            error_type, error_digest = self._safe_error_identity(exc)
            logger.error(
                "team_leader.invalid_issue",
                error_code="INVALID_ISSUE_EVENT",
                error_type=error_type,
                error_digest=error_digest,
            )
            await self._emit_event(
                "issue.rejected",
                {
                    "schema_version": "devflow.issue-rejection/v1",
                    "reason": "invalid_issue_payload",
                    "error_type": error_type,
                    "error_digest": error_digest,
                },
            )
            return
        self._ensure_context(issue.issue_number)
        self._set_lifecycle(issue.issue_number, IssueLifecycle.NEW)
        # Kick off triage — classification is the first step of decomposition.
        await self.route_task(
            Task(
                task_id=f"{issue.issue_number}-1-triageagent",
                agent="TriageAgent",
                skill="issue-classifier",
                input_data={
                    "issue_id": issue.issue_number,
                    "issue": issue.model_dump(mode="json"),
                },
                # The real tier is Triage's output; use the conservative
                # scheduling policy until that classification exists.
                tier=ComplexityLevel.T3,
            )
        )

    async def _on_agent_completed(self, payload: dict[str, Any]) -> None:
        agent = payload.get("agent")
        issue_id = payload.get("issue_id")
        outcome = payload.get("outcome")
        if issue_id is None or outcome not in {None, "execution_succeeded"}:
            return
        try:
            issue_id = int(issue_id)
        except (TypeError, ValueError):
            return
        if issue_id < 1:
            return
        context = self._issue_context.get(issue_id, {})
        # A successful Tester *invocation* is not a passing test gate. The
        # domain-level test.passed/test.failed hand-off is the only authority
        # for semantic progression, so a generic completion can never advance
        # the issue even when failure routing itself was rejected.
        if agent == "TesterAgent":
            retry_pending = (
                "pending_test_retry" in context
                or "semantic_test_failure" in context
            )
            await self._emit_event(
                "agent.completion.ignored",
                {
                    "schema_version": "devflow.completion-decision/v1",
                    "issue_id": issue_id,
                    "completed_agent": "TesterAgent",
                    "reason": (
                        "semantic_test_retry_pending"
                        if retry_pending
                        else "semantic_test_outcome_required"
                    ),
                },
            )
            return
        current = self.get_lifecycle(issue_id)
        # Advance the lifecycle based on which agent just completed.
        transitions: dict[IssueLifecycle, tuple[str, IssueLifecycle]] = {
            IssueLifecycle.NEW: ("TriageAgent", IssueLifecycle.TRIAGED),
            IssueLifecycle.TRIAGED: ("LocatorAgent", IssueLifecycle.LOCATING),
            IssueLifecycle.LOCATING: ("CoderAgent", IssueLifecycle.CODING),
            IssueLifecycle.TESTING: ("ReviewerAgent", IssueLifecycle.REVIEWING),
        }
        expected = transitions.get(current)
        if expected and expected[0] == agent:
            self._set_lifecycle(issue_id, expected[1])

    async def _on_agent_failed(self, payload: dict[str, Any]) -> None:
        try:
            failure = AgentFailureEvent.model_validate(payload)
        except ValidationError:
            failure_id = self._opaque_payload_digest(payload)
            if failure_id in self._handled_execution_failures:
                await self._repeat_failure_outcome(failure_id)
                return
            await self._record_failure_outcome(
                failure_id=failure_id,
                failed_agent="untrusted",
                resolution="escalated",
                reason="invalid_failure_event",
            )
            return
        if failure.failure_id in self._handled_execution_failures:
            await self._repeat_failure_outcome(failure.failure_id)
            return

        safe_agent = failure.agent if failure.agent in _WORKER_NAMES else "untrusted"
        if not failure.correlation_trusted:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=safe_agent,
                resolution="escalated",
                reason="untrusted_execution_context",
            )
            return
        if failure.agent not in _WORKER_NAMES:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent="untrusted",
                resolution="escalated",
                reason="failed_agent_not_routable",
            )
            return

        assert failure.issue_id is not None
        assert failure.run_id is not None
        assert failure.task_id is not None
        assert failure.trace_id is not None
        assert failure.idempotency_key is not None
        assert failure.execution_attempt is not None
        assert failure.handoff_sha256 is not None
        route = self._execution_routes.get(failure.task_id)
        if route is None:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="canonical_replay_context_unavailable",
            )
            return
        try:
            route_attempt = self._route_execution_attempt(route)
        except AgentError:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="canonical_replay_context_invalid",
            )
            return
        if (
            route.issue_id != failure.issue_id
            or route.run_id != failure.run_id
            or route.task_id != failure.task_id
            or route.trace_id != failure.trace_id
            or route.idempotency_key != failure.idempotency_key
            or route.consumer != failure.agent
            or route_attempt != failure.execution_attempt
            or self._handoff_sha256(route) != failure.handoff_sha256
        ):
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="canonical_replay_context_mismatch",
            )
            return

        route_claim = (
            failure.handoff_sha256,
            failure.execution_attempt,
        )
        claimed_failure_id = self._execution_route_claims.get(route_claim)
        if claimed_failure_id is not None:
            await self._record_route_claim_duplicate(
                failure=failure,
                route_claim=route_claim,
                claimed_failure_id=claimed_failure_id,
            )
            return
        # This mutation is intentionally synchronous and happens before the
        # first await below, so concurrent deliveries cannot both own routing.
        self._execution_route_claims[route_claim] = failure.failure_id

        if failure.agent == "CoderAgent":
            try:
                model_call_attempt = self._coder_model_call_attempt(route)
            except AgentError:
                model_call_attempt = None
            if (
                model_call_attempt is None
                or model_call_attempt >= _MAX_CODER_GENERATION_ATTEMPTS
            ):
                self._set_lifecycle(failure.issue_id, IssueLifecycle.REJECTED)
                await self._record_failure_outcome(
                    failure_id=failure.failure_id,
                    failed_agent=failure.agent,
                    resolution="escalated",
                    reason="generation_retry_budget_exhausted",
                    retry_domain=failure.retry_domain,
                    issue_id=failure.issue_id,
                    execution_attempt=failure.execution_attempt,
                    generation_attempt=model_call_attempt,
                    route_claim=route_claim,
                )
                return

            inline = copy.deepcopy(route.artifact.inline)
            if (
                not isinstance(inline, dict)
                or not isinstance(inline.get("input"), dict)
                or not isinstance(inline.get("depends_on"), list)
            ):
                await self._record_failure_outcome(
                    failure_id=failure.failure_id,
                    failed_agent=failure.agent,
                    resolution="escalated",
                    reason="canonical_generation_context_invalid",
                    retry_domain=failure.retry_domain,
                    issue_id=failure.issue_id,
                    execution_attempt=failure.execution_attempt,
                    generation_attempt=model_call_attempt,
                    route_claim=route_claim,
                )
                return
            request = inline["input"]
            dependencies = inline["depends_on"]
            if (
                not isinstance(request, dict)
                or not isinstance(dependencies, list)
                or any(
                    not isinstance(dependency, str) or not dependency
                    for dependency in dependencies
                )
            ):
                await self._record_failure_outcome(
                    failure_id=failure.failure_id,
                    failed_agent=failure.agent,
                    resolution="escalated",
                    reason="canonical_generation_context_invalid",
                    retry_domain=failure.retry_domain,
                    issue_id=failure.issue_id,
                    execution_attempt=failure.execution_attempt,
                    generation_attempt=model_call_attempt,
                    route_claim=route_claim,
                )
                return

            next_model_call_attempt = model_call_attempt + 1
            request["model_call_attempt"] = next_model_call_attempt
            request["validator_feedback_code"] = (
                "CANDIDATE_INVALID"
                if failure.error_code == "CANDIDATE_INVALID"
                else "MODEL_CALL_FAILED"
            )
            inline["depends_on"] = list(
                dict.fromkeys([*dependencies, route.task_id])
            )
            inline["generation_retry"] = {
                "schema_version": "devflow.generation-retry/v1",
                "model_call_attempt": next_model_call_attempt,
                "max_model_calls": _MAX_CODER_GENERATION_ATTEMPTS,
                "failure_id": failure.failure_id,
                "reason": request["validator_feedback_code"],
            }
            generation_budget = inline.get("generation_budget")
            if generation_budget is not None:
                if (
                    not isinstance(generation_budget, dict)
                    or generation_budget.get("schema_version")
                    != "devflow.generation-budget/v1"
                ):
                    await self._record_failure_outcome(
                        failure_id=failure.failure_id,
                        failed_agent=failure.agent,
                        resolution="escalated",
                        reason="canonical_generation_context_invalid",
                        retry_domain=failure.retry_domain,
                        issue_id=failure.issue_id,
                        execution_attempt=failure.execution_attempt,
                        generation_attempt=model_call_attempt,
                        route_claim=route_claim,
                    )
                    return
                generation_budget["model_call_attempt"] = next_model_call_attempt
                generation_budget["max_model_calls"] = (
                    _MAX_CODER_GENERATION_ATTEMPTS
                )
            retry_envelope = HandoffEnvelope.create(
                run_id=route.run_id,
                issue_id=route.issue_id,
                task_id=(
                    f"{route.issue_id}-coderagent-model-call-"
                    f"{next_model_call_attempt}-{failure.failure_id[:12]}"
                ),
                producer=self.name,
                consumer="CoderAgent",
                skill="patch-generator",
                artifact_type="SkillInvocation",
                status=HandoffStatus.RETRY,
                payload=inline,
            )
            try:
                self._remember_execution_route(retry_envelope)
            except AgentError:
                await self._record_failure_outcome(
                    failure_id=failure.failure_id,
                    failed_agent=failure.agent,
                    resolution="escalated",
                    reason="generation_retry_route_conflict",
                    retry_domain=failure.retry_domain,
                    issue_id=failure.issue_id,
                    execution_attempt=failure.execution_attempt,
                    generation_attempt=model_call_attempt,
                    route_claim=route_claim,
                )
                return
            await self._emit_event(
                "task.route.coderagent",
                retry_envelope.model_dump(mode="json"),
            )
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="retry_routed",
                reason="global_model_call_retry",
                retry_domain=failure.retry_domain,
                issue_id=failure.issue_id,
                next_agent="CoderAgent",
                execution_attempt=failure.execution_attempt,
                generation_attempt=next_model_call_attempt,
                route_claim=route_claim,
            )
            return

        if failure.retry_domain != "execution" or not failure.execution_retry_eligible:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="execution_retry_not_allowed",
                retry_domain=failure.retry_domain,
                issue_id=failure.issue_id,
                execution_attempt=failure.execution_attempt,
                route_claim=route_claim,
            )
            return

        if failure.execution_attempt >= self.max_consecutive_failures:
            self._set_lifecycle(failure.issue_id, IssueLifecycle.REJECTED)
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="execution_retry_budget_exhausted",
                issue_id=failure.issue_id,
                execution_attempt=failure.execution_attempt,
                route_claim=route_claim,
            )
            return

        inline = copy.deepcopy(route.artifact.inline)
        if inline is None:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="canonical_replay_context_invalid",
                route_claim=route_claim,
            )
            return
        prior_retry = inline.get("execution_retry")
        root_task_id = (
            prior_retry.get("root_task_id")
            if isinstance(prior_retry, dict)
            else route.task_id
        )
        dependencies = inline.get("depends_on", [])
        if (
            not isinstance(root_task_id, str)
            or not root_task_id
            or not isinstance(dependencies, list)
            or any(not isinstance(item, str) or not item for item in dependencies)
        ):
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="canonical_replay_context_invalid",
                route_claim=route_claim,
            )
            return
        next_attempt = failure.execution_attempt + 1
        next_task_id = f"{root_task_id}-exec-{next_attempt}"
        inline["depends_on"] = list(dict.fromkeys([*dependencies, route.task_id]))
        inline["execution_retry"] = {
            "schema_version": "devflow.execution-retry/v1",
            "attempt": next_attempt,
            "failure_id": failure.failure_id,
            "root_task_id": root_task_id,
        }
        retry_envelope = HandoffEnvelope.create(
            run_id=route.run_id,
            issue_id=route.issue_id,
            task_id=next_task_id,
            producer=self.name,
            consumer=route.consumer,
            skill=route.skill,
            artifact_type=route.artifact.type,
            status=HandoffStatus.RETRY,
            payload=inline,
        )
        try:
            self._remember_execution_route(retry_envelope)
        except AgentError:
            await self._record_failure_outcome(
                failure_id=failure.failure_id,
                failed_agent=failure.agent,
                resolution="escalated",
                reason="execution_retry_route_conflict",
                issue_id=failure.issue_id,
                execution_attempt=failure.execution_attempt,
                route_claim=route_claim,
            )
            return
        await self._emit_event(
            f"task.route.{failure.agent.lower()}",
            retry_envelope.model_dump(mode="json"),
        )
        await self._record_failure_outcome(
            failure_id=failure.failure_id,
            failed_agent=failure.agent,
            resolution="retry_routed",
            reason="canonical_execution_retry",
            issue_id=failure.issue_id,
            next_agent=failure.agent,
            execution_attempt=next_attempt,
            route_claim=route_claim,
        )

    async def _on_coder_patch_ready(self, payload: dict[str, Any]) -> None:
        """Bind a Coder candidate to the exact generation route that produced it.

        The candidate event is addressed to TesterAgent, but TeamLeader observes
        it to retain the minimum canonical state needed if testing fails.  No
        issue, tier, located context, or attempt value is trusted from the
        candidate alone: each value must agree with a route previously issued
        and retained by this Leader instance.
        """

        if payload.get("envelope_version") != "1.0":
            raise AgentError("Canonical Coder candidate hand-off is required.")
        try:
            incoming = HandoffEnvelope.model_validate(payload)
        except ValueError as exc:
            raise AgentError("Invalid Coder candidate hand-off.") from exc
        if (
            incoming.producer != "CoderAgent"
            or incoming.consumer != "TesterAgent"
            or incoming.skill != "patch-generator"
            or incoming.artifact.type != "PatchCandidate"
            or incoming.artifact.schema_version != "1.2"
            or incoming.status is not HandoffStatus.READY
            or incoming.trace_id != f"{incoming.run_id}:{incoming.task_id}"
            or incoming.idempotency_key
            != (
                f"{incoming.run_id}:{incoming.task_id}:"
                f"{incoming.consumer}:{incoming.skill}"
            )
            or incoming.artifact.inline is None
            or not incoming.artifact.verify_integrity()
        ):
            raise AgentError("Coder candidate hand-off contract does not match.")

        try:
            candidate = PatchCandidate.model_validate(incoming.artifact.inline)
            issue_id = candidate.issue_id
            candidate_tier = ComplexityLevel(candidate.tier)
            patch_attempt = candidate.retry_attempt
            model_call_attempt = candidate.model_call_attempt
        except (TypeError, ValueError) as exc:
            raise AgentError(f"Invalid Coder candidate payload: {exc}") from exc
        if issue_id != incoming.issue_id:
            raise AgentError("Coder candidate issue does not match its envelope.")

        route = self._canonical_coder_model_call_route(
            issue_id,
            model_call_attempt,
        )
        route_inline = route.artifact.inline
        if route_inline is None:
            raise AgentError("Canonical Coder generation artifact is unavailable.")
        request = route_inline.get("input")
        if not isinstance(request, dict):
            raise AgentError("Canonical Coder generation input is unavailable.")
        if (
            route.run_id != incoming.run_id
            or route.trace_id != f"{route.run_id}:{route.task_id}"
            or route.idempotency_key
            != f"{route.run_id}:{route.task_id}:{route.consumer}:{route.skill}"
            or (
                model_call_attempt == 1
                and route.status is not HandoffStatus.READY
            )
            or (
                model_call_attempt > 1
                and route.status is not HandoffStatus.RETRY
            )
        ):
            raise AgentError("Coder candidate does not match its canonical route.")

        initial_fields = {
            "issue_id",
            "issue",
            "tier",
            "located_context",
            "model_call_attempt",
        }
        retry_fields = initial_fields | {
            "previous_patch",
            "test_failure_evidence",
            "retry_attempt",
        }
        actual_fields = set(request)
        expected_fields = initial_fields if patch_attempt == 1 else retry_fields
        if actual_fields - {"validator_feedback_code"} != expected_fields:
            raise AgentError("Canonical Coder generation input fields do not match.")
        try:
            request_issue_id_raw = request["issue_id"]
            if isinstance(request_issue_id_raw, bool):
                raise TypeError("issue_id must be an integer")
            request_issue_id = int(request_issue_id_raw)
            issue = IssueData.model_validate(request["issue"])
            route_tier = ComplexityLevel(request["tier"])
            located = LocatedContext.model_validate(request["located_context"])
            route_model_call_attempt_raw = request["model_call_attempt"]
            if isinstance(route_model_call_attempt_raw, bool):
                raise TypeError("model_call_attempt must be an integer")
            route_model_call_attempt = int(route_model_call_attempt_raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(f"Canonical Coder generation input is invalid: {exc}") from exc
        if (
            request_issue_id != issue_id
            or issue.issue_number != issue_id
            or route_tier is not candidate_tier
            or route_inline.get("tier") != route_tier.value
            or route_model_call_attempt != model_call_attempt
        ):
            raise AgentError("Coder candidate metadata conflicts with its route.")

        expected_boundary = EvidenceBoundary.create(
            located_context_digest=canonical_artifact_digest(located),
            allowed_files=frozenset(
                {
                    located.root_cause.file,
                    *located.related_tests,
                    *located.impact_analysis.affected_files,
                    *located.impact_analysis.test_files_needed,
                    *(item.path for item in located.affected_files),
                }
            ),
        )
        if candidate.evidence_boundary != expected_boundary:
            raise AgentError("Coder candidate evidence scope conflicts with its route.")

        if patch_attempt == 1:
            if candidate.revision_of is not None:
                raise AgentError("Initial Coder candidate cannot claim a revision.")
        else:
            try:
                request_attempt_raw = request["retry_attempt"]
                if isinstance(request_attempt_raw, bool):
                    raise TypeError("retry_attempt must be an integer")
                request_attempt = int(request_attempt_raw)
                previous_patch = Patch.model_validate(request["previous_patch"])
                evidence = TestFailureEvidence.model_validate(
                    request["test_failure_evidence"]
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise AgentError(f"Canonical Coder retry input is invalid: {exc}") from exc
            if (
                request_attempt != patch_attempt
                or evidence.issue_id != issue_id
                or not evidence.verifies_candidate(previous_patch)
                or candidate.revision_of != evidence.candidate_digest
            ):
                raise AgentError("Coder revision does not match its retry evidence.")

        self.record_retry_context(
            issue_id,
            issue=issue,
            tier=route_tier,
            located_context=located,
            previous_patch=candidate.patch,
            patch_attempt=patch_attempt,
            model_call_attempt=model_call_attempt,
        )
        candidate_payload = candidate.model_dump(mode="json", exclude_none=True)
        candidate_key = (issue_id, model_call_attempt)
        tester_route = self._tester_candidate_routes.get(candidate_key)
        if tester_route is None:
            tester_route = HandoffEnvelope.create(
                run_id=incoming.run_id,
                issue_id=issue_id,
                task_id=(
                    f"{issue_id}-{model_call_attempt}-testeragent-candidate-"
                    f"{candidate.candidate_digest[:12]}"
                ),
                producer=self.name,
                consumer="TesterAgent",
                skill="test-runner",
                artifact_type="PatchCandidate",
                artifact_schema_version="1.2",
                status=HandoffStatus.READY,
                payload=candidate_payload,
            )
            self._remember_execution_route(tester_route)
            self._tester_candidate_routes[candidate_key] = tester_route.model_copy(
                deep=True
            )
        elif tester_route.artifact.inline != candidate_payload:
            raise AgentError(
                "Coder generation attempt conflicts with its retained Tester route."
            )
        self._set_lifecycle(issue_id, IssueLifecycle.TESTING)
        await self._emit_event(
            "task.route.testeragent",
            tester_route.model_dump(mode="json"),
        )

    async def _on_review_rejected(self, payload: dict[str, Any]) -> None:
        """Fail closed until review feedback has a revision-bound contract."""

        if payload.get("envelope_version") != "1.0":
            raise AgentError("Canonical Reviewer hand-off is required.")
        try:
            incoming = HandoffEnvelope.model_validate(payload)
        except ValueError as exc:
            raise AgentError("Invalid Reviewer rejection hand-off.") from exc
        if (
            incoming.producer != "ReviewerAgent"
            or incoming.consumer != self.name
            or incoming.skill != "pr-reviewer"
            or incoming.artifact.type != "ReviewDecision"
            or incoming.status is not HandoffStatus.RETRY
            or incoming.artifact.inline is None
            or not incoming.artifact.verify_integrity()
            or incoming.trace_id != f"{incoming.run_id}:{incoming.task_id}"
            or incoming.idempotency_key
            != (
                f"{incoming.run_id}:{incoming.task_id}:"
                f"{incoming.consumer}:{incoming.skill}"
            )
        ):
            raise AgentError("Reviewer rejection hand-off contract does not match.")
        review_payload = incoming.artifact.inline
        if set(review_payload) != {"issue_id", "tier", "review"}:
            raise AgentError("Reviewer rejection payload fields do not match.")
        try:
            issue_id_raw = review_payload["issue_id"]
            if isinstance(issue_id_raw, bool):
                raise TypeError("issue_id must be an integer")
            issue_id = int(issue_id_raw)
            tier = ComplexityLevel(review_payload["tier"])
            review = ReviewResult.model_validate(review_payload["review"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(f"Reviewer rejection payload is invalid: {exc}") from exc
        if (
            issue_id != incoming.issue_id
            or review.decision is not ReviewDecision.CHANGES_REQUESTED
        ):
            raise AgentError("Reviewer rejection metadata is inconsistent.")

        context = self._ensure_context(issue_id)
        context["review_rejection"] = {
            "tier": tier.value,
            "review_digest": canonical_artifact_digest(review),
        }
        self._set_lifecycle(issue_id, IssueLifecycle.REJECTED)
        await self._emit_event(
            "review.remediation_blocked",
            {
                "schema_version": "devflow.review-remediation/v1",
                "issue_id": issue_id,
                "reason": "feedback_not_bound_to_exact_candidate",
                "review_digest": canonical_artifact_digest(review),
                "requires_human_replan": True,
            },
        )

    async def _on_test_failed(self, payload: dict[str, Any]) -> None:
        if payload.get("envelope_version") != "1.0":
            raise AgentError(
                "Canonical retry context is incomplete: typed Tester hand-off required."
            )
        try:
            incoming = HandoffEnvelope.model_validate(payload)
        except ValueError as exc:
            raise AgentError("Invalid Tester failure hand-off.") from exc
        if (
            incoming.producer != "TesterAgent"
            or incoming.consumer != "TeamLeader"
            or incoming.skill != "test-runner"
            or incoming.artifact.type != "TestEvidence"
            or incoming.status is not HandoffStatus.RETRY
            or incoming.trace_id != f"{incoming.run_id}:{incoming.task_id}"
            or incoming.idempotency_key
            != (
                f"{incoming.run_id}:{incoming.task_id}:"
                f"{incoming.consumer}:{incoming.skill}"
            )
        ):
            raise AgentError("Tester failure hand-off contract does not match.")

        failure_payload = self._handoff_payload(payload)
        try:
            issue_id = int(failure_payload["issue_id"])
            result_raw = failure_payload["test_result"]
            evidence_raw = failure_payload["failure_evidence"]
            result = (
                result_raw
                if isinstance(result_raw, TestRunResult)
                else TestRunResult.model_validate(result_raw)
            )
            evidence = (
                evidence_raw
                if isinstance(evidence_raw, TestFailureEvidence)
                else TestFailureEvidence.model_validate(evidence_raw)
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(f"Invalid test failure evidence: {exc}") from exc
        if issue_id < 1 or evidence.issue_id != issue_id:
            raise AgentError("Test failure evidence issue id does not match.")
        if not evidence.verifies_test_result(result):
            raise AgentError("Test failure evidence does not match the test result digest.")
        if failure_payload.get("candidate_digest") not in {
            None,
            evidence.candidate_digest,
        }:
            raise AgentError("Test failure candidate digest is inconsistent.")
        supplied_failing_tests = failure_payload.get("failing_tests")
        if (
            supplied_failing_tests is not None
            and supplied_failing_tests != evidence.failing_tests
        ):
            raise AgentError("Test failure names are inconsistent with the evidence.")

        context = self._issue_context.get(issue_id)
        required_context = {
            "issue",
            "tier",
            "located_context",
            "previous_patch",
            "previous_patch_digest",
            "patch_attempt",
            "model_call_attempt",
        }
        missing = sorted(required_context - set(context or {}))
        if context is None or missing:
            detail = ", ".join(missing) if missing else "all fields"
            raise AgentError(f"Canonical retry context is incomplete: {detail}.")
        try:
            issue = IssueData.model_validate(context["issue"])
            tier = ComplexityLevel(context["tier"])
            located = LocatedContext.model_validate(context["located_context"])
            previous_patch = Patch.model_validate(context["previous_patch"])
            patch_attempt = int(context["patch_attempt"])
            model_call_attempt = int(context["model_call_attempt"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AgentError(f"Canonical retry context is invalid: {exc}") from exc
        if issue.issue_number != issue_id:
            raise AgentError("Canonical retry issue does not match the failure evidence.")
        previous_digest = canonical_artifact_digest(previous_patch)
        if (
            context["previous_patch_digest"] != previous_digest
            or not evidence.verifies_candidate(previous_patch)
        ):
            raise AgentError("Test failure evidence does not match the previous patch digest.")

        pending_raw = context.get("pending_test_retry")
        if pending_raw is not None:
            if not isinstance(pending_raw, dict):
                raise AgentError("Canonical pending retry state is invalid.")
            if pending_raw.get("test_result_digest") != evidence.test_result_digest:
                raise AgentError("A different test retry is already pending.")
            try:
                retry_envelope = HandoffEnvelope.model_validate(pending_raw["envelope"])
            except (KeyError, ValueError) as exc:
                raise AgentError("Canonical pending retry hand-off is invalid.") from exc
            self._remember_execution_route(retry_envelope)
            context["semantic_test_failure"] = {
                "test_result_digest": evidence.test_result_digest,
                "candidate_digest": evidence.candidate_digest,
            }
            await self._emit_event(
                "task.route.coderagent",
                retry_envelope.model_dump(mode="json"),
            )
            return

        next_attempt = patch_attempt + 1
        next_model_call_attempt = model_call_attempt + 1
        if (
            next_attempt > _MAX_CODER_GENERATION_ATTEMPTS
            or next_model_call_attempt > _MAX_CODER_GENERATION_ATTEMPTS
        ):
            self._set_lifecycle(issue_id, IssueLifecycle.REJECTED)
            await self._emit_event(
                "generation.budget_exhausted",
                {
                    "schema_version": "devflow.generation-budget/v1",
                    "issue_id": issue_id,
                    "patch_attempt": patch_attempt,
                    "model_calls_used": model_call_attempt,
                    "max_model_calls": _MAX_CODER_GENERATION_ATTEMPTS,
                    "test_result_digest": evidence.test_result_digest,
                },
            )
            return

        source_task_id = incoming.task_id
        retry_input = {
            "issue_id": issue_id,
            "tier": tier.value,
            "issue": issue.model_dump(mode="json"),
            "located_context": located.model_dump(mode="json"),
            "previous_patch": previous_patch.model_dump(mode="json"),
            "test_failure_evidence": evidence.model_dump(mode="json"),
            "retry_attempt": next_attempt,
            "model_call_attempt": next_model_call_attempt,
        }
        retry_envelope = HandoffEnvelope.create(
            run_id=incoming.run_id,
            issue_id=issue_id,
            task_id=(
                f"{issue_id}-{next_model_call_attempt}-coderagent-retry-"
                f"{evidence.test_result_digest[:12]}"
            ),
            producer=self.name,
            consumer="CoderAgent",
            skill="patch-generator",
            artifact_type="SkillInvocation",
            status=HandoffStatus.RETRY,
            payload={
                "tier": tier.value,
                "input": retry_input,
                "depends_on": [source_task_id],
                "retry": {
                    "attempt": next_attempt,
                    "max_attempts": _MAX_CODER_GENERATION_ATTEMPTS,
                    "reason": "test_failed",
                    "test_result_digest": evidence.test_result_digest,
                },
                "generation_budget": {
                    "schema_version": "devflow.generation-budget/v1",
                    "model_call_attempt": next_model_call_attempt,
                    "max_model_calls": _MAX_CODER_GENERATION_ATTEMPTS,
                },
            },
        )
        self._remember_execution_route(retry_envelope)
        context["semantic_test_failure"] = {
            "test_result_digest": evidence.test_result_digest,
            "candidate_digest": evidence.candidate_digest,
        }
        context["pending_test_retry"] = {
            "test_result_digest": evidence.test_result_digest,
            "envelope": retry_envelope.model_dump(mode="json"),
        }
        self._set_lifecycle(issue_id, IssueLifecycle.CODING)
        await self._emit_event(
            "task.route.coderagent",
            retry_envelope.model_dump(mode="json"),
        )

    async def _on_approval_required(self, payload: dict[str, Any]) -> None:
        payload = self._handoff_payload(payload)
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

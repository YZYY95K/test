"""Boundary-safe routing for the in-process Agent runtime.

The production deployment uses AgentTeams as its scheduler and transport.  A
local run still needs an explicit scheduler: publishing ``task.route.*`` is
not, by itself, execution.  :class:`LocalAgentTaskRouter` is the deliberately
small participant that closes that gap without making Workers subscribe to
one another's traffic.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from devflow.event_bus import publish, subscribe, unsubscribe
from devflow.skills.contracts import HandoffEnvelope, HandoffStatus

RouteHandler = Callable[[dict[str, Any]], Awaitable[None]]


class LocalRouteAuthority(Protocol):
    """Minimum authority surface the router accepts from TeamLeader."""

    @property
    def name(self) -> str:
        """Return the issuer's exact Agent name."""
        ...

    def is_authorized_execution_route(self, envelope: HandoffEnvelope) -> bool:
        """Return whether ``envelope`` is an immutable route issued here."""
        ...

    def claim_execution_route(self, envelope: HandoffEnvelope) -> bool:
        """Claim one authorized route for exactly one scheduler dispatch."""
        ...

    def finish_execution_route(
        self,
        envelope: HandoffEnvelope,
        *,
        succeeded: bool,
    ) -> bool:
        """Seal the scheduler claim after an explicit Worker outcome."""
        ...


class LocalRoutedWorker(Protocol):
    """Minimum Worker surface used by the local scheduler."""

    @property
    def name(self) -> str:
        """Return the Worker's exact Agent name."""
        ...

    @property
    def skills(self) -> list[str]:
        """Return the Skills this Worker may execute."""
        ...

    async def execute(self, input_data: Any) -> Any:
        """Execute one validated hand-off through the Agent boundary."""
        ...


@dataclass(frozen=True)
class _RouteBinding:
    worker: LocalRoutedWorker
    event_type: str
    skills: frozenset[str]


class LocalAgentTaskRouter:
    """Dispatch exact TeamLeader routes to exactly one matching Worker.

    The router subscribes once per configured Worker to that Worker's exact
    ``task.route.<agent>`` address.  It never subscribes Workers themselves,
    never listens to wildcard routes, and never stores or republishes Worker
    return values. TeamLeader owns the scheduler dispatch claim so replacing a
    Worker cannot replay an old route; ``BaseAgent.execute`` remains a second
    validation and direct-delivery idempotency boundary.

    Worker bindings are dynamic, so a focused Coder/Tester loop and the fixed
    five-Worker/six-role team use the same implementation.
    """

    def __init__(
        self,
        authority: LocalRouteAuthority,
        *workers: LocalRoutedWorker,
    ) -> None:
        if authority.name != "TeamLeader":
            raise ValueError("local route authority must be TeamLeader")
        if not workers:
            raise ValueError("local task router requires at least one Worker")

        bindings: dict[str, _RouteBinding] = {}
        worker_names: set[str] = set()
        for worker in workers:
            name = worker.name
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", name) is None:
                raise ValueError("local Worker name is not route-safe")
            folded_name = name.casefold()
            if folded_name == authority.name.casefold():
                raise ValueError("TeamLeader cannot be registered as a routed Worker")
            if folded_name in worker_names:
                raise ValueError("local task router contains a duplicate Worker name")
            worker_names.add(folded_name)

            skills = frozenset(worker.skills)
            if not skills or any(
                re.fullmatch(r"[a-z0-9-]+", skill) is None for skill in skills
            ):
                raise ValueError("local Worker must declare route-safe Skills")
            event_type = f"task.route.{name.lower()}"
            bindings[event_type] = _RouteBinding(
                worker=worker,
                event_type=event_type,
                skills=skills,
            )

        self._authority = authority
        self._bindings = bindings
        self._handlers: dict[str, RouteHandler] = {}

    @property
    def route_events(self) -> tuple[str, ...]:
        """Return the exact, non-wildcard addresses owned by this router."""

        return tuple(self._bindings)

    def subscribe_events(self) -> None:
        """Attach one stable handler for each configured Worker address."""

        for event_type, binding in self._bindings.items():
            handler = self._handlers.get(event_type)
            if handler is None:
                handler = self._make_handler(binding)
                self._handlers[event_type] = handler
            subscribe(event_type, handler)

    def unsubscribe_events(self) -> None:
        """Detach only the exact handlers owned by this router."""

        for event_type, handler in self._handlers.items():
            unsubscribe(event_type, handler)

    def _make_handler(self, binding: _RouteBinding) -> RouteHandler:
        async def _handler(payload: dict[str, Any]) -> None:
            envelope, rejection = self._validate_route(binding, payload)
            if envelope is None:
                await self._audit_rejection(binding.event_type, payload, rejection)
                return
            if not self._authority.claim_execution_route(envelope):
                await self._audit_duplicate(binding.event_type, envelope)
                return
            # Deliberately discard the return value. Agent outputs cross only
            # through their typed, redacted events; they never become router
            # state or a second unbounded collaboration channel.
            try:
                await binding.worker.execute(envelope)
            except Exception:
                self._authority.finish_execution_route(
                    envelope,
                    succeeded=False,
                )
                raise
            else:
                self._authority.finish_execution_route(
                    envelope,
                    succeeded=True,
                )

        return _handler

    def _validate_route(
        self,
        binding: _RouteBinding,
        payload: dict[str, Any],
    ) -> tuple[HandoffEnvelope | None, str]:
        try:
            envelope = HandoffEnvelope.model_validate(payload)
        except (TypeError, ValueError):
            return None, "invalid_envelope"
        if envelope.producer != self._authority.name:
            return None, "issuer_mismatch"
        if envelope.consumer != binding.worker.name:
            return None, "consumer_mismatch"
        if envelope.skill not in binding.skills:
            return None, "skill_mismatch"
        if envelope.status not in {HandoffStatus.READY, HandoffStatus.RETRY}:
            return None, "non_executable_status"
        if envelope.artifact.inline is None or not envelope.artifact.verify_integrity():
            return None, "artifact_integrity_failed"
        if (
            envelope.trace_id != f"{envelope.run_id}:{envelope.task_id}"
            or envelope.idempotency_key
            != (
                f"{envelope.run_id}:{envelope.task_id}:"
                f"{envelope.consumer}:{envelope.skill}"
            )
        ):
            return None, "correlation_mismatch"
        if not self._authority.is_authorized_execution_route(envelope):
            return None, "route_not_issued"
        return envelope, ""

    @staticmethod
    async def _audit_duplicate(
        event_type: str,
        envelope: HandoffEnvelope,
    ) -> None:
        """Record duplicate scheduler delivery without invoking any Worker."""

        await publish(
            "local.route.duplicate",
            {
                "schema_version": "devflow.local-route-duplicate/v1",
                "route_event": event_type,
                "issue_id": envelope.issue_id,
                "task_id_sha256": hashlib.sha256(
                    envelope.task_id.encode("utf-8")
                ).hexdigest(),
                "artifact_sha256": envelope.artifact.sha256,
            },
        )

    @staticmethod
    async def _audit_rejection(
        event_type: str,
        payload: dict[str, Any],
        reason: str,
    ) -> None:
        """Publish a payload-free rejection receipt for local audit."""

        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                default=lambda _value: "<non-json>",
            ).encode("utf-8")
        except (TypeError, ValueError):
            encoded = b"invalid-local-route"
        await publish(
            "local.route.rejected",
            {
                "schema_version": "devflow.local-route-rejection/v1",
                "route_event": event_type,
                "reason": reason,
                "payload_sha256": hashlib.sha256(encoded).hexdigest(),
            },
        )


__all__ = [
    "LocalAgentTaskRouter",
    "LocalRouteAuthority",
    "LocalRoutedWorker",
]

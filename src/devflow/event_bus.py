"""Small asynchronous event bus used by the local runtime and tests.

The production AgentTeams deployment transports collaboration through Matrix.
This in-process bus mirrors the same typed-event contract for local execution,
making the domain pipeline runnable without external infrastructure.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import math
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

EventHandler = Callable[[dict[str, Any]], Awaitable[None] | None]

_MAX_EVENT_PAYLOAD_DEPTH = 64
_MAX_EVENT_PAYLOAD_BYTES = 1_048_576
_DEFAULT_HISTORY_LIMIT = 10_000


class EventPayloadError(ValueError):
    """Raised when an event payload cannot cross the JSON-safe bus boundary."""


class EventSubscriber(Protocol):
    """Participant managed by the explicit local event-runtime boundary."""

    def subscribe_events(self) -> None:
        """Attach the participant's stable handlers to the process bus."""
        ...

    def unsubscribe_events(self) -> None:
        """Detach every handler previously attached by the participant."""
        ...


@dataclass(frozen=True)
class EventRecord:
    """Auditable record of a published event."""

    event_type: str
    payload: dict[str, Any]
    timestamp: datetime


class EventBus:
    """Concurrency-safe, fail-isolated asynchronous publish/subscribe bus."""

    def __init__(self, *, history_limit: int = _DEFAULT_HISTORY_LIMIT) -> None:
        if history_limit < 1 or history_limit > 1_000_000:
            raise ValueError("event history_limit must be between 1 and 1000000")
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: deque[EventRecord] = deque(maxlen=history_limit)
        self._history_dropped = 0
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        if handler not in self._handlers[event_type]:
            self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        encoded_payload = _encode_payload(payload)
        record = EventRecord(
            event_type=event_type,
            payload=_decode_payload(encoded_payload),
            timestamp=datetime.now(timezone.utc),
        )
        async with self._lock:
            if len(self._history) == self._history.maxlen:
                self._history_dropped += 1
            self._history.append(record)
            handlers = tuple(self._handlers.get(event_type, ()))
        if not handlers:
            return
        results: list[tuple[EventHandler, Awaitable[None]]] = []
        for handler in handlers:
            try:
                value = handler(_decode_payload(encoded_payload))
            except Exception as exc:  # noqa: BLE001 - isolate subscribers
                await self._record_delivery_failure(
                    event_type=event_type,
                    encoded_payload=encoded_payload,
                    handler=handler,
                    error=exc,
                )
                continue
            if inspect.isawaitable(value):
                results.append((handler, value))
        if results:
            outcomes = await asyncio.gather(
                *(value for _handler, value in results),
                return_exceptions=True,
            )
            for (handler, _value), outcome in zip(results, outcomes, strict=True):
                if isinstance(outcome, BaseException):
                    await self._record_delivery_failure(
                        event_type=event_type,
                        encoded_payload=encoded_payload,
                        handler=handler,
                        error=outcome,
                    )

    async def _record_delivery_failure(
        self,
        *,
        event_type: str,
        encoded_payload: str,
        handler: EventHandler,
        error: BaseException,
    ) -> None:
        """Append and fan out a bounded, payload-free dead-letter receipt."""

        error_type = type(error).__name__
        if not error_type.isascii() or not error_type.isidentifier():
            error_type = "Exception"
        try:
            error_text = str(error)
        except Exception:  # noqa: BLE001 - hostile formatter
            error_text = "<unprintable>"
        handler_name = getattr(handler, "__qualname__", type(handler).__name__)
        failure_payload = {
            "schema_version": "devflow.event-delivery-failure/v1",
            "source_event_type": event_type,
            "payload_sha256": hashlib.sha256(
                encoded_payload.encode("utf-8")
            ).hexdigest(),
            "handler_sha256": hashlib.sha256(
                handler_name.encode("utf-8", errors="replace")
            ).hexdigest(),
            "error_type": error_type,
            "error_digest": hashlib.sha256(
                f"{error_type}\0{error_text}".encode("utf-8", errors="replace")
            ).hexdigest(),
        }
        encoded_failure = _encode_payload(failure_payload)
        record = EventRecord(
            event_type="event.delivery_failed",
            payload=_decode_payload(encoded_failure),
            timestamp=datetime.now(timezone.utc),
        )
        async with self._lock:
            if len(self._history) == self._history.maxlen:
                self._history_dropped += 1
            self._history.append(record)
            failure_handlers = tuple(
                self._handlers.get("event.delivery_failed", ())
            )
        if event_type == "event.delivery_failed":
            return
        for failure_handler in failure_handlers:
            try:
                value = failure_handler(_decode_payload(encoded_failure))
                if inspect.isawaitable(value):
                    await value
            except Exception:  # noqa: BLE001 - dead-letter delivery is terminal
                continue

    def history(self) -> list[EventRecord]:
        return [
            EventRecord(
                event_type=record.event_type,
                payload=_clone_payload(record.payload),
                timestamp=record.timestamp,
            )
            for record in self._history
        ]

    def subscriber_count(self, event_type: str) -> int:
        """Return the current subscriber count for startup health checks."""

        return len(self._handlers.get(event_type, ()))

    @property
    def history_dropped(self) -> int:
        """Number of old audit records evicted by bounded retention."""

        return self._history_dropped

    def clear(self) -> None:
        self._handlers.clear()
        self._history.clear()
        self._history_dropped = 0


def _encode_payload(payload: dict[str, Any]) -> str:
    """Validate and serialize one event payload without invoking user hooks.

    Only exact built-in JSON container and scalar types are accepted.  This
    deliberately rejects objects with custom ``__deepcopy__``/serialization
    behavior and ensures the encoded form can be decoded into an independent
    object for history and every subscriber.
    """

    _validate_json_value(payload, path="payload", depth=0, active=set())
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise EventPayloadError("event payload is not finite JSON data") from exc
    if len(encoded.encode("utf-8")) > _MAX_EVENT_PAYLOAD_BYTES:
        raise EventPayloadError("event payload exceeds the byte limit")
    return encoded


def _validate_json_value(
    value: Any,
    *,
    path: str,
    depth: int,
    active: set[int],
) -> None:
    if depth > _MAX_EVENT_PAYLOAD_DEPTH:
        raise EventPayloadError("event payload exceeds the nesting limit")

    value_type = type(value)
    if value is None or value_type in {str, bool, int}:
        return
    if value_type is float:
        if not math.isfinite(value):
            raise EventPayloadError("event payload contains a non-finite number")
        return
    if value_type not in {dict, list}:
        raise EventPayloadError(
            f"event payload contains unsupported type at {path}"
        )

    identity = id(value)
    if identity in active:
        raise EventPayloadError("event payload contains a cyclic container")
    active.add(identity)
    try:
        if value_type is dict:
            for key, nested in value.items():
                if type(key) is not str:
                    raise EventPayloadError(
                        f"event payload contains a non-string key at {path}"
                    )
                _validate_json_value(
                    nested,
                    path=f"{path}.{key}",
                    depth=depth + 1,
                    active=active,
                )
        else:
            for index, nested in enumerate(value):
                _validate_json_value(
                    nested,
                    path=f"{path}[{index}]",
                    depth=depth + 1,
                    active=active,
                )
    finally:
        active.remove(identity)


def _decode_payload(encoded_payload: str) -> dict[str, Any]:
    decoded = json.loads(encoded_payload)
    if type(decoded) is not dict:  # pragma: no cover - guarded by validation
        raise EventPayloadError("event payload must be a JSON object")
    return decoded


def _clone_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return _decode_payload(
        json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
    )


event_bus = EventBus()


class LocalAgentEventRuntime:
    """Explicit, reversible composition root for the in-process Agent bus.

    Constructing an Agent never mutates global subscriptions. The application
    must start this object after all participants have been assembled and stop
    it during shutdown. Repeated ``start``/``stop`` calls are idempotent.
    """

    def __init__(self, *participants: EventSubscriber) -> None:
        if not participants:
            raise ValueError("local Agent event runtime requires a participant")
        identities = [id(participant) for participant in participants]
        if len(identities) != len(set(identities)):
            raise ValueError("local Agent event runtime contains a duplicate participant")
        self._participants = tuple(participants)
        self._started = False

    @property
    def started(self) -> bool:
        """Whether this composition root currently owns active subscriptions."""

        return self._started

    def start(self) -> LocalAgentEventRuntime:
        """Subscribe each participant exactly once, rolling back on failure."""

        if self._started:
            return self
        attached: list[EventSubscriber] = []
        try:
            for participant in self._participants:
                participant.subscribe_events()
                attached.append(participant)
        except Exception:
            for participant in reversed(attached):
                participant.unsubscribe_events()
            raise
        self._started = True
        return self

    def stop(self) -> None:
        """Remove every subscription owned by this composition root."""

        if not self._started:
            return
        for participant in reversed(self._participants):
            participant.unsubscribe_events()
        self._started = False

    def __enter__(self) -> LocalAgentEventRuntime:
        return self.start()

    def __exit__(self, *_exc: object) -> None:
        self.stop()


def subscribe(event_type: str, handler: EventHandler) -> None:
    """Subscribe a handler to the process-wide bus."""

    event_bus.subscribe(event_type, handler)


def unsubscribe(event_type: str, handler: EventHandler) -> None:
    """Unsubscribe a handler from the process-wide bus."""

    event_bus.unsubscribe(event_type, handler)


async def publish(event_type: str, payload: dict[str, Any]) -> None:
    """Publish an event on the process-wide bus."""

    await event_bus.publish(event_type, payload)


def clear() -> None:
    """Reset subscribers and event history (primarily for tests)."""

    event_bus.clear()

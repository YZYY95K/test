"""Small asynchronous event bus used by the local runtime and tests.

The production AgentTeams deployment transports collaboration through Matrix.
This in-process bus mirrors the same typed-event contract for local execution,
making the domain pipeline runnable without external infrastructure.
"""

from __future__ import annotations

import asyncio
import inspect
from collections import defaultdict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

EventHandler = Callable[[dict[str, Any]], Awaitable[None] | None]


@dataclass(frozen=True)
class EventRecord:
    """Auditable record of a published event."""

    event_type: str
    payload: dict[str, Any]
    timestamp: datetime


class EventBus:
    """Concurrency-safe, fail-isolated asynchronous publish/subscribe bus."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: list[EventRecord] = []
        self._lock = asyncio.Lock()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        if handler not in self._handlers[event_type]:
            self._handlers[event_type].append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)

    async def publish(self, event_type: str, payload: dict[str, Any]) -> None:
        record = EventRecord(
            event_type=event_type,
            payload=dict(payload),
            timestamp=datetime.now(timezone.utc),
        )
        async with self._lock:
            self._history.append(record)
            handlers = tuple(self._handlers.get(event_type, ()))
        if not handlers:
            return
        results = []
        for handler in handlers:
            value = handler(dict(payload))
            if inspect.isawaitable(value):
                results.append(value)
        if results:
            await asyncio.gather(*results, return_exceptions=True)

    def history(self) -> list[EventRecord]:
        return list(self._history)

    def clear(self) -> None:
        self._handlers.clear()
        self._history.clear()


event_bus = EventBus()


def subscribe(event_type: str, handler: EventHandler) -> None:
    """Subscribe a handler to the process-wide bus."""

    event_bus.subscribe(event_type, handler)


async def publish(event_type: str, payload: dict[str, Any]) -> None:
    """Publish an event on the process-wide bus."""

    await event_bus.publish(event_type, payload)


def clear() -> None:
    """Reset subscribers and event history (primarily for tests)."""

    event_bus.clear()


"""Event-bus behavior tests."""

from __future__ import annotations

import pytest

from devflow.event_bus import EventBus


@pytest.mark.asyncio
async def test_event_bus_isolates_handler_failure_and_keeps_history() -> None:
    bus = EventBus()
    received: list[int] = []

    async def broken(_: dict[str, int]) -> None:
        raise RuntimeError("expected test failure")

    async def working(payload: dict[str, int]) -> None:
        received.append(payload["value"])

    bus.subscribe("sample", broken)
    bus.subscribe("sample", working)
    await bus.publish("sample", {"value": 7})

    assert received == [7]
    assert bus.history()[0].event_type == "sample"
    assert bus.history()[0].payload == {"value": 7}


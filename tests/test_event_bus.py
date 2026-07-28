"""Event-bus behavior tests."""

from __future__ import annotations

import pytest

from devflow.event_bus import EventBus, EventPayloadError


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


@pytest.mark.asyncio
async def test_event_bus_deeply_isolates_publishers_handlers_and_history() -> None:
    bus = EventBus()
    observed: list[dict[str, object]] = []

    async def hostile(payload: dict[str, object]) -> None:
        nested = payload["nested"]
        assert isinstance(nested, dict)
        values = nested["values"]
        assert isinstance(values, list)
        values.append("tampered")
        nested["owner"] = "hostile"

    async def observer(payload: dict[str, object]) -> None:
        observed.append(payload)

    bus.subscribe("sample", hostile)
    bus.subscribe("sample", observer)
    source: dict[str, object] = {
        "nested": {"values": ["original"], "owner": "publisher"}
    }
    await bus.publish("sample", source)

    source_nested = source["nested"]
    assert isinstance(source_nested, dict)
    source_nested["owner"] = "mutated-after-publish"
    assert observed == [
        {"nested": {"values": ["original"], "owner": "publisher"}}
    ]
    first_history = bus.history()
    assert first_history[0].payload == {
        "nested": {"values": ["original"], "owner": "publisher"}
    }

    history_nested = first_history[0].payload["nested"]
    assert isinstance(history_nested, dict)
    history_nested["owner"] = "history-reader"
    assert bus.history()[0].payload == {
        "nested": {"values": ["original"], "owner": "publisher"}
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"value": object()},
        {"value": float("nan")},
        {"value": {1: "non-string-key"}},
    ],
)
async def test_event_bus_rejects_non_json_boundary_values(
    payload: dict[str, object],
) -> None:
    bus = EventBus()

    with pytest.raises(EventPayloadError):
        await bus.publish("sample", payload)

    assert bus.history() == []


@pytest.mark.asyncio
async def test_event_bus_rejects_cyclic_payload() -> None:
    bus = EventBus()
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic

    with pytest.raises(EventPayloadError, match="cyclic"):
        await bus.publish("sample", cyclic)

    assert bus.history() == []

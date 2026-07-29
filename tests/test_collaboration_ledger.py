"""Restart, concurrency, and tamper tests for the durable route authority."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from devflow.agents.base import AgentConfig, AgentIdentity, BaseAgent
from devflow.agents.team_leader import Task, TeamLeader
from devflow.collaboration.ledger import DurableRouteLedger, LedgerConflictError
from devflow.event_bus import LocalAgentEventRuntime, event_bus, publish
from devflow.local_runtime import LocalAgentTaskRouter
from devflow.models.issue import ComplexityLevel
from devflow.skills.contracts import HandoffEnvelope


def _route(*, task_id: str = "17-1-locatoragent") -> HandoffEnvelope:
    return HandoffEnvelope.create(
        run_id="issue-17",
        issue_id=17,
        task_id=task_id,
        producer="TeamLeader",
        consumer="LocatorAgent",
        skill="code-root-cause",
        artifact_type="SkillInvocation",
        payload={
            "tier": "T2",
            "input": {"issue_id": 17, "scope": "src"},
            "depends_on": [],
        },
    )


class _Worker(BaseAgent):
    def __init__(self) -> None:
        super().__init__(
            config=AgentConfig(
                name="LocatorAgent",
                identity=AgentIdentity(
                    role="Ledger test Worker",
                    description="Execute a route once.",
                    model="test",
                ),
                skills=["code-root-cause"],
            )
        )
        self.calls = 0

    async def run(self, input_data: Any) -> dict[str, bool]:
        del input_data
        self.calls += 1
        return {"ok": True}


@pytest.fixture(autouse=True)
def _clear_bus() -> Any:
    event_bus.clear()
    yield
    event_bus.clear()


def test_route_registration_is_immutable_and_idempotent(tmp_path: Path) -> None:
    ledger = DurableRouteLedger(tmp_path / "routes.sqlite3", owner_id="router-a")
    route = _route()

    assert ledger.register_route(route) is True
    assert ledger.register_route(route) is False
    assert ledger.authorized_route(route) is True

    conflicting = HandoffEnvelope.create(
        run_id=route.run_id,
        issue_id=route.issue_id,
        task_id=route.task_id,
        producer="TeamLeader",
        consumer="LocatorAgent",
        skill="code-root-cause",
        artifact_type="SkillInvocation",
        payload={"tier": "T2", "input": {"issue_id": 17, "scope": "tests"}},
    )
    with pytest.raises(LedgerConflictError, match="task_id conflicts"):
        ledger.register_route(conflicting)


def test_competing_schedulers_get_one_lease_and_terminal_route(tmp_path: Path) -> None:
    path = tmp_path / "routes.sqlite3"
    first = DurableRouteLedger(path, owner_id="router-a")
    second = DurableRouteLedger(path, owner_id="router-b")
    route = _route()
    first.register_route(route)

    assert first.claim_route(route) is True
    assert second.claim_route(route) is False
    assert first.finish_route(route, status="succeeded") is True
    assert second.claim_route(route) is False

    snapshot = second.snapshot()
    assert snapshot.succeeded == 1
    assert snapshot.pending == snapshot.leased == snapshot.failed == 0
    verification = second.verify_audit_chain()
    assert verification.valid is True
    assert verification.entries == 3
    assert verification.head_sha256 is not None


def test_expired_lease_is_recovered_by_new_scheduler(tmp_path: Path) -> None:
    path = tmp_path / "routes.sqlite3"
    first = DurableRouteLedger(
        path,
        owner_id="router-a",
        lease_seconds=5,
    )
    second = DurableRouteLedger(
        path,
        owner_id="router-b",
        lease_seconds=5,
    )
    route = _route()
    started = datetime(2026, 7, 28, 1, 0, tzinfo=timezone.utc)
    first.register_route(route)
    assert first.claim_route(route, now=started) is True

    before_expiry = started + timedelta(seconds=4)
    assert second.claim_route(route, now=before_expiry) is False
    assert second.recoverable_routes(now=before_expiry) == ()

    after_expiry = started + timedelta(seconds=6)
    recoverable = second.recoverable_routes(now=after_expiry)
    assert len(recoverable) == 1
    assert recoverable[0].lease_expired is True
    assert second.claim_route(route, now=after_expiry) is True
    assert first.finish_route(route, status="succeeded", now=after_expiry) is False
    assert second.finish_route(route, status="succeeded", now=after_expiry) is True


@pytest.mark.asyncio
async def test_teamleader_recovers_pending_route_after_process_replacement(
    tmp_path: Path,
) -> None:
    path = tmp_path / "routes.sqlite3"
    first_ledger = DurableRouteLedger(path, owner_id="first-process")
    first_leader = TeamLeader(execution_ledger=first_ledger)
    await first_leader.route_task(
        Task(
            task_id="17-1-locatoragent",
            agent="LocatorAgent",
            skill="code-root-cause",
            input_data={"issue_id": 17, "scope": "src"},
            tier=ComplexityLevel.T2,
        )
    )
    emitted = next(
        record
        for record in event_bus.history()
        if record.event_type == "task.route.locatoragent"
    )

    # A new TeamLeader process reconstructs route authority from SQLite and
    # explicitly republishes the pending route; no private process memory is
    # required for validation or the scheduler claim.
    event_bus.clear()
    replacement_ledger = DurableRouteLedger(path, owner_id="replacement-process")
    replacement = TeamLeader(execution_ledger=replacement_ledger)
    worker = _Worker()
    router = LocalAgentTaskRouter(replacement, worker)
    runtime = LocalAgentEventRuntime(router).start()
    try:
        assert replacement.recoverable_execution_routes() == (
            HandoffEnvelope.model_validate(emitted.payload),
        )
        await publish(emitted.event_type, emitted.payload)
        assert worker.calls == 1
        assert replacement_ledger.snapshot().succeeded == 1

        await publish(emitted.event_type, emitted.payload)
        assert worker.calls == 1
        assert event_bus.history()[-1].event_type == "local.route.duplicate"
    finally:
        runtime.stop()


def test_audit_chain_detects_database_tampering(tmp_path: Path) -> None:
    path = tmp_path / "routes.sqlite3"
    ledger = DurableRouteLedger(path, owner_id="router-a")
    route = _route()
    ledger.register_route(route)
    ledger.claim_route(route)
    assert ledger.verify_audit_chain().valid is True

    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE collaboration_audit SET event_type = 'route.forged' "
            "WHERE sequence = 1"
        )

    verification = ledger.verify_audit_chain()
    assert verification.valid is False
    assert verification.first_invalid_sequence == 1


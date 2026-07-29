"""Transactional route leases and tamper-evident collaboration audit records.

The AgentTeams deployment may deliver the same Matrix event more than once and
the local process may restart while a Worker owns a task.  This module keeps
the TeamLeader's authority decision outside any Worker process.  A route is
registered once, claimed under a bounded lease, and sealed as succeeded or
failed only by the current lease owner.

Audit rows deliberately contain digests and routing metadata, not source code,
issue bodies, model prompts, credentials, or tool responses.  Every row chains
to the preceding row so an exported evidence bundle can be verified offline.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from devflow.skills.contracts import HandoffEnvelope, HandoffStatus

RouteTerminalStatus = Literal["succeeded", "failed"]


class LedgerConflictError(ValueError):
    """Raised when immutable collaboration state conflicts with the ledger."""


@dataclass(frozen=True)
class RecoverableRoute:
    """One pending or expired route that a scheduler may safely redeliver."""

    envelope: HandoffEnvelope
    status: str
    delivery_count: int
    lease_expired: bool


@dataclass(frozen=True)
class RouteLedgerSnapshot:
    """Aggregate state suitable for health checks and Prometheus metrics."""

    pending: int
    leased: int
    succeeded: int
    failed: int
    expired_leases: int
    audit_entries: int


@dataclass(frozen=True)
class AuditChainVerification:
    """Result of recomputing the append-only collaboration audit chain."""

    valid: bool
    entries: int
    head_sha256: str | None
    first_invalid_sequence: int | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    normalized = value.astimezone(timezone.utc)
    return normalized.isoformat(timespec="microseconds")


def _parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise LedgerConflictError("ledger timestamp is not timezone-aware")
    return parsed.astimezone(timezone.utc)


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _envelope_json(envelope: HandoffEnvelope) -> str:
    return _canonical_json(envelope.model_dump(mode="json"))


def _entry_hash(
    *,
    timestamp: str,
    event_type: str,
    subject_sha256: str,
    payload_sha256: str,
    previous_sha256: str | None,
) -> str:
    return _sha256_text(
        _canonical_json(
            {
                "timestamp": timestamp,
                "event_type": event_type,
                "subject_sha256": subject_sha256,
                "payload_sha256": payload_sha256,
                "previous_sha256": previous_sha256,
            }
        )
    )


class DurableRouteLedger:
    """SQLite-backed TeamLeader authority with atomic, expiring route leases.

    The class opens a short-lived connection for each operation.  SQLite's
    ``BEGIN IMMEDIATE`` then serializes competing scheduler processes without
    requiring a process-local lock for correctness; the lock only avoids noisy
    same-process contention.  WAL mode keeps evidence readers independent from
    a scheduler writer.
    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        path: str | Path,
        *,
        lease_seconds: int = 120,
        owner_id: str | None = None,
    ) -> None:
        if lease_seconds < 1 or lease_seconds > 3600:
            raise ValueError("route lease_seconds must be between 1 and 3600")
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lease_seconds = lease_seconds
        self.owner_id = owner_id or f"router-{uuid.uuid4().hex}"
        if not self.owner_id or len(self.owner_id) > 200:
            raise ValueError("route ledger owner_id is invalid")
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=10,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        return connection

    def _initialize(self) -> None:
        with self._lock, self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ledger_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS execution_routes (
                    task_id TEXT PRIMARY KEY,
                    route_sha256 TEXT NOT NULL UNIQUE,
                    envelope_json TEXT NOT NULL,
                    issue_id INTEGER NOT NULL CHECK (issue_id >= 1),
                    consumer TEXT NOT NULL,
                    skill TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('pending','leased','succeeded','failed')),
                    lease_owner TEXT,
                    lease_expires_at TEXT,
                    delivery_count INTEGER NOT NULL DEFAULT 0
                        CHECK (delivery_count >= 0),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    CHECK (
                        (status = 'leased' AND lease_owner IS NOT NULL
                            AND lease_expires_at IS NOT NULL)
                        OR status != 'leased'
                    )
                );
                CREATE INDEX IF NOT EXISTS idx_execution_routes_recovery
                    ON execution_routes(status, lease_expires_at, issue_id);
                CREATE TABLE IF NOT EXISTS human_approval_consumptions (
                    approval_id TEXT PRIMARY KEY,
                    issue_id INTEGER NOT NULL CHECK (issue_id >= 1),
                    target_sha256 TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL UNIQUE,
                    consumed_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS collaboration_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    subject_sha256 TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_sha256 TEXT,
                    entry_sha256 TEXT NOT NULL UNIQUE
                );
                """
            )
            existing = connection.execute(
                "SELECT value FROM ledger_metadata WHERE key = 'schema_version'"
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO ledger_metadata(key, value) VALUES(?, ?)",
                    ("schema_version", str(self.SCHEMA_VERSION)),
                )
            elif int(existing["value"]) != self.SCHEMA_VERSION:
                raise LedgerConflictError("route ledger schema version is unsupported")

    @staticmethod
    def route_sha256(envelope: HandoffEnvelope) -> str:
        """Return the canonical digest used as the immutable route identity."""

        return _sha256_text(_envelope_json(envelope))

    @staticmethod
    def _validate_route(envelope: HandoffEnvelope) -> None:
        if (
            envelope.producer != "TeamLeader"
            or envelope.status not in {HandoffStatus.READY, HandoffStatus.RETRY}
            or envelope.artifact.inline is None
            or not envelope.artifact.verify_integrity()
        ):
            raise LedgerConflictError("only canonical TeamLeader routes may enter the ledger")

    def register_route(self, envelope: HandoffEnvelope) -> bool:
        """Register an immutable route; return ``False`` for an exact replay."""

        self._validate_route(envelope)
        encoded = _envelope_json(envelope)
        digest = _sha256_text(encoded)
        now = _iso(_utcnow())
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT route_sha256, envelope_json FROM execution_routes WHERE task_id = ?",
                    (envelope.task_id,),
                ).fetchone()
                if row is not None:
                    if row["route_sha256"] != digest or row["envelope_json"] != encoded:
                        raise LedgerConflictError(
                            "route task_id conflicts with immutable ledger state"
                        )
                    connection.commit()
                    return False
                connection.execute(
                    """
                    INSERT INTO execution_routes(
                        task_id, route_sha256, envelope_json, issue_id,
                        consumer, skill, status, created_at, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        envelope.task_id,
                        digest,
                        encoded,
                        envelope.issue_id,
                        envelope.consumer,
                        envelope.skill,
                        now,
                        now,
                    ),
                )
                self._append_audit(
                    connection,
                    timestamp=now,
                    event_type="route.registered",
                    subject_sha256=digest,
                    payload={
                        "issue_id": envelope.issue_id,
                        "consumer": envelope.consumer,
                        "skill": envelope.skill,
                        "status": "pending",
                    },
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def consume_approval(
        self,
        *,
        approval_id: str,
        issue_id: int,
        target_sha256: str,
        evidence_sha256: str,
        now: datetime | None = None,
    ) -> bool:
        """Atomically consume one verified human approval exactly once."""

        if (
            len(approval_id) != 32
            or any(character not in "0123456789abcdef" for character in approval_id)
            or issue_id < 1
            or len(target_sha256) != 64
            or len(evidence_sha256) != 64
        ):
            raise ValueError("approval consumption identity is invalid")
        consumed_at = _iso((now or _utcnow()).astimezone(timezone.utc))
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT 1 FROM human_approval_consumptions "
                    "WHERE approval_id = ? OR evidence_sha256 = ?",
                    (approval_id, evidence_sha256),
                ).fetchone()
                if existing is not None:
                    connection.commit()
                    return False
                connection.execute(
                    """
                    INSERT INTO human_approval_consumptions(
                        approval_id, issue_id, target_sha256,
                        evidence_sha256, consumed_at
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        approval_id,
                        issue_id,
                        target_sha256,
                        evidence_sha256,
                        consumed_at,
                    ),
                )
                self._append_audit(
                    connection,
                    timestamp=consumed_at,
                    event_type="approval.consumed",
                    subject_sha256=evidence_sha256,
                    payload={
                        "issue_id": issue_id,
                        "target_sha256": target_sha256,
                        "approval_id_sha256": _sha256_text(approval_id),
                    },
                )
                connection.commit()
                return True
            except sqlite3.IntegrityError:
                connection.rollback()
                return False
            except Exception:
                connection.rollback()
                raise

    def approval_consumed(self, approval_id: str) -> bool:
        """Return whether a human approval id has already been consumed."""

        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM human_approval_consumptions WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        return row is not None

    def authorized_route(self, envelope: HandoffEnvelope) -> bool:
        """Return whether the ledger contains this exact immutable route."""

        try:
            self._validate_route(envelope)
        except LedgerConflictError:
            return False
        encoded = _envelope_json(envelope)
        digest = _sha256_text(encoded)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT route_sha256, envelope_json FROM execution_routes WHERE task_id = ?",
                (envelope.task_id,),
            ).fetchone()
        return bool(
            row is not None and row["route_sha256"] == digest and row["envelope_json"] == encoded
        )

    def route_was_dispatched(self, envelope: HandoffEnvelope) -> bool:
        """Return whether the exact route has ever acquired a scheduler lease."""

        try:
            self._validate_route(envelope)
        except LedgerConflictError:
            return False
        encoded = _envelope_json(envelope)
        digest = _sha256_text(encoded)
        with self._lock, self._connect() as connection:
            row = connection.execute(
                "SELECT route_sha256, envelope_json, delivery_count "
                "FROM execution_routes WHERE task_id = ?",
                (envelope.task_id,),
            ).fetchone()
        return bool(
            row is not None
            and row["route_sha256"] == digest
            and row["envelope_json"] == encoded
            and int(row["delivery_count"]) > 0
        )

    def claim_route(
        self,
        envelope: HandoffEnvelope,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Atomically lease one route to this scheduler instance.

        Pending routes and expired leases may be claimed.  Active leases and
        terminal routes reject duplicate delivery.
        """

        self._validate_route(envelope)
        encoded = _envelope_json(envelope)
        digest = _sha256_text(encoded)
        claimed_at = (now or _utcnow()).astimezone(timezone.utc)
        expires_at = claimed_at + timedelta(seconds=self.lease_seconds)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM execution_routes WHERE task_id = ?",
                    (envelope.task_id,),
                ).fetchone()
                if row is None or row["route_sha256"] != digest or row["envelope_json"] != encoded:
                    connection.commit()
                    return False
                if row["status"] in {"succeeded", "failed"}:
                    connection.commit()
                    return False
                lease_expired = (
                    row["status"] == "leased"
                    and _parse_timestamp(row["lease_expires_at"]) <= claimed_at
                )
                if row["status"] == "leased" and not lease_expired:
                    connection.commit()
                    return False
                connection.execute(
                    """
                    UPDATE execution_routes
                    SET status = 'leased', lease_owner = ?, lease_expires_at = ?,
                        delivery_count = delivery_count + 1, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        self.owner_id,
                        _iso(expires_at),
                        _iso(claimed_at),
                        envelope.task_id,
                    ),
                )
                self._append_audit(
                    connection,
                    timestamp=_iso(claimed_at),
                    event_type=("route.lease_recovered" if lease_expired else "route.claimed"),
                    subject_sha256=digest,
                    payload={
                        "owner_sha256": _sha256_text(self.owner_id),
                        "lease_expires_at": _iso(expires_at),
                        "delivery_count": int(row["delivery_count"]) + 1,
                    },
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def finish_route(
        self,
        envelope: HandoffEnvelope,
        *,
        status: RouteTerminalStatus,
        now: datetime | None = None,
    ) -> bool:
        """Seal a currently owned lease as succeeded or explicitly failed."""

        self._validate_route(envelope)
        if status not in {"succeeded", "failed"}:
            raise ValueError("route terminal status is invalid")
        encoded = _envelope_json(envelope)
        digest = _sha256_text(encoded)
        completed_at = (now or _utcnow()).astimezone(timezone.utc)
        with self._lock, self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM execution_routes WHERE task_id = ?",
                    (envelope.task_id,),
                ).fetchone()
                if row is None or row["route_sha256"] != digest or row["envelope_json"] != encoded:
                    connection.commit()
                    return False
                if row["status"] == status:
                    connection.commit()
                    return True
                if row["status"] != "leased" or row["lease_owner"] != self.owner_id:
                    connection.commit()
                    return False
                connection.execute(
                    """
                    UPDATE execution_routes
                    SET status = ?, lease_owner = NULL, lease_expires_at = NULL,
                        completed_at = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        status,
                        _iso(completed_at),
                        _iso(completed_at),
                        envelope.task_id,
                    ),
                )
                self._append_audit(
                    connection,
                    timestamp=_iso(completed_at),
                    event_type=f"route.{status}",
                    subject_sha256=digest,
                    payload={
                        "owner_sha256": _sha256_text(self.owner_id),
                        "delivery_count": int(row["delivery_count"]),
                    },
                )
                connection.commit()
                return True
            except Exception:
                connection.rollback()
                raise

    def all_routes(self) -> tuple[HandoffEnvelope, ...]:
        """Load canonical routes for Leader recovery and budget reconstruction."""

        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT envelope_json FROM execution_routes ORDER BY rowid"
            ).fetchall()
        try:
            return tuple(HandoffEnvelope.model_validate_json(row["envelope_json"]) for row in rows)
        except ValueError as exc:
            raise LedgerConflictError("route ledger contains an invalid envelope") from exc

    def recoverable_routes(
        self,
        *,
        now: datetime | None = None,
    ) -> tuple[RecoverableRoute, ...]:
        """Return pending routes and expired leases without mutating claims."""

        observed_at = (now or _utcnow()).astimezone(timezone.utc)
        with self._lock, self._connect() as connection:
            rows = connection.execute(
                """
                SELECT envelope_json, status, delivery_count, lease_expires_at
                FROM execution_routes
                WHERE status = 'pending'
                   OR (status = 'leased' AND lease_expires_at <= ?)
                ORDER BY issue_id, rowid
                """,
                (_iso(observed_at),),
            ).fetchall()
        return tuple(
            RecoverableRoute(
                envelope=HandoffEnvelope.model_validate_json(row["envelope_json"]),
                status=row["status"],
                delivery_count=int(row["delivery_count"]),
                lease_expired=row["status"] == "leased",
            )
            for row in rows
        )

    def snapshot(self, *, now: datetime | None = None) -> RouteLedgerSnapshot:
        """Return bounded aggregate state without route contents."""

        observed_at = (now or _utcnow()).astimezone(timezone.utc)
        with self._lock, self._connect() as connection:
            counts = {
                row["status"]: int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM execution_routes GROUP BY status"
                ).fetchall()
            }
            expired = connection.execute(
                "SELECT COUNT(*) AS count FROM execution_routes "
                "WHERE status = 'leased' AND lease_expires_at <= ?",
                (_iso(observed_at),),
            ).fetchone()
            audits = connection.execute(
                "SELECT COUNT(*) AS count FROM collaboration_audit"
            ).fetchone()
        return RouteLedgerSnapshot(
            pending=counts.get("pending", 0),
            leased=counts.get("leased", 0),
            succeeded=counts.get("succeeded", 0),
            failed=counts.get("failed", 0),
            expired_leases=int(expired["count"]),
            audit_entries=int(audits["count"]),
        )

    def verify_audit_chain(self) -> AuditChainVerification:
        """Recompute every audit link and report the first invalid sequence."""

        with self._lock, self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM collaboration_audit ORDER BY sequence"
            ).fetchall()
        previous: str | None = None
        for row in rows:
            expected = _entry_hash(
                timestamp=row["timestamp"],
                event_type=row["event_type"],
                subject_sha256=row["subject_sha256"],
                payload_sha256=row["payload_sha256"],
                previous_sha256=previous,
            )
            if row["previous_sha256"] != previous or row["entry_sha256"] != expected:
                return AuditChainVerification(
                    valid=False,
                    entries=len(rows),
                    head_sha256=previous,
                    first_invalid_sequence=int(row["sequence"]),
                )
            previous = row["entry_sha256"]
        return AuditChainVerification(
            valid=True,
            entries=len(rows),
            head_sha256=previous,
        )

    @staticmethod
    def _append_audit(
        connection: sqlite3.Connection,
        *,
        timestamp: str,
        event_type: str,
        subject_sha256: str,
        payload: dict[str, Any],
    ) -> None:
        previous_row = connection.execute(
            "SELECT entry_sha256 FROM collaboration_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous = previous_row["entry_sha256"] if previous_row is not None else None
        payload_sha256 = _sha256_text(_canonical_json(payload))
        digest = _entry_hash(
            timestamp=timestamp,
            event_type=event_type,
            subject_sha256=subject_sha256,
            payload_sha256=payload_sha256,
            previous_sha256=previous,
        )
        connection.execute(
            """
            INSERT INTO collaboration_audit(
                timestamp, event_type, subject_sha256, payload_sha256,
                previous_sha256, entry_sha256
            ) VALUES(?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                event_type,
                subject_sha256,
                payload_sha256,
                previous,
                digest,
            ),
        )


__all__ = [
    "AuditChainVerification",
    "DurableRouteLedger",
    "LedgerConflictError",
    "RecoverableRoute",
    "RouteLedgerSnapshot",
]

"""Trusted, expiring approval evidence for dangerous MCP operations."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Protocol

from devflow.mcp.contracts import ApprovalEvidence


class ApprovalVerifier(Protocol):
    """Verify that evidence was issued for an exact operation."""

    def verify(
        self,
        evidence: ApprovalEvidence,
        *,
        action: str,
        target: str,
        artifact_digest: str,
    ) -> bool: ...


class HMACApprovalAuthority:
    """Issue and verify approvals without exposing the signing key to Agents."""

    def __init__(
        self,
        signing_key: bytes,
        *,
        max_age: timedelta = timedelta(hours=24),
        clock_skew: timedelta = timedelta(minutes=5),
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("approval signing key must contain at least 32 bytes")
        if max_age <= timedelta(0):
            raise ValueError("approval max age must be positive")
        self._signing_key = signing_key
        self._max_age = max_age
        self._clock_skew = clock_skew

    def issue(
        self,
        *,
        action: str,
        target: str,
        artifact_digest: str,
        approved_by: str,
        approved_at: datetime | None = None,
    ) -> ApprovalEvidence:
        """Create signed evidence from a trusted human-approval boundary."""

        timestamp = approved_at or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            raise ValueError("approved_at must be timezone-aware")
        unsigned = {
            "approval_id": uuid.uuid4().hex,
            "action": action,
            "target": target,
            "artifact_digest": artifact_digest,
            "approved_by": approved_by,
            "approved_at": timestamp.astimezone(timezone.utc),
        }
        signature = self._sign(unsigned)
        return ApprovalEvidence.model_validate({**unsigned, "signature": signature})

    def verify(
        self,
        evidence: ApprovalEvidence,
        *,
        action: str,
        target: str,
        artifact_digest: str,
    ) -> bool:
        """Validate signature, scope, and expiry using constant-time comparison."""

        if (
            evidence.action != action
            or evidence.target != target
            or evidence.artifact_digest != artifact_digest
            or evidence.approved_at.tzinfo is None
        ):
            return False
        now = datetime.now(timezone.utc)
        approved_at = evidence.approved_at.astimezone(timezone.utc)
        if approved_at > now + self._clock_skew or now - approved_at > self._max_age:
            return False
        unsigned = evidence.model_dump(exclude={"signature"})
        expected = self._sign(unsigned)
        return hmac.compare_digest(evidence.signature, expected)

    def _sign(self, payload: dict[str, object]) -> str:
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        )
        return hmac.new(
            self._signing_key,
            serialized.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    raise TypeError(f"unsupported approval field type: {type(value).__name__}")


__all__ = ["ApprovalVerifier", "HMACApprovalAuthority"]

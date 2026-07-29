"""Fail-closed repository and tenant boundaries for RAG records."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import struct
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from numbers import Real
from typing import Any

from devflow.exceptions import SkillError

_IDENTITY_COMPONENT = re.compile(r"^[a-z0-9._-]{1,128}$")
_EXACT_REVISION = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_SCHEMA_VERSION = "rag-record/v1"
_SCOPE_FIELDS = frozenset(
    {
        "rag_schema_version",
        "tenant_id",
        "repo_owner",
        "repo_name",
        "repository_id",
        "repository_revision",
        "namespace",
        "indexed_at",
        "expires_at",
        "embedding_sha256",
        "integrity_algorithm",
        "integrity_key_id",
        "record_hmac_sha256",
    }
)


def _canonical_component(value: str, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    canonical = value.casefold()
    if value != value.strip() or canonical in {".", ".."}:
        raise ValueError(f"{field} is not canonical")
    if _IDENTITY_COMPONENT.fullmatch(canonical) is None:
        raise ValueError(f"{field} contains unsupported characters")
    return canonical


@dataclass(frozen=True, slots=True)
class RepositoryScope:
    """One immutable RAG namespace: tenant + repository + exact Git revision."""

    tenant_id: str
    repo_owner: str
    repo_name: str
    revision: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "tenant_id", _canonical_component(self.tenant_id, "tenant_id")
        )
        object.__setattr__(
            self, "repo_owner", _canonical_component(self.repo_owner, "repo_owner")
        )
        object.__setattr__(
            self, "repo_name", _canonical_component(self.repo_name, "repo_name")
        )
        if not isinstance(self.revision, str):
            raise ValueError("revision must be text")
        canonical_revision = self.revision.casefold()
        if self.revision != self.revision.strip():
            raise ValueError("revision is not canonical")
        if _EXACT_REVISION.fullmatch(canonical_revision) is None:
            raise ValueError(
                "revision must be an exact 40- or 64-character Git object id"
            )
        object.__setattr__(self, "revision", canonical_revision)

    @property
    def repository_id(self) -> str:
        """Return the canonical repository identity."""
        return f"{self.repo_owner}/{self.repo_name}"

    @property
    def namespace(self) -> str:
        """Return a deterministic opaque namespace bound to every identity field."""
        material = (
            f"{_SCHEMA_VERSION}\0{self.tenant_id}\0"
            f"{self.repository_id}\0{self.revision}"
        )
        return f"rag-v1:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"

    def metadata(self, *, now: int, ttl_seconds: int) -> dict[str, str | int]:
        """Build authoritative scalar metadata for a newly written record."""
        return {
            "rag_schema_version": _SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "repo_owner": self.repo_owner,
            "repo_name": self.repo_name,
            "repository_id": self.repository_id,
            "repository_revision": self.revision,
            "namespace": self.namespace,
            "indexed_at": now,
            "expires_at": now + ttl_seconds,
        }


def resolve_scope(
    supplied: RepositoryScope | None,
    bound: RepositoryScope | None,
) -> RepositoryScope:
    """Resolve a method scope and reject absent or conflicting identities."""
    if supplied is None and bound is None:
        raise SkillError(
            "RAG operation requires an explicit tenant, repository, and exact revision"
        )
    if supplied is not None and bound is not None and supplied != bound:
        raise SkillError("RAG operation scope conflicts with the bound repository scope")
    return supplied or bound  # type: ignore[return-value]


def query_result_row(results: Any, field: str) -> list[Any]:
    """Extract one query row without unsafe truth-value coercion."""
    if not isinstance(results, Mapping):
        raise SkillError("RAG backend returned a malformed query result")
    raw = results.get(field)
    if raw is None:
        return []
    if isinstance(raw, (str, bytes, bytearray, dict)):
        raise SkillError(f"RAG backend returned malformed {field}")
    try:
        outer = list(raw)
    except TypeError as exc:
        raise SkillError(f"RAG backend returned malformed {field}") from exc
    if len(outer) != 1:
        raise SkillError(f"RAG backend returned malformed {field}")
    row = outer[0]
    if row is None:
        return []
    if isinstance(row, (str, bytes, bytearray, dict)):
        raise SkillError(f"RAG backend returned malformed {field}")
    try:
        return list(row)
    except TypeError as exc:
        raise SkillError(f"RAG backend returned malformed {field}") from exc


def validate_user_metadata(metadata: Mapping[str, Any]) -> dict[str, str | int | float | bool]:
    """Accept only Chroma-compatible scalars and reserve provenance fields."""
    overlap = _SCOPE_FIELDS.intersection(metadata)
    if overlap:
        fields = ", ".join(sorted(overlap))
        raise SkillError(f"RAG metadata cannot override reserved fields: {fields}")

    validated: dict[str, str | int | float | bool] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not key or key != key.strip():
            raise SkillError("RAG metadata keys must be non-empty canonical text")
        if not isinstance(value, (str, int, float, bool)):
            raise SkillError(f"RAG metadata field {key!r} must be a scalar")
        if isinstance(value, str) and value != value.strip():
            raise SkillError(f"RAG metadata field {key!r} is not canonical")
        if isinstance(value, float) and not math.isfinite(value):
            raise SkillError(f"RAG metadata field {key!r} must be finite")
        validated[key] = value
    return validated


def seal_record(
    *,
    record_id: str,
    document: str,
    metadata: Mapping[str, Any],
    integrity_key: bytes,
) -> dict[str, Any]:
    """Return metadata carrying a keyed digest over the complete record."""
    key = require_integrity_key(integrity_key)
    sealed = dict(metadata)
    if "record_hmac_sha256" in sealed:
        raise SkillError("record metadata is already sealed")
    sealed["integrity_algorithm"] = "hmac-sha256"
    sealed["integrity_key_id"] = hashlib.sha256(key).hexdigest()[:16]
    sealed["record_hmac_sha256"] = _record_digest(
        record_id=record_id,
        document=document,
        metadata=sealed,
        integrity_key=key,
    )
    return sealed


def verify_record(
    *,
    record_id: Any,
    document: Any,
    metadata: Any,
    scope: RepositoryScope,
    integrity_key: bytes,
    now: int | None = None,
) -> tuple[str, dict[str, Any]]:
    """Verify one result before releasing it to an agent."""
    key = require_integrity_key(integrity_key)
    if not isinstance(record_id, str) or not record_id:
        raise SkillError("RAG backend returned a record without an id")
    if not isinstance(document, str):
        raise SkillError("RAG backend returned a non-text document")
    if not isinstance(metadata, dict):
        raise SkillError("RAG backend returned malformed record metadata")

    expected_scope = {
        "rag_schema_version": _SCHEMA_VERSION,
        "tenant_id": scope.tenant_id,
        "repo_owner": scope.repo_owner,
        "repo_name": scope.repo_name,
        "repository_id": scope.repository_id,
        "repository_revision": scope.revision,
        "namespace": scope.namespace,
    }
    for field, expected in expected_scope.items():
        if metadata.get(field) != expected:
            raise SkillError(f"RAG record failed closed: {field} does not match scope")

    indexed_at = metadata.get("indexed_at")
    expires_at = metadata.get("expires_at")
    if (
        not isinstance(indexed_at, int)
        or isinstance(indexed_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= indexed_at
    ):
        raise SkillError("RAG record failed closed: invalid lifetime metadata")
    current_time = int(time.time()) if now is None else now
    if expires_at <= current_time:
        raise SkillError("RAG record failed closed: record is expired")

    if metadata.get("integrity_algorithm") != "hmac-sha256":
        raise SkillError("RAG record failed closed: integrity algorithm mismatch")
    if metadata.get("integrity_key_id") != hashlib.sha256(key).hexdigest()[:16]:
        raise SkillError("RAG record failed closed: integrity key id mismatch")
    claimed_digest = metadata.get("record_hmac_sha256")
    if not isinstance(claimed_digest, str):
        raise SkillError("RAG record failed closed: integrity digest is missing")
    digest_metadata = dict(metadata)
    del digest_metadata["record_hmac_sha256"]
    expected_digest = _record_digest(
        record_id=record_id,
        document=document,
        metadata=digest_metadata,
        integrity_key=key,
    )
    if not hmac.compare_digest(claimed_digest, expected_digest):
        raise SkillError("RAG record failed closed: integrity digest mismatch")
    return document, metadata


def utc_epoch(clock: Callable[[], float]) -> int:
    """Return a clock value as a finite non-negative integer epoch."""
    value = clock()
    if not math.isfinite(value) or value < 0:
        raise SkillError("RAG clock returned an invalid timestamp")
    return int(value)


def embedding_sha256(embedding: Any) -> str:
    """Digest a finite vector after deterministic IEEE-754 float32 coercion."""
    canonical_values = _canonical_embedding(embedding)
    canonical = json.dumps(
        canonical_values,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def cosine_similarity(left: Any, right: Any) -> float:
    """Recompute similarity locally from an authenticated stored vector."""
    left_values = _canonical_embedding(left)
    right_values = _canonical_embedding(right)
    if len(left_values) != len(right_values):
        raise SkillError("RAG embeddings have conflicting dimensions")
    left_norm = math.sqrt(sum(value * value for value in left_values))
    right_norm = math.sqrt(sum(value * value for value in right_values))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    similarity = sum(
        left_value * right_value
        for left_value, right_value in zip(left_values, right_values, strict=True)
    ) / (left_norm * right_norm)
    return max(-1.0, min(1.0, similarity))


def _canonical_embedding(embedding: Any) -> list[float]:
    if isinstance(embedding, (str, bytes, bytearray, dict)):
        raise SkillError("RAG embedding must be a numeric vector")
    try:
        values = list(embedding)
    except TypeError as exc:
        raise SkillError("RAG embedding must be a numeric vector") from exc
    if not values or len(values) > 16_384:
        raise SkillError("RAG embedding has an invalid dimension")

    canonical_values: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, Real):
            raise SkillError("RAG embedding contains a non-numeric value")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise SkillError("RAG embedding contains a non-finite value")
        try:
            float32 = struct.unpack("!f", struct.pack("!f", numeric))[0]
        except OverflowError as exc:
            raise SkillError("RAG embedding value exceeds float32 range") from exc
        if not math.isfinite(float32):
            raise SkillError("RAG embedding value exceeds float32 range")
        canonical_values.append(float32)
    return canonical_values


def require_integrity_key(key: bytes) -> bytes:
    """Reject missing or weak record-authentication keys."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise SkillError("RAG integrity key must contain at least 32 bytes")
    return key


def _record_digest(
    *,
    record_id: str,
    document: str,
    metadata: Mapping[str, Any],
    integrity_key: bytes,
) -> str:
    payload = {
        "record_id": record_id,
        "document": document,
        "metadata": metadata,
    }
    try:
        canonical = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SkillError("RAG record cannot be canonically sealed") from exc
    return hmac.new(integrity_key, canonical, hashlib.sha256).hexdigest()


__all__ = [
    "RepositoryScope",
    "cosine_similarity",
    "embedding_sha256",
    "query_result_row",
    "resolve_scope",
    "require_integrity_key",
    "seal_record",
    "utc_epoch",
    "validate_user_metadata",
    "verify_record",
]

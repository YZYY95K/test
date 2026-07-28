"""Fail-closed, envelope-bound authorization for the GitHub Evidence Skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

READ_TOOLS = frozenset({"get_file_contents"})
QUALIFIED_READ_TOOLS = frozenset(
    {
        "github:get_file_contents",
        "devflow-github-readonly.get_file_contents",
    }
)
ENVELOPE_FIELDS = frozenset(
    {
        "envelope_version",
        "run_id",
        "issue_id",
        "task_id",
        "producer",
        "consumer",
        "skill",
        "trace_id",
        "idempotency_key",
        "created_at",
        "status",
        "artifact",
    }
)
ARTIFACT_FIELDS = frozenset({"type", "schema_version", "inline", "sha256"})
ASSIGNMENT_BASE_FIELDS = frozenset({"repository", "revision", "capability"})
ALLOWED_CONSUMERS = frozenset({"devflow-locator", "LocatorAgent"})
ALLOWED_PRODUCERS = frozenset({"devflow-lead", "TeamLeader"})
COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CAPABILITY = re.compile(r"^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$")
OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?$")
BROKER_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
ENCODED_PATH_SEPARATOR = re.compile(r"%(?:2e|2f|5c)", re.IGNORECASE)
MAX_ENVELOPE_AGE = timedelta(minutes=15)
MAX_FUTURE_SKEW = timedelta(seconds=60)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    code: str
    profile: str
    tool: str
    risk: str
    scope_digest: str = ""


@dataclass(frozen=True)
class Assignment:
    owner: str
    repo: str
    revision: str
    paths: tuple[str, ...]
    task_id: str
    capability: str
    trace_id: str
    idempotency_key: str
    envelope_digest: str


class EnvelopeError(ValueError):
    """An envelope failed a stable, fail-closed validation rule."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeError("HANDOFF_INVALID")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise EnvelopeError("HANDOFF_INVALID")


def _nonempty_string(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value == value.strip()
        and CONTROL_CHARACTER.search(value) is None
    )


def _canonical_path(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = PurePosixPath(value.replace("\\", "/"))
    if (
        not value
        or value in {".", ".."}
        or value.endswith(("/", "\\"))
        or "\\" in value
        or candidate.is_absolute()
        or ".." in candidate.parts
        or candidate.as_posix() != value
        or BROKER_PATH.fullmatch(value) is None
        or CONTROL_CHARACTER.search(value)
        or ENCODED_PATH_SEPARATOR.search(value)
    ):
        return None
    return candidate.as_posix()


def _created_at(value: Any, now: datetime) -> datetime:
    if not isinstance(value, str) or not value:
        raise EnvelopeError("HANDOFF_INVALID")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        raise EnvelopeError("HANDOFF_INVALID") from None
    if parsed.tzinfo is None:
        raise EnvelopeError("HANDOFF_INVALID")
    parsed = parsed.astimezone(timezone.utc)
    if parsed > now + MAX_FUTURE_SKEW or now - parsed > MAX_ENVELOPE_AGE:
        raise EnvelopeError("HANDOFF_EXPIRED")
    return parsed


def _assignment_paths(inline: dict[str, Any]) -> tuple[str, ...]:
    has_path = "path" in inline
    has_paths = "paths" in inline
    if has_path == has_paths:
        raise EnvelopeError("HANDOFF_INVALID")
    expected = ASSIGNMENT_BASE_FIELDS | ({"path"} if has_path else {"paths"})
    if set(inline) != expected:
        raise EnvelopeError("HANDOFF_INVALID")
    raw_paths: Any = [inline["path"]] if has_path else inline["paths"]
    if (
        not isinstance(raw_paths, list)
        or not raw_paths
        or len(raw_paths) > 32
        or len(raw_paths) != len(set(str(item) for item in raw_paths))
    ):
        raise EnvelopeError("HANDOFF_INVALID")
    paths = tuple(_canonical_path(item) or "" for item in raw_paths)
    if any(not path for path in paths):
        raise EnvelopeError("MCP_SCOPE_INVALID")
    if has_paths and list(paths) != sorted(paths):
        raise EnvelopeError("MCP_SCOPE_INVALID")
    return paths


def validate_envelope(envelope: Any, *, now: datetime | None = None) -> Assignment:
    """Validate a v1 inline assignment and return its immutable scope."""
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise EnvelopeError("HANDOFF_INVALID")
    if envelope.get("envelope_version") != "1.0":
        raise EnvelopeError("HANDOFF_INVALID")
    for field in (
        "run_id",
        "task_id",
        "producer",
        "trace_id",
        "idempotency_key",
    ):
        if not _nonempty_string(envelope.get(field)):
            raise EnvelopeError("HANDOFF_INVALID")
    issue_id = envelope.get("issue_id")
    if isinstance(issue_id, bool) or not isinstance(issue_id, int) or issue_id < 1:
        raise EnvelopeError("HANDOFF_INVALID")
    if TASK_ID.fullmatch(envelope["task_id"]) is None:
        raise EnvelopeError("HANDOFF_INVALID")
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None:
        raise ValueError("authorization clock must be timezone-aware")
    _created_at(envelope.get("created_at"), clock.astimezone(timezone.utc))
    if envelope.get("producer") not in ALLOWED_PRODUCERS:
        raise EnvelopeError("HANDOFF_PRODUCER_MISMATCH")
    if envelope.get("consumer") not in ALLOWED_CONSUMERS:
        raise EnvelopeError("HANDOFF_CONSUMER_MISMATCH")
    if envelope.get("skill") != "github-evidence":
        raise EnvelopeError("HANDOFF_SKILL_MISMATCH")
    if envelope.get("status") != "ready":
        raise EnvelopeError("HANDOFF_STATUS_INVALID")

    artifact = envelope.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_FIELDS:
        raise EnvelopeError("HANDOFF_INVALID")
    if artifact.get("type") != "SkillInvocation" or artifact.get("schema_version") != "1.0":
        raise EnvelopeError("HANDOFF_INVALID")
    inline = artifact.get("inline")
    digest = artifact.get("sha256")
    if not isinstance(inline, dict) or not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise EnvelopeError("HANDOFF_INVALID")
    actual_digest = hashlib.sha256(_canonical_json(inline)).hexdigest()
    if actual_digest != digest:
        raise EnvelopeError("HANDOFF_DIGEST_MISMATCH")

    repository = inline.get("repository")
    if not isinstance(repository, dict) or set(repository) != {"owner", "repo"}:
        raise EnvelopeError("HANDOFF_INVALID")
    owner = repository.get("owner")
    repo = repository.get("repo")
    if (
        not isinstance(owner, str)
        or OWNER.fullmatch(owner) is None
        or "--" in owner
        or not isinstance(repo, str)
        or REPOSITORY.fullmatch(repo) is None
        or repo in {".", ".."}
    ):
        raise EnvelopeError("MCP_SCOPE_INVALID")
    assert isinstance(owner, str) and isinstance(repo, str)
    revision = inline.get("revision")
    if not isinstance(revision, str) or not COMMIT_SHA.fullmatch(revision):
        raise EnvelopeError("REVISION_REQUIRED")
    capability = inline.get("capability")
    if not isinstance(capability, str) or CAPABILITY.fullmatch(capability) is None:
        raise EnvelopeError("MCP_CAPABILITY_REQUIRED")
    paths = _assignment_paths(inline)
    return Assignment(
        owner=owner,
        repo=repo,
        revision=revision,
        paths=paths,
        task_id=envelope["task_id"],
        capability=capability,
        trace_id=envelope["trace_id"],
        idempotency_key=envelope["idempotency_key"],
        envelope_digest=hashlib.sha256(_canonical_json(envelope)).hexdigest(),
    )


def authorize(
    profile: str,
    tool: str,
    *,
    envelope: dict[str, Any] | None,
    owner: str = "",
    repo: str = "",
    path: str = "",
    revision: str = "",
    task_id: str = "",
    capability: str = "",
    now: datetime | None = None,
) -> Decision:
    qualified = tool.strip()
    normalized = re.split(r"[.:]", qualified)[-1]
    if profile != "locator":
        return Decision(False, "UNKNOWN_PROFILE", profile, normalized, "unknown")
    if envelope is None:
        return Decision(False, "HANDOFF_REQUIRED", profile, normalized, "invalid_scope")
    try:
        assignment = validate_envelope(envelope, now=now)
    except EnvelopeError as exc:
        return Decision(False, exc.code, profile, normalized, "invalid_scope")
    if qualified not in QUALIFIED_READ_TOOLS or normalized not in READ_TOOLS:
        return Decision(False, "MCP_TOOL_DENIED", profile, normalized, "forbidden")
    if not COMMIT_SHA.fullmatch(revision):
        return Decision(False, "REVISION_REQUIRED", profile, normalized, "invalid_scope")
    canonical_path = _canonical_path(path)
    if canonical_path is None:
        return Decision(False, "MCP_SCOPE_INVALID", profile, normalized, "invalid_scope")
    if (
        owner != assignment.owner
        or repo != assignment.repo
        or revision != assignment.revision
        or canonical_path not in assignment.paths
        or task_id != assignment.task_id
        or capability != assignment.capability
    ):
        return Decision(False, "MCP_SCOPE_MISMATCH", profile, normalized, "forbidden")
    scope = {
        "envelope_digest": assignment.envelope_digest,
        "idempotency_key": assignment.idempotency_key,
        "owner": assignment.owner,
        "path": canonical_path,
        "repo": assignment.repo,
        "revision": assignment.revision,
        "task_id": assignment.task_id,
        "capability_digest": hashlib.sha256(assignment.capability.encode("ascii")).hexdigest(),
        "tool": normalized,
        "trace_id": assignment.trace_id,
    }
    return Decision(
        True,
        "ALLOW_READ",
        profile,
        normalized,
        "read_only",
        hashlib.sha256(_canonical_json(scope)).hexdigest(),
    )


def _load_envelope(path: str | None) -> tuple[dict[str, Any] | None, str | None]:
    if path is None:
        return None, None
    try:
        envelope_path = Path(path)
        if envelope_path.stat().st_size > 1024 * 1024:
            return None, "HANDOFF_INVALID"
        value = json.loads(
            envelope_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, EnvelopeError):
        return None, "HANDOFF_INVALID"
    if not isinstance(value, dict):
        return None, "HANDOFF_INVALID"
    return value, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--envelope")
    parser.add_argument("--owner", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--capability", required=True)
    args = parser.parse_args()
    envelope, load_error = _load_envelope(args.envelope)
    if load_error is not None:
        decision = Decision(
            False,
            load_error,
            args.profile,
            re.split(r"[.:]", args.tool.strip())[-1],
            "invalid_scope",
        )
    else:
        decision = authorize(
            args.profile,
            args.tool,
            envelope=envelope,
            owner=args.owner,
            repo=args.repo,
            path=args.path,
            revision=args.revision,
            task_id=args.task_id,
            capability=args.capability,
        )
    print(json.dumps(asdict(decision), sort_keys=True))
    return 0 if decision.allowed else 3


if __name__ == "__main__":
    raise SystemExit(main())

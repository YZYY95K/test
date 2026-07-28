"""Strictly validate GitHub Evidence Skill input and output artifacts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?$")
BROKER_PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CAPABILITY = re.compile(r"^[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}$")
CONTENT_SCHEMA = "devflow.github-content-response/v1"
MAX_CONTENT_BYTES = 1_000_000
ROOT_OUTPUT_FIELDS = frozenset(
    {
        "run_id",
        "task_id",
        "repository",
        "revision",
        "operations",
        "evidence",
        "trace_id",
        "digest",
        "status",
    }
)
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "authorization",
        "github",
        "response_digest",
        "receipt_signature",
    }
)
AUTHORIZATION_FIELDS = frozenset(
    {"decision", "task_id", "scope_digest", "capability_digest", "authorized_at"}
)
GITHUB_FIELDS = frozenset(
    {"repository", "revision", "path", "object_sha", "content_base64", "encoding"}
)
EVIDENCE_FIELDS = frozenset({"path", "object_sha", "content_sha256", "response_digest"})


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("artifact contains a duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("artifact contains a non-standard JSON scalar")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or CONTROL.search(value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _repository(value: Any) -> tuple[str, str]:
    if not isinstance(value, dict) or set(value) != {"owner", "repo"}:
        raise ValueError("repository schema is invalid")
    owner = _text(value["owner"], "repository owner", maximum=100)
    repo = _text(value["repo"], "repository name", maximum=100)
    if (
        OWNER.fullmatch(owner) is None
        or "--" in owner
        or REPOSITORY.fullmatch(repo) is None
        or repo in {".", ".."}
    ):
        raise ValueError("repository identity is invalid")
    return owner, repo


def _path(value: Any) -> str:
    text = _text(value, "repository path", maximum=512)
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or BROKER_PATH.fullmatch(text) is None
        or path.as_posix() != text
        or text.endswith("/")
        or "//" in text
        or "\\" in text
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("repository path is unsafe")
    return text


def _canonical_base64(value: Any) -> tuple[str, bytes]:
    text = _text(value, "content_base64", maximum=1_400_000)
    if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", text) is None:
        raise ValueError("content_base64 is malformed")
    try:
        content = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("content_base64 is malformed") from exc
    if len(content) > MAX_CONTENT_BYTES or base64.b64encode(content).decode("ascii") != text:
        raise ValueError("content_base64 is non-canonical or too large")
    return text, content


def _validate_input(artifact: dict[str, Any]) -> None:
    has_path = "path" in artifact
    has_paths = "paths" in artifact
    if has_path == has_paths:
        raise ValueError("input requires exactly one of path or paths")
    expected = {"repository", "revision", "capability", "path" if has_path else "paths"}
    if set(artifact) != expected:
        raise ValueError("input schema is invalid")
    _repository(artifact["repository"])
    revision = artifact["revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("revision must be a lowercase immutable commit SHA")
    capability = artifact["capability"]
    if not isinstance(capability, str) or CAPABILITY.fullmatch(capability) is None:
        raise ValueError("capability is missing or malformed")
    raw_paths = [artifact["path"]] if has_path else artifact["paths"]
    if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 32:
        raise ValueError("input paths are invalid")
    paths = [_path(item) for item in raw_paths]
    if len(paths) != len(set(paths)) or (has_paths and paths != sorted(paths)):
        raise ValueError("input paths are not sorted and unique")


def _validate_receipt(
    value: Any,
    *,
    task_id: str,
    repository: str,
    revision: str,
) -> tuple[dict[str, str], str, str]:
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise ValueError("operation receipt schema is invalid")
    if value["schema_version"] != CONTENT_SCHEMA:
        raise ValueError("operation receipt version is unsupported")
    authorization = value["authorization"]
    github = value["github"]
    if not isinstance(authorization, dict) or set(authorization) != AUTHORIZATION_FIELDS:
        raise ValueError("operation authorization schema is invalid")
    if not isinstance(github, dict) or set(github) != GITHUB_FIELDS:
        raise ValueError("operation GitHub schema is invalid")
    if authorization["decision"] != "allow" or authorization["task_id"] != task_id:
        raise ValueError("operation authorization does not match the task")
    for field in ("scope_digest", "capability_digest"):
        if (
            not isinstance(authorization[field], str)
            or DIGEST.fullmatch(authorization[field]) is None
        ):
            raise ValueError(f"operation {field} is invalid")
    authorized_at = authorization["authorized_at"]
    if isinstance(authorized_at, bool) or not isinstance(authorized_at, int) or authorized_at < 1:
        raise ValueError("operation authorization time is invalid")
    if github["repository"] != repository or github["revision"] != revision:
        raise ValueError("operation repository scope does not match the result")
    path = _path(github["path"])
    object_sha = github["object_sha"]
    if not isinstance(object_sha, str) or REVISION.fullmatch(object_sha) is None:
        raise ValueError("GitHub object SHA is invalid")
    if github["encoding"] != "base64":
        raise ValueError("GitHub content encoding is unsupported")
    _, content = _canonical_base64(github["content_base64"])
    response_digest = value["response_digest"]
    receipt_signature = value["receipt_signature"]
    if not isinstance(response_digest, str) or DIGEST.fullmatch(response_digest) is None:
        raise ValueError("operation response digest is invalid")
    if not isinstance(receipt_signature, str) or DIGEST.fullmatch(receipt_signature) is None:
        raise ValueError("operation receipt signature is invalid")
    unsigned = {
        "schema_version": value["schema_version"],
        "authorization": authorization,
        "github": github,
    }
    if hashlib.sha256(_canonical_json(unsigned)).hexdigest() != response_digest:
        raise ValueError("operation response digest mismatch")
    evidence = {
        "path": path,
        "object_sha": object_sha,
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "response_digest": response_digest,
    }
    return evidence, authorization["scope_digest"], authorization["capability_digest"]


def _validate_output(artifact: dict[str, Any]) -> None:
    if set(artifact) != ROOT_OUTPUT_FIELDS:
        raise ValueError("output schema is invalid")
    run_id = _text(artifact["run_id"], "run_id")
    task_id = _text(artifact["task_id"], "task_id")
    trace_id = _text(artifact["trace_id"], "trace_id")
    del run_id, trace_id
    owner, repo = _repository(artifact["repository"])
    revision = artifact["revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("output revision is invalid")
    if artifact["status"] != "success":
        raise ValueError("GitHubEvidence output status must be success")
    operations = artifact["operations"]
    evidence = artifact["evidence"]
    if (
        not isinstance(operations, list)
        or not 1 <= len(operations) <= 32
        or not isinstance(evidence, list)
        or len(evidence) != len(operations)
    ):
        raise ValueError("operations and evidence must be equal non-empty lists")
    expected_evidence: list[dict[str, str]] = []
    scope_digests: set[str] = set()
    capability_digests: set[str] = set()
    for operation in operations:
        summary, scope_digest, capability_digest = _validate_receipt(
            operation,
            task_id=task_id,
            repository=f"{owner}/{repo}",
            revision=revision,
        )
        expected_evidence.append(summary)
        scope_digests.add(scope_digest)
        capability_digests.add(capability_digest)
    if len(scope_digests) != 1 or len(capability_digests) != 1:
        raise ValueError("operations do not share one assigned capability scope")
    if evidence != expected_evidence or len({item["path"] for item in expected_evidence}) != len(
        expected_evidence
    ):
        raise ValueError("evidence summaries do not exactly match operation receipts")
    digest = artifact["digest"]
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise ValueError("output digest is invalid")
    unsigned = {key: value for key, value in artifact.items() if key != "digest"}
    if hashlib.sha256(_canonical_json(unsigned)).hexdigest() != digest:
        raise ValueError("output digest mismatch")


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"input", "output"}:
        print("usage: validate.py <input|output> <artifact.json>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root / "references" / "contract.yaml")
    try:
        artifact_path = Path(sys.argv[2])
        if artifact_path.stat().st_size > 3_000_000:
            raise ValueError("artifact is too large")
        artifact = json.loads(
            artifact_path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("artifact cannot be loaded as strict JSON") from exc
    if not isinstance(artifact, dict):
        raise ValueError("artifact root must be an object")
    if any(SECRET.search(text) for text in _strings(artifact)):
        raise ValueError("artifact contains secret-shaped content")
    if sys.argv[1] == "input":
        _validate_input(artifact)
    else:
        _validate_output(artifact)
    print(json.dumps({"valid": True, "skill": contract["name"], "mode": sys.argv[1]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

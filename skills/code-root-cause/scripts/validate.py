"""Strictly validate code-root-cause inputs, results, and declared failures."""

from __future__ import annotations

import hashlib
import json
import math
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SKILL = "code-root-cause"
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
OBJECT_SHA = re.compile(r"^[0-9a-f]{40}$")
TIERS = frozenset({"T1", "T2", "T3", "T4", "T5"})
CATEGORIES = frozenset({"bug", "feature", "docs", "refactor"})
PRIORITIES = frozenset({"critical", "high", "medium", "low"})
INPUT_FIELDS = frozenset(
    {"issue_id", "repository_revision", "classified_issue", "github_evidence"}
)
CLASSIFIED_FIELDS = frozenset(
    {
        "issue",
        "complexity_level",
        "category",
        "priority",
        "duplicate_of",
        "estimated_effort_hours",
        "rationale",
        "confidence",
        "evidence",
    }
)
ISSUE_FIELDS = frozenset(
    {
        "issue_number",
        "title",
        "body",
        "labels",
        "state",
        "author",
        "created_at",
        "repo_owner",
        "repo_name",
    }
)
GITHUB_FIELDS = frozenset(
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
GITHUB_EVIDENCE_FIELDS = frozenset(
    {"path", "object_sha", "content_sha256", "response_digest"}
)
OUTPUT_FIELDS = frozenset(
    {
        "issue_id",
        "repository_revision",
        "root_cause",
        "affected_files",
        "related_tests",
        "context_ref",
        "confidence",
        "evidence",
    }
)
FAILURE_FIELDS = frozenset(
    {
        "schema_version",
        "skill",
        "code",
        "retryable",
        "retry_count",
        "max_attempts",
        "exhausted",
        "route_to",
        "event",
        "source_artifact_sha256",
        "summary",
        "diagnostics",
    }
)
FAILURES = {
    "RETRIEVAL_EMPTY": (True, 2, "locator.blocked"),
    "FILE_UNAVAILABLE": (True, 1, "locator.degraded"),
    "UNSAFE_PATH": (False, 0, "boundary.violation"),
}


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("artifact contains a duplicate JSON field")
        value[key] = item
    return value


def _reject_constant(_value: str) -> Any:
    raise ValueError("artifact contains a non-standard JSON scalar")


def _load(path: Path) -> dict[str, Any]:
    try:
        if not 1 <= path.stat().st_size <= 3_000_000:
            raise ValueError("artifact size is invalid")
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("artifact cannot be loaded as strict JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("artifact root must be an object")
    return value


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in _strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in _strings(child)]
    return []


def _text(value: Any, label: str, *, maximum: int = 4_096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or CONTROL.search(value) is not None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _number(value: Any, label: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{label} is outside its allowed range")
    return number


def _path(value: Any, label: str = "repository path") -> str:
    rendered = _text(value, label, maximum=512)
    path = PurePosixPath(rendered)
    if (
        PATH.fullmatch(rendered) is None
        or path.is_absolute()
        or path.as_posix() != rendered
        or rendered.endswith("/")
        or "//" in rendered
        or "\\" in rendered
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} is unsafe")
    return rendered


def _validate_classified(value: Any, *, issue_id: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != CLASSIFIED_FIELDS:
        raise ValueError("classified_issue fields do not match ClassifiedIssue")
    issue = value["issue"]
    if not isinstance(issue, dict) or set(issue) != ISSUE_FIELDS:
        raise ValueError("classified_issue.issue fields do not match IssueData")
    if _positive_int(issue["issue_number"], "issue.issue_number") != issue_id:
        raise ValueError("classified issue identity does not match issue_id")
    _text(issue["title"], "issue.title", maximum=512)
    if issue["body"] is not None and not isinstance(issue["body"], str):
        raise ValueError("issue.body must be text or null")
    labels = issue["labels"]
    if (
        not isinstance(labels, list)
        or len(labels) > 100
        or len(labels) != len(set(item for item in labels if isinstance(item, str)))
        or any(not isinstance(item, str) or not item or len(item) > 256 for item in labels)
    ):
        raise ValueError("issue.labels are invalid")
    if issue["state"] not in {"open", "closed"}:
        raise ValueError("issue.state is unsupported")
    _text(issue["author"], "issue.author", maximum=256)
    _text(issue["created_at"], "issue.created_at", maximum=64)
    _text(issue["repo_owner"], "issue.repo_owner", maximum=100)
    _text(issue["repo_name"], "issue.repo_name", maximum=100)
    if value["complexity_level"] not in TIERS:
        raise ValueError("classified_issue.complexity_level is unsupported")
    if value["category"] not in CATEGORIES or value["priority"] not in PRIORITIES:
        raise ValueError("classified issue category or priority is unsupported")
    duplicate = value["duplicate_of"]
    if duplicate is not None:
        _positive_int(duplicate, "classified_issue.duplicate_of")
    _number(
        value["estimated_effort_hours"],
        "classified_issue.estimated_effort_hours",
        minimum=0.0,
        maximum=100_000.0,
    )
    _text(value["rationale"], "classified_issue.rationale")
    _number(value["confidence"], "classified_issue.confidence", minimum=0.0, maximum=1.0)
    evidence = value["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"risk_floor", "deduplication"}:
        raise ValueError("classified issue evidence is invalid")
    return value


def _validate_github_evidence(
    value: Any,
    *,
    revision: str,
    repository: str,
) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != GITHUB_FIELDS:
        raise ValueError("github_evidence fields do not match GitHubEvidence")
    _text(value["run_id"], "github_evidence.run_id", maximum=256)
    task_id = _text(value["task_id"], "github_evidence.task_id", maximum=256)
    trace_id = _text(value["trace_id"], "github_evidence.trace_id", maximum=512)
    if trace_id != f'{value["run_id"]}:{task_id}':
        raise ValueError("GitHubEvidence trace_id does not match run and task")
    repository_value = value["repository"]
    if not isinstance(repository_value, dict) or set(repository_value) != {"owner", "repo"}:
        raise ValueError("GitHubEvidence repository is invalid")
    rendered_repository = f'{repository_value.get("owner")}/{repository_value.get("repo")}'
    if rendered_repository != repository:
        raise ValueError("GitHubEvidence repository does not match the classified issue")
    if value["revision"] != revision or REVISION.fullmatch(revision) is None:
        raise ValueError("GitHubEvidence revision does not match the invocation")
    if value["status"] != "success":
        raise ValueError("GitHubEvidence status must be success")
    operations = value["operations"]
    evidence = value["evidence"]
    if (
        not isinstance(operations, list)
        or not 1 <= len(operations) <= 32
        or any(not isinstance(item, dict) for item in operations)
        or not isinstance(evidence, list)
        or len(evidence) != len(operations)
    ):
        raise ValueError("GitHubEvidence operations and evidence are invalid")
    by_path: dict[str, dict[str, str]] = {}
    for item in evidence:
        if not isinstance(item, dict) or set(item) != GITHUB_EVIDENCE_FIELDS:
            raise ValueError("GitHubEvidence summary fields do not match")
        path = _path(item["path"], "GitHubEvidence path")
        if path in by_path:
            raise ValueError("GitHubEvidence paths must be unique")
        if not isinstance(item["object_sha"], str) or OBJECT_SHA.fullmatch(item["object_sha"]) is None:
            raise ValueError("GitHubEvidence object_sha is invalid")
        for field in ("content_sha256", "response_digest"):
            if not isinstance(item[field], str) or DIGEST.fullmatch(item[field]) is None:
                raise ValueError(f"GitHubEvidence {field} is invalid")
        by_path[path] = item
    digest = value["digest"]
    unsigned = {key: item for key, item in value.items() if key != "digest"}
    if not isinstance(digest, str) or digest != _canonical_digest(unsigned):
        raise ValueError("GitHubEvidence digest does not match")
    return by_path


def _validate_input(value: dict[str, Any]) -> dict[str, dict[str, str]]:
    if set(value) != INPUT_FIELDS:
        raise ValueError("code-root-cause SkillInvocation fields do not match")
    issue_id = _positive_int(value["issue_id"], "issue_id")
    revision = value["repository_revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("repository_revision must be a lowercase immutable commit SHA")
    classified = _validate_classified(value["classified_issue"], issue_id=issue_id)
    issue = classified["issue"]
    repository = f'{issue["repo_owner"]}/{issue["repo_name"]}'
    return _validate_github_evidence(
        value["github_evidence"],
        revision=revision,
        repository=repository,
    )


def _validate_result(value: dict[str, Any], source: dict[str, Any]) -> None:
    if set(value) != OUTPUT_FIELDS:
        raise ValueError("LocatedContext fields do not match the contract")
    evidence_by_path = _validate_input(source)
    issue_id = _positive_int(value["issue_id"], "issue_id")
    if issue_id != source["issue_id"]:
        raise ValueError("LocatedContext issue_id does not match the invocation")
    revision = value["repository_revision"]
    if revision != source["repository_revision"]:
        raise ValueError("LocatedContext repository revision does not match the invocation")
    root = value["root_cause"]
    if not isinstance(root, dict) or set(root) != {
        "summary",
        "file",
        "start_line",
        "end_line",
        "confidence",
    }:
        raise ValueError("root_cause fields do not match")
    _text(root["summary"], "root_cause.summary", maximum=4_096)
    root_path = _path(root["file"], "root_cause.file")
    start = _positive_int(root["start_line"], "root_cause.start_line")
    end = _positive_int(root["end_line"], "root_cause.end_line")
    if end < start:
        raise ValueError("root_cause line range is reversed")
    root_confidence = _number(
        root["confidence"], "root_cause.confidence", minimum=0.30, maximum=1.0
    )
    confidence = _number(value["confidence"], "confidence", minimum=0.30, maximum=1.0)
    if confidence != root_confidence:
        raise ValueError("LocatedContext confidence does not match root_cause")
    affected = value["affected_files"]
    if not isinstance(affected, list) or not 1 <= len(affected) <= 128:
        raise ValueError("affected_files must be a bounded non-empty list")
    affected_paths: list[str] = []
    for item in affected:
        if not isinstance(item, dict) or set(item) != {"path", "reason", "change_type"}:
            raise ValueError("affected file fields do not match")
        affected_paths.append(_path(item["path"], "affected file path"))
        _text(item["reason"], "affected file reason", maximum=2_048)
        if item["change_type"] not in {"edit", "review", "test"}:
            raise ValueError("affected file change_type is unsupported")
    if len(affected_paths) != len(set(affected_paths)) or root_path not in affected_paths:
        raise ValueError("affected file paths must be unique and include the root cause")
    related = value["related_tests"]
    if (
        not isinstance(related, list)
        or len(related) > 128
        or len(related) != len(set(item for item in related if isinstance(item, str)))
    ):
        raise ValueError("related_tests must be a unique bounded list")
    related_paths = [_path(item, "related test path") for item in related]
    context_ref = value["context_ref"]
    if not isinstance(context_ref, dict) or set(context_ref) != {"path", "sha256"}:
        raise ValueError("context_ref fields do not match")
    if context_ref["path"] != root_path:
        raise ValueError("context_ref path must equal the root-cause path")
    digest = context_ref["sha256"]
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise ValueError("context_ref digest is invalid")
    cited = value["evidence"]
    if not isinstance(cited, list) or not 1 <= len(cited) <= 32:
        raise ValueError("LocatedContext evidence must be a bounded non-empty list")
    cited_paths: list[str] = []
    for item in cited:
        if not isinstance(item, dict) or set(item) != GITHUB_EVIDENCE_FIELDS:
            raise ValueError("LocatedContext evidence fields do not match GitHubEvidence")
        path = _path(item["path"], "LocatedContext evidence path")
        if evidence_by_path.get(path) != item:
            raise ValueError("LocatedContext evidence was not present in verified GitHubEvidence")
        cited_paths.append(path)
    if len(cited_paths) != len(set(cited_paths)):
        raise ValueError("LocatedContext evidence paths must be unique")
    required_paths = {root_path, *affected_paths, *related_paths}
    if not required_paths <= set(cited_paths):
        raise ValueError("LocatedContext cites paths without verified GitHub evidence")
    if evidence_by_path[root_path]["content_sha256"] != digest:
        raise ValueError("context_ref digest does not match verified root-cause content")


def _validate_failure(value: dict[str, Any], source: dict[str, Any]) -> None:
    if set(value) != FAILURE_FIELDS:
        raise ValueError("SkillFailure fields do not match the contract")
    _validate_input(source)
    if value["schema_version"] != "1.0" or value["skill"] != SKILL:
        raise ValueError("SkillFailure identity is invalid")
    rule = FAILURES.get(value["code"])
    if rule is None:
        raise ValueError("SkillFailure code is not declared")
    retryable, maximum, event = rule
    if (
        value["retryable"] is not retryable
        or value["max_attempts"] != maximum
        or value["route_to"] != "TeamLeader"
        or value["event"] != event
    ):
        raise ValueError("SkillFailure policy fields do not match the declared failure")
    count = value["retry_count"]
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= maximum:
        raise ValueError("SkillFailure retry_count is invalid")
    if value["exhausted"] is not (not retryable or count == maximum):
        raise ValueError("SkillFailure exhausted flag is inconsistent")
    digest = value["source_artifact_sha256"]
    if not isinstance(digest, str) or digest != _canonical_digest(source):
        raise ValueError("SkillFailure source digest does not match the invocation")
    _text(value["summary"], "SkillFailure summary", maximum=1_024)
    diagnostics = value["diagnostics"]
    if (
        not isinstance(diagnostics, list)
        or len(diagnostics) > 16
        or len(diagnostics) != len(set(item for item in diagnostics if isinstance(item, str)))
        or any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 2_048
            or item != item.strip()
            or CONTROL.search(item) is not None
            for item in diagnostics
        )
    ):
        raise ValueError("SkillFailure diagnostics are invalid")


def main() -> int:
    if len(sys.argv) not in {3, 4} or sys.argv[1] not in {"input", "output"}:
        print("usage: validate.py <input|output> <artifact.json> [source.json]", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    if (mode == "input" and len(sys.argv) != 3) or (mode == "output" and len(sys.argv) != 4):
        print("output validation requires the exact source artifact", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root / "references" / "contract.yaml")
    artifact = _load(Path(sys.argv[2]))
    if any(SECRET.search(text) for text in _strings(artifact)):
        raise ValueError("artifact contains secret-shaped content")
    if mode == "input":
        _validate_input(artifact)
    else:
        source = _load(Path(sys.argv[3]))
        if any(SECRET.search(text) for text in _strings(source)):
            raise ValueError("source contains secret-shaped content")
        if set(artifact) == FAILURE_FIELDS:
            _validate_failure(artifact, source)
        else:
            _validate_result(artifact, source)
    print(json.dumps({"valid": True, "skill": contract["name"], "mode": mode}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

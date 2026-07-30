"""Strictly validate issue-classifier inputs, results, and declared failures."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SKILL = "issue-classifier"
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
OWNER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?$")
RULE_ID = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
TIERS = ("T1", "T2", "T3", "T4", "T5")
CATEGORIES = frozenset({"bug", "feature", "docs", "refactor"})
PRIORITIES = frozenset({"critical", "high", "medium", "low"})
INTAKE_FIELDS = frozenset(
    {"issue_number", "title", "author", "repo_owner", "repo_name", "created_at"}
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
OUTPUT_FIELDS = frozenset(
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
    "EXPERIENCE_UNAVAILABLE": (True, 1, "triage.degraded"),
    "CLASSIFICATION_INVALID": (True, 2, "triage.degraded"),
    "INPUT_INVALID": (False, 0, "triage.failed"),
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
        if not 1 <= path.stat().st_size <= 1_000_000:
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


def _timestamp(value: Any) -> str:
    rendered = _text(value, "created_at", maximum=64)
    try:
        parsed = dt.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("created_at must include a timezone")
    return rendered


def _repository(owner_value: Any, repo_value: Any) -> tuple[str, str]:
    owner = _text(owner_value, "repo_owner", maximum=100)
    repo = _text(repo_value, "repo_name", maximum=100)
    if (
        OWNER.fullmatch(owner) is None
        or "--" in owner
        or REPOSITORY.fullmatch(repo) is None
        or repo in {".", ".."}
    ):
        raise ValueError("repository identity is invalid")
    return owner, repo


def _validate_intake(value: dict[str, Any]) -> None:
    if set(value) != INTAKE_FIELDS:
        raise ValueError("IssueIntake fields do not match the contract")
    _positive_int(value["issue_number"], "issue_number")
    _text(value["title"], "title", maximum=512)
    _text(value["author"], "author", maximum=256)
    _repository(value["repo_owner"], value["repo_name"])
    _timestamp(value["created_at"])


def _validate_issue(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ISSUE_FIELDS:
        raise ValueError("issue fields do not match IssueData")
    _positive_int(value["issue_number"], "issue.issue_number")
    _text(value["title"], "issue.title", maximum=512)
    body = value["body"]
    if body is not None and (
        not isinstance(body, str)
        or len(body) > 65_536
        or CONTROL.search(body) is not None
    ):
        raise ValueError("issue.body is invalid")
    labels = value["labels"]
    if (
        not isinstance(labels, list)
        or len(labels) > 100
        or len(labels) != len(set(item for item in labels if isinstance(item, str)))
        or any(
            not isinstance(item, str)
            or not 1 <= len(item) <= 256
            or item != item.strip()
            or CONTROL.search(item) is not None
            for item in labels
        )
    ):
        raise ValueError("issue.labels must be unique bounded strings")
    if value["state"] not in {"open", "closed"}:
        raise ValueError("issue.state is unsupported")
    _text(value["author"], "issue.author", maximum=256)
    _repository(value["repo_owner"], value["repo_name"])
    _timestamp(value["created_at"])
    return value


def _validate_risk_evidence(value: Any, *, tier: str, confidence: float) -> None:
    if not isinstance(value, dict) or set(value) != {"risk_floor", "deduplication"}:
        raise ValueError("classification evidence fields do not match")
    risk = value["risk_floor"]
    if not isinstance(risk, dict) or set(risk) != {
        "proposed_tier",
        "effective_tier",
        "rule_ids",
        "model_confidence",
        "conflict",
    }:
        raise ValueError("risk_floor evidence fields do not match")
    proposed = risk["proposed_tier"]
    effective = risk["effective_tier"]
    if proposed not in TIERS or effective != tier:
        raise ValueError("risk-floor tiers do not match the classification")
    if TIERS.index(effective) < TIERS.index(proposed):
        raise ValueError("risk floor may not lower the proposed tier")
    rule_ids = risk["rule_ids"]
    if (
        not isinstance(rule_ids, list)
        or len(rule_ids) > 32
        or rule_ids != sorted(set(rule_ids))
        or any(not isinstance(item, str) or RULE_ID.fullmatch(item) is None for item in rule_ids)
    ):
        raise ValueError("risk_floor.rule_ids must be sorted and unique")
    model_confidence = risk["model_confidence"]
    if model_confidence is None:
        expected_confidence = 0.0
    else:
        expected_confidence = _number(
            model_confidence,
            "risk_floor.model_confidence",
            minimum=0.0,
            maximum=1.0,
        )
    if confidence != expected_confidence:
        raise ValueError("classification confidence does not match risk evidence")
    if not isinstance(risk["conflict"], bool):
        raise ValueError("risk_floor.conflict must be a boolean")
    if (model_confidence is None or expected_confidence < 0.5 or risk["conflict"]) and tier not in {
        "T4",
        "T5",
    }:
        raise ValueError("low-confidence or conflicting classification must be T4 or T5")


def _validate_deduplication(value: Any, *, duplicate_of: int | None) -> None:
    if not isinstance(value, dict) or set(value) != {
        "status",
        "threshold",
        "candidate_issue",
        "candidate_score",
    }:
        raise ValueError("deduplication evidence fields do not match")
    if value["status"] not in {"checked", "degraded"}:
        raise ValueError("deduplication status is unsupported")
    threshold = _number(value["threshold"], "deduplication.threshold", minimum=0.0, maximum=1.0)
    if threshold != 0.92:
        raise ValueError("deduplication threshold must be 0.92")
    candidate_issue = value["candidate_issue"]
    candidate_score = value["candidate_score"]
    if candidate_issue is not None:
        _positive_int(candidate_issue, "deduplication.candidate_issue")
    if candidate_score is not None:
        candidate_score = _number(
            candidate_score,
            "deduplication.candidate_score",
            minimum=0.0,
            maximum=1.0,
        )
    if value["status"] == "degraded":
        if candidate_issue is not None or candidate_score is not None or duplicate_of is not None:
            raise ValueError("degraded deduplication cannot claim a candidate")
    elif (candidate_issue is None) != (candidate_score is None):
        raise ValueError("deduplication candidate identity and score must be paired")
    if duplicate_of is None:
        if candidate_score is not None and candidate_score >= threshold:
            raise ValueError("a threshold-matching candidate must be declared duplicate")
    elif candidate_issue != duplicate_of or candidate_score is None or candidate_score < threshold:
        raise ValueError("duplicate_of is not supported by deduplication evidence")


def _validate_result(value: dict[str, Any], source: dict[str, Any]) -> None:
    if set(value) != OUTPUT_FIELDS:
        raise ValueError("ClassifiedIssue fields do not match the contract")
    issue = _validate_issue(value["issue"])
    for field in INTAKE_FIELDS:
        if issue[field] != source[field]:
            raise ValueError("classified issue identity does not match IssueIntake")
    tier = value["complexity_level"]
    if tier not in TIERS:
        raise ValueError("complexity_level must be T1 through T5")
    if value["category"] not in CATEGORIES:
        raise ValueError("category is unsupported")
    if value["priority"] not in PRIORITIES:
        raise ValueError("priority is unsupported")
    duplicate_of = value["duplicate_of"]
    if duplicate_of is not None:
        _positive_int(duplicate_of, "duplicate_of")
        if duplicate_of == issue["issue_number"]:
            raise ValueError("an issue cannot duplicate itself")
    _number(
        value["estimated_effort_hours"],
        "estimated_effort_hours",
        minimum=0.0,
        maximum=100_000.0,
    )
    _text(value["rationale"], "rationale", maximum=4_096)
    confidence = _number(value["confidence"], "confidence", minimum=0.0, maximum=1.0)
    _validate_risk_evidence(value["evidence"], tier=tier, confidence=confidence)
    _validate_deduplication(value["evidence"]["deduplication"], duplicate_of=duplicate_of)


def _validate_failure(value: dict[str, Any], source: dict[str, Any]) -> None:
    if set(value) != FAILURE_FIELDS:
        raise ValueError("SkillFailure fields do not match the contract")
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
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise ValueError("SkillFailure source digest is invalid")
    if digest != _canonical_digest(source):
        raise ValueError("SkillFailure source digest does not match IssueIntake")
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


def _find_values(value: Any, target: str) -> list[Any]:
    if isinstance(value, dict):
        found = [value[target]] if target in value else []
        return found + [item for child in value.values() for item in _find_values(child, target)]
    if isinstance(value, list):
        return [item for child in value for item in _find_values(child, target)]
    return []


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
    for key in ("file", "file_path", "path"):
        for item in _find_values(artifact, key):
            path = PurePosixPath(str(item).replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe repository path: {item}")
    if mode == "input":
        _validate_intake(artifact)
    else:
        source = _load(Path(sys.argv[3]))
        _validate_intake(source)
        if set(artifact) == FAILURE_FIELDS:
            _validate_failure(artifact, source)
        else:
            _validate_result(artifact, source)
    print(json.dumps({"valid": True, "skill": contract["name"], "mode": mode}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

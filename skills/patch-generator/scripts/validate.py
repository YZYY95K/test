"""Validate patch-generator artifacts and retry envelopes without runtime imports."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}|"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|"
    r"Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    re.IGNORECASE,
)
SHA256 = re.compile(r"^[a-f0-9]{64}$")
REDACTION_MARKER = "[REDACTED]"
DANGEROUS = (
    re.compile(r"eval\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"__import__\s*\("),
    re.compile(r"subprocess\.(?:Popen|call|run)\s*\(.*shell\s*=\s*True"),
    re.compile(r"os\.system\s*\("),
)
FAILURE_FIELDS = {
    "schema_version",
    "issue_id",
    "candidate_digest",
    "test_result_digest",
    "baseline_present",
    "failed",
    "errors",
    "regression",
    "reasons",
    "failing_tests",
    "new_failures",
    "diagnostics",
    "redacted",
    "truncated",
}
INITIAL_INPUT_FIELDS = {
    "issue_id",
    "tier",
    "issue",
    "located_context",
    "model_call_attempt",
}
RETRY_INPUT_FIELDS = {
    "issue_id",
    "tier",
    "issue",
    "located_context",
    "previous_patch",
    "test_failure_evidence",
    "retry_attempt",
    "model_call_attempt",
}
CONTROL_INPUT_FIELDS = {"validator_feedback_code"}
VALIDATOR_FEEDBACK_CODES = {"CANDIDATE_INVALID", "MODEL_CALL_FAILED"}
REASON_ORDER = (
    "baseline_missing",
    "test_failures",
    "test_errors",
    "regression",
    "new_failures",
)


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in strings(child)]
    return []


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _require_boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_text(value: Any, label: str, *, maximum: int | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty text")
    if maximum is not None and len(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} characters")
    return value


def _canonical_repo_path(value: Any, label: str) -> str:
    raw = _require_text(value, label, maximum=4096)
    normalized_input = raw.replace("\\", "/")
    path = PurePosixPath(normalized_input)
    normalized = path.as_posix()
    if (
        path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or normalized in {"", "."}
        or re.match(r"^[A-Za-z]:", normalized) is not None
        or normalized_input.startswith("//")
        or normalized != normalized_input
    ):
        raise ValueError(f"unsafe or non-canonical repository path: {raw}")
    return normalized


def _is_test_path(value: str) -> bool:
    path = PurePosixPath(value)
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name
    lowered = name.lower()
    stem = name.rsplit(".", 1)[0]
    lowered_stem = stem.lower()
    return bool(
        parts.intersection({"test", "tests", "__tests__", "spec", "specs"})
        or lowered_stem in {"test", "tests", "spec", "specs"}
        or lowered_stem.startswith(("test_", "test-"))
        or lowered_stem.endswith(
            ("_test", "-test", ".test", "_spec", "-spec", ".spec", ".tests", ".specs")
        )
        or stem.endswith(("Test", "Tests", "Spec", "Specs"))
        or ".test." in lowered
        or ".spec." in lowered
    )


def _validate_issue(value: Any, issue_id: int) -> None:
    issue = _require_object(value, "issue")
    required = {
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
    if set(issue) != required:
        raise ValueError("issue fields do not match IssueData")
    if issue["issue_number"] != issue_id:
        raise ValueError("issue.issue_number does not match issue_id")
    _require_text(issue["title"], "issue.title", maximum=512)
    if issue["body"] is not None and not isinstance(issue["body"], str):
        raise ValueError("issue.body must be text or null")
    if not isinstance(issue["labels"], list) or any(
        not isinstance(label, str) for label in issue["labels"]
    ):
        raise ValueError("issue.labels must be a string list")
    for field in ("state", "author", "created_at", "repo_owner", "repo_name"):
        _require_text(issue[field], f"issue.{field}")


def _validate_located_context(value: Any) -> dict[str, Any]:
    located = _require_object(value, "located_context")
    required = {
        "root_cause",
        "affected_files",
        "context_payload",
        "related_tests",
        "impact_analysis",
    }
    if set(located) != required:
        raise ValueError("located_context fields do not match LocatedContext")
    root_cause = _require_object(located["root_cause"], "located_context.root_cause")
    if set(root_cause) != {
        "summary",
        "file",
        "start_line",
        "end_line",
        "confidence",
    }:
        raise ValueError("located_context.root_cause fields are invalid")
    _require_text(root_cause["summary"], "located_context.root_cause.summary")
    _canonical_repo_path(root_cause["file"], "located_context.root_cause.file")
    start = _require_integer(
        root_cause["start_line"], "located_context.root_cause.start_line", minimum=1
    )
    end = _require_integer(root_cause["end_line"], "located_context.root_cause.end_line", minimum=1)
    if end < start:
        raise ValueError("located_context.root_cause line range is reversed")
    confidence = root_cause["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise ValueError("located_context.root_cause.confidence must be numeric")
    if not 0 <= confidence <= 1:
        raise ValueError("located_context.root_cause.confidence must be between 0 and 1")
    _require_text(located["context_payload"], "located_context.context_payload")
    affected = located["affected_files"]
    if not isinstance(affected, list):
        raise ValueError("located_context.affected_files must be a list")
    for index, item in enumerate(affected):
        entry = _require_object(item, f"located_context.affected_files[{index}]")
        if set(entry) != {"path", "reason", "change_type"}:
            raise ValueError("located_context.affected_files fields are invalid")
        _canonical_repo_path(entry["path"], f"located_context.affected_files[{index}].path")
        _require_text(entry["reason"], f"located_context.affected_files[{index}].reason")
        if entry["change_type"] not in {"edit", "review", "test"}:
            raise ValueError("located_context affected-file change_type is invalid")
    related = located["related_tests"]
    if not isinstance(related, list):
        raise ValueError("located_context.related_tests must be a list")
    for index, path in enumerate(related):
        _canonical_repo_path(path, f"located_context.related_tests[{index}]")
    impact = _require_object(located["impact_analysis"], "located_context.impact_analysis")
    if set(impact) != {
        "affected_files",
        "affected_modules",
        "risk_level",
        "breaking_changes",
        "test_files_needed",
    }:
        raise ValueError("located_context.impact_analysis fields are invalid")
    for field in ("affected_files", "affected_modules", "test_files_needed"):
        if not isinstance(impact[field], list):
            raise ValueError(f"located_context.impact_analysis.{field} must be a list")
    for field in ("affected_files", "test_files_needed"):
        for index, path in enumerate(impact[field]):
            _canonical_repo_path(path, f"located_context.impact_analysis.{field}[{index}]")
    if any(not isinstance(name, str) or not name for name in impact["affected_modules"]):
        raise ValueError("located_context.impact_analysis.affected_modules is invalid")
    if impact["risk_level"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("located_context.impact_analysis.risk_level is invalid")
    _require_boolean(impact["breaking_changes"], "located_context.impact_analysis.breaking_changes")
    return located


def _allowed_files_from_located(located: dict[str, Any]) -> list[str]:
    supplied = {
        located["root_cause"]["file"],
        *located["related_tests"],
        *located["impact_analysis"]["affected_files"],
        *located["impact_analysis"]["test_files_needed"],
        *(item["path"] for item in located["affected_files"]),
    }
    allowed = sorted(_canonical_repo_path(path, "located evidence path") for path in supplied)
    if not allowed:
        raise ValueError("located evidence does not authorize any patch path")
    return allowed


def _validate_evidence_boundary(value: Any) -> dict[str, Any]:
    boundary = _require_object(value, "evidence_boundary")
    if set(boundary) != {
        "schema_version",
        "located_context_digest",
        "allowed_files",
        "scope_digest",
    }:
        raise ValueError("evidence_boundary fields do not match the contract")
    if boundary["schema_version"] != "1.0":
        raise ValueError("evidence_boundary schema_version must be 1.0")
    _require_digest(boundary["located_context_digest"], "located_context_digest")
    allowed = boundary["allowed_files"]
    if not isinstance(allowed, list) or not 1 <= len(allowed) <= 256:
        raise ValueError("evidence_boundary.allowed_files must contain 1..256 paths")
    normalized = [
        _canonical_repo_path(path, f"evidence_boundary.allowed_files[{index}]")
        for index, path in enumerate(allowed)
    ]
    if normalized != sorted(set(normalized)):
        raise ValueError("evidence_boundary.allowed_files must be sorted and unique")
    scope_body = {
        "schema_version": "1.0",
        "located_context_digest": boundary["located_context_digest"],
        "allowed_files": normalized,
    }
    if _require_digest(boundary["scope_digest"], "scope_digest") != _canonical_digest(scope_body):
        raise ValueError("scope_digest does not bind the exact evidence boundary")
    return boundary


def _validate_patch(value: Any) -> dict[str, Any]:
    patch = _require_object(value, "patch")
    if set(patch) != {"branch_name", "changes", "commit_message", "description"}:
        raise ValueError("patch fields do not match Patch")
    _require_text(patch["branch_name"], "patch.branch_name", maximum=255)
    _require_text(patch["commit_message"], "patch.commit_message")
    _require_text(patch["description"], "patch.description")
    changes = patch["changes"]
    if not isinstance(changes, list) or not changes:
        raise ValueError("patch.changes must be a non-empty list")
    required_change = {
        "file_path",
        "change_type",
        "original_content",
        "new_content",
        "diff",
    }
    seen: set[str] = set()
    for index, change in enumerate(changes):
        if not isinstance(change, dict) or set(change) != required_change:
            raise ValueError(f"patch.changes[{index}] fields do not match FileChange")
        raw_path = _require_text(
            change["file_path"],
            f"patch.changes[{index}].file_path",
        )
        normalized = _canonical_repo_path(
            raw_path,
            f"patch.changes[{index}].file_path",
        )
        if normalized in seen:
            raise ValueError("patch contains duplicate changes for one file")
        seen.add(normalized)
        change_type = change["change_type"]
        if change_type not in {"create", "modify", "delete"}:
            raise ValueError(f"patch.changes[{index}].change_type is invalid")
        if change_type == "delete" and _is_test_path(normalized):
            raise ValueError(f"patch.changes[{index}] cannot delete a test file")
        diff = _require_text(change["diff"], f"patch.changes[{index}].diff")
        for field in ("original_content", "new_content"):
            if change[field] is not None and not isinstance(change[field], str):
                raise ValueError(f"patch.changes[{index}].{field} must be text or null")
        if change_type == "create":
            valid_content = change["original_content"] is None and change["new_content"] is not None
            expected_headers = ("--- /dev/null", f"+++ b/{normalized}")
        elif change_type == "delete":
            valid_content = change["original_content"] is not None and change["new_content"] is None
            expected_headers = (f"--- a/{normalized}", "+++ /dev/null")
        else:
            valid_content = (
                change["original_content"] is not None and change["new_content"] is not None
            )
            expected_headers = (f"--- a/{normalized}", f"+++ b/{normalized}")
        if not valid_content:
            raise ValueError(f"patch.changes[{index}] type conflicts with its contents")
        if tuple(diff.splitlines()[:2]) != expected_headers:
            raise ValueError(f"patch.changes[{index}] unified-diff headers do not match")
        candidate_text = change["new_content"] or change["diff"]
        if any(pattern.search(candidate_text) for pattern in DANGEROUS):
            raise ValueError(f"patch.changes[{index}] contains a dangerous pattern")
        if normalized.endswith(".py") and change["new_content"] is not None:
            try:
                ast.parse(change["new_content"], filename=normalized)
            except SyntaxError as exc:
                raise ValueError(f"patch.changes[{index}] contains invalid Python syntax") from exc
    return patch


def _validate_model_call_attempt(value: Any, retry_attempt: int) -> int:
    attempt = _require_integer(value, "model_call_attempt", minimum=1)
    if attempt > 3:
        raise ValueError("model_call_attempt exceeds the three-call global budget")
    if attempt < retry_attempt:
        raise ValueError("model_call_attempt cannot precede retry_attempt")
    return attempt


def _validate_feedback_code(
    value: dict[str, Any],
    model_call_attempt: int,
    *,
    required: bool = False,
) -> str | None:
    feedback = value.get("validator_feedback_code")
    if feedback is None:
        if required:
            raise ValueError("validator_feedback_code is required for a validation retry")
        return None
    if feedback not in VALIDATOR_FEEDBACK_CODES or model_call_attempt == 1:
        raise ValueError("validator_feedback_code is not trusted for this model-call ordinal")
    return str(feedback)


def _validate_initial_input(
    value: dict[str, Any],
) -> tuple[dict[str, Any], int, int]:
    missing = sorted(INITIAL_INPUT_FIELDS - set(value))
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if set(value) - INITIAL_INPUT_FIELDS - CONTROL_INPUT_FIELDS:
        raise ValueError("initial SkillInvocation fields do not match the contract")
    issue_id = _require_integer(value["issue_id"], "issue_id", minimum=1)
    if value["tier"] not in {"T1", "T2", "T3", "T4", "T5"}:
        raise ValueError("tier must be T1 through T5")
    _validate_issue(value["issue"], issue_id)
    model_call_attempt = _validate_model_call_attempt(value["model_call_attempt"], 1)
    _validate_feedback_code(
        value,
        model_call_attempt,
        required=model_call_attempt > 1,
    )
    return _validate_located_context(value["located_context"]), 1, model_call_attempt


def _validate_patch_candidate(
    value: dict[str, Any],
    *,
    located_context: dict[str, Any] | None = None,
    authorized_retry_attempt: int | None = None,
    authorized_model_call_attempt: int | None = None,
) -> None:
    required = {
        "schema_version",
        "issue_id",
        "tier",
        "patch",
        "candidate_digest",
        "evidence_boundary",
        "model_call_attempt",
        "retry_attempt",
    }
    allowed = required | {"revision_of"}
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if set(value) - allowed:
        raise ValueError("PatchCandidate fields do not match the contract")
    if value["schema_version"] != "1.2":
        raise ValueError("PatchCandidate schema_version must be 1.2")
    _require_integer(value["issue_id"], "issue_id", minimum=1)
    if value["tier"] not in {"T1", "T2", "T3", "T4", "T5"}:
        raise ValueError("tier must be T1 through T5")
    patch = _validate_patch(value["patch"])
    candidate_digest = _require_digest(value["candidate_digest"], "candidate_digest")
    if candidate_digest != _canonical_digest(patch):
        raise ValueError("candidate_digest does not bind the exact patch")
    boundary = _validate_evidence_boundary(value["evidence_boundary"])
    allowed_files = frozenset(boundary["allowed_files"])
    for change in patch["changes"]:
        if change["file_path"] not in allowed_files:
            raise ValueError("Patch changes a file outside the located evidence boundary")
    attempt = _require_integer(value["retry_attempt"], "retry_attempt", minimum=1)
    if attempt > 3:
        raise ValueError("retry_attempt exceeds the three-attempt budget")
    model_call_attempt = _validate_model_call_attempt(value["model_call_attempt"], attempt)
    if authorized_retry_attempt is not None and attempt != authorized_retry_attempt:
        raise ValueError("retry_attempt does not match the verified authorization source")
    if (
        authorized_model_call_attempt is not None
        and model_call_attempt != authorized_model_call_attempt
    ):
        raise ValueError("model_call_attempt does not match the verified authorization source")
    revision_of = value.get("revision_of")
    if attempt == 1 and revision_of is not None:
        raise ValueError("initial PatchCandidate cannot declare revision_of")
    if attempt > 1:
        _require_digest(revision_of, "revision_of")
    if located_context is not None:
        expected_body = {
            "schema_version": "1.0",
            "located_context_digest": _canonical_digest(located_context),
            "allowed_files": _allowed_files_from_located(located_context),
        }
        expected = {
            **expected_body,
            "scope_digest": _canonical_digest(expected_body),
        }
        if boundary != expected:
            raise ValueError("evidence_boundary does not match the verified LocatedContext")


def _bounded_names(value: Any, label: str, *, maximum: int = 128) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must contain at most {maximum} names")
    if any(not isinstance(name, str) or not 1 <= len(name) <= 512 for name in value):
        raise ValueError(f"{label} names must contain 1..512 characters")
    if len(value) != len(set(value)):
        raise ValueError(f"{label} names must be unique")
    return value


def _validate_diagnostics(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError("diagnostics must contain at most 32 entries")
    allowed = {"name", "status", "error_message", "traceback"}
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) - allowed or not {"name", "status"} <= set(item):
            raise ValueError(f"diagnostics[{index}] has an invalid shape")
        name = item["name"]
        if not isinstance(name, str) or not 1 <= len(name) <= 512:
            raise ValueError(f"diagnostics[{index}].name must contain 1..512 characters")
        if item["status"] not in {"failed", "error"}:
            raise ValueError(f"diagnostics[{index}].status must be failed or error")
        for field, maximum in (("error_message", 2048), ("traceback", 4000)):
            text = item.get(field)
            if text is not None and (not isinstance(text, str) or len(text) > maximum):
                raise ValueError(f"diagnostics[{index}].{field} exceeds its bound")


def _validate_failure_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("test_failure_evidence must be an object")
    missing = sorted(FAILURE_FIELDS - set(value))
    extra = sorted(set(value) - FAILURE_FIELDS)
    if missing:
        raise ValueError(f"missing failure evidence fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"unknown failure evidence fields: {', '.join(extra)}")
    if value["schema_version"] != "1.2":
        raise ValueError("failure evidence schema_version must be 1.2")
    _require_integer(value["issue_id"], "failure evidence issue_id", minimum=1)
    _require_digest(value["candidate_digest"], "candidate_digest")
    _require_digest(value["test_result_digest"], "test_result_digest")
    baseline_present = _require_boolean(value["baseline_present"], "baseline_present")
    failed = _require_integer(value["failed"], "failed")
    errors = _require_integer(value["errors"], "errors")
    regression = _require_boolean(value["regression"], "regression")
    new_failures = _bounded_names(value["new_failures"], "new_failures")
    _bounded_names(value["failing_tests"], "failing_tests")
    _validate_diagnostics(value["diagnostics"])
    _require_boolean(value["truncated"], "truncated")
    redacted = _require_boolean(value["redacted"], "redacted")

    expected: list[str] = []
    facts = (
        not baseline_present,
        failed > 0,
        errors > 0,
        regression,
        bool(new_failures),
    )
    expected.extend(reason for reason, present in zip(REASON_ORDER, facts, strict=True) if present)
    if not expected:
        raise ValueError("passing facts cannot produce TestFailureEvidence")
    if value["reasons"] != expected:
        raise ValueError("failure reasons do not match the ordered gate facts")
    if any(REDACTION_MARKER in text for text in strings(value)) and not redacted:
        raise ValueError("redacted must report use of the redaction marker")
    return value


def _contains_key(value: Any, target: str) -> bool:
    if isinstance(value, dict):
        return target in value or any(_contains_key(child, target) for child in value.values())
    if isinstance(value, list):
        return any(_contains_key(child, target) for child in value)
    return False


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def _validate_retry_input(
    value: Any,
) -> tuple[int, int, int, dict[str, Any], dict[str, Any]]:
    retry_input = _require_object(value, "retry input")
    missing = sorted(RETRY_INPUT_FIELDS - set(retry_input))
    extra = sorted(set(retry_input) - RETRY_INPUT_FIELDS - CONTROL_INPUT_FIELDS)
    if missing:
        raise ValueError(f"missing retry input fields: {', '.join(missing)}")
    if _contains_key(retry_input, "test_result"):
        raise ValueError("raw or sanitized test_result is forbidden in a Coder retry")
    if extra:
        raise ValueError(f"unknown retry input fields: {', '.join(extra)}")

    issue_id = _require_integer(retry_input["issue_id"], "issue_id", minimum=1)
    attempt = _require_integer(retry_input["retry_attempt"], "retry_attempt", minimum=2)
    if attempt > 3:
        raise ValueError("retry_attempt exceeds the three-attempt budget")
    model_call_attempt = _validate_model_call_attempt(
        retry_input["model_call_attempt"],
        attempt,
    )
    _validate_feedback_code(retry_input, model_call_attempt)
    if retry_input["tier"] not in {"T1", "T2", "T3", "T4", "T5"}:
        raise ValueError("tier must be T1 through T5")

    _validate_issue(retry_input["issue"], issue_id)
    located_context = _validate_located_context(retry_input["located_context"])
    previous_patch = _validate_patch(retry_input["previous_patch"])
    evidence = _validate_failure_evidence(retry_input["test_failure_evidence"])
    if evidence["issue_id"] != issue_id:
        raise ValueError("failure evidence issue_id does not match retry input")
    if evidence["candidate_digest"] != _canonical_digest(previous_patch):
        raise ValueError("failure evidence does not bind the exact previous_patch")
    return issue_id, attempt, model_call_attempt, evidence, located_context


def _validate_generation_budget(value: Any, model_call_attempt: int) -> None:
    budget = _require_object(value, "generation_budget")
    expected = {
        "schema_version": "devflow.generation-budget/v1",
        "model_call_attempt": model_call_attempt,
        "max_model_calls": 3,
    }
    if budget != expected:
        raise ValueError("generation_budget does not match the retry input")


def _validate_generation_retry(
    value: Any,
    *,
    model_call_attempt: int,
    feedback_code: str | None,
) -> None:
    retry = _require_object(value, "generation_retry")
    required = {
        "schema_version",
        "model_call_attempt",
        "max_model_calls",
        "failure_id",
        "reason",
    }
    if set(retry) != required:
        raise ValueError("generation_retry has an invalid shape")
    if (
        retry["schema_version"] != "devflow.generation-retry/v1"
        or retry["model_call_attempt"] != model_call_attempt
        or retry["max_model_calls"] != 3
        or retry["reason"] != feedback_code
    ):
        raise ValueError("generation_retry does not match the retry input")
    _require_text(retry["failure_id"], "generation_retry.failure_id", maximum=512)


def _validate_retry_envelope(
    envelope: dict[str, Any],
) -> tuple[dict[str, Any], int, int]:
    required = {
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
    missing = sorted(required - set(envelope))
    if missing:
        raise ValueError(f"missing retry envelope fields: {', '.join(missing)}")
    optional = {"agent", "parent_task_id", "parent_handoff_sha256"}
    if set(envelope) - required - optional:
        raise ValueError("retry envelope contains unknown fields")
    if envelope["envelope_version"] != "1.0":
        raise ValueError("envelope_version must be 1.0")
    if (envelope["producer"], envelope["consumer"], envelope["skill"], envelope["status"]) != (
        "TeamLeader",
        "CoderAgent",
        "patch-generator",
        "retry",
    ):
        raise ValueError("retry envelope producer, consumer, skill, or status is invalid")
    if envelope.get("agent", "TeamLeader") != "TeamLeader":
        raise ValueError("enriched retry envelope agent must be TeamLeader")
    parent_task_id = envelope.get("parent_task_id")
    parent_digest = envelope.get("parent_handoff_sha256")
    if (parent_task_id is None) != (parent_digest is None):
        raise ValueError("retry envelope parent correlation is incomplete")
    if parent_task_id is not None:
        if not isinstance(parent_task_id, str) or not parent_task_id:
            raise ValueError("retry envelope parent task id is invalid")
        if (
            not isinstance(parent_digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", parent_digest) is None
        ):
            raise ValueError("retry envelope parent digest is invalid")
    _require_integer(envelope["issue_id"], "envelope issue_id", minimum=1)

    run_id = envelope["run_id"]
    task_id = envelope["task_id"]
    if not isinstance(run_id, str) or not run_id or not isinstance(task_id, str) or not task_id:
        raise ValueError("run_id and task_id must be non-empty strings")
    if envelope["trace_id"] != f"{run_id}:{task_id}":
        raise ValueError("trace_id is not bound to run_id and task_id")
    expected_key = f"{run_id}:{task_id}:CoderAgent:patch-generator"
    if envelope["idempotency_key"] != expected_key:
        raise ValueError("idempotency_key is not bound to the retry identity")
    try:
        created_at = datetime.fromisoformat(str(envelope["created_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an ISO-8601 timestamp") from exc
    if created_at.tzinfo is None:
        raise ValueError("created_at must include a timezone")

    artifact = _require_object(envelope["artifact"], "artifact")
    artifact_fields = {"type", "schema_version", "inline", "ref", "sha256"}
    if set(artifact) != artifact_fields:
        raise ValueError("retry artifact has an invalid shape")
    if artifact["type"] != "SkillInvocation" or artifact["schema_version"] != "1.0":
        raise ValueError("retry artifact type or schema version is invalid")
    if artifact["ref"] is not None:
        raise ValueError("retry artifact must use an inline payload")
    inline = _require_object(artifact["inline"], "artifact.inline")
    if artifact["sha256"] != _canonical_digest(inline):
        raise ValueError("retry artifact digest does not match its inline payload")
    base_fields = {"tier", "input", "depends_on"}
    allowed_fields = base_fields | {"retry", "generation_budget", "generation_retry"}
    if not base_fields <= set(inline) or set(inline) - allowed_fields:
        raise ValueError("retry SkillInvocation has an invalid shape")

    semantic_retry = "retry" in inline
    if semantic_retry:
        if "generation_budget" not in inline:
            raise ValueError("semantic retry requires generation_budget")
        issue_id, attempt, model_call_attempt, evidence, located_context = (
            _validate_retry_input(inline["input"])
        )
    else:
        if "generation_budget" in inline or "generation_retry" not in inline:
            raise ValueError("validation retry metadata is incomplete")
        located_context, attempt, model_call_attempt = _validate_initial_input(
            _require_object(inline["input"], "retry input")
        )
        issue_id = int(inline["input"]["issue_id"])
        evidence = None
    if envelope["issue_id"] != issue_id or inline["tier"] != inline["input"]["tier"]:
        raise ValueError("retry envelope issue or tier is inconsistent")
    depends_on = inline["depends_on"]
    if (
        not isinstance(depends_on, list)
        or not depends_on
        or any(not isinstance(item, str) or not item for item in depends_on)
    ):
        raise ValueError("depends_on must contain at least one task id")
    if semantic_retry:
        assert evidence is not None
        retry = _require_object(inline["retry"], "retry metadata")
        if set(retry) != {"attempt", "max_attempts", "reason", "test_result_digest"}:
            raise ValueError("retry metadata has an invalid shape")
        if retry != {
            "attempt": attempt,
            "max_attempts": 3,
            "reason": "test_failed",
            "test_result_digest": evidence["test_result_digest"],
        }:
            raise ValueError("retry metadata does not match the bounded retry input")
        _validate_generation_budget(inline["generation_budget"], model_call_attempt)

    feedback_code = inline["input"].get("validator_feedback_code")
    generation_retry = inline.get("generation_retry")
    if generation_retry is None and feedback_code is not None:
        raise ValueError("validator feedback requires generation_retry metadata")
    if generation_retry is not None:
        _validate_generation_retry(
            generation_retry,
            model_call_attempt=model_call_attempt,
            feedback_code=feedback_code,
        )
    return located_context, attempt, model_call_attempt


def _find_values(value: Any, target: str) -> list[Any]:
    if isinstance(value, dict):
        found = [value[target]] if target in value else []
        return found + [item for child in value.values() for item in _find_values(child, target)]
    if isinstance(value, list):
        return [item for child in value for item in _find_values(child, target)]
    return []


def _validate_common(artifact: dict[str, Any]) -> None:
    if any(SECRET.search(text) for text in strings(artifact)):
        raise ValueError("artifact contains secret-shaped content")
    for key in ("file", "file_path", "path"):
        for value in _find_values(artifact, key):
            path = PurePosixPath(str(value).replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe repository path: {value}")


def _run(
    mode: str,
    path: Path,
    source_path: Path | None = None,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root / "references" / "contract.yaml")
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise ValueError("artifact root must be an object")
    if mode == "input":
        _validate_initial_input(artifact)
    elif mode == "output":
        if source_path is None:
            raise ValueError("output validation requires the verified input or retry envelope")
        source = json.loads(source_path.read_text(encoding="utf-8"))
        if not isinstance(source, dict):
            raise ValueError("validation source root must be an object")
        if source.get("envelope_version") == "1.0":
            located_context, retry_attempt, model_call_attempt = _validate_retry_envelope(source)
        else:
            located_context, retry_attempt, model_call_attempt = _validate_initial_input(source)
        _validate_common(source)
        _validate_patch_candidate(
            artifact,
            located_context=located_context,
            authorized_retry_attempt=retry_attempt,
            authorized_model_call_attempt=model_call_attempt,
        )
    elif mode == "retry":
        _validate_retry_envelope(artifact)
    _validate_common(artifact)
    return {"valid": True, "skill": contract["name"], "mode": mode}


def main() -> int:
    if (
        len(sys.argv) not in {3, 4}
        or sys.argv[1] not in {"input", "output", "retry"}
        or (sys.argv[1] == "output") != (len(sys.argv) == 4)
    ):
        print(
            "usage: validate.py <input|retry> <artifact.json> | "
            "validate.py output <candidate.json> <verified-input-or-retry.json>",
            file=sys.stderr,
        )
        return 2
    try:
        source_path = Path(sys.argv[3]) if len(sys.argv) == 4 else None
        result = _run(sys.argv[1], Path(sys.argv[2]), source_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"invalid artifact: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

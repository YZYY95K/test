"""Validate test-runner artifacts without importing the DevFlow runtime."""

from __future__ import annotations

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
INTEGRITY_POLICY = "immutable-baseline-tests/v1"
INTEGRITY_POLICY_DIGEST = "e30d5b49b5bbde322301604354d21f604687483b54d1b4dd0f2e86473462516c"
ISOLATION_BOUNDARY = "stdlib-temporary-directory-process-only-not-os-sandbox"
INTEGRITY_FIELDS = {
    "schema_version",
    "policy",
    "policy_digest",
    "command_digest",
    "baseline_manifest_digest",
    "candidate_baseline_manifest_digest",
    "candidate_pre_run_manifest_digest",
    "candidate_post_run_manifest_digest",
    "added_tests_manifest_digest",
    "baseline_protected_file_count",
    "added_test_file_count",
    "full_suite",
    "verified",
    "isolation_boundary",
}
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
    "truncated",
    "redacted",
}
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


def _validate_patch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("patch must be an object")
    if set(value) != {"branch_name", "changes", "commit_message", "description"}:
        raise ValueError("patch fields do not match Patch")
    _require_text(value["branch_name"], "patch.branch_name", maximum=255)
    _require_text(value["commit_message"], "patch.commit_message")
    _require_text(value["description"], "patch.description")
    changes = value["changes"]
    if not isinstance(changes, list) or not changes:
        raise ValueError("patch.changes must be a non-empty list")
    required_change = {
        "file_path",
        "change_type",
        "original_content",
        "new_content",
        "diff",
    }
    for index, change in enumerate(changes):
        if not isinstance(change, dict) or set(change) != required_change:
            raise ValueError(f"patch.changes[{index}] fields do not match FileChange")
        normalized = _canonical_repo_path(
            change["file_path"],
            f"patch.changes[{index}].file_path",
        )
        if change["change_type"] not in {"create", "modify", "delete"}:
            raise ValueError(f"patch.changes[{index}].change_type is invalid")
        if change["change_type"] == "delete" and _is_test_path(normalized):
            raise ValueError(f"patch.changes[{index}] cannot delete a test file")
        _require_text(change["diff"], f"patch.changes[{index}].diff")
        for field in ("original_content", "new_content"):
            if change[field] is not None and not isinstance(change[field], str):
                raise ValueError(f"patch.changes[{index}].{field} must be text or null")
    return value


def _validate_evidence_boundary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("evidence_boundary must be an object")
    if set(value) != {
        "schema_version",
        "located_context_digest",
        "allowed_files",
        "scope_digest",
    }:
        raise ValueError("evidence_boundary fields do not match the contract")
    if value["schema_version"] != "1.0":
        raise ValueError("evidence_boundary schema_version must be 1.0")
    _require_digest(value["located_context_digest"], "located_context_digest")
    allowed = value["allowed_files"]
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
        "located_context_digest": value["located_context_digest"],
        "allowed_files": normalized,
    }
    if _require_digest(value["scope_digest"], "scope_digest") != _canonical_digest(scope_body):
        raise ValueError("scope_digest does not bind the exact evidence boundary")
    return value


def _validate_patch_candidate(value: dict[str, Any]) -> dict[str, Any]:
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
    if _require_digest(value["candidate_digest"], "candidate_digest") != _canonical_digest(patch):
        raise ValueError("candidate_digest does not bind the exact patch")
    boundary = _validate_evidence_boundary(value["evidence_boundary"])
    allowed_files = frozenset(boundary["allowed_files"])
    for change in patch["changes"]:
        if change["file_path"] not in allowed_files:
            raise ValueError("Patch changes a file outside the located evidence boundary")
    attempt = _require_integer(value["retry_attempt"], "retry_attempt", minimum=1)
    if attempt > 3:
        raise ValueError("retry_attempt exceeds the three-attempt budget")
    model_call_attempt = _require_integer(
        value["model_call_attempt"],
        "model_call_attempt",
        minimum=1,
    )
    if model_call_attempt > 3:
        raise ValueError("model_call_attempt exceeds the three-call global budget")
    if model_call_attempt < attempt:
        raise ValueError("model_call_attempt cannot precede retry_attempt")
    revision_of = value.get("revision_of")
    if attempt == 1 and revision_of is not None:
        raise ValueError("initial PatchCandidate cannot declare revision_of")
    if attempt > 1:
        _require_digest(revision_of, "revision_of")
    return value


def _validate_candidate_binding(
    candidate: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    if evidence.get("issue_id") != candidate["issue_id"]:
        raise ValueError("evidence issue_id does not match the verified PatchCandidate")
    if evidence.get("candidate_digest") != candidate["candidate_digest"]:
        raise ValueError("evidence candidate_digest does not match the verified PatchCandidate")


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


def _validate_failure_evidence(artifact: dict[str, Any]) -> None:
    missing = sorted(FAILURE_FIELDS - set(artifact))
    extra = sorted(set(artifact) - FAILURE_FIELDS)
    if missing:
        raise ValueError(f"missing failure evidence fields: {', '.join(missing)}")
    if extra:
        raise ValueError(f"unknown failure evidence fields: {', '.join(extra)}")
    if artifact["schema_version"] != "1.2":
        raise ValueError("failure evidence schema_version must be 1.2")
    _require_integer(artifact["issue_id"], "issue_id", minimum=1)
    _require_digest(artifact["candidate_digest"], "candidate_digest")
    _require_digest(artifact["test_result_digest"], "test_result_digest")
    baseline_present = _require_boolean(artifact["baseline_present"], "baseline_present")
    failed = _require_integer(artifact["failed"], "failed")
    errors = _require_integer(artifact["errors"], "errors")
    regression = _require_boolean(artifact["regression"], "regression")
    new_failures = _bounded_names(artifact["new_failures"], "new_failures")
    _bounded_names(artifact["failing_tests"], "failing_tests")
    _validate_diagnostics(artifact["diagnostics"])
    _require_boolean(artifact["truncated"], "truncated")
    redacted = _require_boolean(artifact["redacted"], "redacted")

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
    if artifact["reasons"] != expected:
        raise ValueError("failure reasons do not match the ordered gate facts")

    contains_marker = any(REDACTION_MARKER in text for text in strings(artifact))
    if contains_marker != redacted:
        raise ValueError("redacted must exactly report bounded evidence redaction")


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_integrity_attestation(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != INTEGRITY_FIELDS:
        raise ValueError("test integrity attestation fields do not match v1.0")
    if value["schema_version"] != "1.0":
        raise ValueError("test integrity attestation schema_version must be 1.0")
    if value["policy"] != INTEGRITY_POLICY:
        raise ValueError("test integrity attestation policy is unsupported")
    if value["policy_digest"] != INTEGRITY_POLICY_DIGEST:
        raise ValueError("test integrity policy digest is unsupported")
    for field in (
        "command_digest",
        "baseline_manifest_digest",
        "candidate_baseline_manifest_digest",
        "candidate_pre_run_manifest_digest",
        "candidate_post_run_manifest_digest",
        "added_tests_manifest_digest",
    ):
        _require_digest(value[field], f"integrity_attestation.{field}")
    _require_integer(
        value["baseline_protected_file_count"],
        "integrity_attestation.baseline_protected_file_count",
    )
    _require_integer(
        value["added_test_file_count"],
        "integrity_attestation.added_test_file_count",
    )
    _require_boolean(value["full_suite"], "integrity_attestation.full_suite")
    verified = _require_boolean(value["verified"], "integrity_attestation.verified")
    if value["isolation_boundary"] != ISOLATION_BOUNDARY:
        raise ValueError("test integrity isolation boundary is unsupported")
    if verified and (
        value["baseline_manifest_digest"] != value["candidate_baseline_manifest_digest"]
    ):
        raise ValueError("verified integrity evidence changed the immutable baseline")
    if verified and (
        value["candidate_pre_run_manifest_digest"] != value["candidate_post_run_manifest_digest"]
    ):
        raise ValueError("verified integrity evidence changed during execution")
    return value


def _validate_test_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("test_result must be an object")
    required = {
        "total",
        "passed",
        "failed",
        "errors",
        "skipped",
        "duration_ms",
        "results",
        "baseline_comparison",
        "integrity_attestation",
    }
    missing = sorted(required - set(value))
    if missing:
        raise ValueError(f"missing test_result fields: {', '.join(missing)}")
    if set(value) != required:
        raise ValueError("test_result fields do not match the contract")
    for field in ("total", "passed", "failed", "errors", "skipped", "duration_ms"):
        _require_integer(value[field], f"test_result.{field}")
    if not isinstance(value["results"], list):
        raise ValueError("test_result.results must be a list")
    if value["total"] != sum(value[field] for field in ("passed", "failed", "errors", "skipped")):
        raise ValueError("test_result totals are inconsistent")
    for index, case in enumerate(value["results"]):
        if not isinstance(case, dict):
            raise ValueError(f"test_result.results[{index}] must be an object")
        required_case = {
            "name",
            "status",
            "duration_ms",
            "error_message",
            "traceback",
        }
        if not required_case <= set(case):
            raise ValueError(f"test_result.results[{index}] is incomplete")
        if not isinstance(case["name"], str) or not case["name"]:
            raise ValueError(f"test_result.results[{index}].name must be non-empty")
        if case["status"] not in {"passed", "failed", "error", "skipped"}:
            raise ValueError(f"test_result.results[{index}].status is invalid")
        _require_integer(
            case["duration_ms"],
            f"test_result.results[{index}].duration_ms",
        )
        for field in ("error_message", "traceback"):
            if case[field] is not None and not isinstance(case[field], str):
                raise ValueError(f"test_result.results[{index}].{field} must be text or null")
    if value["results"]:
        if len(value["results"]) != value["total"]:
            raise ValueError("non-empty test_result.results length must equal total")
        status_counts = {
            status: sum(case["status"] == status for case in value["results"])
            for status in ("passed", "failed", "error", "skipped")
        }
        expected_counts = {
            "passed": value["passed"],
            "failed": value["failed"],
            "error": value["errors"],
            "skipped": value["skipped"],
        }
        if status_counts != expected_counts:
            raise ValueError("test_result status counters do not match results")
    comparison = value["baseline_comparison"]
    if comparison is not None:
        if not isinstance(comparison, dict):
            raise ValueError("test_result.baseline_comparison must be an object or null")
        comparison_fields = {
            "baseline_passed",
            "current_passed",
            "new_failures",
            "fixed_tests",
            "regression",
        }
        if not comparison_fields <= set(comparison):
            raise ValueError("test_result.baseline_comparison is incomplete")
        _require_integer(
            comparison["baseline_passed"],
            "baseline_comparison.baseline_passed",
        )
        _require_integer(
            comparison["current_passed"],
            "baseline_comparison.current_passed",
        )
        if comparison["current_passed"] != value["passed"]:
            raise ValueError("baseline_comparison.current_passed must equal passed")
        for field in ("new_failures", "fixed_tests"):
            names = comparison[field]
            if not isinstance(names, list) or any(not isinstance(name, str) for name in names):
                raise ValueError(f"baseline_comparison.{field} must be a string list")
        _require_boolean(comparison["regression"], "baseline_comparison.regression")
    _validate_integrity_attestation(value["integrity_attestation"])
    return value


def _derive_bounded_names(values: list[str]) -> tuple[list[str], bool]:
    names: list[str] = []
    seen: set[str] = set()
    truncated = False
    for raw in values:
        name = raw[:512] or "unnamed-test"
        truncated = truncated or len(raw) > 512
        if name in seen:
            continue
        seen.add(name)
        if len(names) >= 128:
            truncated = True
            continue
        names.append(name)
    return names, truncated


def _derive_failure_view(
    result: dict[str, Any],
) -> tuple[list[str], list[str], list[dict[str, Any]], bool]:
    failed_cases = [case for case in result["results"] if case["status"] in {"failed", "error"}]
    failing_tests, names_truncated = _derive_bounded_names([case["name"] for case in failed_cases])
    comparison = result["baseline_comparison"]
    raw_new_failures = [] if comparison is None else comparison["new_failures"]
    new_failures, new_truncated = _derive_bounded_names(raw_new_failures)
    diagnostic_cases = failed_cases[:32]
    diagnostics = [
        {
            "name": case["name"][:512] or "unnamed-test",
            "status": case["status"],
            "error_message": (
                None if case["error_message"] is None else case["error_message"][:2048]
            ),
            "traceback": (None if case["traceback"] is None else case["traceback"][:4000]),
        }
        for case in diagnostic_cases
    ]
    diagnostics_truncated = len(failed_cases) > 32 or any(
        len(case["name"]) > 512
        or (case["error_message"] is not None and len(case["error_message"]) > 2048)
        or (case["traceback"] is not None and len(case["traceback"]) > 4000)
        for case in diagnostic_cases
    )
    return (
        failing_tests,
        new_failures,
        diagnostics,
        names_truncated or new_truncated or diagnostics_truncated,
    )


def _validate_failure_payload(artifact: dict[str, Any]) -> None:
    required = {
        "issue_id",
        "candidate_digest",
        "test_result",
        "test_result_redacted",
        "failing_tests",
        "failure_evidence",
    }
    missing = sorted(required - set(artifact))
    if missing:
        raise ValueError(f"missing failure handoff fields: {', '.join(missing)}")
    extra = sorted(set(artifact) - required)
    if extra:
        raise ValueError(f"unknown failure handoff fields: {', '.join(extra)}")
    issue_id = _require_integer(artifact["issue_id"], "issue_id", minimum=1)
    candidate_digest = _require_digest(artifact["candidate_digest"], "candidate_digest")
    result_redacted = _require_boolean(
        artifact["test_result_redacted"],
        "test_result_redacted",
    )
    result = _validate_test_result(artifact["test_result"])
    evidence = artifact["failure_evidence"]
    if not isinstance(evidence, dict):
        raise ValueError("failure_evidence must be an object")
    _validate_failure_evidence(evidence)
    if evidence["issue_id"] != issue_id:
        raise ValueError("failure evidence issue_id does not match the handoff")
    if evidence["candidate_digest"] != candidate_digest:
        raise ValueError("failure evidence candidate_digest does not match the handoff")
    if evidence["test_result_digest"] != _canonical_digest(result):
        raise ValueError("test result digest does not match the sanitized handoff")
    if evidence["redacted"] and not result_redacted:
        raise ValueError("bounded evidence redaction requires result redaction")
    if artifact["failing_tests"] != evidence["failing_tests"]:
        raise ValueError("handoff failing_tests do not match failure evidence")
    if evidence["failed"] != result["failed"] or evidence["errors"] != result["errors"]:
        raise ValueError("failure counts do not match the sanitized test result")
    comparison = result["baseline_comparison"]
    if evidence["baseline_present"] != (comparison is not None):
        raise ValueError("baseline presence does not match the sanitized test result")
    regression = False if comparison is None else comparison["regression"]
    if evidence["regression"] != regression:
        raise ValueError("regression flag does not match the sanitized test result")
    failing_tests, new_failures, diagnostics, truncated = _derive_failure_view(result)
    if evidence["failing_tests"] != failing_tests:
        raise ValueError("failure names are not the canonical bounded result view")
    if evidence["new_failures"] != new_failures:
        raise ValueError("new failures are not the canonical bounded result view")
    if evidence["diagnostics"] != diagnostics:
        raise ValueError("diagnostics are not the canonical bounded result view")
    if evidence["truncated"] != truncated:
        raise ValueError("truncated does not match the canonical bounded result view")
    contains_marker = any(REDACTION_MARKER in text for text in strings(result))
    if contains_marker != result_redacted:
        raise ValueError("test_result_redacted must exactly report result redaction")


def _validate_test_evidence(artifact: dict[str, Any]) -> None:
    required = {
        "issue_id",
        "candidate_digest",
        "test_result",
        "test_result_redacted",
        "failing_tests",
    }
    allowed = required | {"failure_evidence"}
    missing = sorted(required - set(artifact))
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if set(artifact) - allowed:
        raise ValueError("TestEvidence fields do not match the contract")
    _require_integer(artifact["issue_id"], "issue_id", minimum=1)
    _require_digest(artifact["candidate_digest"], "candidate_digest")
    result = _validate_test_result(artifact["test_result"])
    result_redacted = _require_boolean(
        artifact["test_result_redacted"],
        "test_result_redacted",
    )
    contains_marker = any(REDACTION_MARKER in text for text in strings(result))
    if contains_marker != result_redacted:
        raise ValueError("test_result_redacted must exactly report result redaction")
    comparison = result["baseline_comparison"]
    passed = bool(
        comparison is not None
        and result["failed"] == 0
        and result["errors"] == 0
        and not comparison["regression"]
        and not comparison["new_failures"]
    )
    if passed:
        attestation = result["integrity_attestation"]
        if attestation is None or not attestation["verified"]:
            raise ValueError("passing TestEvidence requires verified integrity evidence")
        if artifact["failing_tests"] != []:
            raise ValueError("passing TestEvidence cannot contain failing_tests")
        if "failure_evidence" in artifact:
            raise ValueError("passing TestEvidence cannot contain failure_evidence")
        return
    _validate_failure_payload(artifact)


def _validate_failure_handoff(envelope: dict[str, Any]) -> None:
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
        raise ValueError(f"missing failure envelope fields: {', '.join(missing)}")
    optional = {"agent", "parent_task_id", "parent_handoff_sha256"}
    if set(envelope) - required - optional:
        raise ValueError("failure envelope contains unknown fields")
    if envelope["envelope_version"] != "1.0":
        raise ValueError("envelope_version must be 1.0")
    route = (
        envelope["producer"],
        envelope["consumer"],
        envelope["skill"],
        envelope["status"],
    )
    if route != ("TesterAgent", "TeamLeader", "test-runner", "retry"):
        raise ValueError("failure envelope must route TesterAgent to TeamLeader")
    if envelope.get("agent", "TesterAgent") != "TesterAgent":
        raise ValueError("enriched failure envelope agent must be TesterAgent")
    parent_task_id = envelope.get("parent_task_id")
    parent_digest = envelope.get("parent_handoff_sha256")
    if (parent_task_id is None) != (parent_digest is None):
        raise ValueError("failure envelope parent correlation is incomplete")
    if parent_task_id is not None:
        if not isinstance(parent_task_id, str) or not parent_task_id:
            raise ValueError("failure envelope parent task id is invalid")
        if (
            not isinstance(parent_digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", parent_digest) is None
        ):
            raise ValueError("failure envelope parent digest is invalid")
    issue_id = _require_integer(envelope["issue_id"], "envelope issue_id", minimum=1)

    run_id = envelope["run_id"]
    task_id = envelope["task_id"]
    if not isinstance(run_id, str) or not run_id or not isinstance(task_id, str) or not task_id:
        raise ValueError("run_id and task_id must be non-empty strings")
    if envelope["trace_id"] != f"{run_id}:{task_id}":
        raise ValueError("trace_id is not bound to run_id and task_id")
    expected_key = f"{run_id}:{task_id}:TeamLeader:test-runner"
    if envelope["idempotency_key"] != expected_key:
        raise ValueError("idempotency_key is not bound to the failure identity")
    try:
        created_at = datetime.fromisoformat(str(envelope["created_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("created_at must be an ISO-8601 timestamp") from exc
    if created_at.tzinfo is None:
        raise ValueError("created_at must include a timezone")

    artifact = envelope["artifact"]
    if not isinstance(artifact, dict):
        raise ValueError("artifact must be an object")
    if set(artifact) != {"type", "schema_version", "inline", "ref", "sha256"}:
        raise ValueError("failure artifact has an invalid shape")
    if artifact["type"] != "TestEvidence" or artifact["schema_version"] != "1.0":
        raise ValueError("failure artifact type or schema version is invalid")
    if artifact["ref"] is not None or not isinstance(artifact["inline"], dict):
        raise ValueError("failure artifact must use an inline payload")
    if artifact["sha256"] != _canonical_digest(artifact["inline"]):
        raise ValueError("failure artifact digest does not match its inline payload")
    _validate_failure_payload(artifact["inline"])
    if artifact["inline"]["issue_id"] != issue_id:
        raise ValueError("failure envelope issue_id does not match its payload")


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
    candidate_path: Path | None = None,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root / "references" / "contract.yaml")
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise ValueError("artifact root must be an object")
    if mode == "input":
        _validate_patch_candidate(artifact)
    else:
        if candidate_path is None:
            raise ValueError(f"{mode} validation requires the verified PatchCandidate")
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        if not isinstance(candidate, dict):
            raise ValueError("PatchCandidate source root must be an object")
        _validate_patch_candidate(candidate)
        _validate_common(candidate)
        if mode == "output":
            _validate_test_evidence(artifact)
            _validate_candidate_binding(candidate, artifact)
            result = artifact["test_result"]
            comparison = result["baseline_comparison"]
            passed = bool(
                comparison is not None
                and result["failed"] == 0
                and result["errors"] == 0
                and not comparison["regression"]
                and not comparison["new_failures"]
            )
            if (
                passed
                and candidate["tier"] in {"T3", "T4", "T5"}
                and not result["integrity_attestation"]["full_suite"]
            ):
                raise ValueError("T3 through T5 passes require a full-suite attestation")
        elif mode == "failure":
            _validate_failure_evidence(artifact)
            _validate_candidate_binding(candidate, artifact)
        elif mode == "failure-handoff":
            _validate_failure_handoff(artifact)
            inline = artifact["artifact"]["inline"]
            _validate_candidate_binding(candidate, inline)
    _validate_common(artifact)
    return {"valid": True, "skill": contract["name"], "mode": mode}


def main() -> int:
    modes = {"input", "output", "failure", "failure-handoff"}
    if (
        len(sys.argv) not in {3, 4}
        or sys.argv[1] not in modes
        or (sys.argv[1] == "input") != (len(sys.argv) == 3)
    ):
        print(
            "usage: validate.py input <candidate.json> | "
            "validate.py <output|failure|failure-handoff> "
            "<artifact.json> <verified-candidate.json>",
            file=sys.stderr,
        )
        return 2
    try:
        candidate_path = Path(sys.argv[3]) if len(sys.argv) == 4 else None
        result = _run(sys.argv[1], Path(sys.argv[2]), candidate_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"invalid artifact: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

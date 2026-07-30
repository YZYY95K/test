"""Strictly validate terminal experience inputs, stored results, and failures."""

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

SKILL = "experience-distiller"
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
APPROVAL_ID = re.compile(r"^[0-9a-f]{32}$")
ACTION = re.compile(r"^[a-z0-9_.:-]+$")
TIERS = frozenset({"T1", "T2", "T3", "T4", "T5"})
INPUT_FIELDS = frozenset(
    {
        "issue_id",
        "issue",
        "tier",
        "repository_revision",
        "located_context",
        "patch",
        "test_result",
        "review",
        "trace_id",
        "terminal_receipt",
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
LOCATED_FIELDS = frozenset(
    {"root_cause", "affected_files", "context_payload", "related_tests", "impact_analysis"}
)
PATCH_FIELDS = frozenset({"branch_name", "changes", "commit_message", "description"})
CHANGE_FIELDS = frozenset(
    {"file_path", "change_type", "original_content", "new_content", "diff"}
)
TEST_FIELDS = frozenset(
    {
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
)
TEST_CASE_FIELDS = frozenset(
    {"name", "status", "duration_ms", "error_message", "traceback"}
)
COMPARISON_FIELDS = frozenset(
    {"baseline_passed", "current_passed", "new_failures", "fixed_tests", "regression"}
)
INTEGRITY_FIELDS = frozenset(
    {
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
)
REVIEW_FIELDS = frozenset(
    {"decision", "findings", "summary", "pr_url", "requires_human_approval"}
)
REVIEW_FINDING_FIELDS = frozenset({"severity", "category", "message", "file_path"})
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "issuer",
        "run_id",
        "issue_id",
        "repository_revision",
        "terminal_state",
        "candidate_digest",
        "test_result_digest",
        "review_digest",
        "approval_digest",
        "receipt_sha256",
    }
)
APPROVAL_FIELDS = frozenset(
    {"approval_id", "action", "target", "artifact_digest", "approved_by", "approved_at", "signature"}
)
OUTPUT_FIELDS = frozenset(
    {
        "pattern_id",
        "schema_version",
        "outcome",
        "summary",
        "reusable_lesson",
        "provenance",
        "redaction",
        "stored",
    }
)
PROVENANCE_FIELDS = frozenset(
    {
        "trace_id",
        "issue_id",
        "repository_revision",
        "candidate_digest",
        "review_digest",
        "terminal_receipt_sha256",
    }
)
REDACTION_FIELDS = frozenset(
    {"policy_version", "secret_scan_passed", "pii_scan_passed"}
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
    "NON_TERMINAL_EVIDENCE": (False, 0, "experience.rejected"),
    "PROVENANCE_INCOMPLETE": (False, 0, "experience.rejected"),
    "REDACTION_UNCERTAIN": (False, 0, "experience.quarantined"),
    "STORE_UNAVAILABLE": (True, 2, "experience.degraded"),
}
POLICY_DIGEST = "e30d5b49b5bbde322301604354d21f604687483b54d1b4dd0f2e86473462516c"
ISOLATION_BOUNDARY = "stdlib-temporary-directory-process-only-not-os-sandbox"


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


def _text(value: Any, label: str, *, maximum: int = 8_192) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or CONTROL.search(value) is not None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _positive_int(value: Any, label: str) -> int:
    return _integer(value, label, minimum=1)


def _number(value: Any, label: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise ValueError(f"{label} is invalid")
    return result


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _path(value: Any, label: str) -> str:
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


def _timestamp(value: Any, label: str) -> str:
    rendered = _text(value, label, maximum=64)
    try:
        parsed = dt.datetime.fromisoformat(rendered.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return rendered


def _unique_text_list(value: Any, label: str, *, maximum: int = 1_024) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded list")
    result = [_text(item, label, maximum=1_024) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must be unique")
    return result


def _validate_issue(value: Any, *, issue_id: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != ISSUE_FIELDS:
        raise ValueError("issue fields do not match IssueData")
    if _positive_int(value["issue_number"], "issue.issue_number") != issue_id:
        raise ValueError("issue identity does not match issue_id")
    _text(value["title"], "issue.title", maximum=512)
    if value["body"] is not None and not isinstance(value["body"], str):
        raise ValueError("issue.body must be text or null")
    _unique_text_list(value["labels"], "issue.labels", maximum=100)
    if value["state"] not in {"open", "closed"}:
        raise ValueError("issue.state is unsupported")
    _text(value["author"], "issue.author", maximum=256)
    _timestamp(value["created_at"], "issue.created_at")
    _text(value["repo_owner"], "issue.repo_owner", maximum=100)
    _text(value["repo_name"], "issue.repo_name", maximum=100)
    return value


def _validate_located(value: Any) -> None:
    if not isinstance(value, dict) or set(value) != LOCATED_FIELDS:
        raise ValueError("located_context fields do not match LocatedContext")
    root = value["root_cause"]
    if not isinstance(root, dict) or set(root) != {
        "summary",
        "file",
        "start_line",
        "end_line",
        "confidence",
    }:
        raise ValueError("located_context.root_cause fields do not match")
    _text(root["summary"], "root_cause.summary")
    _path(root["file"], "root_cause.file")
    start = _positive_int(root["start_line"], "root_cause.start_line")
    end = _positive_int(root["end_line"], "root_cause.end_line")
    if end < start:
        raise ValueError("root_cause line range is reversed")
    confidence = _number(root["confidence"], "root_cause.confidence")
    if confidence > 1:
        raise ValueError("root_cause.confidence is invalid")
    affected = value["affected_files"]
    if not isinstance(affected, list) or len(affected) > 256:
        raise ValueError("located_context.affected_files is invalid")
    paths: list[str] = []
    for item in affected:
        if not isinstance(item, dict) or set(item) != {"path", "reason", "change_type"}:
            raise ValueError("located_context affected-file fields do not match")
        paths.append(_path(item["path"], "affected file path"))
        _text(item["reason"], "affected file reason")
        if item["change_type"] not in {"edit", "review", "test"}:
            raise ValueError("affected file change_type is unsupported")
    if len(paths) != len(set(paths)):
        raise ValueError("affected file paths must be unique")
    if not isinstance(value["context_payload"], str) or len(value["context_payload"]) > 128_000:
        raise ValueError("located_context.context_payload is invalid")
    [_path(item, "related test path") for item in _unique_text_list(value["related_tests"], "related_tests")]
    impact = value["impact_analysis"]
    if not isinstance(impact, dict) or set(impact) != {
        "affected_files",
        "affected_modules",
        "risk_level",
        "breaking_changes",
        "test_files_needed",
    }:
        raise ValueError("impact_analysis fields do not match")
    for field in ("affected_files", "test_files_needed"):
        [_path(item, f"impact_analysis.{field}") for item in _unique_text_list(impact[field], field)]
    _unique_text_list(impact["affected_modules"], "affected_modules")
    if impact["risk_level"] not in {"low", "medium", "high", "critical"}:
        raise ValueError("impact_analysis.risk_level is unsupported")
    if not isinstance(impact["breaking_changes"], bool):
        raise ValueError("impact_analysis.breaking_changes must be a boolean")


def _validate_patch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PATCH_FIELDS:
        raise ValueError("patch fields do not match Patch")
    _text(value["branch_name"], "patch.branch_name", maximum=256)
    _text(value["commit_message"], "patch.commit_message", maximum=1_024)
    _text(value["description"], "patch.description", maximum=8_192)
    changes = value["changes"]
    if not isinstance(changes, list) or not 1 <= len(changes) <= 256:
        raise ValueError("patch.changes must be a bounded non-empty list")
    paths: list[str] = []
    for item in changes:
        if not isinstance(item, dict) or set(item) != CHANGE_FIELDS:
            raise ValueError("patch change fields do not match")
        paths.append(_path(item["file_path"], "patch change file_path"))
        if item["change_type"] not in {"add", "modify", "delete"}:
            raise ValueError("patch change_type is unsupported")
        for field in ("original_content", "new_content", "diff"):
            if not isinstance(item[field], str) or len(item[field]) > 1_000_000:
                raise ValueError(f"patch change {field} is invalid")
    if len(paths) != len(set(paths)):
        raise ValueError("patch change paths must be unique")
    return value


def _validate_test_result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != TEST_FIELDS:
        raise ValueError("test_result fields do not match TestRunResult")
    counts = {
        key: _integer(value[key], f"test_result.{key}")
        for key in ("total", "passed", "failed", "errors", "skipped")
    }
    if counts["total"] < 1 or counts["total"] != sum(
        counts[key] for key in ("passed", "failed", "errors", "skipped")
    ):
        raise ValueError("test_result counters are inconsistent")
    _number(value["duration_ms"], "test_result.duration_ms")
    results = value["results"]
    if not isinstance(results, list) or len(results) != counts["total"]:
        raise ValueError("test_result.results must match total")
    observed = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    names: list[str] = []
    for item in results:
        if not isinstance(item, dict) or set(item) != TEST_CASE_FIELDS:
            raise ValueError("test case fields do not match")
        names.append(_text(item["name"], "test case name", maximum=4_096))
        status = item["status"]
        if status not in {"passed", "failed", "error", "skipped"}:
            raise ValueError("test case status is unsupported")
        counter = "errors" if status == "error" else status
        observed[counter] += 1
        _number(item["duration_ms"], "test case duration_ms")
        for field in ("error_message", "traceback"):
            if item[field] is not None and not isinstance(item[field], str):
                raise ValueError(f"test case {field} must be text or null")
    if len(names) != len(set(names)) or any(counts[key] != observed[key] for key in observed):
        raise ValueError("test case statuses do not match summary counters")
    comparison = value["baseline_comparison"]
    if not isinstance(comparison, dict) or set(comparison) != COMPARISON_FIELDS:
        raise ValueError("baseline comparison fields do not match")
    _integer(comparison["baseline_passed"], "baseline_passed")
    current = _integer(comparison["current_passed"], "current_passed")
    new_failures = _unique_text_list(comparison["new_failures"], "new_failures")
    _unique_text_list(comparison["fixed_tests"], "fixed_tests")
    if (
        current != counts["passed"]
        or comparison["regression"] is not False
        or new_failures
        or counts["failed"] != 0
        or counts["errors"] != 0
    ):
        raise ValueError("trusted experience requires a clean regression gate")
    integrity = value["integrity_attestation"]
    if not isinstance(integrity, dict) or set(integrity) != INTEGRITY_FIELDS:
        raise ValueError("integrity_attestation fields do not match")
    for field in (
        "policy_digest",
        "command_digest",
        "baseline_manifest_digest",
        "candidate_baseline_manifest_digest",
        "candidate_pre_run_manifest_digest",
        "candidate_post_run_manifest_digest",
        "added_tests_manifest_digest",
    ):
        _digest(integrity[field], f"integrity_attestation.{field}")
    if (
        integrity["schema_version"] != "1.0"
        or integrity["policy"] != "immutable-baseline-tests/v1"
        or integrity["policy_digest"] != POLICY_DIGEST
        or integrity["verified"] is not True
        or integrity["baseline_manifest_digest"]
        != integrity["candidate_baseline_manifest_digest"]
        or integrity["candidate_pre_run_manifest_digest"]
        != integrity["candidate_post_run_manifest_digest"]
        or integrity["isolation_boundary"] != ISOLATION_BOUNDARY
    ):
        raise ValueError("test integrity attestation is not trusted")
    _integer(integrity["baseline_protected_file_count"], "baseline_protected_file_count")
    _integer(integrity["added_test_file_count"], "added_test_file_count")
    if not isinstance(integrity["full_suite"], bool):
        raise ValueError("integrity_attestation.full_suite must be a boolean")
    return value


def _validate_review(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REVIEW_FIELDS:
        raise ValueError("review fields do not match ReviewResult")
    if value["decision"] != "approved" or value["requires_human_approval"] is not False:
        raise ValueError("trusted experience requires an approved review")
    findings = value["findings"]
    if not isinstance(findings, list) or len(findings) > 256:
        raise ValueError("review.findings must be a bounded list")
    for item in findings:
        if not isinstance(item, dict) or set(item) != REVIEW_FINDING_FIELDS:
            raise ValueError("review finding fields do not match")
        if item["severity"] not in {"info", "low", "medium", "high", "critical"}:
            raise ValueError("review finding severity is unsupported")
        _text(item["category"], "review finding category", maximum=256)
        _text(item["message"], "review finding message")
        if item["file_path"] is not None:
            _path(item["file_path"], "review finding file_path")
    if any(item["severity"] in {"high", "critical"} for item in findings):
        raise ValueError("approved review contains a blocking finding")
    _text(value["summary"], "review.summary")
    if value["pr_url"] is not None and (
        not isinstance(value["pr_url"], str)
        or re.fullmatch(r"https://github\.com/[^/\s]+/[^/\s]+/pull/[1-9][0-9]*", value["pr_url"])
        is None
    ):
        raise ValueError("review.pr_url is invalid")
    return value


def _validate_approval(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != APPROVAL_FIELDS:
        raise ValueError("human_approval fields do not match ApprovalEvidence")
    if not isinstance(value["approval_id"], str) or APPROVAL_ID.fullmatch(value["approval_id"]) is None:
        raise ValueError("human_approval.approval_id is invalid")
    if not isinstance(value["action"], str) or ACTION.fullmatch(value["action"]) is None:
        raise ValueError("human_approval.action is invalid")
    _text(value["target"], "human_approval.target", maximum=300)
    _digest(value["artifact_digest"], "human_approval.artifact_digest")
    _text(value["approved_by"], "human_approval.approved_by", maximum=200)
    _timestamp(value["approved_at"], "human_approval.approved_at")
    _digest(value["signature"], "human_approval.signature")
    return value


def _validate_input(value: dict[str, Any]) -> None:
    if set(value) not in (INPUT_FIELDS, INPUT_FIELDS | {"human_approval"}):
        raise ValueError("VerifiedRunBundle fields do not match")
    issue_id = _positive_int(value["issue_id"], "issue_id")
    _validate_issue(value["issue"], issue_id=issue_id)
    tier = value["tier"]
    if tier not in TIERS:
        raise ValueError("tier must be T1 through T5")
    revision = value["repository_revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("repository_revision must be a lowercase immutable commit SHA")
    _validate_located(value["located_context"])
    patch = _validate_patch(value["patch"])
    tests = _validate_test_result(value["test_result"])
    review = _validate_review(value["review"])
    trace_id = _text(value["trace_id"], "trace_id", maximum=512)
    approval = value.get("human_approval")
    if approval is not None:
        approval = _validate_approval(approval)
    if (tier in {"T4", "T5"}) != (approval is not None):
        raise ValueError("T4/T5 terminal evidence requires exact human approval")
    receipt = value["terminal_receipt"]
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise ValueError("terminal receipt fields do not match")
    for field in ("candidate_digest", "test_result_digest", "review_digest", "receipt_sha256"):
        _digest(receipt[field], f"terminal_receipt.{field}")
    if receipt["approval_digest"] is not None:
        _digest(receipt["approval_digest"], "terminal_receipt.approval_digest")
    receipt_body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    if receipt["receipt_sha256"] != _canonical_digest(receipt_body):
        raise ValueError("terminal receipt digest does not match")
    expected_state = "human_approved" if approval is not None else "review_approved"
    if (
        receipt["schema_version"] != "1.0"
        or receipt["issuer"] != "TeamLeader"
        or receipt["run_id"] != trace_id
        or receipt["issue_id"] != issue_id
        or receipt["repository_revision"] != revision
        or receipt["terminal_state"] != expected_state
        or receipt["candidate_digest"] != _canonical_digest(patch)
        or receipt["test_result_digest"] != _canonical_digest(tests)
        or receipt["review_digest"] != _canonical_digest(review)
        or receipt["approval_digest"]
        != (_canonical_digest(approval) if approval is not None else None)
    ):
        raise ValueError("terminal receipt does not bind the exact reviewed run")


def _validate_result(value: dict[str, Any], source: dict[str, Any]) -> None:
    if set(value) != OUTPUT_FIELDS:
        raise ValueError("ExperiencePattern fields do not match the contract")
    _validate_input(source)
    patch_digest = _canonical_digest(source["patch"])
    review_digest = _canonical_digest(source["review"])
    receipt = source["terminal_receipt"]
    expected_pattern = f'exp-{source["issue_id"]}-{patch_digest[:12]}'
    if value["pattern_id"] != expected_pattern:
        raise ValueError("pattern_id does not bind the exact candidate")
    if value["schema_version"] != "1.0" or value["outcome"] != "approved":
        raise ValueError("ExperiencePattern outcome is not trusted")
    _text(value["summary"], "summary", maximum=16_384)
    _text(value["reusable_lesson"], "reusable_lesson", maximum=16_384)
    provenance = value["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE_FIELDS:
        raise ValueError("experience provenance fields do not match")
    expected_provenance = {
        "trace_id": source["trace_id"],
        "issue_id": source["issue_id"],
        "repository_revision": source["repository_revision"],
        "candidate_digest": patch_digest,
        "review_digest": review_digest,
        "terminal_receipt_sha256": receipt["receipt_sha256"],
    }
    if provenance != expected_provenance:
        raise ValueError("experience provenance does not bind the source bundle")
    redaction = value["redaction"]
    if not isinstance(redaction, dict) or set(redaction) != REDACTION_FIELDS:
        raise ValueError("experience redaction fields do not match")
    if (
        redaction["policy_version"] != "1.0"
        or redaction["secret_scan_passed"] is not True
        or redaction["pii_scan_passed"] is not True
    ):
        raise ValueError("experience redaction gates did not pass")
    if value["stored"] is not True:
        raise ValueError("successful ExperiencePattern must be durably stored")


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
    if value["source_artifact_sha256"] != _canonical_digest(source):
        raise ValueError("SkillFailure source digest does not match the terminal bundle")
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

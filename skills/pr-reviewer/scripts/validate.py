"""Strictly validate candidate-review inputs, decisions, and declared failures."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SKILL = "pr-reviewer"
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
PATH = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
TIERS = frozenset({"T1", "T2", "T3", "T4", "T5"})
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
DECISIONS = frozenset({"approved", "changes_requested", "human_approval_required"})
INPUT_FIELDS = frozenset(
    {
        "issue_id",
        "tier",
        "candidate",
        "candidate_digest",
        "baseline_revision",
        "suite",
        "status",
        "totals",
        "baseline_comparison",
        "evidence",
    }
)
CANDIDATE_FIELDS = frozenset(
    {
        "schema_version",
        "issue_id",
        "tier",
        "patch",
        "candidate_digest",
        "evidence_boundary",
        "model_call_attempt",
        "retry_attempt",
    }
)
PATCH_FIELDS = frozenset({"branch_name", "changes", "commit_message", "description"})
CHANGE_FIELDS = frozenset(
    {"file_path", "change_type", "original_content", "new_content", "diff"}
)
TOTAL_FIELDS = frozenset({"total", "passed", "failed", "errors", "skipped"})
COMPARISON_FIELDS = frozenset(
    {"baseline_passed", "current_passed", "new_failures", "fixed_tests", "regression"}
)
EVIDENCE_FIELDS = frozenset(
    {"test_result_sha256", "integrity_attestation_sha256", "security_scan"}
)
SCAN_FIELDS = frozenset(
    {"schema_version", "scanner", "policy_version", "status", "findings", "report_sha256"}
)
SCAN_FINDING_FIELDS = frozenset(
    {"severity", "category", "message", "file_path", "disposition"}
)
OUTPUT_FIELDS = frozenset({"issue_id", "tier", "review"})
REVIEW_FIELDS = frozenset(
    {"decision", "findings", "summary", "pr_url", "requires_human_approval"}
)
REVIEW_FINDING_FIELDS = frozenset({"severity", "category", "message", "file_path"})
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
    "EVIDENCE_INVALID": (False, 0, "review.failed"),
    "REVIEW_GENERATION_INVALID": (True, 2, "review.failed"),
    "POLICY_BLOCK": (False, 0, "approval.required"),
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


def _integer(value: Any, label: str, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _positive_int(value: Any, label: str) -> int:
    return _integer(value, label, minimum=1)


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


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _unique_text_list(value: Any, label: str, *, maximum: int = 1_024) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded list")
    result = [_text(item, label, maximum=1_024) for item in value]
    if len(result) != len(set(result)):
        raise ValueError(f"{label} must be unique")
    return result


def _validate_patch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PATCH_FIELDS:
        raise ValueError("candidate.patch fields do not match Patch")
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
            content = item[field]
            if not isinstance(content, str) or len(content) > 1_000_000:
                raise ValueError(f"patch change {field} is invalid")
    if len(paths) != len(set(paths)):
        raise ValueError("patch change paths must be unique")
    return value


def _validate_candidate(value: Any, *, issue_id: int, tier: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) not in (
        CANDIDATE_FIELDS,
        CANDIDATE_FIELDS | {"revision_of"},
    ):
        raise ValueError("candidate fields do not match PatchCandidate 1.2")
    if value["schema_version"] != "1.2":
        raise ValueError("candidate schema_version must be 1.2")
    if value["issue_id"] != issue_id or value["tier"] != tier:
        raise ValueError("candidate identity does not match review input")
    patch = _validate_patch(value["patch"])
    candidate_digest = _digest(value["candidate_digest"], "candidate.candidate_digest")
    if candidate_digest != _canonical_digest(patch):
        raise ValueError("candidate digest does not bind the exact Patch")
    boundary = value["evidence_boundary"]
    if not isinstance(boundary, dict) or set(boundary) != {
        "schema_version",
        "located_context_digest",
        "allowed_files",
        "scope_digest",
    }:
        raise ValueError("candidate evidence_boundary fields do not match")
    if boundary["schema_version"] != "1.0":
        raise ValueError("candidate evidence boundary version is unsupported")
    _digest(boundary["located_context_digest"], "located_context_digest")
    allowed = [_path(item, "evidence_boundary.allowed_files") for item in _unique_text_list(
        boundary["allowed_files"], "evidence_boundary.allowed_files", maximum=256
    )]
    if not allowed or allowed != sorted(allowed):
        raise ValueError("evidence_boundary.allowed_files must be sorted and non-empty")
    boundary_body = {
        "schema_version": "1.0",
        "located_context_digest": boundary["located_context_digest"],
        "allowed_files": allowed,
    }
    if _digest(boundary["scope_digest"], "scope_digest") != _canonical_digest(boundary_body):
        raise ValueError("candidate scope_digest does not bind the evidence boundary")
    changed_paths = {item["file_path"] for item in patch["changes"]}
    if not changed_paths <= set(allowed):
        raise ValueError("candidate changes escape the evidence boundary")
    model_attempt = _integer(value["model_call_attempt"], "model_call_attempt", minimum=1, maximum=3)
    retry_attempt = _integer(value["retry_attempt"], "retry_attempt", minimum=1, maximum=3)
    if model_attempt < retry_attempt:
        raise ValueError("model_call_attempt cannot precede retry_attempt")
    revision_of = value.get("revision_of")
    if retry_attempt == 1 and revision_of is not None:
        raise ValueError("initial candidate cannot declare revision_of")
    if retry_attempt > 1:
        _digest(revision_of, "revision_of")
    return value


def _validate_finding(value: Any, *, scan: bool) -> dict[str, Any]:
    fields = SCAN_FINDING_FIELDS if scan else REVIEW_FINDING_FIELDS
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("finding fields do not match the contract")
    if value["severity"] not in SEVERITIES:
        raise ValueError("finding severity is unsupported")
    _text(value["category"], "finding.category", maximum=256)
    _text(value["message"], "finding.message", maximum=8_192)
    if value["file_path"] is not None:
        _path(value["file_path"], "finding.file_path")
    if scan and value["disposition"] not in {"open", "resolved"}:
        raise ValueError("security finding disposition is unsupported")
    return value


def _validate_input(value: dict[str, Any]) -> None:
    if set(value) != INPUT_FIELDS:
        raise ValueError("candidate-review input fields do not match")
    issue_id = _positive_int(value["issue_id"], "issue_id")
    tier = value["tier"]
    if tier not in TIERS:
        raise ValueError("tier must be T1 through T5")
    candidate = _validate_candidate(value["candidate"], issue_id=issue_id, tier=tier)
    candidate_digest = _digest(value["candidate_digest"], "candidate_digest")
    if candidate_digest != candidate["candidate_digest"]:
        raise ValueError("candidate_digest does not match the candidate")
    revision = value["baseline_revision"]
    if not isinstance(revision, str) or REVISION.fullmatch(revision) is None:
        raise ValueError("baseline_revision must be a lowercase immutable commit SHA")
    _text(value["suite"], "suite", maximum=256)
    if value["status"] != "passed":
        raise ValueError("candidate review requires passed test evidence")
    totals = value["totals"]
    if not isinstance(totals, dict) or set(totals) != TOTAL_FIELDS:
        raise ValueError("test totals fields do not match")
    counts = {key: _integer(totals[key], f"totals.{key}") for key in TOTAL_FIELDS}
    if counts["total"] < 1 or counts["total"] != sum(
        counts[key] for key in ("passed", "failed", "errors", "skipped")
    ):
        raise ValueError("test totals are inconsistent")
    if counts["failed"] != 0 or counts["errors"] != 0:
        raise ValueError("candidate review cannot consume red tests")
    comparison = value["baseline_comparison"]
    if not isinstance(comparison, dict) or set(comparison) != COMPARISON_FIELDS:
        raise ValueError("baseline comparison fields do not match")
    _integer(comparison["baseline_passed"], "baseline_comparison.baseline_passed")
    current = _integer(comparison["current_passed"], "baseline_comparison.current_passed")
    new_failures = _unique_text_list(comparison["new_failures"], "new_failures")
    _unique_text_list(comparison["fixed_tests"], "fixed_tests")
    if current != counts["passed"] or comparison["regression"] is not False or new_failures:
        raise ValueError("candidate review requires a clean baseline comparison")
    evidence = value["evidence"]
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_FIELDS:
        raise ValueError("review evidence fields do not match")
    _digest(evidence["test_result_sha256"], "test_result_sha256")
    _digest(evidence["integrity_attestation_sha256"], "integrity_attestation_sha256")
    scan = evidence["security_scan"]
    if not isinstance(scan, dict) or set(scan) != SCAN_FIELDS:
        raise ValueError("security_scan fields do not match")
    if scan["schema_version"] != "1.0" or scan["status"] != "passed":
        raise ValueError("candidate review requires a completed passing security scan")
    _text(scan["scanner"], "security_scan.scanner", maximum=256)
    _text(scan["policy_version"], "security_scan.policy_version", maximum=256)
    findings = scan["findings"]
    if not isinstance(findings, list) or len(findings) > 256:
        raise ValueError("security_scan.findings must be a bounded list")
    validated = [_validate_finding(item, scan=True) for item in findings]
    if any(
        item["severity"] in {"high", "critical"} and item["disposition"] == "open"
        for item in validated
    ):
        raise ValueError("security scan has unresolved high or critical findings")
    scan_body = {key: item for key, item in scan.items() if key != "report_sha256"}
    if _digest(scan["report_sha256"], "security_scan.report_sha256") != _canonical_digest(
        scan_body
    ):
        raise ValueError("security scan digest does not bind the report")


def _validate_result(value: dict[str, Any], source: dict[str, Any]) -> None:
    if set(value) != OUTPUT_FIELDS:
        raise ValueError("ReviewDecision fields do not match the contract")
    _validate_input(source)
    if value["issue_id"] != source["issue_id"] or value["tier"] != source["tier"]:
        raise ValueError("ReviewDecision identity does not match the candidate")
    review = value["review"]
    if not isinstance(review, dict) or set(review) != REVIEW_FIELDS:
        raise ValueError("review fields do not match ReviewResult")
    decision = review["decision"]
    if decision not in DECISIONS:
        raise ValueError("review decision is unsupported")
    findings = review["findings"]
    if not isinstance(findings, list) or len(findings) > 256:
        raise ValueError("review findings must be a bounded list")
    validated = [_validate_finding(item, scan=False) for item in findings]
    _text(review["summary"], "review.summary", maximum=8_192)
    if review["pr_url"] is not None:
        raise ValueError("candidate reviewer cannot create or claim a pull request")
    if not isinstance(review["requires_human_approval"], bool):
        raise ValueError("requires_human_approval must be a boolean")
    tier = value["tier"]
    expected_human = decision == "human_approval_required"
    if review["requires_human_approval"] is not expected_human:
        raise ValueError("review decision and human-approval flag are inconsistent")
    if decision == "approved":
        if tier in {"T4", "T5"} or any(
            item["severity"] in {"high", "critical"} for item in validated
        ):
            raise ValueError("review approval violates risk or finding gates")
    elif decision == "human_approval_required":
        if tier not in {"T4", "T5"} or any(
            item["severity"] in {"high", "critical"} for item in validated
        ):
            raise ValueError("human approval cannot bypass unresolved blocking findings")
    elif not validated:
        raise ValueError("changes_requested requires at least one actionable finding")


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
        raise ValueError("SkillFailure source digest does not match the candidate review input")
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

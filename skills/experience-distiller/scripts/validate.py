"""Validate one Skill input or output artifact; exit nonzero on violations."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from _contract import load_contract

SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in strings(child)]
    return []


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in {"input", "output"}:
        print("usage: validate.py <input|output> <artifact.json>", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parents[1]
    contract = load_contract(root / "references" / "contract.yaml")
    artifact = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise ValueError("artifact root must be an object")
    required = contract[sys.argv[1]]["required_fields"]
    missing = [key for key in required if key not in artifact]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")
    if any(SECRET.search(text) for text in strings(artifact)):
        raise ValueError("artifact contains secret-shaped content")
    for key in ("file", "file_path", "path"):
        for value in _find_values(artifact, key):
            path = PurePosixPath(str(value).replace("\\", "/"))
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe repository path: {value}")
    if sys.argv[1] == "input":
        _validate_verified_input(artifact, set(required))
    else:
        _validate_output(artifact, set(required))
    print(json.dumps({"valid": True, "skill": contract["name"], "mode": sys.argv[1]}))
    return 0


def _digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _validate_verified_input(
    artifact: dict[str, Any],
    required: set[str],
) -> None:
    if set(artifact) not in (required, required | {"human_approval"}):
        raise ValueError("verified run input contains unknown fields")
    issue_id = artifact["issue_id"]
    if isinstance(issue_id, bool) or not isinstance(issue_id, int) or issue_id < 1:
        raise ValueError("issue_id must be a positive integer")
    issue = _object(artifact["issue"], "issue")
    if issue.get("issue_number") != issue_id:
        raise ValueError("issue identity does not match")
    revision = artifact["repository_revision"]
    if not isinstance(revision, str) or not revision:
        raise ValueError("repository_revision must be non-empty")
    patch = _object(artifact["patch"], "patch")
    tests = _object(artifact["test_result"], "test_result")
    review = _object(artifact["review"], "review")
    comparison = _object(tests.get("baseline_comparison"), "baseline_comparison")
    integrity = _object(tests.get("integrity_attestation"), "integrity_attestation")
    if (
        tests.get("failed") != 0
        or tests.get("errors") != 0
        or comparison.get("regression") is not False
        or comparison.get("new_failures") != []
        or integrity.get("schema_version") != "1.0"
        or integrity.get("policy") != "immutable-baseline-tests/v1"
        or integrity.get("policy_digest")
        != "e30d5b49b5bbde322301604354d21f604687483b54d1b4dd0f2e86473462516c"
        or integrity.get("verified") is not True
        or integrity.get("baseline_manifest_digest")
        != integrity.get("candidate_baseline_manifest_digest")
        or integrity.get("candidate_pre_run_manifest_digest")
        != integrity.get("candidate_post_run_manifest_digest")
        or integrity.get("isolation_boundary")
        != "stdlib-temporary-directory-process-only-not-os-sandbox"
    ):
        raise ValueError("trusted experience requires a clean regression gate")
    if review.get("decision") != "approved" or review.get("requires_human_approval") is not False:
        raise ValueError("trusted experience requires an approved review")
    receipt = _object(artifact["terminal_receipt"], "terminal_receipt")
    receipt_fields = {
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
    if set(receipt) != receipt_fields:
        raise ValueError("terminal receipt fields do not match")
    receipt_body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != _digest(receipt_body):
        raise ValueError("terminal receipt digest does not match")
    if (
        receipt.get("schema_version") != "1.0"
        or receipt.get("issuer") != "TeamLeader"
        or receipt.get("terminal_state") not in {"review_approved", "human_approved"}
        or receipt.get("issue_id") != issue_id
        or receipt.get("repository_revision") != revision
        or receipt.get("run_id") != artifact["trace_id"]
        or receipt.get("candidate_digest") != _digest(patch)
        or receipt.get("test_result_digest") != _digest(tests)
        or receipt.get("review_digest") != _digest(review)
    ):
        raise ValueError("terminal receipt does not bind the supplied artifacts")
    human_approval = artifact.get("human_approval")
    if human_approval is not None:
        approval = _object(human_approval, "human_approval")
        approval_fields = {
            "approval_id",
            "action",
            "target",
            "artifact_digest",
            "approved_by",
            "approved_at",
            "signature",
        }
        if set(approval) != approval_fields:
            raise ValueError("human approval evidence fields do not match")
        if receipt.get("terminal_state") != "human_approved" or receipt.get(
            "approval_digest"
        ) != _digest(approval):
            raise ValueError("terminal receipt does not bind human approval")
    elif (
        receipt.get("terminal_state") != "review_approved"
        or receipt.get("approval_digest") is not None
    ):
        raise ValueError("autonomous terminal receipt has human approval claims")


def _validate_output(artifact: dict[str, Any], required: set[str]) -> None:
    if set(artifact) != required:
        raise ValueError("experience output contains unknown fields")
    if artifact.get("outcome") != "approved":
        raise ValueError("trusted experience outcome must be approved")
    if not isinstance(artifact.get("stored"), bool):
        raise ValueError("stored must be a boolean")
    provenance = _object(artifact.get("provenance"), "provenance")
    receipt_digest = provenance.get("terminal_receipt_sha256")
    if not isinstance(receipt_digest, str) or re.fullmatch(r"[a-f0-9]{64}", receipt_digest) is None:
        raise ValueError("experience provenance requires a terminal receipt digest")
    redaction = _object(artifact.get("redaction"), "redaction")
    if (
        redaction.get("secret_scan_passed") is not True
        or redaction.get("pii_scan_passed") is not True
    ):
        raise ValueError("experience redaction gates did not pass")


def _find_values(value: Any, target: str) -> list[Any]:
    if isinstance(value, dict):
        found = [value[target]] if target in value else []
        return found + [item for child in value.values() for item in _find_values(child, target)]
    if isinstance(value, list):
        return [item for child in value for item in _find_values(child, target)]
    return []


if __name__ == "__main__":
    raise SystemExit(main())

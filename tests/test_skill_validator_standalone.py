"""Prove every packaged Skill validator runs without site-packages."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.build_agentteams_package import (
    PACKAGE_VERSION,
    ROLE_SKILLS,
    build_role_packages,
    manifest_digest,
)
from scripts.github_scope_broker import (
    CapabilityCodec,
    ContentRequest,
    GitHubContent,
    OpenSSLEd25519ReceiptSigner,
    Scope,
    content_receipt,
)

ROOT = Path(__file__).resolve().parents[1]
SKILLS = tuple(sorted(path.name for path in (ROOT / "skills").iterdir() if path.is_dir()))
OPENSSL = next(
    path
    for path in (
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path("/usr/bin/openssl"),
    )
    if path.is_file()
)


def _isolated_env() -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONNOUSERSITE"] = "1"
    return env


def _canonical_digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _github_artifact(mode: str) -> dict[str, Any]:
    capability = (
        base64.urlsafe_b64encode(b'{"grant":"test"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(b"s" * 32).rstrip(b"=").decode()
    )
    if mode == "input":
        return {
            "repository": {"owner": "example", "repo": "repo"},
            "revision": "a" * 40,
            "capability": capability,
            "path": "README.md",
        }
    receipt: dict[str, Any] = {
        "schema_version": "devflow.github-content-response/v1",
        "authorization": {
            "decision": "allow",
            "task_id": "task-1",
            "scope_digest": "b" * 64,
            "capability_digest": hashlib.sha256(capability.encode()).hexdigest(),
            "authorized_at": 1,
        },
        "github": {
            "repository": "example/repo",
            "revision": "a" * 40,
            "path": "README.md",
            "object_sha": "c" * 40,
            "content_base64": "ZmlsZQ==",
            "encoding": "base64",
        },
    }
    receipt["response_digest"] = _canonical_digest(receipt)
    receipt["receipt_signature"] = "d" * 64
    artifact: dict[str, Any] = {
        "run_id": "run-1",
        "task_id": "task-1",
        "repository": {"owner": "example", "repo": "repo"},
        "revision": "a" * 40,
        "operations": [receipt],
        "evidence": [
            {
                "path": "README.md",
                "object_sha": "c" * 40,
                "content_sha256": hashlib.sha256(b"file").hexdigest(),
                "response_digest": receipt["response_digest"],
            }
        ],
        "trace_id": "run-1:task-1",
        "status": "success",
    }
    artifact["digest"] = _canonical_digest(artifact)
    return artifact


def _prepare_signed_github_output(
    tmp_path: Path,
    skills_root: Path,
    *,
    label: str,
) -> dict[str, Any]:
    trust_root = tmp_path / f"github-receipt-trust-{label}"
    trust_root.mkdir(parents=True)
    private_key = trust_root / "test-only-receipt-ed25519.pem"
    public_key = trust_root / "test-only-receipt-ed25519.pub"
    policy_path = trust_root / "receipt-policy.json"
    subprocess.run(
        [
            str(OPENSSL),
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            str(OPENSSL),
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        check=True,
        capture_output=True,
    )
    private_key.chmod(0o400)
    public_der = subprocess.run(
        [
            str(OPENSSL),
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    ).stdout
    policy = {
        "schemaVersion": "1.0",
        "algorithm": "Ed25519",
        "audience": "devflow.github-content-response/v2",
        "signatureDomain": "devflow.github-content-receipt/v2",
        "consumerRuntimeName": "devflow-locator",
        "publicKeyPath": str(public_key),
        "publicKeySha256": hashlib.sha256(public_der).hexdigest(),
        "publicKeyFileSha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "policyPath": str(policy_path),
        "opensslPath": str(OPENSSL),
    }
    policy_path.write_text(
        json.dumps(policy, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    public_key.chmod(0o444)
    policy_path.chmod(0o444)
    validator = skills_root / "github-evidence" / "scripts" / "validate.py"
    source = validator.read_text(encoding="utf-8")
    source = source.replace(
        'PRODUCTION_RECEIPT_PUBLIC_KEY = Path(\n'
        '    "/etc/devflow/github-evidence/receipt-ed25519.pub"\n'
        ")",
        f"PRODUCTION_RECEIPT_PUBLIC_KEY = Path({str(public_key)!r})",
    )
    source = source.replace(
        'PRODUCTION_RECEIPT_POLICY = Path(\n'
        '    "/etc/devflow/github-evidence/receipt-policy.json"\n'
        ")",
        f"PRODUCTION_RECEIPT_POLICY = Path({str(policy_path)!r})",
    )
    source = source.replace(
        'PRODUCTION_OPENSSL = Path("/usr/bin/openssl")',
        f"PRODUCTION_OPENSSL = Path({str(OPENSSL)!r})",
    )
    validator.write_text(source, encoding="utf-8")

    codec = CapabilityCodec(b"test-only-capability-hmac-key-32-bytes")
    capability, claims = codec.issue(
        Scope.from_issuer_document(
            {
                "run_id": "run-1",
                "task_id": "task-1",
                "trace_id": "run-1:task-1",
                "owner": "example",
                "repo": "repo",
                "revision": "a" * 40,
                "paths": ["README.md"],
            }
        ),
        now=1,
        jti="0" * 32,
    )
    receipt = content_receipt(
        signer=OpenSSLEd25519ReceiptSigner(private_key, openssl_path=OPENSSL),
        capability=capability,
        claims=claims,
        request=ContentRequest(
            task_id="task-1",
            owner="example",
            repo="repo",
            path="README.md",
            revision="a" * 40,
        ),
        content=GitHubContent(object_sha="c" * 40, content_base64="ZmlsZQ=="),
        authorized_at=1,
    )
    artifact: dict[str, Any] = {
        "run_id": "run-1",
        "task_id": "task-1",
        "repository": {"owner": "example", "repo": "repo"},
        "revision": "a" * 40,
        "operations": [receipt],
        "evidence": [
            {
                "path": "README.md",
                "object_sha": "c" * 40,
                "content_sha256": hashlib.sha256(b"file").hexdigest(),
                "response_digest": receipt["response_digest"],
            }
        ],
        "trace_id": "run-1:task-1",
        "status": "success",
    }
    artifact["digest"] = _canonical_digest(artifact)
    return artifact


def _patch() -> dict[str, Any]:
    return {
        "branch_name": "devflow/issue-7",
        "changes": [
            {
                "file_path": "calculator.py",
                "change_type": "modify",
                "original_content": "return a - b\n",
                "new_content": "return a + b\n",
                "diff": (
                    "--- a/calculator.py\n+++ b/calculator.py\n-return a - b\n+return a + b\n"
                ),
            }
        ],
        "commit_message": "Fix addition",
        "description": "Use addition in the add helper.",
    }


def _issue_intake() -> dict[str, Any]:
    return {
        "issue_number": 7,
        "title": "Addition is wrong",
        "author": "reporter",
        "repo_owner": "example",
        "repo_name": "calculator",
        "created_at": "2026-07-28T12:00:00+00:00",
    }


def _classified_issue() -> dict[str, Any]:
    issue = _patch_generator_input()["issue"]
    return {
        "issue": issue,
        "complexity_level": "T2",
        "category": "bug",
        "priority": "high",
        "duplicate_of": None,
        "estimated_effort_hours": 2.0,
        "rationale": "A bounded arithmetic defect with an existing regression test.",
        "confidence": 0.96,
        "evidence": {
            "risk_floor": {
                "proposed_tier": "T2",
                "effective_tier": "T2",
                "rule_ids": [],
                "model_confidence": 0.96,
                "conflict": False,
            },
            "deduplication": {
                "status": "checked",
                "threshold": 0.92,
                "candidate_issue": None,
                "candidate_score": None,
            },
        },
    }


def _root_cause_input() -> dict[str, Any]:
    github = _github_artifact("output")
    github["repository"] = {"owner": "example", "repo": "calculator"}
    github["revision"] = "a" * 40
    for operation in github["operations"]:
        operation["github"]["repository"] = "example/calculator"
        operation["github"]["revision"] = "a" * 40
        unsigned = {
            "schema_version": operation["schema_version"],
            "authorization": operation["authorization"],
            "github": operation["github"],
        }
        operation["response_digest"] = _canonical_digest(unsigned)
    github["evidence"][0]["response_digest"] = github["operations"][0][
        "response_digest"
    ]
    github["digest"] = _canonical_digest(
        {key: value for key, value in github.items() if key != "digest"}
    )
    return {
        "issue_id": 7,
        "repository_revision": "a" * 40,
        "classified_issue": _classified_issue(),
        "github_evidence": github,
    }


def _located_output() -> dict[str, Any]:
    evidence = _root_cause_input()["github_evidence"]["evidence"][0]
    return {
        "issue_id": 7,
        "repository_revision": "a" * 40,
        "root_cause": {
            "summary": "The documented operation is implemented incorrectly.",
            "file": "README.md",
            "start_line": 1,
            "end_line": 1,
            "confidence": 0.9,
        },
        "affected_files": [
            {
                "path": "README.md",
                "reason": "Contains the verified root-cause evidence.",
                "change_type": "edit",
            }
        ],
        "related_tests": [],
        "context_ref": {
            "path": "README.md",
            "sha256": evidence["content_sha256"],
        },
        "confidence": 0.9,
        "evidence": [evidence],
    }


def _patch_candidate() -> dict[str, Any]:
    patch = _patch()
    located = _patch_generator_input()["located_context"]
    boundary_body = {
        "schema_version": "1.0",
        "located_context_digest": _canonical_digest(located),
        "allowed_files": ["calculator.py", "tests/test_calculator.py"],
    }
    return {
        "schema_version": "1.2",
        "issue_id": 7,
        "tier": "T2",
        "patch": patch,
        "candidate_digest": _canonical_digest(patch),
        "evidence_boundary": {
            **boundary_body,
            "scope_digest": _canonical_digest(boundary_body),
        },
        "model_call_attempt": 1,
        "retry_attempt": 1,
    }


def _patch_generator_input() -> dict[str, Any]:
    return {
        "issue_id": 7,
        "tier": "T2",
        "model_call_attempt": 1,
        "issue": {
            "issue_number": 7,
            "title": "Addition is wrong",
            "body": "The helper subtracts.",
            "labels": ["bug"],
            "state": "open",
            "author": "reporter",
            "created_at": "2026-07-28T12:00:00+00:00",
            "repo_owner": "example",
            "repo_name": "calculator",
        },
        "located_context": {
            "root_cause": {
                "summary": "The helper subtracts instead of adding.",
                "file": "calculator.py",
                "start_line": 1,
                "end_line": 1,
                "confidence": 0.99,
            },
            "affected_files": [],
            "context_payload": "return a - b",
            "related_tests": ["tests/test_calculator.py"],
            "impact_analysis": {
                "affected_files": ["calculator.py"],
                "affected_modules": [],
                "risk_level": "low",
                "breaking_changes": False,
                "test_files_needed": ["tests/test_calculator.py"],
            },
        },
    }


def _test_evidence() -> dict[str, Any]:
    repository = {
        "archive_sha256": "1" * 64,
        "manifest_sha256": "2" * 64,
    }
    execution_policy = {
        "schema": "devflow.test-execution-policy/v1",
        "profile": "focused",
        "isolation_profile": "agentteams-bwrap-tests/v1",
        "isolation_boundary": (
            "linux-bubblewrap-unshare-all-cap-drop-process-boundary-"
            "not-node-root-or-kernel"
        ),
        "credentials_forwarded": False,
        "network": "bubblewrap-unshare-all-mask-runtime-credentials",
        "shell": False,
        "deployment_tools_exposed": False,
        "timeout_seconds": 120,
        "resource_limits_applied": True,
        "policy_digest": "3" * 64,
        "server_digest": "4" * 64,
        "repository_archive_sha256": repository["archive_sha256"],
        "repository_manifest_sha256": repository["manifest_sha256"],
        "remaining_threat": "Host root or kernel compromise remains out of scope.",
    }
    artifact: dict[str, Any] = {
        "issue_id": 7,
        "tier": "T2",
        "candidate_digest": _patch_candidate()["candidate_digest"],
        "repository": repository,
        "revision": "a" * 40,
        "workspace_binding": "3" * 64,
        "execution_profile": "focused",
        "isolation_profile": "agentteams-bwrap-tests/v1",
        "execution_policy": execution_policy,
        "test_result": {
            "total": 1,
            "passed": 1,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "duration_ms": 1,
            "results": [
                {
                    "name": "tests/test_calculator.py::test_add",
                    "status": "passed",
                    "duration_ms": 1,
                    "error_message": None,
                    "traceback": None,
                }
            ],
            "baseline_comparison": {
                "baseline_passed": 0,
                "current_passed": 1,
                "new_failures": [],
                "fixed_tests": ["tests/test_calculator.py::test_add"],
                "regression": False,
            },
            "integrity_attestation": {
                "schema_version": "1.0",
                "policy": "agentteams-bwrap-tests/v1",
                "policy_digest": (
                    "e1527ec714370ab983443b14559953d1a0d6a0a4d838930a120c3559f095fe13"
                ),
                "command_digest": "a" * 64,
                "baseline_manifest_digest": "b" * 64,
                "candidate_baseline_manifest_digest": "b" * 64,
                "candidate_pre_run_manifest_digest": "c" * 64,
                "candidate_post_run_manifest_digest": "c" * 64,
                "added_tests_manifest_digest": "d" * 64,
                "baseline_protected_file_count": 1,
                "added_test_file_count": 0,
                "full_suite": False,
                "verified": True,
                "isolation_boundary": (
                    "linux-bubblewrap-unshare-all-cap-drop-process-boundary-"
                    "not-node-root-or-kernel"
                ),
            },
        },
        "test_result_redacted": False,
        "failing_tests": [],
    }
    run_id = "issue-7"
    task_id = "7-testeragent-test-runner"
    artifact["test_execution_receipt"] = {
        "schema": "devflow.test-execution-receipt/v1",
        "algorithm": "Ed25519",
        "issuer": "devflow-tester-cicd",
        "audience": "devflow-teamharness",
        "run_id": run_id,
        "task_id": task_id,
        "trace_id": f"{run_id}:{task_id}",
        "issue_id": artifact["issue_id"],
        "repository": repository,
        "revision": artifact["revision"],
        "workspace_binding": artifact["workspace_binding"],
        "candidate_digest": artifact["candidate_digest"],
        "tier": artifact["tier"],
        "execution_profile": artifact["execution_profile"],
        "isolation_profile": artifact["isolation_profile"],
        "test_result_digest": _canonical_digest(artifact["test_result"]),
        "execution_policy_digest": _canonical_digest(execution_policy),
        "policy_digest": execution_policy["policy_digest"],
        "server_digest": execution_policy["server_digest"],
        "key_sha256": "5" * 64,
        "iat": 1_800_000_000,
        "exp": 1_800_000_120,
        "jti": "6" * 32,
        "signature": "A" * 86,
    }
    return artifact


def _review_input() -> dict[str, Any]:
    candidate = _patch_candidate()
    tests = _test_evidence()["test_result"]
    scan_body: dict[str, Any] = {
        "schema_version": "1.0",
        "scanner": "devflow-static-analysis",
        "policy_version": "1.0",
        "status": "passed",
        "findings": [],
    }
    return {
        "issue_id": 7,
        "tier": "T2",
        "candidate": candidate,
        "candidate_digest": candidate["candidate_digest"],
        "baseline_revision": "a" * 40,
        "suite": "python-unit",
        "status": "passed",
        "totals": {
            name: tests[name] for name in ("total", "passed", "failed", "errors", "skipped")
        },
        "baseline_comparison": tests["baseline_comparison"],
        "evidence": {
            "test_result_sha256": _canonical_digest(tests),
            "integrity_attestation_sha256": _canonical_digest(
                tests["integrity_attestation"]
            ),
            "security_scan": {
                **scan_body,
                "report_sha256": _canonical_digest(scan_body),
            },
        },
    }


def _review_output() -> dict[str, Any]:
    return {
        "issue_id": 7,
        "tier": "T2",
        "review": {
            "decision": "approved",
            "findings": [],
            "summary": "The candidate is bounded, green, and free of blocking findings.",
            "pr_url": None,
            "requires_human_approval": False,
        },
    }


def _experience_input() -> dict[str, Any]:
    patch = _patch()
    test_result = _test_evidence()["test_result"]
    # Experience-distiller's local fixture exercises the portable runtime
    # boundary. AgentTeams evidence uses the separate receipt-backed profile.
    test_result["integrity_attestation"].update(
        {
            "policy": "immutable-baseline-tests/v1",
            "policy_digest": (
                "e30d5b49b5bbde322301604354d21f604687483b54d1b4dd0f2e86473462516c"
            ),
            "isolation_boundary": (
                "stdlib-temporary-directory-process-only-not-os-sandbox"
            ),
        }
    )
    review: dict[str, Any] = {
        "decision": "approved",
        "findings": [],
        "summary": "The candidate is regression-free and within scope.",
        "pr_url": None,
        "requires_human_approval": False,
    }
    receipt_body: dict[str, Any] = {
        "schema_version": "1.0",
        "issuer": "TeamLeader",
        "run_id": "run-7",
        "issue_id": 7,
        "repository_revision": "a" * 40,
        "terminal_state": "review_approved",
        "candidate_digest": _canonical_digest(patch),
        "test_result_digest": _canonical_digest(test_result),
        "review_digest": _canonical_digest(review),
        "approval_digest": None,
    }
    return {
        "issue_id": 7,
        "issue": _patch_generator_input()["issue"],
        "tier": "T2",
        "repository_revision": "a" * 40,
        "located_context": _patch_generator_input()["located_context"],
        "patch": patch,
        "test_result": test_result,
        "review": review,
        "trace_id": "run-7",
        "terminal_receipt": {
            **receipt_body,
            "receipt_sha256": _canonical_digest(receipt_body),
        },
    }


def _experience_output() -> dict[str, Any]:
    source = _experience_input()
    patch_digest = _canonical_digest(source["patch"])
    return {
        "pattern_id": f"exp-7-{patch_digest[:12]}",
        "schema_version": "1.0",
        "outcome": "approved",
        "summary": "A bounded fix passed the regression gate.",
        "reusable_lesson": "Bind fixes to exact reviewed evidence.",
        "provenance": {
            "trace_id": source["trace_id"],
            "issue_id": 7,
            "repository_revision": source["repository_revision"],
            "candidate_digest": patch_digest,
            "review_digest": _canonical_digest(source["review"]),
            "terminal_receipt_sha256": source["terminal_receipt"]["receipt_sha256"],
        },
        "redaction": {
            "policy_version": "1.0",
            "secret_scan_passed": True,
            "pii_scan_passed": True,
        },
        "stored": True,
    }


def _artifact(skill: str, mode: str) -> dict[str, Any]:
    if skill == "github-evidence":
        return _github_artifact(mode)
    if skill == "patch-generator":
        return _patch_generator_input() if mode == "input" else _patch_candidate()
    if skill == "test-runner":
        return _patch_candidate() if mode == "input" else _test_evidence()
    if skill == "experience-distiller":
        return _experience_input() if mode == "input" else _experience_output()
    if skill == "issue-classifier":
        return _issue_intake() if mode == "input" else _classified_issue()
    if skill == "code-root-cause":
        return _root_cause_input() if mode == "input" else _located_output()
    if skill == "pr-reviewer":
        return _review_input() if mode == "input" else _review_output()
    contract = yaml.safe_load(
        (ROOT / "skills" / skill / "references" / "contract.yaml").read_text(encoding="utf-8")
    )
    return {field: "value" for field in contract[mode]["required_fields"]}


def _run_validator(
    skill: str,
    mode: str,
    artifact_path: Path,
    *,
    skills_root: Path = ROOT / "skills",
    source_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    validator = skills_root / skill / "scripts" / "validate.py"
    command = [sys.executable, "-S", str(validator), mode, str(artifact_path)]
    if source_path is not None:
        command.append(str(source_path))
    return subprocess.run(
        command,
        cwd=artifact_path.parent,
        env=_isolated_env(),
        text=True,
        capture_output=True,
        check=False,
    )


def test_isolation_really_removes_pyyaml() -> None:
    probe = subprocess.run(
        [sys.executable, "-S", "-c", "import yaml"],
        env=_isolated_env(),
        text=True,
        capture_output=True,
        check=False,
    )
    assert probe.returncode != 0
    assert "yaml" in probe.stderr


@pytest.mark.parametrize("skill", SKILLS)
@pytest.mark.parametrize("mode", ("input", "output"))
def test_validator_accepts_complete_artifact_without_site_packages(
    tmp_path: Path,
    skill: str,
    mode: str,
) -> None:
    skills_root = ROOT / "skills"
    artifact = _artifact(skill, mode)
    if skill == "github-evidence" and mode == "output":
        skills_root = tmp_path / "test-skills"
        shutil.copytree(
            ROOT / "skills" / "github-evidence",
            skills_root / "github-evidence",
        )
        artifact = _prepare_signed_github_output(
            tmp_path,
            skills_root,
            label="standalone",
        )
    artifact_path = tmp_path / f"{skill}-{mode}.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    source_path: Path | None = None
    if skill == "patch-generator" and mode == "output":
        source_path = tmp_path / "patch-generator-output-source.json"
        source_path.write_text(json.dumps(_patch_generator_input()), encoding="utf-8")
    elif skill == "test-runner" and mode == "output":
        source_path = tmp_path / "test-runner-output-source.json"
        source_path.write_text(json.dumps(_patch_candidate()), encoding="utf-8")
    elif skill in {
        "issue-classifier",
        "code-root-cause",
        "pr-reviewer",
        "experience-distiller",
    } and mode == "output":
        source_path = tmp_path / f"{skill}-output-source.json"
        source_path.write_text(json.dumps(_artifact(skill, "input")), encoding="utf-8")

    completed = _run_validator(
        skill,
        mode,
        artifact_path,
        skills_root=skills_root,
        source_path=source_path,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "valid": True,
        "skill": skill,
        "mode": mode,
    }


@pytest.mark.parametrize("skill", SKILLS)
def test_validator_remains_fail_closed_without_site_packages(
    tmp_path: Path,
    skill: str,
) -> None:
    artifact = _artifact(skill, "input")
    artifact.pop(next(iter(artifact)))
    artifact_path = tmp_path / f"{skill}-invalid.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    completed = _run_validator(skill, "input", artifact_path)

    assert completed.returncode != 0
    if skill == "github-evidence":
        assert "input schema is invalid" in completed.stderr
    elif skill in {
        "issue-classifier",
        "code-root-cause",
        "pr-reviewer",
        "experience-distiller",
    }:
        assert "fields do not match" in completed.stderr
    else:
        assert "missing required fields" in completed.stderr


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda value: value.pop("model_call_attempt"), "missing required fields"),
        (
            lambda value: value.update(model_call_attempt=4),
            "three-call global budget",
        ),
        (
            lambda value: value.update(
                retry_attempt=2,
                model_call_attempt=1,
                revision_of="a" * 64,
            ),
            "cannot precede retry_attempt",
        ),
    ],
)
@pytest.mark.parametrize("skill", ("patch-generator", "test-runner"))
def test_patch_candidate_model_call_contract_fails_closed_without_site_packages(
    tmp_path: Path,
    skill: str,
    mutation: Any,
    expected: str,
) -> None:
    candidate = _patch_candidate()
    mutation(candidate)
    artifact_path = tmp_path / f"{skill}-candidate-attempt-invalid.json"
    artifact_path.write_text(json.dumps(candidate), encoding="utf-8")
    source_path: Path | None = None
    mode = "input"
    if skill == "patch-generator":
        mode = "output"
        source_path = tmp_path / "patch-generator-attempt-source.json"
        source_path.write_text(json.dumps(_patch_generator_input()), encoding="utf-8")

    completed = _run_validator(
        skill,
        mode,
        artifact_path,
        source_path=source_path,
    )

    assert completed.returncode == 1
    assert expected in completed.stderr


def test_patch_generator_binds_model_call_ordinal_to_verified_source(
    tmp_path: Path,
) -> None:
    candidate = _patch_candidate()
    candidate["model_call_attempt"] = 2
    artifact_path = tmp_path / "patch-generator-unbound-model-call.json"
    artifact_path.write_text(json.dumps(candidate), encoding="utf-8")
    source_path = tmp_path / "patch-generator-call-one-source.json"
    source_path.write_text(json.dumps(_patch_generator_input()), encoding="utf-8")

    completed = _run_validator(
        "patch-generator",
        "output",
        artifact_path,
        source_path=source_path,
    )

    assert completed.returncode == 1
    assert "model_call_attempt does not match" in completed.stderr


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value["test_result"]["baseline_comparison"].update(
            regression=True,
            new_failures=["hidden_regression"],
        ),
        lambda value: value["review"].update(decision="changes_requested"),
        lambda value: value["terminal_receipt"].update(receipt_sha256="0" * 64),
        lambda value: value["terminal_receipt"].update(issue_id=8),
    ),
)
def test_experience_validator_rejects_untrusted_terminal_evidence(
    tmp_path: Path,
    mutation: Any,
) -> None:
    artifact = copy.deepcopy(_experience_input())
    mutation(artifact)
    artifact_path = tmp_path / "experience-untrusted.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    completed = _run_validator(
        "experience-distiller",
        "input",
        artifact_path,
    )

    assert completed.returncode != 0


FAILURE_RULES: dict[str, tuple[str, bool, int, str]] = {
    "issue-classifier": ("INPUT_INVALID", False, 0, "triage.failed"),
    "code-root-cause": ("RETRIEVAL_EMPTY", True, 2, "locator.blocked"),
    "pr-reviewer": ("EVIDENCE_INVALID", False, 0, "review.failed"),
    "experience-distiller": (
        "STORE_UNAVAILABLE",
        True,
        2,
        "experience.degraded",
    ),
}


def _skill_failure(skill: str, source: dict[str, Any]) -> dict[str, Any]:
    code, retryable, maximum, event = FAILURE_RULES[skill]
    retry_count = 0
    return {
        "schema_version": "1.0",
        "skill": skill,
        "code": code,
        "retryable": retryable,
        "retry_count": retry_count,
        "max_attempts": maximum,
        "exhausted": not retryable or retry_count == maximum,
        "route_to": "TeamLeader",
        "event": event,
        "source_artifact_sha256": _canonical_digest(source),
        "summary": "The bounded invocation failed without emitting a success artifact.",
        "diagnostics": ["deterministic failure fixture"],
    }


@pytest.mark.parametrize("skill", tuple(FAILURE_RULES))
def test_validator_accepts_strict_source_bound_skill_failure(
    tmp_path: Path,
    skill: str,
) -> None:
    source = _artifact(skill, "input")
    artifact_path = tmp_path / f"{skill}-failure.json"
    source_path = tmp_path / f"{skill}-failure-source.json"
    artifact_path.write_text(json.dumps(_skill_failure(skill, source)), encoding="utf-8")
    source_path.write_text(json.dumps(source), encoding="utf-8")

    completed = _run_validator(
        skill,
        "output",
        artifact_path,
        source_path=source_path,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize("skill", tuple(FAILURE_RULES))
@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.update(route_to="HumanReviewer"),
        lambda value: value.update(source_artifact_sha256="0" * 64),
        lambda value: value.update(exhausted=not value["exhausted"]),
        lambda value: value.update(undeclared=True),
    ),
)
def test_validator_rejects_unbound_or_policy_drifting_skill_failure(
    tmp_path: Path,
    skill: str,
    mutation: Any,
) -> None:
    source = _artifact(skill, "input")
    failure = _skill_failure(skill, source)
    mutation(failure)
    artifact_path = tmp_path / f"{skill}-bad-failure.json"
    source_path = tmp_path / f"{skill}-bad-failure-source.json"
    artifact_path.write_text(json.dumps(failure), encoding="utf-8")
    source_path.write_text(json.dumps(source), encoding="utf-8")

    completed = _run_validator(
        skill,
        "output",
        artifact_path,
        source_path=source_path,
    )

    assert completed.returncode != 0


@pytest.mark.parametrize(
    ("skill", "mutation"),
    (
        (
            "issue-classifier",
            lambda value: value.update(complexity_level="simple"),
        ),
        (
            "issue-classifier",
            lambda value: value["evidence"]["risk_floor"].update(
                effective_tier="T1"
            ),
        ),
        (
            "code-root-cause",
            lambda value: value.update(repository_revision="b" * 40),
        ),
        (
            "code-root-cause",
            lambda value: value["root_cause"].update(confidence=0.29),
        ),
        (
            "pr-reviewer",
            lambda value: value["review"].update(
                pr_url="https://github.com/example/repo/pull/7"
            ),
        ),
        (
            "pr-reviewer",
            lambda value: value.update(tier="T4"),
        ),
        (
            "experience-distiller",
            lambda value: value.update(stored=False),
        ),
        (
            "experience-distiller",
            lambda value: value["provenance"].update(candidate_digest="0" * 64),
        ),
    ),
)
def test_strict_success_validators_reject_false_completion_or_cross_field_drift(
    tmp_path: Path,
    skill: str,
    mutation: Any,
) -> None:
    artifact = copy.deepcopy(_artifact(skill, "output"))
    source = _artifact(skill, "input")
    mutation(artifact)
    artifact_path = tmp_path / f"{skill}-false-success.json"
    source_path = tmp_path / f"{skill}-false-success-source.json"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    source_path.write_text(json.dumps(source), encoding="utf-8")

    completed = _run_validator(
        skill,
        "output",
        artifact_path,
        source_path=source_path,
    )

    assert completed.returncode != 0


def test_worker_package_contains_each_skill_local_contract_reader(tmp_path: Path) -> None:
    build_role_packages(ROOT, tmp_path, source_date_epoch=0)

    packaged: dict[str, set[str]] = {}
    for archive_path in tmp_path.glob("*.zip"):
        role = archive_path.name.split("-v", 1)[0]
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
            manifest = json.loads(archive.read("manifest.json"))
        assert manifest["version"] == PACKAGE_VERSION
        assert manifest["role"] == role
        assert manifest["skills"] == list(ROLE_SKILLS[role])
        assert manifest["manifest_sha256"] == manifest_digest(manifest)
        packaged[role] = {
            name.split("/", 2)[1]
            for name in names
            if name.startswith("skills/") and name.endswith("/scripts/_contract.py")
        }
    assert packaged == {role: set(skills) for role, skills in ROLE_SKILLS.items()}


@pytest.mark.parametrize("mode", ("input", "output"))
def test_packaged_validator_executes_from_its_role_archive_without_site_packages(
    tmp_path: Path,
    mode: str,
) -> None:
    release = tmp_path / "release"
    build_role_packages(ROOT, release, source_date_epoch=0)
    for role, skills in ROLE_SKILLS.items():
        extracted = tmp_path / "extracted" / role
        with zipfile.ZipFile(release / f"{role}-v{PACKAGE_VERSION}.zip") as archive:
            for info in archive.infolist():
                if not info.filename.startswith("skills/"):
                    continue
                destination = extracted.joinpath(*Path(info.filename).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(info))
        for skill in skills:
            artifact_path = tmp_path / f"packaged-{role}-{skill}-{mode}.json"
            artifact = _artifact(skill, mode)
            if skill == "github-evidence" and mode == "output":
                artifact = _prepare_signed_github_output(
                    tmp_path,
                    extracted / "skills",
                    label=f"packaged-{role}",
                )
            artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
            source_path: Path | None = None
            if skill == "patch-generator" and mode == "output":
                source_path = tmp_path / f"packaged-{role}-{skill}-source.json"
                source_path.write_text(json.dumps(_patch_generator_input()), encoding="utf-8")
            elif skill == "test-runner" and mode == "output":
                source_path = tmp_path / f"packaged-{role}-{skill}-source.json"
                source_path.write_text(json.dumps(_patch_candidate()), encoding="utf-8")
            elif skill in {
                "issue-classifier",
                "code-root-cause",
                "pr-reviewer",
                "experience-distiller",
            } and mode == "output":
                source_path = tmp_path / f"packaged-{role}-{skill}-source.json"
                source_path.write_text(
                    json.dumps(_artifact(skill, "input")), encoding="utf-8"
                )
            completed = _run_validator(
                skill,
                mode,
                artifact_path,
                skills_root=extracted / "skills",
                source_path=source_path,
            )
            assert completed.returncode == 0, completed.stderr

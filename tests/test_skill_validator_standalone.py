"""Prove every packaged Skill validator runs without site-packages."""

from __future__ import annotations

import base64
import hashlib
import json
import os
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

ROOT = Path(__file__).resolve().parents[1]
SKILLS = tuple(sorted(path.name for path in (ROOT / "skills").iterdir() if path.is_dir()))


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
        "trace_id": "trace-1",
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
    return {
        "issue_id": 7,
        "candidate_digest": _patch_candidate()["candidate_digest"],
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
        },
        "test_result_redacted": False,
        "failing_tests": [],
    }


def _artifact(skill: str, mode: str) -> dict[str, Any]:
    if skill == "github-evidence":
        return _github_artifact(mode)
    if skill == "patch-generator":
        return _patch_generator_input() if mode == "input" else _patch_candidate()
    if skill == "test-runner":
        return _patch_candidate() if mode == "input" else _test_evidence()
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
    artifact_path = tmp_path / f"{skill}-{mode}.json"
    artifact_path.write_text(json.dumps(_artifact(skill, mode)), encoding="utf-8")
    source_path: Path | None = None
    if skill == "patch-generator" and mode == "output":
        source_path = tmp_path / "patch-generator-output-source.json"
        source_path.write_text(json.dumps(_patch_generator_input()), encoding="utf-8")
    elif skill == "test-runner" and mode == "output":
        source_path = tmp_path / "test-runner-output-source.json"
        source_path.write_text(json.dumps(_patch_candidate()), encoding="utf-8")

    completed = _run_validator(
        skill,
        mode,
        artifact_path,
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
    expected_error = (
        "input schema is invalid" if skill == "github-evidence" else "missing required fields"
    )
    assert expected_error in completed.stderr


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
            artifact_path.write_text(json.dumps(_artifact(skill, mode)), encoding="utf-8")
            source_path: Path | None = None
            if skill == "patch-generator" and mode == "output":
                source_path = tmp_path / f"packaged-{role}-{skill}-source.json"
                source_path.write_text(json.dumps(_patch_generator_input()), encoding="utf-8")
            elif skill == "test-runner" and mode == "output":
                source_path = tmp_path / f"packaged-{role}-{skill}-source.json"
                source_path.write_text(json.dumps(_patch_candidate()), encoding="utf-8")
            completed = _run_validator(
                skill,
                mode,
                artifact_path,
                skills_root=extracted / "skills",
                source_path=source_path,
            )
            assert completed.returncode == 0, completed.stderr

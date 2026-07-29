"""Executable Tester-to-Coder Skill boundary contract tests."""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import yaml

from devflow.agents.coder_agent import CoderAgent
from devflow.agents.locator_agent import LocatedContext
from devflow.exceptions import AgentError
from devflow.models.patch import Patch
from devflow.models.test_result import (
    TestFailureEvidence as FailureEvidence,
)
from devflow.models.test_result import (
    TestRunResult as RunResult,
)
from devflow.models.test_result import (
    canonical_artifact_digest,
    redact_test_result_for_handoff,
)
from devflow.skills.contracts import HandoffEnvelope, HandoffStatus

ROOT = Path(__file__).resolve().parents[1]
TEST_VALIDATOR = ROOT / "skills/test-runner/scripts/validate.py"
PATCH_VALIDATOR = ROOT / "skills/patch-generator/scripts/validate.py"


def _digest(value: dict[str, Any]) -> str:
    serialized = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def _integrity_attestation(*, full_suite: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "policy": "immutable-baseline-tests/v1",
        "policy_digest": "e30d5b49b5bbde322301604354d21f604687483b54d1b4dd0f2e86473462516c",
        "command_digest": "a" * 64,
        "baseline_manifest_digest": "b" * 64,
        "candidate_baseline_manifest_digest": "b" * 64,
        "candidate_pre_run_manifest_digest": "c" * 64,
        "candidate_post_run_manifest_digest": "c" * 64,
        "added_tests_manifest_digest": "d" * 64,
        "baseline_protected_file_count": 1,
        "added_test_file_count": 0,
        "full_suite": full_suite,
        "verified": True,
        "isolation_boundary": "stdlib-temporary-directory-process-only-not-os-sandbox",
    }


def _run_validator(
    tmp_path: Path,
    validator: Path,
    mode: str,
    artifact: dict[str, Any],
    source: dict[str, Any] | None = None,
) -> subprocess.CompletedProcess[str]:
    path = tmp_path / f"{validator.parent.parent.name}-{mode}.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    command = [sys.executable, str(validator), mode, str(path)]
    if source is None and validator == TEST_VALIDATOR and mode != "input":
        source = _patch_candidate()
    if source is not None:
        source_path = tmp_path / f"{validator.parent.parent.name}-{mode}-source.json"
        source_path.write_text(json.dumps(source), encoding="utf-8")
        command.append(str(source_path))
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def _previous_patch() -> dict[str, Any]:
    return {
        "branch_name": "devflow/issue-42",
        "changes": [
            {
                "file_path": "calculator.py",
                "change_type": "modify",
                "original_content": "def add(a, b):\n    return a - b\n",
                "new_content": "def add(a, b):\n    return a + b\n",
                "diff": (
                    "--- a/calculator.py\n"
                    "+++ b/calculator.py\n"
                    "@@ -1,2 +1,2 @@\n"
                    "-    return a - b\n"
                    "+    return a + b\n"
                ),
            }
        ],
        "commit_message": "Fix addition",
        "description": "Correct the calculator addition path.",
    }


def _issue() -> dict[str, Any]:
    return {
        "issue_number": 42,
        "title": "Addition is wrong",
        "body": "The add helper subtracts its arguments.",
        "labels": ["bug"],
        "state": "open",
        "author": "reporter",
        "created_at": "2026-07-28T12:00:00+00:00",
        "repo_owner": "example",
        "repo_name": "calculator",
    }


def _located_context() -> dict[str, Any]:
    return {
        "root_cause": {
            "summary": "The add helper uses subtraction.",
            "file": "calculator.py",
            "start_line": 2,
            "end_line": 2,
            "confidence": 0.99,
        },
        "affected_files": [
            {
                "path": "calculator.py",
                "reason": "Contains the faulty expression.",
                "change_type": "edit",
            }
        ],
        "context_payload": "calculator.py: return a - b",
        "related_tests": ["tests/test_calc.py"],
        "impact_analysis": {
            "affected_files": ["calculator.py"],
            "affected_modules": [],
            "risk_level": "low",
            "breaking_changes": False,
            "test_files_needed": ["tests/test_calc.py"],
        },
    }


def _initial_invocation() -> dict[str, Any]:
    return {
        "issue_id": 42,
        "issue": _issue(),
        "tier": "T2",
        "located_context": _located_context(),
        "model_call_attempt": 1,
    }


def _patch_candidate() -> dict[str, Any]:
    patch = _previous_patch()
    located = _located_context()
    boundary_body = {
        "schema_version": "1.0",
        "located_context_digest": _digest(located),
        "allowed_files": ["calculator.py", "tests/test_calc.py"],
    }
    return {
        "schema_version": "1.2",
        "issue_id": 42,
        "tier": "T2",
        "patch": patch,
        "candidate_digest": _digest(patch),
        "evidence_boundary": {
            **boundary_body,
            "scope_digest": _digest(boundary_body),
        },
        "model_call_attempt": 1,
        "retry_attempt": 1,
    }


def _sanitized_result() -> dict[str, Any]:
    return {
        "total": 2,
        "passed": 1,
        "failed": 1,
        "errors": 0,
        "skipped": 0,
        "duration_ms": 12,
        "results": [
            {
                "name": "tests/test_calc.py::test_add",
                "status": "failed",
                "duration_ms": 4,
                "error_message": "token=[REDACTED]",
                "traceback": "AssertionError: 1 != 2",
            },
            {
                "name": "tests/test_calc.py::test_subtract",
                "status": "passed",
                "duration_ms": 3,
                "error_message": None,
                "traceback": None,
            },
        ],
        "baseline_comparison": {
            "baseline_passed": 2,
            "current_passed": 1,
            "new_failures": ["tests/test_calc.py::test_add"],
            "fixed_tests": [],
            "regression": True,
        },
        "integrity_attestation": _integrity_attestation(),
    }


def _passing_result() -> dict[str, Any]:
    return {
        "total": 2,
        "passed": 2,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "duration_ms": 8,
        "results": [
            {
                "name": "tests/test_calc.py::test_add",
                "status": "passed",
                "duration_ms": 4,
                "error_message": None,
                "traceback": None,
            },
            {
                "name": "tests/test_calc.py::test_subtract",
                "status": "passed",
                "duration_ms": 3,
                "error_message": None,
                "traceback": None,
            },
        ],
        "baseline_comparison": {
            "baseline_passed": 1,
            "current_passed": 2,
            "new_failures": [],
            "fixed_tests": ["tests/test_calc.py::test_add"],
            "regression": False,
        },
        "integrity_attestation": _integrity_attestation(),
    }


def _failure_evidence() -> dict[str, Any]:
    patch = _previous_patch()
    sanitized = _sanitized_result()
    return {
        "schema_version": "1.2",
        "issue_id": 42,
        "candidate_digest": _digest(patch),
        "test_result_digest": _digest(sanitized),
        "baseline_present": True,
        "failed": 1,
        "errors": 0,
        "regression": True,
        "reasons": ["test_failures", "regression", "new_failures"],
        "failing_tests": ["tests/test_calc.py::test_add"],
        "new_failures": ["tests/test_calc.py::test_add"],
        "diagnostics": [
            {
                "name": "tests/test_calc.py::test_add",
                "status": "failed",
                "error_message": "token=[REDACTED]",
                "traceback": "AssertionError: 1 != 2",
            }
        ],
        "redacted": True,
        "truncated": False,
    }


def _failure_payload() -> dict[str, Any]:
    evidence = _failure_evidence()
    return {
        "issue_id": 42,
        "candidate_digest": evidence["candidate_digest"],
        "test_result": _sanitized_result(),
        "test_result_redacted": True,
        "failing_tests": evidence["failing_tests"],
        "failure_evidence": evidence,
    }


def _failure_handoff() -> dict[str, Any]:
    inline = _failure_payload()
    run_id = "issue-42"
    task_id = "42-testeragent-test-runner"
    return {
        "envelope_version": "1.0",
        "run_id": run_id,
        "issue_id": 42,
        "task_id": task_id,
        "producer": "TesterAgent",
        "consumer": "TeamLeader",
        "skill": "test-runner",
        "trace_id": f"{run_id}:{task_id}",
        "idempotency_key": f"{run_id}:{task_id}:TeamLeader:test-runner",
        "created_at": "2026-07-28T12:00:00+00:00",
        "status": "retry",
        "artifact": {
            "type": "TestEvidence",
            "schema_version": "1.0",
            "inline": inline,
            "ref": None,
            "sha256": _digest(inline),
        },
    }


def _refresh_artifact(envelope: dict[str, Any]) -> None:
    envelope["artifact"]["sha256"] = _digest(envelope["artifact"]["inline"])


def _set_semantic_model_call_attempt(
    envelope: dict[str, Any],
    attempt: int,
) -> None:
    inline = envelope["artifact"]["inline"]
    inline["input"]["model_call_attempt"] = attempt
    inline["generation_budget"]["model_call_attempt"] = attempt


def _retry_envelope() -> dict[str, Any]:
    evidence = _failure_evidence()
    retry_input = {
        "issue_id": 42,
        "tier": "T2",
        "issue": _issue(),
        "located_context": _located_context(),
        "previous_patch": _previous_patch(),
        "test_failure_evidence": evidence,
        "retry_attempt": 2,
        "model_call_attempt": 2,
    }
    inline = {
        "tier": "T2",
        "input": retry_input,
        "depends_on": ["42-testeragent-test-runner"],
        "retry": {
            "attempt": 2,
            "max_attempts": 3,
            "reason": "test_failed",
            "test_result_digest": evidence["test_result_digest"],
        },
        "generation_budget": {
            "schema_version": "devflow.generation-budget/v1",
            "model_call_attempt": 2,
            "max_model_calls": 3,
        },
    }
    run_id = "issue-42"
    task_id = f"42-2-coderagent-retry-{evidence['test_result_digest'][:12]}"
    return {
        "envelope_version": "1.0",
        "run_id": run_id,
        "issue_id": 42,
        "task_id": task_id,
        "producer": "TeamLeader",
        "consumer": "CoderAgent",
        "skill": "patch-generator",
        "trace_id": f"{run_id}:{task_id}",
        "idempotency_key": f"{run_id}:{task_id}:CoderAgent:patch-generator",
        "created_at": "2026-07-28T12:00:00+00:00",
        "status": "retry",
        "artifact": {
            "type": "SkillInvocation",
            "schema_version": "1.0",
            "inline": inline,
            "ref": None,
            "sha256": _digest(inline),
        },
    }


def _generation_retry_envelope() -> dict[str, Any]:
    retry_input = _initial_invocation()
    retry_input["model_call_attempt"] = 2
    retry_input["validator_feedback_code"] = "CANDIDATE_INVALID"
    inline = {
        "tier": "T2",
        "input": retry_input,
        "depends_on": ["42-coderagent-patch-generator-call-1-failure"],
        "generation_retry": {
            "schema_version": "devflow.generation-retry/v1",
            "model_call_attempt": 2,
            "max_model_calls": 3,
            "failure_id": "failure-42-call-1",
            "reason": "CANDIDATE_INVALID",
        },
    }
    run_id = "issue-42"
    task_id = "42-coderagent-model-call-2-failure-42"
    return {
        "envelope_version": "1.0",
        "run_id": run_id,
        "issue_id": 42,
        "task_id": task_id,
        "producer": "TeamLeader",
        "consumer": "CoderAgent",
        "skill": "patch-generator",
        "trace_id": f"{run_id}:{task_id}",
        "idempotency_key": f"{run_id}:{task_id}:CoderAgent:patch-generator",
        "created_at": "2026-07-28T12:00:00+00:00",
        "status": "retry",
        "artifact": {
            "type": "SkillInvocation",
            "schema_version": "1.0",
            "inline": inline,
            "ref": None,
            "sha256": _digest(inline),
        },
    }


def test_contracts_publish_compatible_retry_protocol() -> None:
    test_contract = yaml.safe_load(
        (ROOT / "skills/test-runner/references/contract.yaml").read_text(encoding="utf-8")
    )
    patch_contract = yaml.safe_load(
        (ROOT / "skills/patch-generator/references/contract.yaml").read_text(encoding="utf-8")
    )

    assert test_contract["version"] == "4.0.0"
    assert patch_contract["version"] == "3.0.0"
    assert patch_contract["input"] == {
        "type": "SkillInvocation",
        "schema_version": "1.0",
        "required_fields": [
            "issue_id",
            "issue",
            "tier",
            "located_context",
            "model_call_attempt",
        ],
    }
    assert patch_contract["output"]["required_fields"] == [
        "schema_version",
        "issue_id",
        "tier",
        "patch",
        "candidate_digest",
        "evidence_boundary",
        "model_call_attempt",
        "retry_attempt",
    ]
    assert test_contract["input"]["required_fields"] == patch_contract["output"]["required_fields"]
    assert test_contract["output"]["required_fields"] == [
        "issue_id",
        "candidate_digest",
        "test_result",
        "test_result_redacted",
        "failing_tests",
    ]
    assert test_contract["failure_evidence"]["schema_version"] == "1.2"
    failure_fields = test_contract["failure_evidence"]["required_fields"]
    assert "test_result_digest" in failure_fields
    assert "sanitized_test_result_digest" not in failure_fields
    assert "raw_test_result_digest" not in failure_fields
    assert test_contract["retry_protocol"]["patch_attempts"] == {
        "first_retry": 2,
        "maximum_total": 3,
    }
    assert test_contract["failure_handoff"]["consumer"] == "TeamLeader"
    assert test_contract["retry_protocol"]["egress"]["consumer"] == "CoderAgent"
    assert (
        next(handoff for handoff in test_contract["handoffs"] if handoff["on"] == "failure")[
            "consumer"
        ]
        == "TeamLeader"
    )
    assert patch_contract["retry_handoff"]["attempt_bounds"] == {
        "minimum": 2,
        "maximum": 3,
        "maximum_total": 3,
    }
    assert patch_contract["mcp_tools"] == []
    regression = next(
        failure for failure in test_contract["failures"] if failure["code"] == "TEST_REGRESSION"
    )
    assert regression["route_to"] == "TeamLeader"


def test_main_contract_validators_accept_real_agent_boundary_artifacts(
    tmp_path: Path,
) -> None:
    patch_candidate = _patch_candidate()
    passing_evidence = {
        "issue_id": 42,
        "candidate_digest": patch_candidate["candidate_digest"],
        "test_result": _passing_result(),
        "test_result_redacted": False,
        "failing_tests": [],
    }
    processes = [
        _run_validator(tmp_path, PATCH_VALIDATOR, "input", _initial_invocation()),
        _run_validator(
            tmp_path,
            PATCH_VALIDATOR,
            "output",
            patch_candidate,
            _initial_invocation(),
        ),
        _run_validator(tmp_path, TEST_VALIDATOR, "input", patch_candidate),
        _run_validator(tmp_path, TEST_VALIDATOR, "output", _failure_payload()),
        _run_validator(tmp_path, TEST_VALIDATOR, "output", passing_evidence),
    ]

    assert all(process.returncode == 0 for process in processes), [
        process.stderr for process in processes
    ]


def test_test_runner_output_requires_the_verified_patch_candidate(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "test-evidence.json"
    artifact_path.write_text(json.dumps(_failure_payload()), encoding="utf-8")

    process = subprocess.run(
        [sys.executable, str(TEST_VALIDATOR), "output", str(artifact_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode == 2
    assert "verified-candidate" in process.stderr


@pytest.mark.parametrize(
    "mode, artifact_factory",
    [
        ("output", _failure_payload),
        ("failure", _failure_evidence),
        ("failure-handoff", _failure_handoff),
    ],
)
def test_test_runner_rejects_cross_candidate_evidence_for_every_egress_mode(
    tmp_path: Path,
    mode: str,
    artifact_factory: Callable[[], dict[str, Any]],
) -> None:
    other_candidate = _patch_candidate()
    other_candidate["patch"]["changes"][0]["new_content"] = "def add(a, b):\n    return a + b + 0\n"
    other_candidate["patch"]["changes"][0]["diff"] = (
        "--- a/calculator.py\n"
        "+++ b/calculator.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-    return a - b\n"
        "+    return a + b + 0\n"
    )
    other_candidate["candidate_digest"] = _digest(other_candidate["patch"])

    process = _run_validator(
        tmp_path,
        TEST_VALIDATOR,
        mode,
        artifact_factory(),
        other_candidate,
    )

    assert process.returncode == 1
    assert "does not match the verified PatchCandidate" in process.stderr


@pytest.mark.parametrize(
    "validator, artifact, expected",
    [
        (
            PATCH_VALIDATOR,
            {
                "issue_id": 42,
                "branch_name": "legacy-flat-shape",
                "changes": [],
                "candidate_digest": "0" * 64,
                "retry_attempt": 1,
            },
            "missing required fields",
        ),
        (
            TEST_VALIDATOR,
            {
                "issue_id": 42,
                "candidate_digest": "0" * 64,
                "baseline_revision": "legacy",
                "suite": "legacy",
                "status": "passed",
            },
            "missing required fields",
        ),
    ],
)
def test_main_output_contracts_reject_legacy_flat_shapes(
    tmp_path: Path,
    validator: Path,
    artifact: dict[str, Any],
    expected: str,
) -> None:
    process = _run_validator(
        tmp_path,
        validator,
        "output",
        artifact,
        _initial_invocation() if validator == PATCH_VALIDATOR else None,
    )

    assert process.returncode == 1
    assert expected in process.stderr


def test_patch_candidate_digest_must_bind_nested_patch(tmp_path: Path) -> None:
    artifact = _patch_candidate()
    artifact["candidate_digest"] = "0" * 64

    patch_output = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "output",
        artifact,
        _initial_invocation(),
    )
    test_input = _run_validator(
        tmp_path,
        TEST_VALIDATOR,
        "input",
        artifact,
    )

    assert patch_output.returncode == test_input.returncode == 1
    assert "exact patch" in patch_output.stderr
    assert "exact patch" in test_input.stderr


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda value: value["patch"]["changes"][0].update(change_type="create"),
            "type conflicts with its contents",
        ),
        (
            lambda value: value["patch"]["changes"][0].update(
                diff="--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-old\n+new\n"
            ),
            "unified-diff headers do not match",
        ),
        (
            lambda value: value["patch"]["changes"][0].update(
                new_content="def add(a, b):\n    return (\n"
            ),
            "invalid Python syntax",
        ),
    ],
)
def test_patch_generator_standalone_enforces_candidate_safety(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    expected: str,
) -> None:
    artifact = _patch_candidate()
    mutate(artifact)

    process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "output",
        artifact,
        _initial_invocation(),
    )

    assert process.returncode == 1
    assert expected in process.stderr


def test_patch_generator_output_requires_the_verified_authorization_source(
    tmp_path: Path,
) -> None:
    process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "output",
        _patch_candidate(),
    )

    assert process.returncode == 2
    assert "verified-input-or-retry" in process.stderr


def test_patch_generator_rejects_a_self_reported_scope_not_in_locator_evidence(
    tmp_path: Path,
) -> None:
    artifact = _patch_candidate()
    change = artifact["patch"]["changes"][0]
    change["file_path"] = "totally/outside.py"
    change["diff"] = (
        "--- a/totally/outside.py\n"
        "+++ b/totally/outside.py\n"
        "@@ -1 +1 @@\n"
        "-old = False\n"
        "+old = True\n"
    )
    artifact["candidate_digest"] = _digest(artifact["patch"])
    boundary_body = {
        "schema_version": "1.0",
        "located_context_digest": artifact["evidence_boundary"]["located_context_digest"],
        "allowed_files": ["totally/outside.py"],
    }
    artifact["evidence_boundary"] = {
        **boundary_body,
        "scope_digest": _digest(boundary_body),
    }

    process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "output",
        artifact,
        _initial_invocation(),
    )

    assert process.returncode == 1
    assert "does not match the verified LocatedContext" in process.stderr


@pytest.mark.parametrize(
    "test_path",
    [
        "tests/test_calc.py",
        "pkg/foo_test.go",
        "ui/foo.test.tsx",
        "src/FooTest.java",
        "__tests__/widget.jsx",
        "specs/widget.rb",
    ],
)
def test_runtime_and_standalone_reject_deleting_a_located_test(
    tmp_path: Path,
    test_path: str,
) -> None:
    source = _initial_invocation()
    source["located_context"]["related_tests"].append(test_path)
    artifact = _patch_candidate()
    change = artifact["patch"]["changes"][0]
    change.update(
        file_path=test_path,
        change_type="delete",
        original_content="def test_add():\n    assert False\n",
        new_content=None,
        diff=(
            f"--- a/{test_path}\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-def test_add():\n"
            "-    assert False\n"
        ),
    )
    artifact["candidate_digest"] = _digest(artifact["patch"])
    allowed_files = sorted(
        {
            "calculator.py",
            "tests/test_calc.py",
            test_path,
        }
    )
    boundary_body = {
        "schema_version": "1.0",
        "located_context_digest": _digest(source["located_context"]),
        "allowed_files": allowed_files,
    }
    artifact["evidence_boundary"] = {
        **boundary_body,
        "scope_digest": _digest(boundary_body),
    }

    process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "output",
        artifact,
        source,
    )
    located = LocatedContext.model_validate(source["located_context"])

    assert process.returncode == 1
    assert "cannot delete a test file" in process.stderr
    with pytest.raises(AgentError, match="cannot delete a test file"):
        CoderAgent._validate_patch(Patch.model_validate(artifact["patch"]), located)


def test_runtime_coder_enforces_located_blast_radius() -> None:
    located = LocatedContext.model_validate(_located_context())
    CoderAgent._validate_patch(Patch.model_validate(_previous_patch()), located)
    outside = _previous_patch()
    outside["changes"][0]["file_path"] = "README.md"
    outside["changes"][0]["diff"] = "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n"

    with pytest.raises(AgentError, match="outside the located evidence boundary"):
        CoderAgent._validate_patch(Patch.model_validate(outside), located)


def test_new_failures_cannot_pass_without_failure_evidence(tmp_path: Path) -> None:
    artifact: dict[str, Any] = {
        "issue_id": 42,
        "candidate_digest": _patch_candidate()["candidate_digest"],
        "test_result": _passing_result(),
        "test_result_redacted": False,
        "failing_tests": [],
    }
    artifact["test_result"]["baseline_comparison"]["new_failures"] = [
        "tests/test_calc.py::test_add"
    ]

    process = _run_validator(tmp_path, TEST_VALIDATOR, "output", artifact)

    assert process.returncode == 1
    assert "failure_evidence" in process.stderr


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda result, source: result.update(integrity_attestation=None),
            "requires verified integrity evidence",
        ),
        (
            lambda result, source: result["integrity_attestation"].update(verified=False),
            "requires verified integrity evidence",
        ),
        (
            lambda result, source: result["integrity_attestation"].update(
                candidate_baseline_manifest_digest="e" * 64
            ),
            "changed the immutable baseline",
        ),
        (
            lambda result, source: source.update(tier="T3"),
            "full-suite attestation",
        ),
    ],
)
def test_test_runner_pass_requires_exact_integrity_attestation(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any], dict[str, Any]], None],
    expected: str,
) -> None:
    result = _passing_result()
    source = _patch_candidate()
    mutate(result, source)
    artifact = {
        "issue_id": 42,
        "candidate_digest": source["candidate_digest"],
        "test_result": result,
        "test_result_redacted": False,
        "failing_tests": [],
    }

    process = _run_validator(
        tmp_path,
        TEST_VALIDATOR,
        "output",
        artifact,
        source,
    )

    assert process.returncode == 1
    assert expected in process.stderr


def test_test_runner_validates_failure_evidence_and_sanitized_handoff(
    tmp_path: Path,
) -> None:
    evidence = _run_validator(tmp_path, TEST_VALIDATOR, "failure", _failure_evidence())
    handoff = _run_validator(
        tmp_path,
        TEST_VALIDATOR,
        "failure-handoff",
        _failure_handoff(),
    )

    assert evidence.returncode == 0, evidence.stderr
    assert handoff.returncode == 0, handoff.stderr
    assert json.loads(handoff.stdout)["mode"] == "failure-handoff"


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda value: value.update(schema_version="1.1"),
            "schema_version must be 1.2",
        ),
        (
            lambda value: value.update(
                failed=0,
                regression=False,
                new_failures=[],
                reasons=[],
            ),
            "passing facts cannot produce",
        ),
        (
            lambda value: value["diagnostics"][0].update(traceback="sk-" + "A" * 24),
            "secret-shaped",
        ),
        (
            lambda value: value["diagnostics"][0].update(traceback="ghp_" + "B" * 30),
            "secret-shaped",
        ),
        (
            lambda value: value["diagnostics"][0].update(
                traceback="bearer " + "Mixed_Case-Token" * 2
            ),
            "secret-shaped",
        ),
        (
            lambda value: value.update(redacted=False),
            "redacted must exactly report",
        ),
    ],
)
def test_test_runner_rejects_malformed_or_unredacted_failure_evidence(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    expected: str,
) -> None:
    value = _failure_evidence()
    mutate(value)

    process = _run_validator(tmp_path, TEST_VALIDATOR, "failure", value)

    assert process.returncode == 1
    assert expected in process.stderr


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda value: value["artifact"]["inline"]["failure_evidence"].update(
                test_result_digest="0" * 64
            ),
            "test result digest",
        ),
        (
            lambda value: value["artifact"]["inline"].update(test_result_redacted=False),
            "bounded evidence redaction requires",
        ),
        (
            lambda value: value.update(consumer="CoderAgent"),
            "TesterAgent to TeamLeader",
        ),
        (
            lambda value: value["artifact"]["inline"]["failure_evidence"].update(
                raw_test_result_digest="0" * 64
            ),
            "unknown failure evidence fields",
        ),
        (
            lambda value: value["artifact"]["inline"]["test_result"].update(
                passed=2,
                failed=0,
            ),
            "status counters do not match results",
        ),
        (
            lambda value: value["artifact"]["inline"]["test_result"]["baseline_comparison"].update(
                current_passed=0
            ),
            "current_passed must equal passed",
        ),
    ],
)
def test_test_runner_rejects_inconsistent_sanitized_handoff(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    expected: str,
) -> None:
    value = _failure_handoff()
    mutate(value)
    _refresh_artifact(value)

    process = _run_validator(tmp_path, TEST_VALIDATOR, "failure-handoff", value)

    assert process.returncode == 1
    assert expected in process.stderr


def test_full_result_redaction_does_not_falsely_mark_bounded_evidence(
    tmp_path: Path,
) -> None:
    raw = _sanitized_result()
    raw["results"][0]["error_message"] = "ordinary assertion"
    raw["results"][1]["name"] += " ghp_" + "P" * 30
    result = RunResult.model_validate(raw)
    sanitized, result_redacted = redact_test_result_for_handoff(result)
    evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=Patch.model_validate(_previous_patch()),
        result=result,
    )
    payload = {
        "issue_id": 42,
        "candidate_digest": evidence.candidate_digest,
        "test_result": sanitized.model_dump(mode="json"),
        "test_result_redacted": result_redacted,
        "failing_tests": evidence.failing_tests,
        "failure_evidence": evidence.model_dump(mode="json"),
    }
    value = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=42,
        task_id="42-testeragent-test-runner",
        producer="TesterAgent",
        consumer="TeamLeader",
        skill="test-runner",
        artifact_type="TestEvidence",
        payload=payload,
        status=HandoffStatus.RETRY,
    ).model_dump(mode="json")

    assert result_redacted is True
    assert evidence.redacted is False

    process = _run_validator(tmp_path, TEST_VALIDATOR, "failure-handoff", value)

    assert process.returncode == 0, process.stderr


def test_patch_generator_validates_complete_retry_envelope(tmp_path: Path) -> None:
    process = _run_validator(tmp_path, PATCH_VALIDATOR, "retry", _retry_envelope())

    assert process.returncode == 0, process.stderr
    assert json.loads(process.stdout)["mode"] == "retry"


def test_patch_generator_validates_generation_retry_and_binds_its_candidate(
    tmp_path: Path,
) -> None:
    envelope = _generation_retry_envelope()
    candidate = _patch_candidate()
    candidate["model_call_attempt"] = 2

    retry_process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "retry",
        envelope,
    )
    output_process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "output",
        candidate,
        envelope,
    )

    assert retry_process.returncode == 0, retry_process.stderr
    assert output_process.returncode == 0, output_process.stderr


def test_patch_generator_rejects_generation_retry_metadata_drift(
    tmp_path: Path,
) -> None:
    envelope = _generation_retry_envelope()
    envelope["artifact"]["inline"]["generation_retry"]["model_call_attempt"] = 3
    _refresh_artifact(envelope)

    process = _run_validator(tmp_path, PATCH_VALIDATOR, "retry", envelope)

    assert process.returncode == 1
    assert "generation_retry does not match" in process.stderr


def test_runtime_models_produce_validator_accepted_boundary_artifacts(
    tmp_path: Path,
) -> None:
    patch = Patch.model_validate(_previous_patch())
    raw_result = _sanitized_result()
    raw_result["results"][0]["error_message"] = "token=ghp_" + "C" * 30
    result = RunResult.model_validate(raw_result)
    sanitized, result_redacted = redact_test_result_for_handoff(result)
    evidence = FailureEvidence.from_test_result(
        issue_id=42,
        candidate=patch,
        result=result,
    )
    failure_payload = {
        "issue_id": 42,
        "candidate_digest": canonical_artifact_digest(patch),
        "test_result": sanitized.model_dump(mode="json"),
        "test_result_redacted": result_redacted,
        "failing_tests": evidence.failing_tests,
        "failure_evidence": evidence.model_dump(mode="json"),
    }
    failure_envelope = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=42,
        task_id="42-testeragent-test-runner",
        producer="TesterAgent",
        consumer="TeamLeader",
        skill="test-runner",
        artifact_type="TestEvidence",
        payload=failure_payload,
        status=HandoffStatus.RETRY,
    )
    retry_input = {
        "issue_id": 42,
        "tier": "T2",
        "issue": _issue(),
        "located_context": _located_context(),
        "previous_patch": patch.model_dump(mode="json"),
        "test_failure_evidence": evidence.model_dump(mode="json"),
        "retry_attempt": 2,
        "model_call_attempt": 2,
    }
    retry_payload = {
        "tier": "T2",
        "input": retry_input,
        "depends_on": ["42-testeragent-test-runner"],
        "retry": {
            "attempt": 2,
            "max_attempts": 3,
            "reason": "test_failed",
            "test_result_digest": evidence.test_result_digest,
        },
        "generation_budget": {
            "schema_version": "devflow.generation-budget/v1",
            "model_call_attempt": 2,
            "max_model_calls": 3,
        },
    }
    retry_envelope = HandoffEnvelope.create(
        run_id="issue-42",
        issue_id=42,
        task_id=f"42-2-coderagent-retry-{evidence.test_result_digest[:12]}",
        producer="TeamLeader",
        consumer="CoderAgent",
        skill="patch-generator",
        artifact_type="SkillInvocation",
        payload=retry_payload,
        status=HandoffStatus.RETRY,
    )

    evidence_process = _run_validator(
        tmp_path,
        TEST_VALIDATOR,
        "failure",
        evidence.model_dump(mode="json"),
    )
    handoff_process = _run_validator(
        tmp_path,
        TEST_VALIDATOR,
        "failure-handoff",
        failure_envelope.model_dump(mode="json"),
    )
    retry_process = _run_validator(
        tmp_path,
        PATCH_VALIDATOR,
        "retry",
        retry_envelope.model_dump(mode="json"),
    )

    assert evidence_process.returncode == 0, evidence_process.stderr
    assert handoff_process.returncode == 0, handoff_process.stderr
    assert retry_process.returncode == 0, retry_process.stderr


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (
            lambda value: value["artifact"]["inline"]["input"]["test_failure_evidence"].update(
                candidate_digest="0" * 64
            ),
            "exact previous_patch",
        ),
        (
            lambda value: value["artifact"]["inline"]["input"].update(test_result={"failed": 1}),
            "test_result is forbidden",
        ),
        (
            lambda value: value["artifact"]["inline"]["input"].update(retry_attempt=4),
            "three-attempt budget",
        ),
        (
            lambda value: _set_semantic_model_call_attempt(value, 1),
            "cannot precede retry_attempt",
        ),
        (
            lambda value: value.update(idempotency_key="unbound"),
            "idempotency_key",
        ),
        (
            lambda value: value["artifact"].update(sha256="0" * 64),
            "artifact digest",
        ),
    ],
)
def test_patch_generator_rejects_unbound_or_out_of_budget_retry(
    tmp_path: Path,
    mutate: Callable[[dict[str, Any]], None],
    expected: str,
) -> None:
    value = copy.deepcopy(_retry_envelope())
    mutate(value)
    if "artifact digest" not in expected:
        value["artifact"]["sha256"] = _digest(value["artifact"]["inline"])

    process = _run_validator(tmp_path, PATCH_VALIDATOR, "retry", value)

    assert process.returncode == 1
    assert expected in process.stderr

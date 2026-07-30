"""Decision/status invariants enforced by the AgentTeams Skill gate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _guard_module() -> ModuleType:
    path = ROOT / "agentteams" / "teamharness" / "guarded_server.py"
    spec = importlib.util.spec_from_file_location("devflow_test_guarded_server", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    upstream = ModuleType("server")
    upstream.handle_request = lambda _request: None  # type: ignore[attr-defined]
    previous_upstream = sys.modules.get("server")
    sys.modules["server"] = upstream
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous_upstream is None:
            del sys.modules["server"]
        else:
            sys.modules["server"] = previous_upstream
    return module


def test_test_runner_v6_contract_pin_matches_packaged_bytes() -> None:
    guard = _guard_module()
    contract = (ROOT / "skills/test-runner/references/contract.yaml").read_bytes()

    assert b'version: "6.0.0"' in contract
    assert b"devflow.test-execution-receipt/v1" in contract
    assert b"devflow-cicd:run_tests" in contract
    assert guard.SKILL_VALIDATOR_FILES["test-runner"][
        "references/contract.yaml"
    ] == (len(contract), hashlib.sha256(contract).hexdigest())


GUARD = _guard_module()


def _review(*, decision: str, requires_human: bool, tier: str) -> dict[str, Any]:
    return {
        "issue_id": 17,
        "tier": tier,
        "review": {
            "decision": decision,
            "findings": [],
            "summary": "bounded review",
            "pr_url": "https://github.com/example/repo/pull/17",
            "requires_human_approval": requires_human,
        },
    }


def _test_result(*, failed: int, verified: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "test_result": {
            "failed": failed,
            "errors": 0,
            "baseline_comparison": {
                "regression": failed > 0,
                "new_failures": ["tests/test_fix.py::test_case"] if failed else [],
            },
            "integrity_attestation": {"verified": verified},
        }
    }
    if failed:
        result["failure_evidence"] = {
            "summary": "candidate introduced a regression",
            "failed_tests": ["tests/test_fix.py::test_case"],
        }
    return result


@pytest.mark.parametrize(
    ("status", "inline"),
    [
        ("ready", _test_result(failed=0)),
        ("retry", _test_result(failed=1)),
        ("blocked", _review(decision="human_approval_required", requires_human=True, tier="T4")),
        ("retry", _review(decision="changes_requested", requires_human=False, tier="T3")),
    ],
)
def test_valid_skill_decisions_match_transport_status(
    status: str,
    inline: dict[str, Any],
) -> None:
    skill = "test-runner" if "test_result" in inline else "pr-reviewer"

    GUARD._validate_skill_result_semantics(skill, status, inline)


@pytest.mark.parametrize(
    ("skill", "status", "inline"),
    [
        ("test-runner", "ready", _test_result(failed=1)),
        ("test-runner", "retry", _test_result(failed=0)),
        (
            "pr-reviewer",
            "blocked",
            _review(decision="approved", requires_human=False, tier="T4"),
        ),
        (
            "pr-reviewer",
            "ready",
            _review(decision="approved", requires_human=False, tier="T4"),
        ),
        (
            "pr-reviewer",
            "blocked",
            _review(decision="human_approval_required", requires_human=True, tier="T3"),
        ),
    ],
)
def test_invalid_skill_decisions_fail_closed(
    skill: str,
    status: str,
    inline: dict[str, Any],
) -> None:
    with pytest.raises(GUARD.GuardPolicyError, match="skill_result_status_invalid"):
        GUARD._validate_skill_result_semantics(skill, status, inline)


def _source() -> dict[str, Any]:
    return {"artifact": {"inline": {"issue_id": 17, "operation": "bounded"}}}


def _failure(skill: str, code: str) -> dict[str, Any]:
    policy = GUARD.SKILL_FAILURE_POLICIES[skill][code]
    source = _source()["artifact"]["inline"]
    digest = hashlib.sha256(
        json.dumps(
            source,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "1.0",
        "skill": skill,
        "code": code,
        "retryable": policy.retryable,
        "retry_count": 0,
        "max_attempts": policy.max_attempts,
        "exhausted": not policy.retryable or policy.max_attempts == 0,
        "route_to": "TeamLeader",
        "event": policy.event,
        "source_artifact_sha256": digest,
        "summary": "A bounded Worker invocation failed.",
        "diagnostics": [],
    }


@pytest.mark.parametrize(
    ("skill", "code"),
    [
        (skill, code)
        for skill, policies in GUARD.SKILL_FAILURE_POLICIES.items()
        for code in policies
    ],
)
def test_all_control_plane_skill_failures_are_typed_and_leader_only(
    skill: str,
    code: str,
) -> None:
    GUARD._validate_skill_failure(skill, "failed", _failure(skill, code), _source())


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value.update(route_to="CoderAgent"),
        lambda value: value.update(source_artifact_sha256="0" * 64),
        lambda value: value.update(exhausted=not value["exhausted"]),
        lambda value: value.update(unknown=True),
    ),
)
def test_control_plane_rejects_failure_policy_drift(mutation: Any) -> None:
    artifact = _failure("issue-classifier", "INPUT_INVALID")
    mutation(artifact)

    with pytest.raises(GUARD.GuardPolicyError, match="skill_failure_invalid"):
        GUARD._validate_skill_failure(
            "issue-classifier",
            "failed",
            artifact,
            _source(),
        )

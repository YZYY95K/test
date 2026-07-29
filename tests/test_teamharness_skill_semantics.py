"""Decision/status invariants enforced by the AgentTeams Skill gate."""

from __future__ import annotations

import importlib.util
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

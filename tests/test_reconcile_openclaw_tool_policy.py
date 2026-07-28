"""Fail-closed tests for the OpenClaw native tool-boundary audit."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts.reconcile_openclaw_tool_policy import (
    ALL_CORE_TOOLS,
    BLOCKER_CODES,
    CODER_ROLE,
    EXPECTED_OPENCLAW_COMMIT,
    EXPECTED_OPENCLAW_VERSION,
    BoundaryAuditError,
    BoundaryBlockedError,
    SubprocessRunner,
    _audit_schema,
    _parse_report,
    _summary,
    audit,
    recommended_tool_policy,
    reconcile,
)
from scripts.reconcile_teamharness_openclaw import (
    NAMESPACE,
    RUNTIME_LABEL,
    TEAM_LABEL,
    TEAM_NAME,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile_openclaw_tool_policy.py"
ROLES = (
    "devflow-coder",
    "devflow-lead",
    "devflow-locator",
    "devflow-reviewer",
    "devflow-tester",
    "devflow-triage",
)


def _team() -> dict[str, Any]:
    return {
        "apiVersion": "agentteams.io/v1beta1",
        "kind": "Team",
        "metadata": {"name": TEAM_NAME, "namespace": NAMESPACE},
        "spec": {
            "leader": {"name": "devflow-lead"},
            "workers": [
                {"name": role} for role in ROLES if role != "devflow-lead"
            ],
        },
        "status": {
            "members": [
                {
                    "name": f"member-{index}",
                    "runtimeName": role,
                    "matrixUserID": f"@{role}:matrix.invalid",
                }
                for index, role in enumerate(ROLES)
            ]
        },
    }


def _pod_spec(role: str) -> dict[str, Any]:
    if role != "devflow-lead":
        return {"containers": [{"name": "worker"}]}
    return {
        "serviceAccountName": "agentteams-worker-devflow-lead",
        "automountServiceAccountToken": False,
        "volumes": [
            {
                "name": "agentteams-token",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "audience": "agentteams-controller",
                                "expirationSeconds": 3600,
                                "path": "token",
                            }
                        }
                    ]
                },
            }
        ],
        "containers": [
            {
                "name": "worker",
                "volumeMounts": [
                    {
                        "name": "agentteams-token",
                        "mountPath": "/var/run/secrets/agentteams",
                        "readOnly": True,
                    }
                ],
            }
        ],
    }


def _pods() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "PodList",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {
                    "name": f"pod-{role}",
                    "namespace": NAMESPACE,
                    "labels": {
                        TEAM_LABEL: TEAM_NAME,
                        RUNTIME_LABEL: "openclaw",
                        "agentteams.io/worker": f"member-{index}",
                    },
                },
                "spec": _pod_spec(role),
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [{"name": "worker", "ready": True}],
                },
            }
            for index, role in enumerate(ROLES)
        ],
    }


def _report(role: str, *, state: str = "unmanaged") -> str:
    value = {
        "ok": True,
        "role": role,
        "openclawVersion": (
            f"OpenClaw {EXPECTED_OPENCLAW_VERSION} ({EXPECTED_OPENCLAW_COMMIT})"
        ),
        "sourceDigest": "a" * 64,
        "liveDigest": "b" * 64,
        "remoteDigest": "c" * 64,
        "recommendedPolicyDigest": "d" * 64,
        "livePolicyState": state,
        "remotePolicyState": state,
        "liveConfigValid": True,
        "remoteConfigValid": True,
        "schemaAudited": True,
        "runtimeUid": 0,
        "workspaceWritable": True,
        "activeConfigTargetInWorkspace": True,
        "execApprovalStateInWorkspace": True,
        "mcCredentialMaterialInWorkspace": True,
        "mcporterConfigInWorkspace": True,
        "canEnforceStrongBoundary": False,
        "blockers": list(BLOCKER_CODES),
    }
    return json.dumps(value, sort_keys=True)


class _FakeRunner:
    def __init__(self, *, state: str = "unmanaged") -> None:
        self.state = state
        self.calls: list[list[str]] = []

    def run(self, args: list[str]) -> str:
        self.calls.append(list(args))
        if "get" in args and "team" in args:
            return json.dumps(_team())
        if "get" in args and "pods" in args:
            return json.dumps(_pods())
        if "exec" in args:
            pod = next(value for value in args if value.startswith("pod-devflow-"))
            return _report(pod.removeprefix("pod-"), state=self.state)
        return ""


def _minimal_schema() -> dict[str, Any]:
    return {
        "properties": {
            "tools": {
                "properties": {
                    "allow": {"type": "array"},
                    "deny": {"type": "array"},
                    "fs": {"properties": {"workspaceOnly": {"type": "boolean"}}},
                    "elevated": {
                        "properties": {"enabled": {"type": "boolean"}}
                    },
                    "exec": {
                        "properties": {
                            "host": {
                                "enum": ["auto", "sandbox", "gateway", "node"]
                            },
                            "security": {
                                "enum": ["deny", "allowlist", "full"]
                            },
                            "ask": {"enum": ["off", "on-miss", "always"]},
                            "safeBins": {"type": "array"},
                            "strictInlineEval": {"type": "boolean"},
                            "applyPatch": {
                                "properties": {
                                    "workspaceOnly": {"type": "boolean"}
                                }
                            },
                        }
                    },
                }
            }
        }
    }


def test_recommendation_is_exact_role_minimum_and_denies_lateral_surfaces() -> None:
    coder = recommended_tool_policy(CODER_ROLE)
    worker = recommended_tool_policy("devflow-reviewer")

    assert set(coder["allow"]) == {"read", "write", "edit", "apply_patch", "exec"}
    assert set(worker["allow"]) == {"read", "exec"}
    assert set(coder["allow"]) | set(coder["deny"]) == ALL_CORE_TOOLS
    assert set(worker["allow"]) | set(worker["deny"]) == ALL_CORE_TOOLS
    for forbidden in (
        "process",
        "web_search",
        "web_fetch",
        "sessions_send",
        "sessions_spawn",
        "subagents",
        "browser",
        "cron",
        "gateway",
        "nodes",
    ):
        assert forbidden in worker["deny"]
    assert coder["fs"] == {"workspaceOnly": True}
    assert coder["elevated"] == {"enabled": False}
    assert coder["exec"]["security"] == "allowlist"
    assert coder["exec"]["ask"] == "always"
    assert coder["exec"]["safeBins"] == []
    assert coder["exec"]["strictInlineEval"] is True
    assert coder["exec"]["applyPatch"] == {
        "enabled": True,
        "workspaceOnly": True,
    }
    assert worker["exec"]["applyPatch"]["enabled"] is False
    with pytest.raises(BoundaryAuditError, match="outside"):
        recommended_tool_policy("devflow-unknown")


def test_schema_audit_pins_all_security_relevant_native_fields() -> None:
    schema = _minimal_schema()
    _audit_schema(schema)

    drifted = deepcopy(schema)
    drifted["properties"]["tools"]["properties"]["exec"]["properties"][
        "security"
    ]["enum"] = ["allowlist", "full"]
    with pytest.raises(BoundaryAuditError, match="security"):
        _audit_schema(drifted)


def test_audit_preflights_exactly_six_pods_and_returns_only_blocked_reports() -> None:
    runner = _FakeRunner()
    reports = audit(runner, kubectl="kubectl")

    assert len(reports) == 6
    assert {report.target.role_name for report in reports} == set(ROLES)
    assert all(report.strong_boundary is False for report in reports)
    assert all(report.blockers == BLOCKER_CODES for report in reports)
    exec_calls = [args for args in runner.calls if "exec" in args]
    assert len(exec_calls) == 6
    assert all("python3" in args and "-c" in args for args in exec_calls)


def test_apply_refuses_only_after_all_six_preflights_and_never_mutates() -> None:
    runner = _FakeRunner()

    with pytest.raises(BoundaryBlockedError):
        reconcile(runner, kubectl="kubectl", apply=True)

    exec_calls = [args for args in runner.calls if "exec" in args]
    assert len(exec_calls) == 6
    rendered = "\n".join(" ".join(args) for args in runner.calls)
    assert not re.search(r"\bkubectl\b.*\b(?:apply|create|patch|delete|replace)\b", rendered)
    assert " get secret" not in rendered.lower()


def test_repeated_check_is_idempotent_and_drift_never_becomes_verified() -> None:
    first = audit(_FakeRunner(state="unknown-or-relaxed-drift"))
    second = audit(_FakeRunner(state="unknown-or-relaxed-drift"))

    assert first == second
    summary = _summary(first, apply=False)
    assert summary["verified"] is False
    assert summary["strongBoundaryEnforceable"] is False
    assert all(
        role["livePolicyState"] == "unknown-or-relaxed-drift"
        for role in summary["roles"]
    )


def test_report_parser_rejects_extra_fields_and_incomplete_blockers() -> None:
    target = audit(_FakeRunner())[0].target
    value = json.loads(_report(target.role_name))
    value["credential"] = "must-not-cross-boundary"
    with pytest.raises(BoundaryAuditError, match="unexpected summary"):
        _parse_report(json.dumps(value), target)

    value.pop("credential")
    value["blockers"].pop()
    with pytest.raises(BoundaryAuditError, match="blocker"):
        _parse_report(json.dumps(value), target)


def test_subprocess_failures_do_not_echo_remote_output(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Completed:
        returncode = 1
        stdout = ""
        stderr = "sensitive-runtime-output"

    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: _Completed())
    with pytest.raises(BoundaryAuditError) as caught:
        SubprocessRunner().run(["kubectl", "exec"])
    assert "sensitive-runtime-output" not in str(caught.value)


def test_script_contains_no_secret_values_or_rbac_mutations() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    for forbidden in (
        "ghp_",
        "accessToken",
        "gatewayKey",
        "AGENTTEAMS_WORKER_MATRIX_TOKEN",
        "AGENTTEAMS_WORKER_GATEWAY_KEY",
        "set -x",
    ):
        assert forbidden not in text
    assert "get\", \"secret" not in text.lower()
    assert "canEnforceStrongBoundary\": False" in text


def test_script_help_runs_without_site_packages_and_defaults_to_check() -> None:
    completed = subprocess.run(
        [sys.executable, "-S", str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--apply" in completed.stdout
    assert "fails closed" in completed.stdout

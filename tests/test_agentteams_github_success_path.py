"""Fail-closed tests for the one-time real AgentTeams GitHub driver."""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import scripts.run_agentteams_github_success_path as success_driver
from scripts.reconcile_teamharness_openclaw import Target
from scripts.run_agentteams_github_success_path import (
    CONFIRMATION,
    EVIDENCE_PATH,
    EXPECTED_MCP_SCHEMA_CANONICAL_BYTES,
    EXPECTED_MCP_SCHEMA_CANONICAL_SHA256,
    EXPECTED_MCPORTER_GID,
    EXPECTED_MCPORTER_MODE,
    EXPECTED_MCPORTER_NLINK,
    EXPECTED_MCPORTER_SHA256,
    EXPECTED_MCPORTER_SIZE,
    EXPECTED_MCPORTER_UID,
    EXPECTED_MCPORTER_VERSION,
    GITHUB_TOOL,
    HOST_CLEANUP_MARGIN_SECONDS,
    HOST_CONTROL_TIMEOUT_SECONDS,
    HOST_LOCATOR_TIMEOUT_SECONDS,
    HOST_PREFLIGHT_TIMEOUT_SECONDS,
    ISSUE_ID,
    LEADER_ROLE,
    LOCATOR_ROLE,
    LOCATOR_SUMMARY_FIELDS,
    MAX_KUBECTL_ARGUMENT_BYTES,
    MAX_KUBECTL_ARGV_BYTES,
    MCP_SCHEMA_CANONICALIZATION_ID,
    OWNER,
    PLAN_STAGES,
    REMOTE_CONTROL_DEADLINE_SECONDS,
    REMOTE_CONTROL_HELPER,
    REMOTE_LOCATOR_CALL_COUNT,
    REMOTE_LOCATOR_DEADLINE_SECONDS,
    REMOTE_LOCATOR_FAILURE_STAGE_MAP,
    REMOTE_LOCATOR_HELPER,
    REMOTE_MCP_CALL_TIMEOUT_SECONDS,
    REMOTE_PREFLIGHT_DEADLINE_SECONDS,
    REMOTE_PREFLIGHT_HELPER,
    REMOTE_STDIN_BOOTSTRAP,
    REPOSITORY,
    REVISION,
    RISK_TIER,
    SUBMIT_SUMMARY,
    DriverError,
    KubernetesBackend,
    RuntimeContext,
    _assert_public_safe,
    _canonical_bytes,
    _canonical_text,
    _canonicalize_mcporter_schema,
    _expected_broker_scope,
    _expected_project_binding,
    _normalized_mcporter_config,
    _remote_ack_spec,
    _remote_frame,
    _remote_http_mcp_call,
    _remote_http_request,
    _remote_parse_http_mcp,
    _remote_persisted_task_spec,
    _remote_receipt,
    _remote_role_task_root,
    _remote_run_bounded_process,
    _remote_sanitized_markdown,
    _remote_stdio_mcp_call,
    _remote_team_payload,
    _remote_validate_conflicting_submission,
    _remote_validate_first_submission,
    _remote_validate_idempotent_submission,
    _submission_digest,
    execute_success_path,
    main,
    plan_report,
)

PROJECT_ID = "devflow-live-github-20260727-a1"
TASK_ID = PROJECT_ID + "-evidence"
ROOM_ID = "!" + "private-room" + ":" + "matrix.example"
MATRIX_USER_ID = "@devflow-locator:matrix.example"
LEADER_MATRIX_USER_ID = "@devflow-lead:matrix.example"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _locator_summary(task_id: str = TASK_ID) -> dict[str, Any]:
    run_id = task_id.removesuffix("-evidence")
    deliverables = [
        f"shared/tasks/{task_id}/result.md",
        f"shared/tasks/{task_id}/GitHubEvidence/result.md",
    ]
    return {
        "ok": True,
        "taskId": task_id,
        "artifactSha256": _hash("artifact"),
        "authorizerScopeSha256": _hash("authorizer-scope"),
        "brokerScopeSha256": _expected_broker_scope(task_id),
        "capabilitySha256": _hash("capability"),
        "contentSha256": _hash("content"),
        "conflictRequestedSha256": _submission_digest(
            task_id,
            deliverables,
            summary=SUBMIT_SUMMARY + " Changed retry.",
        ),
        "envelopeSha256": _hash("envelope"),
        "idempotencyKeySha256": _hash(
            f"{run_id}:{task_id}:{LOCATOR_ROLE}:github-evidence"
        ),
        "objectSha": "c" * 40,
        "responseSha256": _hash("response"),
        "submissionSha256": _submission_digest(task_id, deliverables),
        "deliverables": deliverables,
        "validatorPassed": True,
        "firstSubmit": True,
        "idempotentRetry": True,
        "conflictRetry": True,
    }


class FakeBackend:
    """A stateful TeamHarness-shaped backend with no filesystem or network use."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.preflight_calls = 0
        self.locator_calls: list[tuple[str, str]] = []
        self.project: dict[str, Any] | None = None
        self.task: dict[str, Any] | None = None
        self.locator_summary = _locator_summary()
        self.room_response: dict[str, Any] = {
            "roomId": ROOM_ID,
            "reused": False,
            "private": True,
            "joinRule": "invite",
            "membershipStateVerified": True,
            "membershipProjection": "non-creator-requested-worker-invitees",
            "creator": LEADER_MATRIX_USER_ID,
            "invite": [MATRIX_USER_ID],
            "members": [MATRIX_USER_ID],
            "authorizedMemberCount": 2,
            "authorizedMembersSha256": _hash(
                f"{LEADER_MATRIX_USER_ID}\n{MATRIX_USER_ID}"
            ),
            "binding": _expected_project_binding(PROJECT_ID),
        }
        self.checked_summary = SUBMIT_SUMMARY
        self.final_pending_override: bool | None = None
        self.filesync_stat_remove: set[str] = set()
        self.filesync_stat_overrides: dict[str, Any] = {}
        self.filesync_stat_mutated = False
        self.filesync_push_remove: set[str] = set()
        self.filesync_push_overrides: dict[str, Any] = {}

    def preflight(self) -> RuntimeContext:
        self.preflight_calls += 1
        return RuntimeContext(
            leader_matrix_user_id=LEADER_MATRIX_USER_ID,
            locator_matrix_user_id=MATRIX_USER_ID,
        )

    def _response(self, tool: str, action: str, **values: Any) -> dict[str, Any]:
        return {"ok": True, "tool": tool, "action": action, **values}

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        snapshot = deepcopy(arguments)
        action = str(arguments.get("action") or "")
        self.calls.append((tool, action, snapshot))
        payload = arguments.get("payload")
        payload = payload if isinstance(payload, dict) else {}

        if (tool, action) == ("projectflow", "resolve_project"):
            if self.project is None:
                return {
                    "ok": False,
                    "tool": tool,
                    "action": action,
                    "error": "project not found",
                }
            project = deepcopy(self.project)
            if self.final_pending_override is not None:
                project["requester_report"]["pending"] = self.final_pending_override
            return self._response(tool, action, project=project)

        if (tool, action) == ("taskflow", "check_task"):
            if self.task is None:
                return {
                    "ok": False,
                    "tool": tool,
                    "action": action,
                    "error": "task not found",
                }
            deliverables = list(self.task["deliverables"])
            return self._response(
                tool,
                action,
                task=deepcopy(self.task),
                result={
                    "status": "SUCCESS",
                    "summary": self.checked_summary,
                    "deliverables": deliverables,
                },
                validationErrors=[],
                effective=True,
                pulled=True,
            )

        if (tool, action) == ("projectflow", "create_project"):
            self.project = {
                "project_id": payload["projectId"],
                "title": payload["title"],
                "source": payload["source"],
                "risk_tier": arguments["riskTier"],
                "binding": _expected_project_binding(payload["projectId"]),
                "status": "active",
                "tasks": [],
            }
            return self._response(tool, action, project=deepcopy(self.project))

        if (tool, action) == ("projectflow", "plan_dag"):
            assert self.project is not None
            planned = payload["tasks"][0]
            self.project["tasks"] = [
                {
                    "task_id": planned["taskId"],
                    "title": planned["title"],
                    "assigned_to": planned["assignedTo"],
                    "depends_on": planned["dependsOn"],
                    "status": "planned",
                }
            ]
            return self._response(tool, action, project=deepcopy(self.project))

        if (tool, action) == ("roomflow", "create_task_room"):
            return self._response(tool, action, **deepcopy(self.room_response))

        if (tool, action) == ("taskflow", "delegate_task"):
            assert self.project is not None
            self.project["tasks"][0]["status"] = "assigned"
            self.task = {
                "task_id": payload["taskId"],
                "project_id": payload["projectId"],
                "assigned_to": payload["assignedTo"],
                "room_id": payload["roomId"],
                "status": "assigned",
            }
            return self._response(tool, action, task=deepcopy(self.task), synced=True)

        if (tool, action) == ("projectflow", "accept_task_result"):
            assert self.project is not None
            self.project["tasks"][0]["status"] = "completed"
            self.project["requester_report"] = {
                "pending": True,
                "task_id": payload["taskId"],
                "result_status": "SUCCESS",
            }
            return self._response(
                tool,
                action,
                accepted=True,
                nodeStatus="completed",
                project=deepcopy(self.project),
            )

        if (tool, action) == ("projectflow", "complete_project"):
            assert self.project is not None
            self.project["status"] = "completed"
            return self._response(tool, action, project=deepcopy(self.project))

        if (tool, action) == ("projectflow", "mark_requester_report_sent"):
            assert self.project is not None
            self.project["requester_report"]["pending"] = False
            self.project["requester_report"]["sent_at"] = "2026-07-27T20:00:00Z"
            return self._response(tool, action, project=deepcopy(self.project))

        if tool == "filesync" and action in {"push", "stat"}:
            path = str(arguments["path"])
            workspace = f"/root/hiclaw-fs/agents/{LEADER_ROLE}"
            response = self._response(
                tool,
                action,
                kind="shared",
                path=path,
                localPath=f"{workspace}/{path.rstrip('/')}",
                workspaceBindingSha256=_hash(workspace),
            )
            if action == "stat":
                response["exists"] = True
                if not self.filesync_stat_mutated and (
                    self.filesync_stat_remove or self.filesync_stat_overrides
                ):
                    for field in self.filesync_stat_remove:
                        response.pop(field, None)
                    response.update(self.filesync_stat_overrides)
                    self.filesync_stat_mutated = True
            else:
                response.update(
                    expectedObjectCount=2,
                    verifiedObjectCount=2,
                    localTreeSha256=_hash("project-tree"),
                )
                for field in self.filesync_push_remove:
                    response.pop(field, None)
                response.update(self.filesync_push_overrides)
            return response

        raise AssertionError(f"unexpected fake call: {tool}.{action}")

    def locator_execute(self, run_id: str, task_id: str) -> dict[str, Any]:
        self.locator_calls.append((run_id, task_id))
        assert self.project is not None and self.task is not None
        deliverables = list(self.locator_summary["deliverables"])
        self.task.update(
            {
                "status": "submitted",
                "result_status": "SUCCESS",
                "summary": SUBMIT_SUMMARY,
                "deliverables": deliverables,
                "result_path": f"shared/tasks/{task_id}/result.md",
            }
        )
        self.project["tasks"][0]["status"] = "submitted"
        return deepcopy(self.locator_summary)


def test_default_plan_is_no_contact_and_complete() -> None:
    report = plan_report()

    assert report["mode"] == "plan"
    assert report["executionMode"] == "operator-driven"
    assert report["writes"] is False
    assert report["riskTier"] == "T2"
    assert tuple(report["stages"]) == PLAN_STAGES
    assert report["fixedScope"] == {
        "repository": f"{OWNER}/{REPOSITORY}",
        "revision": REVISION,
        "paths": [EVIDENCE_PATH],
    }
    _assert_public_safe(report)


def test_main_plan_does_not_construct_or_contact_a_backend(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "plan"
    assert output["writes"] is False


def test_success_path_has_exact_transition_order_and_safe_result() -> None:
    backend = FakeBackend()

    result = execute_success_path(
        backend,
        project_id=PROJECT_ID,
        confirmation=CONFIRMATION,
    )

    assert backend.preflight_calls == 1
    assert backend.locator_calls == [(PROJECT_ID, TASK_ID)]
    assert [(tool, action) for tool, action, _arguments in backend.calls] == [
        ("projectflow", "resolve_project"),
        ("taskflow", "check_task"),
        ("projectflow", "create_project"),
        ("projectflow", "plan_dag"),
        ("roomflow", "create_task_room"),
        ("taskflow", "delegate_task"),
        ("taskflow", "check_task"),
        ("projectflow", "accept_task_result"),
        ("projectflow", "complete_project"),
        ("projectflow", "mark_requester_report_sent"),
        ("filesync", "push"),
        ("filesync", "stat"),
        ("filesync", "stat"),
        ("projectflow", "resolve_project"),
    ]
    assert result["projectStatus"] == "completed"
    assert result["executionMode"] == "operator-driven"
    assert result["requesterReportPending"] is False
    assert result["filesyncPushed"] is True
    assert result["filesyncVerifiedObjects"] == 2
    assert all(result["proofs"].values())
    serialized = _canonical_text(result)
    assert ROOM_ID not in serialized
    assert "repository-original-sentinel" not in serialized
    _assert_public_safe(result)


def test_create_is_explicit_t2_and_delegation_is_canonical_without_capability() -> None:
    backend = FakeBackend()
    execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)

    create = next(arguments for tool, action, arguments in backend.calls if action == "create_project")
    assert create["riskTier"] == RISK_TIER
    assert "approval" not in create
    delegate = next(arguments for tool, action, arguments in backend.calls if action == "delegate_task")
    spec = delegate["payload"]["spec"]
    assert spec == _canonical_text(json.loads(spec))
    request = json.loads(spec)
    assert request == {
        "schema": "devflow.github-assignment-request/v1",
        "run_id": PROJECT_ID,
        "issue_id": ISSUE_ID,
        "task_id": TASK_ID,
        "trace_id": f"{PROJECT_ID}:{TASK_ID}",
        "idempotency_key": f"{PROJECT_ID}:{TASK_ID}:{LOCATOR_ROLE}:github-evidence",
        "repository": {"owner": OWNER, "repo": REPOSITORY},
        "revision": REVISION,
        "paths": [EVIDENCE_PATH],
    }
    assert "capability" not in spec.lower()
    assert GITHUB_TOOL not in spec
    bound_project_actions = {
        "create_project",
        "plan_dag",
        "accept_task_result",
        "complete_project",
        "mark_requester_report_sent",
    }
    for tool, action, arguments in backend.calls:
        if tool == "projectflow" and action in bound_project_actions:
            assert arguments["riskTier"] == RISK_TIER
    assert backend.calls[-1][2]["riskTier"] == RISK_TIER


def test_confirmation_failure_happens_before_preflight() -> None:
    backend = FakeBackend()
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation="wrong")
    assert raised.value.code == "confirmation_required"
    assert backend.preflight_calls == 0
    assert backend.calls == []


@pytest.mark.parametrize(
    "project_id",
    [
        "other-project",
        "devflow-live-github-",
        "devflow-live-github-UPPER",
        "devflow-live-github-a/escape",
        "devflow-live-github-a\nnext",
        "devflow-live-github-" + "a" * 40,
    ],
)
def test_unsafe_project_id_fails_before_preflight(project_id: str) -> None:
    backend = FakeBackend()
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=project_id, confirmation=CONFIRMATION)
    assert raised.value.stage == "input"
    assert backend.preflight_calls == 0


def test_freshness_failure_never_echoes_remote_error_details() -> None:
    class ExistingBackend(FakeBackend):
        def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if arguments.get("action") == "resolve_project":
                return {
                    "ok": False,
                    "tool": "projectflow",
                    "action": "resolve_project",
                    "error": "already exists credential-value-must-not-leak",
                }
            return super().leader_call(tool, arguments)

    with pytest.raises(DriverError) as raised:
        execute_success_path(
            ExistingBackend(),
            project_id=PROJECT_ID,
            confirmation=CONFIRMATION,
        )

    assert raised.value.code == "freshness_not_proven"
    assert "credential-value-must-not-leak" not in str(raised.value)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("brokerScopeSha256", "0" * 64, "locator_scope_mismatch"),
        ("artifactSha256", "not-a-digest", "locator_digest_invalid"),
        (
            "idempotencyKeySha256",
            "0" * 64,
            "locator_idempotency_binding_invalid",
        ),
        ("submissionSha256", "0" * 64, "locator_submission_binding_invalid"),
        (
            "conflictRequestedSha256",
            "0" * 64,
            "locator_conflict_binding_invalid",
        ),
        ("idempotentRetry", False, "locator_transition_unproven"),
        ("conflictRetry", False, "locator_transition_unproven"),
        ("validatorPassed", False, "locator_transition_unproven"),
    ],
)
def test_locator_proofs_are_mandatory(field: str, value: Any, code: str) -> None:
    backend = FakeBackend()
    backend.locator_summary[field] = value
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.code == code


def test_locator_summary_surface_is_closed() -> None:
    backend = FakeBackend()
    assert set(backend.locator_summary) == LOCATOR_SUMMARY_FIELDS
    backend.locator_summary["raw"] = "repository-original-sentinel"
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.code == "locator_summary_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("private", False),
        ("reused", True),
        ("joinRule", "public"),
        ("membershipStateVerified", False),
        ("membershipProjection", "all-members"),
        ("creator", "@unexpected:matrix.example"),
        ("invite", [MATRIX_USER_ID, "@unexpected:matrix.example"]),
        ("members", [MATRIX_USER_ID, "@unexpected:matrix.example"]),
        ("authorizedMemberCount", 4),
        ("authorizedMemberCount", 2.0),
        ("authorizedMembersSha256", "not-a-digest"),
        ("binding", {"schema": "untrusted"}),
    ],
)
def test_room_must_be_fresh_private_and_have_exact_members(
    field: str, value: Any
) -> None:
    backend = FakeBackend()
    backend.room_response[field] = value
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.code == "fresh_room_invalid"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("risk_tier", "T3"),
        ("source", "chat"),
        ("binding", {"schema": "untrusted"}),
    ],
)
def test_project_risk_and_source_are_response_bound(field: str, value: Any) -> None:
    class DriftBackend(FakeBackend):
        def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
            response = super().leader_call(tool, arguments)
            if arguments.get("action") == "create_project" and response.get("ok") is True:
                response["project"][field] = value
            return response

    with pytest.raises(DriverError) as raised:
        execute_success_path(
            DriftBackend(), project_id=PROJECT_ID, confirmation=CONFIRMATION
        )
    assert raised.value.code == "project_binding_invalid"


def test_post_conflict_readback_is_bound_to_original_submission_digest() -> None:
    backend = FakeBackend()
    backend.checked_summary = SUBMIT_SUMMARY + " drift"
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.code == "post_conflict_readback_mismatch"


def test_final_pending_false_is_verified_after_filesync() -> None:
    backend = FakeBackend()
    backend.final_pending_override = True
    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.code == "final_state_invalid"
    assert backend.calls[-4][1] == "push"
    assert [call[1] for call in backend.calls[-3:-1]] == ["stat", "stat"]
    assert backend.calls[-1][1] == "resolve_project"


def test_filesync_push_readback_order_and_paths_are_exact() -> None:
    backend = FakeBackend()
    execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)

    filesync_calls = [
        (action, arguments["path"])
        for tool, action, arguments in backend.calls
        if tool == "filesync"
    ]
    assert filesync_calls == [
        ("push", f"shared/projects/{PROJECT_ID}/"),
        ("stat", f"shared/projects/{PROJECT_ID}/meta.json"),
        ("stat", f"shared/projects/{PROJECT_ID}/plan.md"),
    ]


@pytest.mark.parametrize(
    "missing_field",
    [
        "ok",
        "tool",
        "action",
        "kind",
        "path",
        "localPath",
        "workspaceBindingSha256",
        "exists",
    ],
)
def test_filesync_stat_readback_fails_closed_when_any_field_is_missing(
    missing_field: str,
) -> None:
    backend = FakeBackend()
    backend.filesync_stat_remove = {missing_field}

    with pytest.raises(DriverError):
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert [(tool, action) for tool, action, _arguments in backend.calls[-2:]] == [
        ("filesync", "push"),
        ("filesync", "stat"),
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("exists", False),
        ("path", f"shared/projects/{PROJECT_ID}/wrong.json"),
        ("kind", "global-shared"),
        ("localPath", "/unexpected/local/path"),
        ("workspaceBindingSha256", "0" * 64),
        ("unexpected", True),
    ],
)
def test_filesync_stat_readback_rejects_false_or_mismatched_attestation(
    field: str,
    value: Any,
) -> None:
    backend = FakeBackend()
    backend.filesync_stat_overrides = {field: value}

    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.stage == "filesync-readback"


@pytest.mark.parametrize(
    ("field", "value", "remove"),
    [
        ("expectedObjectCount", None, True),
        ("verifiedObjectCount", None, True),
        ("localTreeSha256", None, True),
        ("expectedObjectCount", 3, False),
        ("verifiedObjectCount", 1, False),
        ("verifiedObjectCount", True, False),
        ("localTreeSha256", "not-a-digest", False),
    ],
)
def test_filesync_push_requires_two_digest_attested_objects(
    field: str,
    value: Any,
    remove: bool,
) -> None:
    backend = FakeBackend()
    if remove:
        backend.filesync_push_remove = {field}
    else:
        backend.filesync_push_overrides = {field: value}

    with pytest.raises(DriverError) as raised:
        execute_success_path(backend, project_id=PROJECT_ID, confirmation=CONFIRMATION)
    assert raised.value.code == "filesync_attestation_invalid"
    assert raised.value.stage == "filesync-push"


@pytest.mark.parametrize(
    "unsafe",
    [
        {"roomId": ROOM_ID},
        {"value": ROOM_ID},
        {"value": "A" * 16 + "." + "B" * 43},
        {"value": "ghp_" + "A" * 36},
        {"content_base64": "ZmlsZQ=="},
    ],
)
def test_public_output_gate_rejects_sensitive_surfaces(unsafe: dict[str, str]) -> None:
    with pytest.raises(DriverError):
        _assert_public_safe(unsafe)


def test_sanitized_markdown_contains_only_metadata_and_digests() -> None:
    markdown = _remote_sanitized_markdown(
        task_id=TASK_ID,
        artifact_digest=_hash("artifact"),
        authorizer_scope=_hash("authorizer"),
        broker_scope=_expected_broker_scope(TASK_ID),
        capability_digest=_hash("capability"),
        content_digest=_hash("repository-original-sentinel"),
        envelope_digest=_hash("envelope"),
        object_sha="c" * 40,
        response_digest=_hash("response"),
    ).decode("utf-8")

    assert "repository-original-sentinel" not in markdown
    assert ROOM_ID not in markdown
    assert "content_base64" not in markdown
    assert f"{OWNER}/{REPOSITORY}" in markdown
    assert REVISION in markdown
    assert "Repository bytes written to disk: `no`" in markdown


def test_remote_team_payload_unwraps_one_json_text_candidate() -> None:
    payload = {"ok": True, "tool": "taskflow", "action": "check_task", "task": {}}
    wrapper = {"content": [{"type": "text", "text": _canonical_text(payload)}]}
    assert _remote_team_payload(wrapper, "taskflow", "check_task") == payload


def test_remote_team_payload_rejects_ambiguous_candidates() -> None:
    first = {"ok": True, "tool": "taskflow", "action": "check_task", "task": {}}
    second = {"ok": False, "tool": "taskflow", "action": "check_task", "error": "x"}
    with pytest.raises(RuntimeError):
        _remote_team_payload([first, second], "taskflow", "check_task")


def _submission_transition_fixture() -> tuple[list[str], str, str]:
    deliverables = [
        f"shared/tasks/{TASK_ID}/result.md",
        f"shared/tasks/{TASK_ID}/GitHubEvidence/result.md",
    ]
    current = _submission_digest(TASK_ID, deliverables)
    requested = _submission_digest(
        TASK_ID,
        deliverables,
        summary=SUBMIT_SUMMARY + " Changed retry.",
    )
    return deliverables, current, requested


def _first_ack_fixture(spec: str = '{"handoff":"fixed"}\n') -> dict[str, Any]:
    return {
        "ok": True,
        "tool": "taskflow",
        "action": "ack_task",
        "task": {
            "task_id": TASK_ID,
            "project_id": PROJECT_ID,
            "room_id": ROOM_ID,
            "status": "in_progress",
            "spec_path": f"shared/tasks/{TASK_ID}/spec.md",
            "assigned_to": LOCATOR_ROLE,
            "task_title": "Collect revision-pinned GitHub evidence",
            "assigned_at": "2026-07-28T12:34:56Z",
            "acknowledged_by_role": "worker",
        },
        "spec": spec,
        "pulled": True,
        "synced": True,
    }


def test_first_ack_contract_is_exact_and_returns_response_spec() -> None:
    response = _first_ack_fixture()

    assert _remote_ack_spec(response, "/not-read-for-first-ack", TASK_ID) == response["spec"]

    response["task"]["task_title"] = TASK_ID
    assert _remote_ack_spec(response, "/not-read-for-first-ack", TASK_ID) == response["spec"]


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("unexpected",), True),
        (("tool",), "other"),
        (("action",), "submit_task"),
        (("ok",), 1),
        (("pulled",), False),
        (("synced",), False),
        (("spec",), 7),
        (("task", "unexpected"), True),
        (("task", "task_id"), "wrong"),
        (("task", "project_id"), "wrong"),
        (("task", "room_id"), "not-a-room"),
        (("task", "status"), "assigned"),
        (("task", "spec_path"), "shared/tasks/other/spec.md"),
        (("task", "assigned_to"), "other"),
        (("task", "task_title"), ""),
        (("task", "task_title"), "bad\ntitle"),
        (("task", "task_title"), "x" * 257),
        (("task", "assigned_at"), "2026-07-28T12:34:56+00:00"),
        (("task", "acknowledged_by_role"), "leader"),
    ],
)
def test_first_ack_contract_rejects_extra_or_mismatched_fields(
    path: tuple[str, ...], value: Any
) -> None:
    response = _first_ack_fixture()
    target = response
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(RuntimeError):
        _remote_ack_spec(response, "/not-read-for-invalid-ack", TASK_ID)


def test_first_ack_contract_rejects_missing_fields() -> None:
    for field in _first_ack_fixture():
        response = _first_ack_fixture()
        del response[field]
        with pytest.raises(RuntimeError):
            _remote_ack_spec(response, "/not-read-for-invalid-ack", TASK_ID)


def test_first_ack_contract_rejects_every_missing_task_field() -> None:
    task = _first_ack_fixture()["task"]
    for field in task:
        response = _first_ack_fixture()
        del response["task"][field]
        with pytest.raises(RuntimeError):
            _remote_ack_spec(response, "/not-read-for-invalid-ack", TASK_ID)


@pytest.mark.parametrize(
    "assigned_at",
    [
        None,
        "",
        "2026-07-28T12:34:56",
        "2026-07-28T12:34:56.000Z",
        "2026-07-28t12:34:56z",
        "2026-07-28T12:34:56+00:00",
        "2026-02-30T12:34:56Z",
        "2026-07-28T25:34:56Z",
        "2026-07-28T12:34:56Z\n",
        "20260-07-28T12:34:56Z",
    ],
)
def test_first_ack_rejects_noncanonical_or_invalid_assigned_at(
    assigned_at: Any,
) -> None:
    response = _first_ack_fixture()
    response["task"]["assigned_at"] = assigned_at

    with pytest.raises(RuntimeError):
        _remote_ack_spec(response, "/not-read-for-invalid-ack", TASK_ID)


@pytest.mark.parametrize("task_title", [None, "", "   ", "bad\x7ftitle", "界" * 86])
def test_first_ack_rejects_unbounded_empty_or_controlled_task_title(
    task_title: Any,
) -> None:
    response = _first_ack_fixture()
    response["task"]["task_title"] = task_title

    with pytest.raises(RuntimeError):
        _remote_ack_spec(response, "/not-read-for-invalid-ack", TASK_ID)


def test_exact_idempotent_ack_reuses_only_the_persisted_fixed_task_spec(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "hiclaw-fs" / "agents" / LOCATOR_ROLE
    task_root = workspace / "shared" / "tasks" / TASK_ID
    task_root.mkdir(parents=True)
    expected = '{"handoff":"persisted"}\n'
    (task_root / "spec.md").write_bytes(expected.encode("utf-8"))
    response = {
        "ok": True,
        "idempotent": True,
        "action": "ack_task",
        "role": "worker",
        "taskState": "in_progress",
        "taskId": TASK_ID,
    }

    assert _remote_ack_spec(response, str(workspace), TASK_ID) == expected
    assert _remote_persisted_task_spec(str(workspace), TASK_ID) == expected


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ok", 1),
        ("idempotent", 1),
        ("action", "submit_task"),
        ("role", "leader"),
        ("taskState", "submitted"),
        ("taskId", "other"),
        ("unexpected", True),
    ],
)
def test_idempotent_ack_contract_rejects_nonexact_fields(
    field: str, value: Any
) -> None:
    response = {
        "ok": True,
        "idempotent": True,
        "action": "ack_task",
        "role": "worker",
        "taskState": "in_progress",
        "taskId": TASK_ID,
    }
    response[field] = value

    with pytest.raises(RuntimeError):
        _remote_ack_spec(response, "/not-read-for-invalid-ack", TASK_ID)


def test_idempotent_ack_contract_rejects_every_missing_field() -> None:
    response = {
        "ok": True,
        "idempotent": True,
        "action": "ack_task",
        "role": "worker",
        "taskState": "in_progress",
        "taskId": TASK_ID,
    }
    for field in response:
        missing = dict(response)
        del missing[field]
        with pytest.raises(RuntimeError):
            _remote_ack_spec(missing, "/not-read-for-invalid-ack", TASK_ID)


def test_persisted_ack_spec_rejects_symlink_and_oversized_file(tmp_path: Path) -> None:
    workspace = tmp_path / "hiclaw-fs" / "agents" / LOCATOR_ROLE
    task_root = workspace / "shared" / "tasks" / TASK_ID
    task_root.mkdir(parents=True)
    spec_path = task_root / "spec.md"
    spec_path.write_bytes(b"x" * 1_000_001)

    with pytest.raises(RuntimeError):
        _remote_persisted_task_spec(str(workspace), TASK_ID)

    spec_path.unlink()
    target = task_root / "target.md"
    target.write_text("fixed\n", encoding="utf-8")
    try:
        spec_path.symlink_to(target)
    except OSError:
        pytest.skip("host does not permit test symlinks")
    with pytest.raises(RuntimeError):
        _remote_persisted_task_spec(str(workspace), TASK_ID)


def test_role_task_root_accepts_only_the_real_per_role_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "hiclaw-fs" / "agents" / LOCATOR_ROLE
    task_root = workspace / "shared" / "tasks" / TASK_ID
    task_root.mkdir(parents=True)

    assert _remote_role_task_root(str(workspace), TASK_ID) == task_root


def test_role_task_root_never_falls_back_to_global_shared_or_escape(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "hiclaw-fs" / "agents" / LOCATOR_ROLE
    workspace.mkdir(parents=True)
    global_task = tmp_path / "hiclaw-fs" / "shared" / "tasks" / TASK_ID
    global_task.mkdir(parents=True)
    (global_task / "spec.md").write_text("global must not be read\n", encoding="utf-8")

    with pytest.raises(RuntimeError):
        _remote_role_task_root(str(workspace), TASK_ID)
    with pytest.raises(RuntimeError):
        _remote_role_task_root(str(tmp_path / "hiclaw-fs"), TASK_ID)
    with pytest.raises(RuntimeError):
        _remote_role_task_root(str(workspace), "../escaped-task")
    with pytest.raises(RuntimeError):
        _remote_role_task_root(
            str(workspace.parent / "intermediate" / ".." / LOCATOR_ROLE),
            TASK_ID,
        )


def test_role_task_root_rejects_symlinked_workspace_components(tmp_path: Path) -> None:
    workspace = tmp_path / "hiclaw-fs" / "agents" / LOCATOR_ROLE
    workspace.mkdir(parents=True)
    external_shared = tmp_path / "external-shared"
    (external_shared / "tasks" / TASK_ID).mkdir(parents=True)
    try:
        (workspace / "shared").symlink_to(external_shared, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit test directory symlinks")

    with pytest.raises(RuntimeError):
        _remote_role_task_root(str(workspace), TASK_ID)


def test_first_submission_requires_matching_optional_guard_attestation() -> None:
    deliverables, current, _requested = _submission_transition_fixture()
    first = {
        "ok": True,
        "synced": True,
        "task": {
            "task_id": TASK_ID,
            "status": "submitted",
            "result_status": "SUCCESS",
            "summary": SUBMIT_SUMMARY,
            "deliverables": deliverables,
        },
    }
    _remote_validate_first_submission(first, TASK_ID, deliverables, current)
    attested = {**first, "taskId": TASK_ID, "submissionDigest": current}
    _remote_validate_first_submission(attested, TASK_ID, deliverables, current)

    for invalid in (
        {**first, "taskId": TASK_ID},
        {**first, "submissionDigest": current},
        {**first, "taskId": "wrong", "submissionDigest": current},
        {**first, "taskId": TASK_ID, "submissionDigest": "0" * 64},
    ):
        with pytest.raises(RuntimeError):
            _remote_validate_first_submission(invalid, TASK_ID, deliverables, current)


def test_idempotent_retry_contract_is_exact_and_digest_bound() -> None:
    _deliverables, current, _requested = _submission_transition_fixture()
    response = {
        "ok": True,
        "idempotent": True,
        "action": "submit_task",
        "role": "worker",
        "taskState": "submitted",
        "taskId": TASK_ID,
        "submissionDigest": current,
    }
    _remote_validate_idempotent_submission(response, TASK_ID, current)
    for field, value in (
        ("taskId", "wrong"),
        ("submissionDigest", "0" * 64),
        ("taskState", "completed"),
    ):
        invalid = {**response, field: value}
        with pytest.raises(RuntimeError):
            _remote_validate_idempotent_submission(invalid, TASK_ID, current)
    with pytest.raises(RuntimeError):
        _remote_validate_idempotent_submission(
            {**response, "unexpected": True}, TASK_ID, current
        )


def test_conflict_retry_contract_binds_current_and_changed_digests() -> None:
    _deliverables, current, requested = _submission_transition_fixture()
    response = {
        "ok": False,
        "error": "submit_result_conflict",
        "tool": "taskflow",
        "action": "submit_task",
        "role": "worker",
        "taskId": TASK_ID,
        "currentDigest": current,
        "requestedDigest": requested,
    }
    _remote_validate_conflicting_submission(
        response, TASK_ID, current, requested
    )
    for field, value in (
        ("taskId", "wrong"),
        ("currentDigest", "0" * 64),
        ("requestedDigest", "f" * 64),
    ):
        invalid = {**response, field: value}
        with pytest.raises(RuntimeError):
            _remote_validate_conflicting_submission(
                invalid, TASK_ID, current, requested
            )
    with pytest.raises(RuntimeError):
        _remote_validate_conflicting_submission(response, TASK_ID, current, current)


def test_remote_receipt_parser_never_needs_repository_bytes_on_host() -> None:
    receipt = {
        "schema_version": "devflow.github-content-response/v1",
        "authorization": {},
        "github": {"content_base64": "cmF3"},
        "response_digest": "a" * 64,
        "receipt_signature": "b" * 64,
    }
    wrapper = {"content": [{"text": _canonical_text(receipt)}]}
    assert _remote_receipt(wrapper) == receipt


def test_cli_rejects_execute_arguments_without_execute_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["--project-id", PROJECT_ID]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error == {"ok": False, "code": "execute_flag_required", "stage": "input"}


def test_driver_source_contains_no_embedded_credentials() -> None:
    source = Path(__file__).resolve().parents[1] / "scripts" / "run_agentteams_github_success_path.py"
    text = source.read_text(encoding="utf-8")
    assert re.search(r"ghp_[A-Za-z0-9]{36}", text) is None
    assert re.search(r"github_pat_[A-Za-z0-9_]{30,}", text) is None
    assert "PRIVATE KEY-----" in text  # detector pattern only
    assert "password" not in text.lower()


def test_mcporter_and_canonical_schema_attestations_are_fully_pinned() -> None:
    assert EXPECTED_MCPORTER_SHA256 == (
        "ec13274c40bc0c71e73e994cf773b9d3801ce909d38f4b133f11450c9e0c458b"
    )
    assert EXPECTED_MCPORTER_VERSION == "0.9.0"
    assert (
        EXPECTED_MCPORTER_UID,
        EXPECTED_MCPORTER_GID,
        EXPECTED_MCPORTER_MODE,
        EXPECTED_MCPORTER_NLINK,
        EXPECTED_MCPORTER_SIZE,
    ) == (0, 0, 0o755, 1, 8_254)
    assert "metadata.st_uid != 0" in REMOTE_PREFLIGHT_HELPER
    assert "metadata.st_gid != 0" in REMOTE_PREFLIGHT_HELPER
    assert "stat.S_IMODE(metadata.st_mode) != 0o755" in REMOTE_PREFLIGHT_HELPER
    assert "metadata.st_nlink != 1" in REMOTE_PREFLIGHT_HELPER
    assert "metadata.st_size != 8254" in REMOTE_PREFLIGHT_HELPER
    assert "stderr=subprocess.PIPE" in REMOTE_PREFLIGHT_HELPER
    assert '"stderr_size", 65536' in REMOTE_PREFLIGHT_HELPER
    assert "if schema_stderr:" in REMOTE_PREFLIGHT_HELPER
    assert MCP_SCHEMA_CANONICALIZATION_ID == (
        "mcporter-v0.9.0-terminal-latency-zeroed"
    )
    assert EXPECTED_MCP_SCHEMA_CANONICAL_BYTES == {
        LEADER_ROLE: {"teamharness": 28_909},
        LOCATOR_ROLE: {
            "devflow-github-readonly": 1_742,
            "teamharness": 4_203,
        },
    }
    for role_pins in EXPECTED_MCP_SCHEMA_CANONICAL_SHA256.values():
        for digest in role_pins.values():
            assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert EXPECTED_MCP_SCHEMA_CANONICAL_SHA256 == {
        LEADER_ROLE: {
            "teamharness": (
                "985fbb53710bc62f34e0194783a68852e4a7400bea794b6600023f96bf730eea"
            )
        },
        LOCATOR_ROLE: {
            "devflow-github-readonly": (
                "2588f5c5d201588468e86c93899f22ff913b98c7c6784173b23640b1718ab887"
            ),
            "teamharness": (
                "a4243ba99239622210efd749ac06e30d3d7d1673c4cbf07db80720ed5859b69a"
            ),
        },
    }
    assert 're.fullmatch(r"[0-9a-f]{64}", digest) is None' in REMOTE_PREFLIGHT_HELPER
    assert '"schemaCanonicalization"' in REMOTE_PREFLIGHT_HELPER
    assert '"schemaCanonicalSha256"' in REMOTE_PREFLIGHT_HELPER
    assert '"schemaCanonicalBytes"' in REMOTE_PREFLIGHT_HELPER
    assert '"schemaSha256"' not in REMOTE_PREFLIGHT_HELPER
    assert '"schemaBytes"' not in REMOTE_PREFLIGHT_HELPER


def _mcporter_schema_fixture(
    latency: bytes,
    *,
    prefix: bytes = b"fixed-schema",
    tool_count: bytes = b"7",
    tool_label: bytes = b"tools",
) -> bytes:
    bullet = "·".encode()
    return (
        prefix
        + b"\n  "
        + tool_count
        + b" "
        + tool_label
        + b" "
        + bullet
        + b" "
        + latency
        + b"ms "
        + bullet
        + b" STDIO /usr/bin/python3\n\n"
    )


def test_mcporter_schema_canonicalization_changes_only_terminal_latency() -> None:
    one_digit = _mcporter_schema_fixture(b"4")
    six_digits = _mcporter_schema_fixture(b"987654")
    expected = _mcporter_schema_fixture(b"0")

    assert expected.endswith(b"\n\n") and not expected.endswith(b"\n\n\n")
    assert _canonicalize_mcporter_schema(one_digit) == expected
    assert _canonicalize_mcporter_schema(six_digits) == expected
    latency_start = six_digits.index(b"987654")
    canonical = _canonicalize_mcporter_schema(six_digits)
    assert canonical[:latency_start] == six_digits[:latency_start]
    assert canonical[latency_start + 1 :] == six_digits[latency_start + 6 :]


@pytest.mark.parametrize(
    ("tool_count", "tool_label"),
    [(b"1", b"tool"), (b"19", b"tools")],
)
def test_mcporter_schema_canonicalization_accepts_grammatical_tool_labels(
    tool_count: bytes,
    tool_label: bytes,
) -> None:
    raw = _mcporter_schema_fixture(
        b"42",
        tool_count=tool_count,
        tool_label=tool_label,
    )
    expected = _mcporter_schema_fixture(
        b"0",
        tool_count=tool_count,
        tool_label=tool_label,
    )
    assert _canonicalize_mcporter_schema(raw) == expected


def test_mcporter_schema_non_latency_drift_does_not_match_canonical_pin() -> None:
    baseline = _canonicalize_mcporter_schema(
        _mcporter_schema_fixture(b"12", prefix=b"fixed-schema")
    )
    drifted = _canonicalize_mcporter_schema(
        _mcporter_schema_fixture(b"99", prefix=b"fixed-schemb")
    )
    assert len(baseline) == len(drifted)
    assert hashlib.sha256(baseline).hexdigest() != hashlib.sha256(drifted).hexdigest()


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff\n" + _mcporter_schema_fixture(b"1"),
        b"schema-without-summary\n",
        _mcporter_schema_fixture(b"1") + _mcporter_schema_fixture(b"2"),
        _mcporter_schema_fixture(b"1.5"),
        _mcporter_schema_fixture(b"01"),
        _mcporter_schema_fixture(b"1", tool_label=b"tool(s)"),
        _mcporter_schema_fixture(b"1").replace(
            b"/usr/bin/python3", b"/usr/bin/python3 9ms"
        ),
        _mcporter_schema_fixture(b"1") + b"unexpected-tail\n",
        _mcporter_schema_fixture(b"1").rstrip(b"\n"),
        _mcporter_schema_fixture(b"1")[:-1],
        _mcporter_schema_fixture(b"1") + b"\n",
        _mcporter_schema_fixture(b"1").replace(b"\n\n", b"\r\n\r\n"),
    ],
)
def test_mcporter_schema_canonicalization_rejects_ambiguous_or_malformed_output(
    raw: bytes,
) -> None:
    with pytest.raises(ValueError):
        _canonicalize_mcporter_schema(raw)


def test_mcporter_schema_canonicalization_rejects_oversized_output() -> None:
    with pytest.raises(ValueError):
        _canonicalize_mcporter_schema(b"x" * 1_000_001)


def test_normalized_mcporter_config_is_full_and_role_exact() -> None:
    leader = _normalized_mcporter_config(LEADER_ROLE)
    locator = _normalized_mcporter_config(LOCATOR_ROLE)
    assert leader == {
        "mcpServers": {
            "teamharness": {
                "command": "/usr/bin/python3",
                "args": ["/opt/devflow/teamharness/guarded_server.py"],
                "transport": "stdio",
                "env": {"TEAMHARNESS_SHARED_DIR": "/root/hiclaw-fs/shared"},
            }
        }
    }
    assert locator["mcpServers"]["teamharness"] == leader["mcpServers"]["teamharness"]
    assert locator["mcpServers"]["devflow-github-readonly"] == {
        "url": (
            "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
            "mcp-servers/devflow-github-readonly/mcp"
        ),
        "transport": "http",
        "headers": {"Authorization": "Bearer <redacted>"},
    }
    with pytest.raises(DriverError):
        _normalized_mcporter_config("unexpected-role")


def test_sensitive_teamharness_arguments_are_stdin_not_secondary_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    capability = "A" * 16 + "." + "B" * 43

    def fake_run(
        arguments: list[str],
        *,
        cwd: str,
        input_data: bytes,
        timeout_seconds: int,
        max_stdout_bytes: int,
        environment: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        captured.update(
            arguments=arguments,
            cwd=cwd,
            input_data=input_data,
            timeout_seconds=timeout_seconds,
            max_stdout_bytes=max_stdout_bytes,
            environment=environment,
        )
        return 0, _canonical_bytes({"jsonrpc": "2.0", "id": 1, "result": {}})

    monkeypatch.setattr(success_driver, "_remote_run_bounded_process", fake_run)
    _remote_stdio_mcp_call(
        "/root/hiclaw-fs/agents/devflow-locator",
        "taskflow",
        {"action": "delegate_task", "payload": {"roomId": ROOM_ID, "grant": capability}},
    )

    argv = "\n".join(captured["arguments"])
    assert captured["arguments"] == [
        "/usr/bin/python3",
        "/opt/devflow/teamharness/guarded_server.py",
    ]
    assert ROOM_ID not in argv
    assert capability not in argv
    assert ROOM_ID.encode("utf-8") in captured["input_data"]
    assert capability.encode("utf-8") in captured["input_data"]
    assert "--args" not in REMOTE_CONTROL_HELPER
    assert "--args" not in REMOTE_LOCATOR_HELPER
    assert '"/usr/bin/mcporter", "call"' not in REMOTE_CONTROL_HELPER
    assert '"/usr/bin/mcporter", "call"' not in REMOTE_LOCATOR_HELPER
    assert '"filesync": {"push", "stat"}' in REMOTE_CONTROL_HELPER
    assert '"filesync": {"push", "stat", "pull"}' not in REMOTE_CONTROL_HELPER


def test_github_mcp_uses_in_process_streamable_http_not_a_secondary_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []
    capability = "A" * 16 + "." + "B" * 43

    monkeypatch.setattr(
        success_driver,
        "_remote_read_locator_config",
        lambda _workspace: (
            "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
            "mcp-servers/devflow-github-readonly/mcp",
            "Bearer in-memory-only",
        ),
    )

    def fake_http_request(**values: Any) -> tuple[bytes, str, str | None]:
        calls.append(values)
        body = values["body"]
        if values["method"] == "DELETE":
            return b"", "", values["session_id"]
        document = json.loads(body) if body else {}
        if document.get("method") == "initialize":
            response = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"protocolVersion": "2025-03-26"},
            }
            return _canonical_bytes(response), "application/json", "session-1"
        if document.get("method") == "notifications/initialized":
            return b"", "", "session-1"
        response = {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}
        return _canonical_bytes(response), "application/json", "session-1"

    monkeypatch.setattr(success_driver, "_remote_http_request", fake_http_request)
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("GitHub HTTP transport must not start a child process")
        ),
    )

    response = _remote_http_mcp_call(
        "/root/hiclaw-fs/agents/devflow-locator",
        GITHUB_TOOL,
        {
            "task_id": TASK_ID,
            "capability": capability,
            "owner": OWNER,
            "repo": REPOSITORY,
            "path": EVIDENCE_PATH,
            "revision": REVISION,
        },
    )

    assert response == {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}
    assert [call["method"] for call in calls] == ["POST", "POST", "POST", "DELETE"]
    assert calls[0]["session_id"] is None
    assert calls[1]["session_id"] == "session-1"
    assert capability.encode("utf-8") in calls[2]["body"]
    assert all(call["authorization"] == "Bearer in-memory-only" for call in calls)


@pytest.mark.parametrize(
    "tool_result",
    [
        {"content": [{"type": "text", "text": "bounded-error"}], "isError": True},
        {"content": [{"type": "text", "text": "bounded-error"}], "isError": 1},
        {"content": [], "error": {"code": "bounded-error"}},
    ],
)
def test_github_mcp_rejects_error_results_before_receipt_processing(
    monkeypatch: pytest.MonkeyPatch,
    tool_result: dict[str, Any],
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        success_driver,
        "_remote_read_locator_config",
        lambda _workspace: (
            "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
            "mcp-servers/devflow-github-readonly/mcp",
            "Bearer in-memory-only",
        ),
    )

    def fake_http_request(**values: Any) -> tuple[bytes, str, str | None]:
        calls.append(values["method"])
        if values["method"] == "DELETE":
            return b"", "", values["session_id"]
        document = json.loads(values["body"]) if values["body"] else {}
        if document.get("method") == "initialize":
            return (
                _canonical_bytes(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"protocolVersion": "2025-03-26"},
                    }
                ),
                "application/json",
                "session-1",
            )
        if document.get("method") == "notifications/initialized":
            return b"", "", "session-1"
        return (
            _canonical_bytes({"jsonrpc": "2.0", "id": 2, "result": tool_result}),
            "application/json",
            "session-1",
        )

    monkeypatch.setattr(success_driver, "_remote_http_request", fake_http_request)

    with pytest.raises(RuntimeError):
        _remote_http_mcp_call(
            "/root/hiclaw-fs/agents/devflow-locator",
            GITHUB_TOOL,
            {
                "task_id": TASK_ID,
                "capability": "A" * 16 + "." + "B" * 43,
                "owner": OWNER,
                "repo": REPOSITORY,
                "path": EVIDENCE_PATH,
                "revision": REVISION,
            },
        )
    assert calls == ["POST", "POST", "POST", "DELETE"]


def test_streamable_http_headers_notification_and_sse_response_are_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeResponse:
        status = 202

        @staticmethod
        def read(maximum: int) -> bytes:
            assert maximum == 3_200_001
            return b""

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return []

    class FakeConnection:
        def __init__(self, host: str, port: int, timeout: int) -> None:
            captured.update(host=host, port=port, timeout=timeout)

        def request(
            self,
            method: str,
            path: str,
            *,
            body: bytes,
            headers: dict[str, str],
        ) -> None:
            captured.update(method=method, path=path, body=body, headers=headers)

        @staticmethod
        def getresponse() -> FakeResponse:
            return FakeResponse()

        @staticmethod
        def close() -> None:
            return None

    monkeypatch.setattr(http.client, "HTTPConnection", FakeConnection)
    notification = _canonical_bytes(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    body, content_type, session = _remote_http_request(
        url=(
            "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
            "mcp-servers/devflow-github-readonly/mcp"
        ),
        authorization="Bearer in-memory-only",
        method="POST",
        body=notification,
        session_id="session-1",
        expected_status=(202,),
        timeout_seconds=35,
    )
    assert (body, content_type, session) == (b"", "", "session-1")
    assert captured["headers"] == {
        "Authorization": "Bearer in-memory-only",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2025-03-26",
        "Connection": "close",
        "Mcp-Session-Id": "session-1",
    }

    response = {"jsonrpc": "2.0", "id": 2, "result": {"content": []}}
    event = b"event: message\r\ndata: " + _canonical_bytes(response) + b"\r\n\r\n"
    assert _remote_parse_http_mcp(event, "text/event-stream", 2) == response
    duplicate = event + event
    with pytest.raises(RuntimeError):
        _remote_parse_http_mcp(duplicate, "text/event-stream", 2)


def test_bounded_process_discards_stderr_and_kills_a_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    noisy = (
        "import sys;"
        "sys.stderr.buffer.write(b'x'*2000000);"
        "sys.stderr.flush();"
        "sys.stdout.write('{}')"
    )
    returncode, stdout = _remote_run_bounded_process(
        [sys.executable, "-c", noisy],
        cwd=str(tmp_path),
        input_data=b"",
        timeout_seconds=5,
        max_stdout_bytes=100,
    )
    assert returncode == 0
    assert stdout == b"{}"

    real_popen = subprocess.Popen
    processes: list[subprocess.Popen[bytes]] = []

    def capture_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "Popen", capture_popen)
    with pytest.raises(RuntimeError):
        _remote_run_bounded_process(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=str(tmp_path),
            input_data=b"",
            timeout_seconds=1,
            max_stdout_bytes=100,
        )
    assert len(processes) == 1
    assert processes[0].poll() is not None


def test_remote_deadlines_fit_cumulative_calls_and_leave_host_cleanup_margin() -> None:
    assert REMOTE_LOCATOR_DEADLINE_SECONDS >= (
        REMOTE_LOCATOR_CALL_COUNT * REMOTE_MCP_CALL_TIMEOUT_SECONDS
    )
    assert HOST_LOCATOR_TIMEOUT_SECONDS >= (
        REMOTE_LOCATOR_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
    )
    assert HOST_CONTROL_TIMEOUT_SECONDS >= (
        REMOTE_CONTROL_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
    )
    assert HOST_PREFLIGHT_TIMEOUT_SECONDS >= (
        REMOTE_PREFLIGHT_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
    )


def test_kubectl_argv_is_short_and_helper_and_payload_are_stdin_framed() -> None:
    class CaptureRunner:
        def __init__(self) -> None:
            self.arguments: list[str] = []
            self.input_data = b""

        def run(
            self,
            arguments: list[str],
            *,
            input_data: bytes | None = None,
            timeout: int = 180,
        ) -> str:
            del timeout
            self.arguments = list(arguments)
            self.input_data = input_data or b""
            return "{}"

    helper = "print('ok')\n" + "# bounded helper\n" * 4_000
    capability = "A" * 16 + "." + "B" * 43
    payload = _canonical_bytes({"room": ROOM_ID, "grant": capability})
    target = Target(
        role_name=LEADER_ROLE,
        member_name="member-lead",
        matrix_user_id="@devflow-lead:matrix.example",
        pod_name="pod-devflow-lead",
    )
    backend = KubernetesBackend()
    capture = CaptureRunner()
    backend.runner = capture  # type: ignore[assignment]

    assert backend._exec(  # noqa: SLF001 - intentional transport-boundary test
        target,
        helper,
        [target.role_name, target.workspace],
        input_data=payload,
        timeout_seconds=HOST_CONTROL_TIMEOUT_SECONDS,
    ) == "{}"

    encoded = [item.encode("utf-8") for item in capture.arguments]
    assert max(map(len, encoded)) <= MAX_KUBECTL_ARGUMENT_BYTES
    assert sum(len(item) + 1 for item in encoded) <= MAX_KUBECTL_ARGV_BYTES
    assert helper not in capture.arguments
    assert ROOM_ID not in "\n".join(capture.arguments)
    assert capability not in "\n".join(capture.arguments)
    source_size = int.from_bytes(capture.input_data[:4], "big")
    input_size = int.from_bytes(capture.input_data[4:8], "big")
    assert capture.input_data[8 : 8 + source_size] == helper.encode("utf-8")
    assert capture.input_data[8 + source_size :] == payload
    assert input_size == len(payload)


def _backend_with_locator_response(
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, Any],
) -> KubernetesBackend:
    backend = KubernetesBackend()
    backend._locator = Target(  # noqa: SLF001 - transport-boundary fixture
        role_name=LOCATOR_ROLE,
        member_name="member-locator",
        matrix_user_id=MATRIX_USER_ID,
        pod_name="pod-devflow-locator",
    )
    monkeypatch.setattr(
        backend,
        "_exec",
        lambda *_args, **_kwargs: _canonical_text(response),
    )
    return backend


def test_locator_failure_stage_map_is_closed_and_public_safe() -> None:
    assert REMOTE_LOCATOR_FAILURE_STAGE_MAP == {
        "bootstrap": "locator-bootstrap",
        "attest-skill": "locator-attest-skill",
        "ack-task": "locator-ack-task",
        "authorize": "locator-authorize",
        "github-mcp": "locator-github-mcp",
        "parse-receipt": "locator-parse-receipt",
        "verify-receipt": "locator-verify-receipt",
        "verify-scope": "locator-verify-scope",
        "validate-evidence": "locator-validate-evidence",
        "write-sanitized": "locator-write-sanitized",
        "submit": "locator-submit",
    }
    _assert_public_safe(list(REMOTE_LOCATOR_FAILURE_STAGE_MAP.values()))


@pytest.mark.parametrize(
    ("remote_stage", "safe_stage"),
    tuple(REMOTE_LOCATOR_FAILURE_STAGE_MAP.items()),
)
def test_locator_failure_maps_only_allowlisted_remote_stages(
    monkeypatch: pytest.MonkeyPatch,
    remote_stage: str,
    safe_stage: str,
) -> None:
    backend = _backend_with_locator_response(
        monkeypatch,
        {
            "ok": False,
            "code": "locator_execution_failed",
            "stage": remote_stage,
        },
    )

    with pytest.raises(DriverError) as raised:
        backend.locator_execute(PROJECT_ID, TASK_ID)
    assert raised.value.code == "locator_execution_failed"
    assert raised.value.stage == safe_stage


@pytest.mark.parametrize(
    "response",
    [
        {"ok": False, "code": "locator_execution_failed"},
        {
            "ok": False,
            "code": "locator_execution_failed",
            "stage": "ack-task",
            "unexpected": True,
        },
        {"ok": 0, "code": "locator_execution_failed", "stage": "ack-task"},
        {"ok": False, "code": "other", "stage": "ack-task"},
        {"ok": False, "code": "locator_execution_failed", "stage": 7},
        {
            "ok": False,
            "code": "locator_execution_failed",
            "stage": "attacker-controlled-sensitive-sentinel",
        },
    ],
)
def test_locator_failure_rejects_malformed_or_unknown_diagnostics_without_echo(
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, Any],
) -> None:
    backend = _backend_with_locator_response(monkeypatch, response)

    with pytest.raises(DriverError) as raised:
        backend.locator_execute(PROJECT_ID, TASK_ID)
    assert raised.value.code == "remote_summary_invalid"
    assert raised.value.stage == "locator-evidence"
    assert "attacker-controlled-sensitive-sentinel" not in str(raised.value)


def test_remote_frame_rejects_unbounded_source_and_input() -> None:
    with pytest.raises(DriverError) as source_error:
        _remote_frame("x" * 400_001, b"")
    with pytest.raises(DriverError) as input_error:
        _remote_frame("pass", b"x" * 250_001)
    assert source_error.value.code == "remote_source_invalid"
    assert input_error.value.code == "remote_input_invalid"


def test_short_bootstrap_executes_framed_source_and_rebinds_stdin() -> None:
    helper = "import sys\nprint(sys.stdin.read())\n"
    payload = b"framed-arguments"
    completed = subprocess.run(
        [sys.executable, "-c", REMOTE_STDIN_BOOTSTRAP],
        input=_remote_frame(helper, payload),
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout.decode("utf-8").strip() == payload.decode("utf-8")
    assert completed.stderr == b""

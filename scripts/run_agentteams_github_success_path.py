#!/usr/bin/env python3
"""Run one fail-closed AgentTeams GitHub evidence success path.

The default mode is a read-free plan: it does not contact Kubernetes. Execution
requires an explicit, fixed confirmation phrase and a fresh project identifier.
Sensitive TeamHarness responses are captured, validated, and never printed.
The GitHub capability and repository bytes never leave the Locator process.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import http.client
import inspect
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import types
import urllib.parse
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

try:
    from scripts.reconcile_teamharness_openclaw import (
        CONTAINER_NAME,
        NAMESPACE,
        TEAM_NAME,
        ReconcileError,
        Target,
        discover_targets,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from reconcile_teamharness_openclaw import (  # type: ignore[no-redef]
        CONTAINER_NAME,
        NAMESPACE,
        TEAM_NAME,
        ReconcileError,
        Target,
        discover_targets,
    )

CONFIRMATION = "EXECUTE_FRESH_T2_GITHUB_EVIDENCE"
LEADER_ROLE = "devflow-lead"
LOCATOR_ROLE = "devflow-locator"
TEAMHARNESS_SERVER = "teamharness"
GITHUB_SERVER = "devflow-github-readonly"
GITHUB_TOOL = f"{GITHUB_SERVER}.get_file_contents"
OWNER = "YZYY95K"
REPOSITORY = "test"
REVISION = "cc6a79d6b633be640a78eadf081469d0038f2dd5"
EVIDENCE_PATH = "README.md"
RISK_TIER = "T2"
ISSUE_ID = 1
PROJECT_PREFIX = "devflow-live-github-"
TASK_SUFFIX = "-evidence"
SUBMIT_SUMMARY = "Validated bounded GitHubEvidence; sanitized deliverables are ready."
EXPECTED_AUTHORIZER_SHA256 = (
    "2ff118f3edbbcfb86db8f092d629d36c6d79e89d28363ba8683262b718cd481d"
)
EXPECTED_VALIDATOR_SHA256 = (
    "668e5bb30e25aab809cf42e49247d5326f26856a7ce5bd4fdadc91a917e59ce4"
)
EXPECTED_CONTRACT_READER_SHA256 = (
    "f4624c2bed5367390897f8a2c14f12736daba0e148795d20bb20ad23ed8eb08f"
)
EXPECTED_CONTRACT_SHA256 = (
    "3446d6183a315f260900bbdb5ea77f8fb4aabb13be3a328cf8e41e94c4e4230c"
)
MCPORTER_PATH = "/usr/bin/mcporter"
EXPECTED_MCPORTER_SHA256 = (
    "ec13274c40bc0c71e73e994cf773b9d3801ce909d38f4b133f11450c9e0c458b"
)
EXPECTED_MCPORTER_VERSION = "0.9.0"
EXPECTED_MCPORTER_SIZE = 8_254
EXPECTED_MCPORTER_UID = 0
EXPECTED_MCPORTER_GID = 0
EXPECTED_MCPORTER_MODE = 0o755
EXPECTED_MCPORTER_NLINK = 1
TEAMHARNESS_COMMAND = "/usr/bin/python3"
TEAMHARNESS_ARGUMENTS = ["/opt/devflow/teamharness/guarded_server.py"]
TEAMHARNESS_SHARED_DIR = "/root/hiclaw-fs/shared"
GITHUB_MCP_URL = (
    "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
    "mcp-servers/devflow-github-readonly/mcp"
)
MCP_PROTOCOL_VERSION = "2025-03-26"
MCP_SCHEMA_CANONICALIZATION_ID = (
    "mcporter-v0.9.0-terminal-latency-zeroed"
)
MAX_REMOTE_SCHEMA_BYTES = 1_000_000

EXPECTED_MCP_SCHEMA_CANONICAL_SHA256: dict[str, dict[str, str]] = {
    LEADER_ROLE: {
        TEAMHARNESS_SERVER: (
            "985fbb53710bc62f34e0194783a68852e4a7400bea794b6600023f96bf730eea"
        )
    },
    LOCATOR_ROLE: {
        GITHUB_SERVER: (
            "2588f5c5d201588468e86c93899f22ff913b98c7c6784173b23640b1718ab887"
        ),
        TEAMHARNESS_SERVER: (
            "a4243ba99239622210efd749ac06e30d3d7d1673c4cbf07db80720ed5859b69a"
        ),
    },
}
EXPECTED_MCP_SCHEMA_CANONICAL_BYTES: dict[str, dict[str, int]] = {
    LEADER_ROLE: {TEAMHARNESS_SERVER: 28_909},
    LOCATOR_ROLE: {
        GITHUB_SERVER: 1_742,
        TEAMHARNESS_SERVER: 4_203,
    },
}

SAFE_PROJECT = re.compile(r"^devflow-live-github-[a-z0-9](?:[a-z0-9-]{0,26}[a-z0-9])?$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
OBJECT_SHA = re.compile(r"^[0-9a-f]{40}$")
MATRIX_USER = re.compile(r"^@([a-z0-9](?:[-a-z0-9.]*[a-z0-9])?):([^:\s]+)$")
MATRIX_ROOM = re.compile(r"![^\s:]{1,255}:[^\s]{1,255}")
CAPABILITY = re.compile(r"[A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43}")
SECRET = re.compile(
    r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[^\s]+)",
    re.IGNORECASE,
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
MAX_KUBECTL_ARGUMENT_BYTES = 4_096
MAX_KUBECTL_ARGV_BYTES = 16_384
MAX_REMOTE_SOURCE_BYTES = 400_000
MAX_REMOTE_INPUT_BYTES = 250_000
MAX_REMOTE_CONFIG_BYTES = 65_536
MAX_REMOTE_MCP_STDOUT_BYTES = 3_200_000
MAX_REMOTE_HTTP_RESPONSE_BYTES = 3_200_000
REMOTE_MCP_CALL_TIMEOUT_SECONDS = 120
REMOTE_MCP_HTTP_STEP_TIMEOUT_SECONDS = 35
REMOTE_LOCATOR_CALL_COUNT = 5
REMOTE_LOCATOR_DEADLINE_SECONDS = (
    REMOTE_MCP_CALL_TIMEOUT_SECONDS * REMOTE_LOCATOR_CALL_COUNT + 30
)
REMOTE_CONTROL_DEADLINE_SECONDS = REMOTE_MCP_CALL_TIMEOUT_SECONDS + 15
REMOTE_PREFLIGHT_COMMAND_TIMEOUT_SECONDS = 30
REMOTE_PREFLIGHT_COMMAND_COUNT = 3
REMOTE_PREFLIGHT_DEADLINE_SECONDS = (
    REMOTE_PREFLIGHT_COMMAND_TIMEOUT_SECONDS * REMOTE_PREFLIGHT_COMMAND_COUNT + 15
)
HOST_CLEANUP_MARGIN_SECONDS = 45
HOST_LOCATOR_TIMEOUT_SECONDS = (
    REMOTE_LOCATOR_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
)
HOST_CONTROL_TIMEOUT_SECONDS = (
    REMOTE_CONTROL_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
)
HOST_PREFLIGHT_TIMEOUT_SECONDS = (
    REMOTE_PREFLIGHT_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
)
REMOTE_LOCATOR_FAILURE_STAGE_MAP: dict[str, str] = {
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

if (
    HOST_LOCATOR_TIMEOUT_SECONDS
    < REMOTE_LOCATOR_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
    or HOST_CONTROL_TIMEOUT_SECONDS
    < REMOTE_CONTROL_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
    or HOST_PREFLIGHT_TIMEOUT_SECONDS
    < REMOTE_PREFLIGHT_DEADLINE_SECONDS + HOST_CLEANUP_MARGIN_SECONDS
):
    raise RuntimeError("remote deadline must leave a host-side cleanup margin")
BANNED_PUBLIC_KEYS = frozenset(
    {
        "authorization",
        "capability",
        "content",
        "content_base64",
        "raw",
        "roomId",
        "room_id",
        "spec",
    }
)
PLAN_STAGES = (
    "attest-ready-runtimes-and-mcporter",
    "prove-project-and-task-are-fresh",
    "create-t2-project",
    "plan-one-node-dag",
    "create-private-task-room",
    "delegate-canonical-github-request",
    "locator-ack-and-parse-handoff",
    "authorize-exact-read",
    "call-readonly-github-mcp",
    "verify-receipt-content-and-scope-in-memory",
    "validate-full-github-evidence-in-memory",
    "write-sanitized-deliverables",
    "submit-success-and-prove-idempotency-conflict",
    "leader-check-accept-complete-and-report",
    "push-project-state",
    "verify-completed-and-report-not-pending",
)
LOCATOR_SUMMARY_FIELDS = frozenset(
    {
        "ok",
        "taskId",
        "artifactSha256",
        "authorizerScopeSha256",
        "brokerScopeSha256",
        "capabilitySha256",
        "contentSha256",
        "envelopeSha256",
        "objectSha",
        "responseSha256",
        "idempotencyKeySha256",
        "submissionSha256",
        "conflictRequestedSha256",
        "deliverables",
        "validatorPassed",
        "firstSubmit",
        "idempotentRetry",
        "conflictRetry",
    }
)


class DriverError(RuntimeError):
    """A stable, non-sensitive success-path failure."""

    def __init__(self, code: str, stage: str) -> None:
        super().__init__(f"{stage}:{code}")
        self.code = code
        self.stage = stage


class _RemoteError(RuntimeError):
    """A remote helper failure whose message is only a stable stage label."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("non-standard JSON scalar")


def _strict_loads(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=_reject_constant,
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_text(value: Any) -> str:
    return _canonical_bytes(value).decode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonicalize_mcporter_schema(raw: bytes) -> bytes:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_REMOTE_SCHEMA_BYTES:
        raise ValueError("schema output bounds are invalid")
    try:
        raw.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("schema output is not UTF-8") from exc
    summary_candidates = list(
        re.finditer(
            rb"(?m)^  (?:0|[1-9][0-9]*) tools? [^\r\n]*\r?$",
            raw,
        )
    )
    terminal = re.search(
        rb"(?m)^  (?:0|[1-9][0-9]*) tools? \xc2\xb7 "
        rb"(?P<latency>0|[1-9][0-9]*)ms \xc2\xb7 "
        rb"[A-Z][A-Z0-9_-]{0,31}(?: [^\r\n]+)?\n\n\Z",
        raw,
    )
    if len(summary_candidates) != 1 or terminal is None:
        raise ValueError("schema terminal summary is invalid")
    terminal_line = terminal.group(0).rstrip(b"\r\n")
    latency_tokens = re.findall(
        rb"(?<![A-Za-z0-9])(?:0|[1-9][0-9]*)ms(?![A-Za-z0-9])",
        terminal_line,
    )
    if len(latency_tokens) != 1:
        raise ValueError("schema terminal latency is ambiguous")
    latency_start, latency_end = terminal.span("latency")
    return raw[:latency_start] + b"0" + raw[latency_end:]


def _normalized_mcporter_config(role: str) -> dict[str, Any]:
    servers: dict[str, Any] = {
        TEAMHARNESS_SERVER: {
            "command": TEAMHARNESS_COMMAND,
            "args": TEAMHARNESS_ARGUMENTS,
            "transport": "stdio",
            "env": {"TEAMHARNESS_SHARED_DIR": TEAMHARNESS_SHARED_DIR},
        }
    }
    if role == LOCATOR_ROLE:
        servers[GITHUB_SERVER] = {
            "url": GITHUB_MCP_URL,
            "transport": "http",
            "headers": {"Authorization": "Bearer <redacted>"},
        }
    if role not in {LEADER_ROLE, LOCATOR_ROLE}:
        raise DriverError("role_invalid", "runtime-preflight")
    return {"mcpServers": servers}


def _assert_public_safe(value: Any) -> None:
    """Reject secrets, capabilities, room identifiers, and raw-data fields."""

    if isinstance(value, dict):
        if any(key in BANNED_PUBLIC_KEYS for key in value):
            raise DriverError("unsafe_public_field", "public-output")
        for child in value.values():
            _assert_public_safe(child)
        return
    if isinstance(value, list | tuple):
        for child in value:
            _assert_public_safe(child)
        return
    if isinstance(value, str) and (
        SECRET.search(value) is not None
        or CAPABILITY.search(value) is not None
        or MATRIX_ROOM.search(value) is not None
    ):
        raise DriverError("unsafe_public_value", "public-output")


def plan_report() -> dict[str, Any]:
    """Return the deterministic no-contact plan."""

    report = {
        "ok": True,
        "mode": "plan",
        "executionMode": "operator-driven",
        "writes": False,
        "riskTier": RISK_TIER,
        "fixedScope": {
            "repository": f"{OWNER}/{REPOSITORY}",
            "revision": REVISION,
            "paths": [EVIDENCE_PATH],
        },
        "executeRequires": {
            "projectIdPrefix": PROJECT_PREFIX,
            "confirmation": CONFIRMATION,
        },
        "stages": list(PLAN_STAGES),
        "sensitiveDataPolicy": (
            "capability, room identifier, repository bytes, and raw MCP responses are never public"
        ),
    }
    _assert_public_safe(report)
    return report


@dataclass(frozen=True)
class RuntimeContext:
    leader_matrix_user_id: str
    locator_matrix_user_id: str


class Backend(Protocol):
    def preflight(self) -> RuntimeContext: ...

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]: ...

    def locator_execute(self, run_id: str, task_id: str) -> dict[str, Any]: ...


def _validate_project_id(project_id: str) -> tuple[str, str]:
    if (
        not isinstance(project_id, str)
        or len(project_id) > 48
        or SAFE_PROJECT.fullmatch(project_id) is None
    ):
        raise DriverError("project_id_invalid", "input")
    task_id = project_id + TASK_SUFFIX
    trace_id = f"{project_id}:{task_id}"
    if SAFE_ID.fullmatch(task_id) is None or len(trace_id) > 128:
        raise DriverError("derived_id_invalid", "input")
    return task_id, trace_id


def _expect_identity(
    response: Any,
    *,
    tool: str,
    action: str,
    stage: str,
) -> dict[str, Any]:
    if (
        not isinstance(response, dict)
        or response.get("tool") != tool
        or response.get("action") != action
    ):
        raise DriverError("response_identity_invalid", stage)
    return response


def _expect_ok(
    response: Any,
    *,
    tool: str,
    action: str,
    stage: str,
) -> dict[str, Any]:
    checked = _expect_identity(response, tool=tool, action=action, stage=stage)
    if checked.get("ok") is not True:
        raise DriverError("remote_action_failed", stage)
    return checked


def _expect_filesync_attestation(
    response: Any,
    *,
    action: str,
    path: str,
    require_exists: bool,
    expected_objects: int | None,
    stage: str,
) -> int:
    checked = _expect_ok(
        response,
        tool="filesync",
        action=action,
        stage=stage,
    )
    expected_fields = {
        "ok",
        "tool",
        "action",
        "kind",
        "path",
        "localPath",
        "workspaceBindingSha256",
    }
    if require_exists:
        expected_fields.add("exists")
    if expected_objects is not None:
        expected_fields.update(
            {
                "expectedObjectCount",
                "verifiedObjectCount",
                "localTreeSha256",
            }
        )
    leader_workspace = f"/root/hiclaw-fs/agents/{LEADER_ROLE}"
    expected_local_path = f"{leader_workspace}/{path.rstrip('/')}"
    expected_count = checked.get("expectedObjectCount")
    verified_count = checked.get("verifiedObjectCount")
    local_tree_digest = checked.get("localTreeSha256")
    if (
        set(checked) != expected_fields
        or checked.get("kind") != "shared"
        or checked.get("path") != path
        or checked.get("localPath") != expected_local_path
        or checked.get("workspaceBindingSha256")
        != _sha256(leader_workspace.encode("utf-8"))
        or (require_exists and checked.get("exists") is not True)
        or (
            expected_objects is not None
            and (
                isinstance(expected_count, bool)
                or not isinstance(expected_count, int)
                or expected_count != expected_objects
                or isinstance(verified_count, bool)
                or not isinstance(verified_count, int)
                or verified_count != expected_objects
                or not isinstance(local_tree_digest, str)
                or DIGEST.fullmatch(local_tree_digest) is None
            )
        )
    ):
        raise DriverError("filesync_attestation_invalid", stage)
    return expected_objects if expected_objects is not None else int(require_exists)


def _expect_absent(
    response: Any,
    *,
    tool: str,
    action: str,
    error: str,
    stage: str,
) -> None:
    checked = _expect_identity(response, tool=tool, action=action, stage=stage)
    if checked.get("ok") is not False or checked.get("error") != error:
        raise DriverError("freshness_not_proven", stage)


def _one_project_task(project: Any, task_id: str, expected_status: str, stage: str) -> None:
    if not isinstance(project, dict):
        raise DriverError("project_state_invalid", stage)
    tasks = project.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 1:
        raise DriverError("project_plan_invalid", stage)
    task = tasks[0]
    if (
        not isinstance(task, dict)
        or task.get("task_id") != task_id
        or task.get("assigned_to") != LOCATOR_ROLE
        or task.get("depends_on") != []
        or task.get("status") != expected_status
    ):
        raise DriverError("project_task_invalid", stage)


def _expected_project_binding(project_id: str) -> dict[str, Any]:
    digest = _sha256(
        _canonical_bytes(
            {
                "projectId": project_id,
                "riskTier": RISK_TIER,
                "source": "operator-driven",
            }
        )
    )
    return {
        "schema": "devflow.project-binding/v1",
        "riskTierAuthority": "root-only-approval-ledger",
        "sourceAuthority": "persistent-project-state",
        "digest": digest,
    }


def _expect_project_binding(project: Any, project_id: str, stage: str) -> dict[str, Any]:
    if (
        not isinstance(project, dict)
        or project.get("project_id") != project_id
        or project.get("risk_tier") != RISK_TIER
        or project.get("source") != "operator-driven"
        or project.get("binding") != _expected_project_binding(project_id)
    ):
        raise DriverError("project_binding_invalid", stage)
    return project


def _expected_broker_scope(task_id: str) -> str:
    scope = {
        "task_id": task_id,
        "owner": OWNER,
        "repo": REPOSITORY,
        "revision": REVISION,
        "paths": [EVIDENCE_PATH],
    }
    return _sha256(_canonical_bytes(scope))


def _submission_digest(
    task_id: str,
    deliverables: list[str],
    *,
    summary: str = SUBMIT_SUMMARY,
) -> str:
    return _sha256(
        _canonical_bytes(
            {
                "taskId": task_id,
                "status": "SUCCESS",
                "summary": summary,
                "deliverables": deliverables,
            }
        )
    )


def _validate_locator_summary(value: Any, task_id: str) -> dict[str, Any]:
    stage = "locator-evidence"
    if not isinstance(value, dict) or set(value) != LOCATOR_SUMMARY_FIELDS:
        raise DriverError("locator_summary_invalid", stage)
    if value.get("ok") is not True or value.get("taskId") != task_id:
        raise DriverError("locator_summary_invalid", stage)
    for name in (
        "artifactSha256",
        "authorizerScopeSha256",
        "brokerScopeSha256",
        "capabilitySha256",
        "contentSha256",
        "conflictRequestedSha256",
        "envelopeSha256",
        "idempotencyKeySha256",
        "responseSha256",
        "submissionSha256",
    ):
        item = value.get(name)
        if not isinstance(item, str) or DIGEST.fullmatch(item) is None:
            raise DriverError("locator_digest_invalid", stage)
    if value.get("brokerScopeSha256") != _expected_broker_scope(task_id):
        raise DriverError("locator_scope_mismatch", stage)
    object_sha = value.get("objectSha")
    if not isinstance(object_sha, str) or OBJECT_SHA.fullmatch(object_sha) is None:
        raise DriverError("locator_object_invalid", stage)
    deliverables = [
        f"shared/tasks/{task_id}/result.md",
        f"shared/tasks/{task_id}/GitHubEvidence/result.md",
    ]
    if value.get("deliverables") != deliverables:
        raise DriverError("locator_deliverables_invalid", stage)
    expected_idempotency_key = (
        f"{task_id.removesuffix(TASK_SUFFIX)}:{task_id}:{LOCATOR_ROLE}:github-evidence"
    )
    if value.get("idempotencyKeySha256") != _sha256(
        expected_idempotency_key.encode("utf-8")
    ):
        raise DriverError("locator_idempotency_binding_invalid", stage)
    if value.get("submissionSha256") != _submission_digest(task_id, deliverables):
        raise DriverError("locator_submission_binding_invalid", stage)
    if value.get("conflictRequestedSha256") != _submission_digest(
        task_id,
        deliverables,
        summary=SUBMIT_SUMMARY + " Changed retry.",
    ):
        raise DriverError("locator_conflict_binding_invalid", stage)
    for name in ("validatorPassed", "firstSubmit", "idempotentRetry", "conflictRetry"):
        if value.get(name) is not True:
            raise DriverError("locator_transition_unproven", stage)
    _assert_public_safe(value)
    return value


def execute_success_path(
    backend: Backend,
    *,
    project_id: str,
    confirmation: str,
) -> dict[str, Any]:
    """Execute and verify the complete one-task T2 success path."""

    if confirmation != CONFIRMATION:
        raise DriverError("confirmation_required", "input")
    task_id, trace_id = _validate_project_id(project_id)
    context = backend.preflight()
    leader_match = MATRIX_USER.fullmatch(context.leader_matrix_user_id)
    matrix_match = MATRIX_USER.fullmatch(context.locator_matrix_user_id)
    if (
        leader_match is None
        or leader_match.group(1) != LEADER_ROLE
        or matrix_match is None
        or matrix_match.group(1) != LOCATOR_ROLE
        or context.leader_matrix_user_id == context.locator_matrix_user_id
    ):
        raise DriverError("locator_identity_invalid", "runtime-preflight")

    _expect_absent(
        backend.leader_call(
            "projectflow",
            {"action": "resolve_project", "payload": {"projectId": project_id}},
        ),
        tool="projectflow",
        action="resolve_project",
        error="project not found",
        stage="fresh-project",
    )
    _expect_absent(
        backend.leader_call(
            "taskflow",
            {"action": "check_task", "payload": {"taskId": task_id}},
        ),
        tool="taskflow",
        action="check_task",
        error="task not found",
        stage="fresh-task",
    )

    created = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "create_project",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "title": "One-time bounded GitHub evidence",
                    "source": "operator-driven",
                },
            },
        ),
        tool="projectflow",
        action="create_project",
        stage="create-project",
    )
    project = _expect_project_binding(
        created.get("project"), project_id, "create-project"
    )
    if project.get("status") != "active" or project.get("tasks") != []:
        raise DriverError("created_project_invalid", "create-project")

    planned = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "plan_dag",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "tasks": [
                        {
                            "taskId": task_id,
                            "title": "Collect revision-pinned GitHub evidence",
                            "assignedTo": LOCATOR_ROLE,
                            "dependsOn": [],
                            "status": "planned",
                        }
                    ],
                },
            },
        ),
        tool="projectflow",
        action="plan_dag",
        stage="plan-dag",
    )
    planned_project = _expect_project_binding(
        planned.get("project"), project_id, "plan-dag"
    )
    _one_project_task(planned_project, task_id, "planned", "plan-dag")

    room = _expect_ok(
        backend.leader_call(
            "roomflow",
            {
                "action": "create_task_room",
                "payload": {
                    "projectId": project_id,
                    "source": "operator-driven",
                    "invite": [context.locator_matrix_user_id],
                },
            },
        ),
        tool="roomflow",
        action="create_task_room",
        stage="create-room",
    )
    room_id = room.get("roomId")
    # `invite`/`members` are a guard-defined projection of requested worker
    # invitees, never a claim that they are the complete Matrix membership.
    # Full state is represented only by the verified count and digest below.
    authorized_member_count = room.get("authorizedMemberCount")
    if (
        not isinstance(room_id, str)
        or MATRIX_ROOM.fullmatch(room_id) is None
        or room.get("reused") is not False
        or room.get("private") is not True
        or room.get("joinRule") != "invite"
        or room.get("membershipStateVerified") is not True
        or room.get("membershipProjection")
        != "non-creator-requested-worker-invitees"
        or room.get("creator") != context.leader_matrix_user_id
        or room.get("invite") != [context.locator_matrix_user_id]
        or room.get("members") != [context.locator_matrix_user_id]
        or isinstance(authorized_member_count, bool)
        or not isinstance(authorized_member_count, int)
        or authorized_member_count not in {2, 3}
        or not isinstance(room.get("authorizedMembersSha256"), str)
        or DIGEST.fullmatch(room["authorizedMembersSha256"]) is None
        or room.get("binding") != _expected_project_binding(project_id)
    ):
        raise DriverError("fresh_room_invalid", "create-room")

    request = {
        "schema": "devflow.github-assignment-request/v1",
        "run_id": project_id,
        "issue_id": ISSUE_ID,
        "task_id": task_id,
        "trace_id": trace_id,
        "idempotency_key": (
            f"{project_id}:{task_id}:{LOCATOR_ROLE}:github-evidence"
        ),
        "repository": {"owner": OWNER, "repo": REPOSITORY},
        "revision": REVISION,
        "paths": [EVIDENCE_PATH],
    }
    delegated = _expect_ok(
        backend.leader_call(
            "taskflow",
            {
                "action": "delegate_task",
                "payload": {
                    "projectId": project_id,
                    "taskId": task_id,
                    "assignedTo": LOCATOR_ROLE,
                    "roomId": room_id,
                    "spec": _canonical_text(request),
                },
            },
        ),
        tool="taskflow",
        action="delegate_task",
        stage="delegate-task",
    )
    delegated_task = delegated.get("task")
    if (
        not isinstance(delegated_task, dict)
        or delegated_task.get("task_id") != task_id
        or delegated_task.get("project_id") != project_id
        or delegated_task.get("assigned_to") != LOCATOR_ROLE
        or delegated_task.get("status") != "assigned"
        or delegated_task.get("room_id") != room_id
        or delegated.get("synced") is not True
    ):
        raise DriverError("delegation_invalid", "delegate-task")
    del room_id, room, delegated, delegated_task

    locator = _validate_locator_summary(
        backend.locator_execute(project_id, task_id),
        task_id,
    )
    deliverables = list(locator["deliverables"])

    checked = _expect_ok(
        backend.leader_call(
            "taskflow",
            {"action": "check_task", "payload": {"taskId": task_id}},
        ),
        tool="taskflow",
        action="check_task",
        stage="leader-check",
    )
    checked_task = checked.get("task")
    expected_result = {
        "status": "SUCCESS",
        "summary": SUBMIT_SUMMARY,
        "deliverables": deliverables,
    }
    checked_result = checked.get("result")
    if (
        not isinstance(checked_result, dict)
        or set(checked_result) != {"status", "summary", "deliverables"}
        or not isinstance(checked_result.get("deliverables"), list)
        or locator["submissionSha256"]
        != _sha256(
            _canonical_bytes(
                {
                    "taskId": task_id,
                    "status": checked_result.get("status"),
                    "summary": checked_result.get("summary"),
                    "deliverables": checked_result.get("deliverables"),
                }
            )
        )
    ):
        raise DriverError("post_conflict_readback_mismatch", "leader-check")
    if (
        checked.get("effective") is not True
        or checked.get("validationErrors") != []
        or checked.get("result") != expected_result
        or checked.get("pulled") is not True
        or not isinstance(checked_task, dict)
        or checked_task.get("task_id") != task_id
        or checked_task.get("assigned_to") != LOCATOR_ROLE
        or checked_task.get("status") != "submitted"
        or checked_task.get("result_status") != "SUCCESS"
        or checked_task.get("summary") != SUBMIT_SUMMARY
        or checked_task.get("deliverables") != deliverables
        or checked_task.get("result_path") != f"shared/tasks/{task_id}/result.md"
    ):
        raise DriverError("checked_result_invalid", "leader-check")

    accepted = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "accept_task_result",
                "riskTier": RISK_TIER,
                "payload": {
                    "projectId": project_id,
                    "taskId": task_id,
                    "resultStatus": "SUCCESS",
                    "accepted": True,
                    "summary": "Validated sanitized GitHubEvidence accepted.",
                },
            },
        ),
        tool="projectflow",
        action="accept_task_result",
        stage="accept-result",
    )
    if accepted.get("accepted") is not True or accepted.get("nodeStatus") != "completed":
        raise DriverError("acceptance_invalid", "accept-result")
    accepted_project = accepted.get("project")
    _expect_project_binding(accepted_project, project_id, "accept-result")
    _one_project_task(accepted_project, task_id, "completed", "accept-result")
    if (
        not isinstance(accepted_project, dict)
        or not isinstance(accepted_project.get("requester_report"), dict)
        or accepted_project["requester_report"].get("pending") is not True
        or accepted_project["requester_report"].get("task_id") != task_id
    ):
        raise DriverError("requester_report_not_pending", "accept-result")

    completed = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "complete_project",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id, "publishArtifacts": False},
            },
        ),
        tool="projectflow",
        action="complete_project",
        stage="complete-project",
    )
    completed_project = completed.get("project")
    _expect_project_binding(completed_project, project_id, "complete-project")
    _one_project_task(completed_project, task_id, "completed", "complete-project")
    if not isinstance(completed_project, dict) or completed_project.get("status") != "completed":
        raise DriverError("completion_invalid", "complete-project")

    reported = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "mark_requester_report_sent",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id},
            },
        ),
        tool="projectflow",
        action="mark_requester_report_sent",
        stage="mark-report-sent",
    )
    reported_project = _expect_project_binding(
        reported.get("project"), project_id, "mark-report-sent"
    )
    if (
        not isinstance(reported_project.get("requester_report"), dict)
        or reported_project["requester_report"].get("pending") is not False
    ):
        raise DriverError("requester_report_pending", "mark-report-sent")

    project_path = f"shared/projects/{project_id}/"
    pushed_object_count = _expect_filesync_attestation(
        backend.leader_call(
            "filesync",
            {"action": "push", "path": project_path},
        ),
        action="push",
        path=project_path,
        require_exists=False,
        expected_objects=2,
        stage="filesync-push",
    )
    verified_filesync_objects = 0
    for filename in ("meta.json", "plan.md"):
        object_path = f"{project_path}{filename}"
        verified_filesync_objects += _expect_filesync_attestation(
            backend.leader_call(
                "filesync",
                {"action": "stat", "path": object_path},
            ),
            action="stat",
            path=object_path,
            require_exists=True,
            expected_objects=None,
            stage="filesync-readback",
        )
    if verified_filesync_objects != pushed_object_count:
        raise DriverError("filesync_readback_count_invalid", "filesync-readback")

    resolved = _expect_ok(
        backend.leader_call(
            "projectflow",
            {
                "action": "resolve_project",
                "riskTier": RISK_TIER,
                "payload": {"projectId": project_id},
            },
        ),
        tool="projectflow",
        action="resolve_project",
        stage="final-verification",
    )
    final_project = resolved.get("project")
    _expect_project_binding(final_project, project_id, "final-verification")
    _one_project_task(final_project, task_id, "completed", "final-verification")
    if (
        not isinstance(final_project, dict)
        or final_project.get("status") != "completed"
        or not isinstance(final_project.get("requester_report"), dict)
        or final_project["requester_report"].get("pending") is not False
        or not isinstance(final_project["requester_report"].get("sent_at"), str)
    ):
        raise DriverError("final_state_invalid", "final-verification")

    result = {
        "ok": True,
        "mode": "execute",
        "executionMode": "operator-driven",
        "projectId": project_id,
        "taskId": task_id,
        "riskTier": RISK_TIER,
        "projectStatus": "completed",
        "requesterReportPending": False,
        "filesyncPushed": True,
        "filesyncVerifiedObjects": verified_filesync_objects,
        "evidence": {
            name: locator[name]
            for name in (
                "artifactSha256",
                "authorizerScopeSha256",
                "brokerScopeSha256",
                "capabilitySha256",
                "contentSha256",
                "conflictRequestedSha256",
                "envelopeSha256",
                "idempotencyKeySha256",
                "objectSha",
                "responseSha256",
                "submissionSha256",
            )
        },
        "proofs": {
            "validatorPassed": True,
            "firstSubmit": True,
            "idempotentRetry": True,
            "conflictRetry": True,
            "postConflictReadbackBound": True,
            "leaderCheckEffective": True,
        },
    }
    _assert_public_safe(result)
    return result


def _remote_walk(value: Any) -> list[Any]:
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(_remote_walk(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(_remote_walk(child))
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        with suppress(TypeError, ValueError, json.JSONDecodeError):
            values.extend(_remote_walk(_strict_loads(value)))
    return values


@contextmanager
def _remote_hard_deadline(seconds: int) -> Any:
    sigalrm = getattr(signal, "SIGALRM", None)
    itimer_real = getattr(signal, "ITIMER_REAL", None)
    getitimer = getattr(signal, "getitimer", None)
    setitimer = getattr(signal, "setitimer", None)
    if (
        not isinstance(seconds, int)
        or seconds < 1
        or sigalrm is None
        or itimer_real is None
        or not callable(getitimer)
        or not callable(setitimer)
        or threading.current_thread() is not threading.main_thread()
    ):
        raise _RemoteError("deadline")
    def _expired(_signum: int, _frame: Any) -> None:
        raise _RemoteError("deadline")

    previous_handler = signal.getsignal(sigalrm)
    previous_timer = getitimer(itimer_real)
    started = time.monotonic()
    signal.signal(sigalrm, _expired)
    setitimer(itimer_real, float(seconds))
    try:
        yield
    finally:
        setitimer(itimer_real, 0.0)
        signal.signal(sigalrm, previous_handler)
        if previous_timer[0] > 0:
            elapsed = time.monotonic() - started
            setitimer(
                itimer_real,
                max(0.000_001, previous_timer[0] - elapsed),
                previous_timer[1],
            )


def _remote_kill_process(process: Any) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        killpg = getattr(os, "killpg", None)
        sigkill = getattr(signal, "SIGKILL", None)
        with suppress(OSError):
            if callable(killpg) and sigkill is not None:
                killpg(process.pid, sigkill)
    with suppress(OSError):
        process.kill()
    with suppress(OSError, subprocess.SubprocessError):
        process.wait(timeout=5)


def _remote_run_bounded_process(
    arguments: list[str],
    *,
    cwd: str,
    input_data: bytes,
    timeout_seconds: int,
    max_stdout_bytes: int,
    environment: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    if (
        not arguments
        or any(not isinstance(item, str) or not item for item in arguments)
        or not isinstance(input_data, bytes)
        or timeout_seconds < 1
        or max_stdout_bytes < 1
    ):
        raise _RemoteError("subprocess-input")
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed, attested executable
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise _RemoteError("subprocess-start") from exc
    chunks: list[bytes] = []
    state = {"size": 0, "overflow": False, "failed": False}

    def _read_stdout() -> None:
        try:
            if process.stdout is None:
                state["failed"] = True
                return
            while True:
                chunk = process.stdout.read(65_536)
                if not chunk:
                    return
                state["size"] += len(chunk)
                if state["size"] <= max_stdout_bytes:
                    chunks.append(chunk)
                else:
                    state["overflow"] = True
        except (OSError, ValueError):
            state["failed"] = True

    def _write_stdin() -> None:
        try:
            if process.stdin is None:
                state["failed"] = True
                return
            process.stdin.write(input_data)
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            state["failed"] = True

    reader = threading.Thread(target=_read_stdout, daemon=True)
    writer = threading.Thread(target=_write_stdin, daemon=True)
    reader.start()
    writer.start()
    timed_out: subprocess.TimeoutExpired | None = None
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        timed_out = exc
        _remote_kill_process(process)
    finally:
        if process.poll() is None:
            _remote_kill_process(process)
    reader.join(timeout=5)
    writer.join(timeout=5)
    if timed_out is not None:
        if reader.is_alive() or writer.is_alive():
            raise _RemoteError("subprocess-cleanup") from timed_out
        raise _RemoteError("subprocess-timeout") from timed_out
    if reader.is_alive() or writer.is_alive() or state["failed"] or state["overflow"]:
        _remote_kill_process(process)
        raise _RemoteError("subprocess-output")
    return int(process.returncode), b"".join(chunks)


def _remote_read_locator_config(workspace: str) -> tuple[str, str]:
    path = Path(workspace) / "config" / "mcporter.json"
    descriptor = -1
    try:
        geteuid = getattr(os, "geteuid", None)
        if not callable(geteuid):
            raise _RemoteError("mcp-config")
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise _RemoteError("mcp-config")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 1 <= metadata.st_size <= MAX_REMOTE_CONFIG_BYTES
        ):
            raise _RemoteError("mcp-config")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise _RemoteError("mcp-config")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _RemoteError("mcp-config")
        raw = b"".join(chunks)
    except OSError as exc:
        raise _RemoteError("mcp-config") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        config = _strict_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise _RemoteError("mcp-config") from exc
    if not isinstance(config, dict) or set(config) != {"mcpServers"}:
        raise _RemoteError("mcp-config")
    servers = config.get("mcpServers")
    if not isinstance(servers, dict) or set(servers) != {
        GITHUB_SERVER,
        TEAMHARNESS_SERVER,
    }:
        raise _RemoteError("mcp-config")
    teamharness = servers.get(TEAMHARNESS_SERVER)
    github = servers.get(GITHUB_SERVER)
    if teamharness != {
        "command": TEAMHARNESS_COMMAND,
        "args": TEAMHARNESS_ARGUMENTS,
        "transport": "stdio",
        "env": {"TEAMHARNESS_SHARED_DIR": TEAMHARNESS_SHARED_DIR},
    } or not isinstance(github, dict):
        raise _RemoteError("mcp-config")
    authorization = github.get("headers", {}).get("Authorization")
    if (
        set(github) != {"url", "transport", "headers"}
        or github.get("url") != GITHUB_MCP_URL
        or github.get("transport") != "http"
        or not isinstance(github.get("headers"), dict)
        or set(github["headers"]) != {"Authorization"}
        or not isinstance(authorization, str)
        or re.fullmatch(r"Bearer [^\s]+", authorization) is None
        or CONTROL.search(authorization) is not None
    ):
        raise _RemoteError("mcp-config")
    normalized = json.loads(json.dumps(config))
    normalized["mcpServers"][GITHUB_SERVER]["headers"]["Authorization"] = (
        "Bearer <redacted>"
    )
    expected = {
        "mcpServers": {
            GITHUB_SERVER: {
                "url": GITHUB_MCP_URL,
                "transport": "http",
                "headers": {"Authorization": "Bearer <redacted>"},
            },
            TEAMHARNESS_SERVER: {
                "command": TEAMHARNESS_COMMAND,
                "args": TEAMHARNESS_ARGUMENTS,
                "transport": "stdio",
                "env": {"TEAMHARNESS_SHARED_DIR": TEAMHARNESS_SHARED_DIR},
            },
        }
    }
    if normalized != expected:
        raise _RemoteError("mcp-config")
    return GITHUB_MCP_URL, authorization


def _remote_parse_http_mcp(body: bytes, content_type: str, request_id: int) -> dict[str, Any]:
    try:
        if content_type.lower().split(";", 1)[0].strip() == "application/json":
            candidates = [_strict_loads(body.decode("utf-8"))]
        elif content_type.lower().split(";", 1)[0].strip() == "text/event-stream":
            text = body.decode("utf-8")
            candidates = []
            data_lines: list[str] = []
            for line in text.replace("\r\n", "\n").split("\n"):
                if line == "":
                    if data_lines:
                        candidates.append(_strict_loads("\n".join(data_lines)))
                        data_lines = []
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
            if data_lines:
                candidates.append(_strict_loads("\n".join(data_lines)))
        else:
            raise _RemoteError("mcp-http-content-type")
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise _RemoteError("mcp-http-output") from exc
    matches = [
        item
        for item in candidates
        if isinstance(item, dict)
        and item.get("jsonrpc") == "2.0"
        and item.get("id") == request_id
    ]
    if len(matches) != 1 or ("result" in matches[0]) == ("error" in matches[0]):
        raise _RemoteError("mcp-http-output")
    return matches[0]


def _remote_http_request(
    *,
    url: str,
    authorization: str,
    method: str,
    body: bytes,
    session_id: str | None,
    expected_status: tuple[int, ...],
    timeout_seconds: int,
) -> tuple[bytes, str, str | None]:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "higress-gateway.agentteams-system.svc.cluster.local"
        or parsed.port not in {None, 80}
        or parsed.query
        or parsed.fragment
        or parsed.path != "/mcp-servers/devflow-github-readonly/mcp"
    ):
        raise _RemoteError("mcp-http-url")
    headers = {
        "Authorization": authorization,
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        "Connection": "close",
    }
    if session_id is not None:
        headers["Mcp-Session-Id"] = session_id
    connection = http.client.HTTPConnection(
        parsed.hostname,
        parsed.port or 80,
        timeout=timeout_seconds,
    )
    try:
        connection.request(method, parsed.path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status not in expected_status:
            raise _RemoteError("mcp-http-status")
        content = response.read(MAX_REMOTE_HTTP_RESPONSE_BYTES + 1)
        if len(content) > MAX_REMOTE_HTTP_RESPONSE_BYTES:
            raise _RemoteError("mcp-http-output")
        content_types = [
            value
            for name, value in response.getheaders()
            if name.lower() == "content-type"
        ]
        session_headers = [
            value
            for name, value in response.getheaders()
            if name.lower() == "mcp-session-id"
        ]
        if len(content_types) > 1 or len(session_headers) > 1:
            raise _RemoteError("mcp-http-headers")
        returned_session = session_headers[0] if session_headers else session_id
        if (
            session_id is not None
            and session_headers
            and returned_session != session_id
        ):
            raise _RemoteError("mcp-http-headers")
        if returned_session is not None and (
            not 1 <= len(returned_session) <= 256
            or CONTROL.search(returned_session) is not None
        ):
            raise _RemoteError("mcp-http-headers")
        return content, content_types[0] if content_types else "", returned_session
    except (OSError, http.client.HTTPException) as exc:
        raise _RemoteError("mcp-http") from exc
    finally:
        connection.close()


def _remote_http_mcp_call(workspace: str, server_tool: str, arguments: dict[str, Any]) -> Any:
    url, authorization = _remote_read_locator_config(workspace)
    if server_tool != GITHUB_TOOL:
        raise _RemoteError("mcp-http-tool")
    tool_name = server_tool.removeprefix(GITHUB_SERVER + ".")
    if not tool_name or tool_name == server_tool or CONTROL.search(tool_name) is not None:
        raise _RemoteError("mcp-http-tool")
    initialize_id = 1
    initialize = {
        "jsonrpc": "2.0",
        "id": initialize_id,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "devflow-success-driver", "version": "1"},
        },
    }
    session_id: str | None = None
    try:
        body, content_type, session_id = _remote_http_request(
            url=url,
            authorization=authorization,
            method="POST",
            body=_canonical_bytes(initialize),
            session_id=None,
            expected_status=(200,),
            timeout_seconds=REMOTE_MCP_HTTP_STEP_TIMEOUT_SECONDS,
        )
        initialized = _remote_parse_http_mcp(body, content_type, initialize_id)
        result = initialized.get("result")
        if (
            not isinstance(result, dict)
            or result.get("protocolVersion") != MCP_PROTOCOL_VERSION
        ):
            raise _RemoteError("mcp-http-initialize")
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        _remote_http_request(
            url=url,
            authorization=authorization,
            method="POST",
            body=_canonical_bytes(notification),
            session_id=session_id,
            expected_status=(200, 202, 204),
            timeout_seconds=REMOTE_MCP_HTTP_STEP_TIMEOUT_SECONDS,
        )
        request_id = 2
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        body, content_type, _returned_session = _remote_http_request(
            url=url,
            authorization=authorization,
            method="POST",
            body=_canonical_bytes(request),
            session_id=session_id,
            expected_status=(200,),
            timeout_seconds=REMOTE_MCP_HTTP_STEP_TIMEOUT_SECONDS,
        )
        response = _remote_parse_http_mcp(body, content_type, request_id)
        if "error" in response:
            raise _RemoteError("mcp-http-call")
        result = response.get("result")
        if not isinstance(result, dict):
            raise _RemoteError("mcp-http-call")
        is_error = result.get("isError")
        if (
            "error" in result
            or ("isError" in result and not isinstance(is_error, bool))
            or is_error is True
        ):
            raise _RemoteError("mcp-http-call")
        return response
    finally:
        if session_id is not None:
            with suppress(Exception):
                _remote_http_request(
                    url=url,
                    authorization=authorization,
                    method="DELETE",
                    body=b"",
                    session_id=session_id,
                    expected_status=(200, 202, 204, 405),
                    timeout_seconds=10,
                )


def _remote_stdio_mcp_call(workspace: str, tool: str, arguments: dict[str, Any]) -> Any:
    request_id = 1
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    child_environment = dict(os.environ)
    child_environment["TEAMHARNESS_SHARED_DIR"] = TEAMHARNESS_SHARED_DIR
    returncode, stdout = _remote_run_bounded_process(
        [TEAMHARNESS_COMMAND, *TEAMHARNESS_ARGUMENTS],
        cwd=workspace,
        input_data=_canonical_bytes(request) + b"\n",
        timeout_seconds=REMOTE_MCP_CALL_TIMEOUT_SECONDS,
        max_stdout_bytes=MAX_REMOTE_MCP_STDOUT_BYTES,
        environment=child_environment,
    )
    if returncode != 0 or not stdout:
        raise _RemoteError("mcp-stdio-call")
    try:
        response = _strict_loads(stdout.decode("utf-8"))
    except (UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _RemoteError("mcp-stdio-output") from exc
    if (
        not isinstance(response, dict)
        or response.get("jsonrpc") != "2.0"
        or response.get("id") != request_id
        or ("result" in response) == ("error" in response)
    ):
        raise _RemoteError("mcp-stdio-output")
    return response


def _remote_team_payload(value: Any, tool: str, action: str) -> dict[str, Any]:
    candidates: dict[bytes, dict[str, Any]] = {}
    for item in _remote_walk(value):
        if (
            isinstance(item, dict)
            and isinstance(item.get("ok"), bool)
            and item.get("action") == action
            and item.get("tool") in {None, tool}
        ):
            candidates[_canonical_bytes(item)] = item
    if len(candidates) != 1:
        raise _RemoteError("teamharness-output")
    return next(iter(candidates.values()))


def _remote_team_call(workspace: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    action = arguments.get("action")
    if not isinstance(action, str):
        raise _RemoteError("teamharness-input")
    value = _remote_stdio_mcp_call(workspace, tool, arguments)
    return _remote_team_payload(value, tool, action)


def _remote_role_task_root(workspace: str, task_id: str) -> Path:
    workspace_root = Path(workspace)
    shared_root = workspace_root / "shared"
    tasks_root = shared_root / "tasks"
    task_root = tasks_root / task_id
    try:
        if (
            SAFE_ID.fullmatch(task_id) is None
            or workspace_root.name != LOCATOR_ROLE
            or workspace_root.parent.name != "agents"
            or workspace_root.is_symlink()
            or workspace_root.resolve(strict=True) != workspace_root
            or not workspace_root.is_dir()
            or shared_root.is_symlink()
            or shared_root.resolve(strict=True) != shared_root
            or not shared_root.is_dir()
            or tasks_root.is_symlink()
            or tasks_root.resolve(strict=True) != tasks_root
            or not tasks_root.is_dir()
            or task_root.is_symlink()
            or task_root.resolve(strict=True) != task_root
            or not task_root.is_dir()
        ):
            raise _RemoteError("task-path")
    except OSError as exc:
        raise _RemoteError("task-path") from exc
    return task_root


def _remote_persisted_task_spec(workspace: str, task_id: str) -> str:
    """Read only the task spec persisted by a successful earlier ACK."""

    try:
        task_root = _remote_role_task_root(workspace, task_id)
    except _RemoteError as exc:
        raise _RemoteError("ack-task") from exc
    spec_path = task_root / "spec.md"
    descriptor = -1
    try:
        if (
            spec_path.is_symlink()
            or spec_path.resolve(strict=True) != spec_path
        ):
            raise _RemoteError("ack-task")
        descriptor = os.open(
            spec_path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not 1 <= metadata.st_size <= 1_000_000
        ):
            raise _RemoteError("ack-task")
        content = bytearray()
        while len(content) < metadata.st_size:
            chunk = os.read(descriptor, min(65_536, metadata.st_size - len(content)))
            if not chunk:
                raise _RemoteError("ack-task")
            content.extend(chunk)
        if os.read(descriptor, 1):
            raise _RemoteError("ack-task")
        return bytes(content).decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise _RemoteError("ack-task") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _remote_ack_spec(ack: dict[str, Any], workspace: str, task_id: str) -> str:
    first_fields = {
        "ok",
        "tool",
        "action",
        "task",
        "spec",
        "pulled",
        "synced",
    }
    if set(ack) == first_fields:
        task = ack.get("task")
        spec = ack.get("spec")
        expected_task_fields = {
            "task_id",
            "project_id",
            "room_id",
            "status",
            "spec_path",
            "assigned_to",
            "task_title",
            "assigned_at",
            "acknowledged_by_role",
        }
        task_title = task.get("task_title") if isinstance(task, dict) else None
        assigned_at = task.get("assigned_at") if isinstance(task, dict) else None
        assigned_at_valid = False
        if (
            isinstance(assigned_at, str)
            and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", assigned_at)
            is not None
        ):
            try:
                assigned_at_valid = (
                    time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ",
                        time.strptime(assigned_at, "%Y-%m-%dT%H:%M:%SZ"),
                    )
                    == assigned_at
                )
            except ValueError:
                assigned_at_valid = False
        if (
            ack.get("ok") is not True
            or ack.get("tool") != "taskflow"
            or ack.get("action") != "ack_task"
            or ack.get("pulled") is not True
            or ack.get("synced") is not True
            or not isinstance(task, dict)
            or set(task) != expected_task_fields
            or task.get("task_id") != task_id
            or task.get("project_id") != task_id.removesuffix(TASK_SUFFIX)
            or not isinstance(task.get("room_id"), str)
            or MATRIX_ROOM.fullmatch(task["room_id"]) is None
            or task.get("status") != "in_progress"
            or task.get("spec_path") != f"shared/tasks/{task_id}/spec.md"
            or task.get("assigned_to") != LOCATOR_ROLE
            or not isinstance(task_title, str)
            or not 1 <= len(task_title.encode("utf-8")) <= 256
            or not task_title.strip()
            or CONTROL.search(task_title) is not None
            or not assigned_at_valid
            or task.get("acknowledged_by_role") != "worker"
            or not isinstance(spec, str)
        ):
            raise _RemoteError("ack-task")
        return spec

    idempotent_fields = {
        "ok",
        "idempotent",
        "action",
        "role",
        "taskState",
        "taskId",
    }
    if (
        set(ack) == idempotent_fields
        and ack.get("ok") is True
        and ack.get("idempotent") is True
        and ack.get("action") == "ack_task"
        and ack.get("role") == "worker"
        and ack.get("taskState") == "in_progress"
        and ack.get("taskId") == task_id
    ):
        return _remote_persisted_task_spec(workspace, task_id)
    raise _RemoteError("ack-task")


def _remote_validate_first_submission(
    first: dict[str, Any],
    task_id: str,
    deliverables: list[str],
    submission_digest: str,
) -> None:
    if (
        first.get("ok") is not True
        or first.get("synced") is not True
        or not isinstance(first.get("task"), dict)
        or first["task"].get("task_id") != task_id
        or first["task"].get("status") != "submitted"
        or first["task"].get("result_status") != "SUCCESS"
        or first["task"].get("summary") != SUBMIT_SUMMARY
        or first["task"].get("deliverables") != deliverables
    ):
        raise _RemoteError("submit")
    emitted = {"taskId", "submissionDigest"}.intersection(first)
    if emitted and (
        emitted != {"taskId", "submissionDigest"}
        or first.get("taskId") != task_id
        or first.get("submissionDigest") != submission_digest
    ):
        raise _RemoteError("submit-attestation")


def _remote_validate_idempotent_submission(
    same: dict[str, Any],
    task_id: str,
    submission_digest: str,
) -> None:
    if set(same) != {
        "ok",
        "idempotent",
        "action",
        "role",
        "taskState",
        "taskId",
        "submissionDigest",
    } or same != {
        "ok": True,
        "idempotent": True,
        "action": "submit_task",
        "role": "worker",
        "taskState": "submitted",
        "taskId": task_id,
        "submissionDigest": submission_digest,
    }:
        raise _RemoteError("idempotent-retry")


def _remote_validate_conflicting_submission(
    changed: dict[str, Any],
    task_id: str,
    current_digest: str,
    requested_digest: str,
) -> None:
    if (
        requested_digest == current_digest
        or set(changed)
        != {
            "ok",
            "error",
            "tool",
            "action",
            "role",
            "taskId",
            "currentDigest",
            "requestedDigest",
        }
        or changed
        != {
            "ok": False,
            "error": "submit_result_conflict",
            "tool": "taskflow",
            "action": "submit_task",
            "role": "worker",
            "taskId": task_id,
            "currentDigest": current_digest,
            "requestedDigest": requested_digest,
        }
    ):
        raise _RemoteError("conflict-retry")


def _remote_receipt(value: Any) -> dict[str, Any]:
    fields = {
        "schema_version",
        "authorization",
        "github",
        "response_digest",
        "receipt_signature",
    }
    candidates: dict[bytes, dict[str, Any]] = {}
    for item in _remote_walk(value):
        if (
            isinstance(item, dict)
            and set(item) == fields
            and item.get("schema_version") == "devflow.github-content-response/v1"
        ):
            candidates[_canonical_bytes(item)] = item
    if len(candidates) != 1:
        raise _RemoteError("github-receipt")
    return next(iter(candidates.values()))


def _remote_fixed_file(path: Path, expected_digest: str) -> bytes:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.stat()
        content = path.read_bytes()
    except OSError as exc:
        raise _RemoteError("skill-attestation") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or _sha256(content) != expected_digest
    ):
        raise _RemoteError("skill-attestation")
    return content


def _remote_load_module(name: str, source: bytes, path: Path) -> types.ModuleType:
    try:
        text = source.decode("utf-8")
        module = types.ModuleType(name)
        module.__file__ = str(path)
        sys.modules[name] = module
        exec(compile(text, str(path), "exec"), module.__dict__)  # noqa: S102
        return module
    except (SyntaxError, UnicodeError, ValueError) as exc:
        raise _RemoteError("skill-load") from exc


def _remote_capability_claims(capability: str) -> dict[str, Any]:
    if CAPABILITY.fullmatch(capability) is None:
        raise _RemoteError("capability")
    encoded, _signature = capability.split(".", 1)
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise _RemoteError("capability") from exc
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        raise _RemoteError("capability")
    try:
        value = _strict_loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise _RemoteError("capability") from exc
    if not isinstance(value, dict) or set(value) != {
        "schema",
        "task_id",
        "owner",
        "repo",
        "revision",
        "paths",
        "iat",
        "exp",
        "jti",
    }:
        raise _RemoteError("capability")
    return value


def _remote_atomic_new_file(path: Path, content: bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        written = 0
        while written < len(content):
            written += os.write(descriptor, content[written:])
        os.fsync(descriptor)
    except OSError as exc:
        raise _RemoteError("write-sanitized") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        if path.read_bytes() != content or stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise _RemoteError("write-sanitized")
    except OSError as exc:
        raise _RemoteError("write-sanitized") from exc


def _remote_sanitized_markdown(
    *,
    task_id: str,
    artifact_digest: str,
    authorizer_scope: str,
    broker_scope: str,
    capability_digest: str,
    content_digest: str,
    envelope_digest: str,
    object_sha: str,
    response_digest: str,
) -> bytes:
    values = (
        artifact_digest,
        authorizer_scope,
        broker_scope,
        capability_digest,
        content_digest,
        envelope_digest,
        response_digest,
    )
    if any(DIGEST.fullmatch(item) is None for item in values):
        raise _RemoteError("sanitize")
    if OBJECT_SHA.fullmatch(object_sha) is None or SAFE_ID.fullmatch(task_id) is None:
        raise _RemoteError("sanitize")
    text = (
        "# GitHubEvidence\n\n"
        "- Status: `SUCCESS`\n"
        f"- Task: `{task_id}`\n"
        f"- Repository: `{OWNER}/{REPOSITORY}`\n"
        f"- Revision: `{REVISION}`\n"
        f"- Path: `{EVIDENCE_PATH}`\n"
        f"- Object SHA: `{object_sha}`\n"
        f"- Content SHA-256: `{content_digest}`\n"
        f"- Broker response SHA-256: `{response_digest}`\n"
        f"- Broker scope SHA-256: `{broker_scope}`\n"
        f"- Authorizer scope SHA-256: `{authorizer_scope}`\n"
        f"- Capability SHA-256: `{capability_digest}`\n"
        f"- Envelope SHA-256: `{envelope_digest}`\n"
        f"- GitHubEvidence SHA-256: `{artifact_digest}`\n"
        "- Full in-memory validator: `passed`\n"
        "- Repository bytes written to disk: `no`\n"
    )
    if (
        SECRET.search(text) is not None
        or CAPABILITY.search(text) is not None
        or MATRIX_ROOM.search(text) is not None
    ):
        raise _RemoteError("sanitize")
    return text.encode("utf-8")


def _remote_attested_skill(workspace: str) -> tuple[types.ModuleType, types.ModuleType]:
    root = Path(workspace) / "skills" / "github-evidence"
    scripts = root / "scripts"
    references = root / "references"
    try:
        if (
            root.is_symlink()
            or scripts.is_symlink()
            or references.is_symlink()
            or root.resolve(strict=True) != root
            or scripts.resolve(strict=True) != scripts
            or references.resolve(strict=True) != references
        ):
            raise _RemoteError("skill-attestation")
    except OSError as exc:
        raise _RemoteError("skill-attestation") from exc
    contract_reader_path = scripts / "_contract.py"
    authorizer_path = scripts / "authorize_tool.py"
    validator_path = scripts / "validate.py"
    contract_path = references / "contract.yaml"
    contract_reader = _remote_fixed_file(
        contract_reader_path,
        EXPECTED_CONTRACT_READER_SHA256,
    )
    authorizer_source = _remote_fixed_file(authorizer_path, EXPECTED_AUTHORIZER_SHA256)
    validator_source = _remote_fixed_file(validator_path, EXPECTED_VALIDATOR_SHA256)
    contract_source = _remote_fixed_file(contract_path, EXPECTED_CONTRACT_SHA256)
    contract_module = _remote_load_module("_contract", contract_reader, contract_reader_path)
    try:
        contract = contract_module._validate_contract(
            contract_module._load_contract_subset(
                contract_source.decode("utf-8")
            )
        )
    except (AttributeError, UnicodeError, ValueError) as exc:
        raise _RemoteError("skill-contract") from exc
    if contract.get("name") != "github-evidence":
        raise _RemoteError("skill-contract")
    authorizer = _remote_load_module(
        "_devflow_github_authorizer",
        authorizer_source,
        authorizer_path,
    )
    validator = _remote_load_module(
        "_devflow_github_validator",
        validator_source,
        validator_path,
    )
    return authorizer, validator


def _remote_locator_main() -> int:
    stage = "bootstrap"
    try:
        if len(sys.argv) != 3:
            raise _RemoteError(stage)
        role, workspace = sys.argv[1:]
        expected_workspace = f"/root/hiclaw-fs/agents/{LOCATOR_ROLE}"
        if (
            role != LOCATOR_ROLE
            or workspace != expected_workspace
            or os.environ.get("AGENTTEAMS_WORKER_NAME") != LOCATOR_ROLE
            or os.environ.get("HOME") != workspace
            or Path.cwd().resolve(strict=True) != Path(workspace)
        ):
            raise _RemoteError(stage)
        raw_parameters = sys.stdin.buffer.read(4097)
        if not 1 <= len(raw_parameters) <= 4096:
            raise _RemoteError(stage)
        parameters = _strict_loads(raw_parameters.decode("utf-8"))
        if not isinstance(parameters, dict) or set(parameters) != {"runId", "taskId"}:
            raise _RemoteError(stage)
        run_id = parameters.get("runId")
        task_id = parameters.get("taskId")
        if (
            not isinstance(run_id, str)
            or not isinstance(task_id, str)
            or SAFE_PROJECT.fullmatch(run_id) is None
            or task_id != run_id + TASK_SUFFIX
            or SAFE_ID.fullmatch(task_id) is None
        ):
            raise _RemoteError(stage)

        stage = "attest-skill"
        authorizer, validator = _remote_attested_skill(workspace)
        stage = "ack-task"
        ack = _remote_team_call(
            workspace,
            "taskflow",
            {"action": "ack_task", "payload": {"taskId": task_id}},
        )
        spec = _remote_ack_spec(ack, workspace, task_id)
        if not 1 <= len(spec.encode("utf-8")) <= 1_000_000:
            raise _RemoteError(stage)
        document = spec[:-1] if spec.endswith("\n") else spec
        if "\r" in spec or not document or document != document.strip():
            raise _RemoteError("handoff")
        envelope = _strict_loads(document)
        if not isinstance(envelope, dict) or _canonical_text(envelope) != document:
            raise _RemoteError("handoff")

        stage = "authorize"
        assignment = authorizer.validate_envelope(envelope)
        if (
            envelope.get("run_id") != run_id
            or envelope.get("issue_id") != ISSUE_ID
            or envelope.get("task_id") != task_id
            or envelope.get("trace_id") != f"{run_id}:{task_id}"
            or envelope.get("idempotency_key")
            != f"{run_id}:{task_id}:{LOCATOR_ROLE}:github-evidence"
            or assignment.owner != OWNER
            or assignment.repo != REPOSITORY
            or assignment.revision != REVISION
            or assignment.paths != (EVIDENCE_PATH,)
            or assignment.task_id != task_id
        ):
            raise _RemoteError(stage)
        decision = authorizer.authorize(
            "locator",
            GITHUB_TOOL,
            envelope=envelope,
            owner=OWNER,
            repo=REPOSITORY,
            path=EVIDENCE_PATH,
            revision=REVISION,
            task_id=task_id,
            capability=assignment.capability,
        )
        if (
            decision.allowed is not True
            or decision.code != "ALLOW_READ"
            or decision.risk != "read_only"
            or DIGEST.fullmatch(decision.scope_digest) is None
        ):
            raise _RemoteError(stage)

        stage = "github-mcp"
        mcp_value = _remote_http_mcp_call(
            workspace,
            GITHUB_TOOL,
            {
                "task_id": task_id,
                "capability": assignment.capability,
                "owner": OWNER,
                "repo": REPOSITORY,
                "path": EVIDENCE_PATH,
                "revision": REVISION,
            },
        )
        stage = "parse-receipt"
        receipt = _remote_receipt(mcp_value)
        stage = "verify-receipt"
        authorization = receipt.get("authorization")
        github = receipt.get("github")
        if not isinstance(authorization, dict) or not isinstance(github, dict):
            raise _RemoteError("verify-receipt")
        broker_scope = _expected_broker_scope(task_id)
        capability_digest = _sha256(assignment.capability.encode("ascii"))
        if (
            authorization.get("decision") != "allow"
            or authorization.get("task_id") != task_id
            or authorization.get("scope_digest") != broker_scope
            or authorization.get("capability_digest") != capability_digest
            or github.get("repository") != f"{OWNER}/{REPOSITORY}"
            or github.get("revision") != REVISION
            or github.get("path") != EVIDENCE_PATH
            or github.get("encoding") != "base64"
        ):
            raise _RemoteError("verify-receipt")
        stage = "verify-scope"
        claims = _remote_capability_claims(assignment.capability)
        authorized_at = authorization.get("authorized_at")
        if (
            claims.get("schema") != "devflow.github-content-capability/v1"
            or claims.get("task_id") != task_id
            or claims.get("owner") != OWNER
            or claims.get("repo") != REPOSITORY
            or claims.get("revision") != REVISION
            or claims.get("paths") != [EVIDENCE_PATH]
            or isinstance(authorized_at, bool)
            or not isinstance(authorized_at, int)
            or isinstance(claims.get("iat"), bool)
            or not isinstance(claims.get("iat"), int)
            or isinstance(claims.get("exp"), bool)
            or not isinstance(claims.get("exp"), int)
            or not claims["iat"] <= authorized_at < claims["exp"]
        ):
            raise _RemoteError("verify-scope")

        stage = "validate-evidence"
        encoded_content = github.get("content_base64")
        if not isinstance(encoded_content, str):
            raise _RemoteError(stage)
        try:
            content = base64.b64decode(encoded_content, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise _RemoteError(stage) from exc
        if base64.b64encode(content).decode("ascii") != encoded_content:
            raise _RemoteError(stage)
        content_digest = _sha256(content)
        evidence = {
            "path": EVIDENCE_PATH,
            "object_sha": github.get("object_sha"),
            "content_sha256": content_digest,
            "response_digest": receipt.get("response_digest"),
        }
        artifact: dict[str, Any] = {
            "run_id": run_id,
            "task_id": task_id,
            "repository": {"owner": OWNER, "repo": REPOSITORY},
            "revision": REVISION,
            "operations": [receipt],
            "evidence": [evidence],
            "trace_id": envelope["trace_id"],
            "status": "success",
        }
        artifact["digest"] = _sha256(_canonical_bytes(artifact))
        validator._validate_output(artifact)
        object_sha = evidence["object_sha"]
        response_digest = evidence["response_digest"]
        if (
            not isinstance(object_sha, str)
            or OBJECT_SHA.fullmatch(object_sha) is None
            or not isinstance(response_digest, str)
            or DIGEST.fullmatch(response_digest) is None
        ):
            raise _RemoteError(stage)

        stage = "write-sanitized"
        markdown = _remote_sanitized_markdown(
            task_id=task_id,
            artifact_digest=artifact["digest"],
            authorizer_scope=decision.scope_digest,
            broker_scope=broker_scope,
            capability_digest=capability_digest,
            content_digest=content_digest,
            envelope_digest=assignment.envelope_digest,
            object_sha=object_sha,
            response_digest=response_digest,
        )
        try:
            task_root = _remote_role_task_root(workspace, task_id)
        except _RemoteError as exc:
            raise _RemoteError(stage) from exc
        evidence_root = task_root / "GitHubEvidence"
        try:
            evidence_root.mkdir(mode=0o700)
        except OSError as exc:
            raise _RemoteError(stage) from exc
        if evidence_root.is_symlink() or stat.S_IMODE(evidence_root.stat().st_mode) != 0o700:
            raise _RemoteError(stage)
        _remote_atomic_new_file(evidence_root / "result.md", markdown)
        _remote_atomic_new_file(task_root / "result.md", markdown)
        deliverables = [
            f"shared/tasks/{task_id}/result.md",
            f"shared/tasks/{task_id}/GitHubEvidence/result.md",
        ]

        stage = "submit"
        submission = {
            "action": "submit_task",
            "payload": {
                "taskId": task_id,
                "status": "SUCCESS",
                "summary": SUBMIT_SUMMARY,
                "deliverables": deliverables,
            },
        }
        idempotency_key = envelope["idempotency_key"]
        idempotency_key_digest = _sha256(idempotency_key.encode("utf-8"))
        submission_digest = _submission_digest(task_id, deliverables)
        first = _remote_team_call(workspace, "taskflow", submission)
        _remote_validate_first_submission(
            first,
            task_id,
            deliverables,
            submission_digest,
        )
        same = _remote_team_call(workspace, "taskflow", submission)
        _remote_validate_idempotent_submission(same, task_id, submission_digest)
        changed_submission = json.loads(json.dumps(submission))
        changed_submission["payload"]["summary"] = SUBMIT_SUMMARY + " Changed retry."
        changed_submission_digest = _submission_digest(
            task_id,
            deliverables,
            summary=SUBMIT_SUMMARY + " Changed retry.",
        )
        changed = _remote_team_call(workspace, "taskflow", changed_submission)
        _remote_validate_conflicting_submission(
            changed,
            task_id,
            submission_digest,
            changed_submission_digest,
        )

        summary = {
            "ok": True,
            "taskId": task_id,
            "artifactSha256": artifact["digest"],
            "authorizerScopeSha256": decision.scope_digest,
            "brokerScopeSha256": broker_scope,
            "capabilitySha256": capability_digest,
            "contentSha256": content_digest,
            "conflictRequestedSha256": changed_submission_digest,
            "envelopeSha256": assignment.envelope_digest,
            "idempotencyKeySha256": idempotency_key_digest,
            "objectSha": object_sha,
            "responseSha256": response_digest,
            "submissionSha256": submission_digest,
            "deliverables": deliverables,
            "validatorPassed": True,
            "firstSubmit": True,
            "idempotentRetry": True,
            "conflictRetry": True,
        }
        _assert_public_safe(summary)
        print(_canonical_text(summary))
        return 0
    except Exception:
        failure = {"ok": False, "code": "locator_execution_failed", "stage": stage}
        print(_canonical_text(failure))
        return 0


_REMOTE_IMPORTS = """\
from __future__ import annotations
import base64
import binascii
import hashlib
import http.client
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
import types
import urllib.parse
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any
"""


def _remote_constant_source() -> str:
    names = (
        "LOCATOR_ROLE",
        "GITHUB_TOOL",
        "OWNER",
        "REPOSITORY",
        "REVISION",
        "EVIDENCE_PATH",
        "ISSUE_ID",
        "TASK_SUFFIX",
        "SUBMIT_SUMMARY",
        "GITHUB_SERVER",
        "TEAMHARNESS_SERVER",
        "TEAMHARNESS_COMMAND",
        "TEAMHARNESS_ARGUMENTS",
        "TEAMHARNESS_SHARED_DIR",
        "GITHUB_MCP_URL",
        "MCP_PROTOCOL_VERSION",
        "MAX_REMOTE_CONFIG_BYTES",
        "MAX_REMOTE_MCP_STDOUT_BYTES",
        "MAX_REMOTE_HTTP_RESPONSE_BYTES",
        "REMOTE_MCP_CALL_TIMEOUT_SECONDS",
        "REMOTE_MCP_HTTP_STEP_TIMEOUT_SECONDS",
        "REMOTE_LOCATOR_DEADLINE_SECONDS",
        "EXPECTED_AUTHORIZER_SHA256",
        "EXPECTED_VALIDATOR_SHA256",
        "EXPECTED_CONTRACT_READER_SHA256",
        "EXPECTED_CONTRACT_SHA256",
    )
    values = globals()
    lines = [f"{name} = {values[name]!r}" for name in names]
    lines.extend(
        [
            f"SAFE_PROJECT = re.compile({SAFE_PROJECT.pattern!r})",
            f"SAFE_ID = re.compile({SAFE_ID.pattern!r})",
            f"DIGEST = re.compile({DIGEST.pattern!r})",
            f"OBJECT_SHA = re.compile({OBJECT_SHA.pattern!r})",
            f"MATRIX_ROOM = re.compile({MATRIX_ROOM.pattern!r})",
            f"CAPABILITY = re.compile({CAPABILITY.pattern!r})",
            f"SECRET = re.compile({SECRET.pattern!r}, re.IGNORECASE)",
            f"CONTROL = re.compile({CONTROL.pattern!r})",
            f"BANNED_PUBLIC_KEYS = frozenset({sorted(BANNED_PUBLIC_KEYS)!r})",
        ]
    )
    return "\n".join(lines)


_REMOTE_FUNCTIONS = (
    DriverError,
    _RemoteError,
    _strict_object,
    _reject_constant,
    _strict_loads,
    _canonical_bytes,
    _canonical_text,
    _sha256,
    _assert_public_safe,
    _expected_broker_scope,
    _submission_digest,
    _remote_walk,
    _remote_hard_deadline,
    _remote_kill_process,
    _remote_run_bounded_process,
    _remote_read_locator_config,
    _remote_parse_http_mcp,
    _remote_http_request,
    _remote_http_mcp_call,
    _remote_stdio_mcp_call,
    _remote_team_payload,
    _remote_team_call,
    _remote_role_task_root,
    _remote_persisted_task_spec,
    _remote_ack_spec,
    _remote_validate_first_submission,
    _remote_validate_idempotent_submission,
    _remote_validate_conflicting_submission,
    _remote_receipt,
    _remote_fixed_file,
    _remote_load_module,
    _remote_capability_claims,
    _remote_atomic_new_file,
    _remote_sanitized_markdown,
    _remote_attested_skill,
    _remote_locator_main,
)


def _remote_locator_entry() -> int:
    with _remote_hard_deadline(REMOTE_LOCATOR_DEADLINE_SECONDS):
        return _remote_locator_main()


REMOTE_LOCATOR_HELPER = "\n\n".join(
    [
        _REMOTE_IMPORTS,
        _remote_constant_source(),
        *(inspect.getsource(item) for item in _REMOTE_FUNCTIONS),
        inspect.getsource(_remote_locator_entry),
        "raise SystemExit(_remote_locator_entry())",
    ]
)

REMOTE_CONTROL_HELPER = r'''
from __future__ import annotations
import json
import os
import signal
import subprocess
import sys
import threading
from contextlib import suppress
from pathlib import Path

def pairs(items):
    value = {}
    for key, child in items:
        if key in value:
            raise ValueError("duplicate")
        value[key] = child
    return value

def load(text):
    return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))

def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def kill(process):
    if process.poll() is not None:
        return
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(OSError):
        process.kill()
    with suppress(OSError, subprocess.SubprocessError):
        process.wait(timeout=5)

def bounded_rpc(workspace, tool, arguments):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments},
    }
    child_environment = dict(os.environ)
    child_environment["TEAMHARNESS_SHARED_DIR"] = "/root/hiclaw-fs/shared"
    try:
        process = subprocess.Popen(
            ["/usr/bin/python3", "/opt/devflow/teamharness/guarded_server.py"],
            cwd=workspace,
            env=child_environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise ValueError("server") from exc
    chunks = []
    state = {"size": 0, "overflow": False, "failed": False}

    def reader():
        try:
            while True:
                chunk = process.stdout.read(65536)
                if not chunk:
                    return
                state["size"] += len(chunk)
                if state["size"] <= 3200000:
                    chunks.append(chunk)
                else:
                    state["overflow"] = True
        except (OSError, ValueError, AttributeError):
            state["failed"] = True

    def writer():
        try:
            process.stdin.write(canonical(request).encode("utf-8") + b"\n")
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError, AttributeError):
            state["failed"] = True

    read_thread = threading.Thread(target=reader, daemon=True)
    write_thread = threading.Thread(target=writer, daemon=True)
    read_thread.start()
    write_thread.start()
    timed_out = False
    try:
        process.wait(timeout=120)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill(process)
    finally:
        if process.poll() is None:
            kill(process)
    read_thread.join(timeout=5)
    write_thread.join(timeout=5)
    if timed_out:
        raise ValueError("timeout")
    if read_thread.is_alive() or write_thread.is_alive() or state["failed"] or state["overflow"] or process.returncode != 0:
        kill(process)
        raise ValueError("server")
    value = load(b"".join(chunks).decode("utf-8"))
    if (
        not isinstance(value, dict)
        or value.get("jsonrpc") != "2.0"
        or value.get("id") != 1
        or ("result" in value) == ("error" in value)
    ):
        raise ValueError("server")
    return value

def walk(value):
    values = [value]
    if isinstance(value, dict):
        for child in value.values():
            values.extend(walk(child))
    elif isinstance(value, list):
        for child in value:
            values.extend(walk(child))
    elif isinstance(value, str) and value.lstrip().startswith(("{", "[")):
        try:
            values.extend(walk(load(value)))
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return values

def main():
    tool = "unknown"
    action = "unknown"
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, lambda _signum, _frame: (_ for _ in ()).throw(TimeoutError()))
    signal.setitimer(signal.ITIMER_REAL, 135.0)
    try:
        if len(sys.argv) != 5:
            raise ValueError("argv")
        role, workspace, tool, action = sys.argv[1:]
        allowed = {
            "projectflow": {"resolve_project", "create_project", "plan_dag", "accept_task_result", "complete_project", "mark_requester_report_sent"},
            "taskflow": {"delegate_task", "check_task"},
            "roomflow": {"create_task_room"},
            "filesync": {"push", "stat"},
        }
        if (
            role != "devflow-lead"
            or workspace != "/root/hiclaw-fs/agents/devflow-lead"
            or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
            or os.environ.get("HOME") != workspace
            or Path.cwd().resolve(strict=True) != Path(workspace)
            or tool not in allowed
            or action not in allowed[tool]
        ):
            raise ValueError("identity")
        raw = sys.stdin.buffer.read(200001)
        if not 1 <= len(raw) <= 200000:
            raise ValueError("input")
        arguments = load(raw.decode("utf-8"))
        if not isinstance(arguments, dict) or arguments.get("action") != action:
            raise ValueError("input")
        value = bounded_rpc(workspace, tool, arguments)
        candidates = {}
        for item in walk(value):
            if isinstance(item, dict) and isinstance(item.get("ok"), bool) and item.get("action") == action and item.get("tool") in {None, tool}:
                candidates[canonical(item)] = item
        if len(candidates) != 1:
            raise ValueError("response")
        print(canonical(next(iter(candidates.values()))))
    except Exception:
        print(canonical({"ok": False, "tool": tool, "action": action, "error": "driver_transport_failed"}))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
    return 0

raise SystemExit(main())
'''.strip()

REMOTE_PREFLIGHT_HELPER = r'''
from __future__ import annotations
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import threading
from contextlib import suppress
from pathlib import Path

MCP_SCHEMA_CANONICAL_PINS = __MCP_SCHEMA_CANONICAL_PINS__
MCP_SCHEMA_CANONICAL_SIZES = __MCP_SCHEMA_CANONICAL_SIZES__
MCP_SCHEMA_CANONICALIZATION_ID = "mcporter-v0.9.0-terminal-latency-zeroed"
MAX_REMOTE_SCHEMA_BYTES = 1000000
PINS = {
    "scripts/authorize_tool.py": "2ff118f3edbbcfb86db8f092d629d36c6d79e89d28363ba8683262b718cd481d",
    "scripts/validate.py": "668e5bb30e25aab809cf42e49247d5326f26856a7ce5bd4fdadc91a917e59ce4",
    "scripts/_contract.py": "f4624c2bed5367390897f8a2c14f12736daba0e148795d20bb20ad23ed8eb08f",
    "references/contract.yaml": "3446d6183a315f260900bbdb5ea77f8fb4aabb13be3a328cf8e41e94c4e4230c",
}

def pairs(items):
    value = {}
    for key, child in items:
        if key in value:
            raise ValueError("duplicate")
        value[key] = child
    return value

def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

__MCP_SCHEMA_CANONICALIZER__

def load(text):
    return json.loads(
        text,
        object_pairs_hook=pairs,
        parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
    )

def bounded_file(path, maximum):
    descriptor = -1
    try:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError("file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not 1 <= metadata.st_size <= maximum
        ):
            raise ValueError("file")
        chunks = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise ValueError("file")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError("file")
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

def kill(process):
    if process.poll() is not None:
        return
    with suppress(OSError):
        os.killpg(process.pid, signal.SIGKILL)
    with suppress(OSError):
        process.kill()
    with suppress(OSError, subprocess.SubprocessError):
        process.wait(timeout=5)

def bounded_command(arguments):
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        raise ValueError("command") from exc
    stdout_chunks = []
    stderr_chunks = []
    state = {
        "stdout_size": 0,
        "stderr_size": 0,
        "overflow": False,
        "failed": False,
    }

    def reader(stream, chunks, size_key, maximum):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                state[size_key] += len(chunk)
                if state[size_key] <= maximum:
                    chunks.append(chunk)
                else:
                    state["overflow"] = True
        except (OSError, ValueError):
            state["failed"] = True

    if process.stdout is None or process.stderr is None:
        kill(process)
        raise ValueError("command")
    stdout_thread = threading.Thread(
        target=reader,
        args=(process.stdout, stdout_chunks, "stdout_size", 1000000),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=reader,
        args=(process.stderr, stderr_chunks, "stderr_size", 65536),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill(process)
    finally:
        if process.poll() is None:
            kill(process)
    stdout_thread.join(timeout=5)
    stderr_thread.join(timeout=5)
    if timed_out:
        raise ValueError("command")
    if (
        stdout_thread.is_alive()
        or stderr_thread.is_alive()
        or state["failed"]
        or state["overflow"]
        or process.returncode != 0
    ):
        kill(process)
        raise ValueError("command")
    return b"".join(stdout_chunks), b"".join(stderr_chunks)

def expected_config(role):
    servers = {
        "teamharness": {
            "command": "/usr/bin/python3",
            "args": ["/opt/devflow/teamharness/guarded_server.py"],
            "transport": "stdio",
            "env": {"TEAMHARNESS_SHARED_DIR": "/root/hiclaw-fs/shared"},
        }
    }
    if role == "devflow-locator":
        servers["devflow-github-readonly"] = {
            "url": "http://higress-gateway.agentteams-system.svc.cluster.local:80/mcp-servers/devflow-github-readonly/mcp",
            "transport": "http",
            "headers": {"Authorization": "Bearer <redacted>"},
        }
    return {"mcpServers": servers}

def main():
    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, lambda _signum, _frame: (_ for _ in ()).throw(TimeoutError()))
    signal.setitimer(signal.ITIMER_REAL, 105.0)
    try:
        if len(sys.argv) != 3:
            raise ValueError("argv")
        role, workspace = sys.argv[1:]
        expected_workspace = f"/root/hiclaw-fs/agents/{role}"
        expected_servers = ["teamharness"]
        if role == "devflow-locator":
            expected_servers.insert(0, "devflow-github-readonly")
        if (
            role not in {"devflow-lead", "devflow-locator"}
            or workspace != expected_workspace
            or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
            or os.environ.get("HOME") != workspace
            or Path.cwd().resolve(strict=True) != Path(workspace)
        ):
            raise ValueError("identity")
        executable = Path("/usr/bin/mcporter")
        link_metadata = executable.lstat()
        resolved = executable.resolve(strict=True)
        metadata = resolved.stat()
        if (
            not stat.S_ISLNK(link_metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_nlink != 1
            or metadata.st_size != 8254
            or not os.access(executable, os.X_OK)
        ):
            raise ValueError("mcporter")
        descriptor = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ValueError("mcporter")
            digest = hashlib.sha256()
            remaining = 8255
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            if remaining != 1 or digest.hexdigest() != "ec13274c40bc0c71e73e994cf773b9d3801ce909d38f4b133f11450c9e0c458b":
                raise ValueError("mcporter")
        finally:
            os.close(descriptor)
        version, version_stderr = bounded_command(["/usr/bin/mcporter", "--version"])
        if version_stderr:
            raise ValueError("mcporter")
        try:
            version_text = version.decode("utf-8").strip()
        except UnicodeError as exc:
            raise ValueError("mcporter") from exc
        if version_text != "0.9.0":
            raise ValueError("mcporter")
        config_path = Path(workspace) / "config" / "mcporter.json"
        config = load(bounded_file(config_path, 65536).decode("utf-8"))
        if not isinstance(config, dict) or set(config) != {"mcpServers"}:
            raise ValueError("config")
        normalized = json.loads(json.dumps(config))
        if role == "devflow-locator":
            try:
                authorization = normalized["mcpServers"]["devflow-github-readonly"]["headers"]["Authorization"]
            except (KeyError, TypeError) as exc:
                raise ValueError("config") from exc
            if (
                not isinstance(authorization, str)
                or re.fullmatch(r"Bearer [^\s]+", authorization) is None
                or re.search(r"[\x00-\x1f\x7f]", authorization) is not None
            ):
                raise ValueError("config")
            normalized["mcpServers"]["devflow-github-readonly"]["headers"]["Authorization"] = "Bearer <redacted>"
        if normalized != expected_config(role):
            raise ValueError("config")
        config_digest = hashlib.sha256(canonical(normalized).encode("utf-8")).hexdigest()
        role_pins = MCP_SCHEMA_CANONICAL_PINS.get(role)
        role_sizes = MCP_SCHEMA_CANONICAL_SIZES.get(role)
        if (
            not isinstance(role_pins, dict)
            or not isinstance(role_sizes, dict)
            or set(role_pins) != set(expected_servers)
            or set(role_sizes) != set(expected_servers)
            or any(
                not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                for digest in role_pins.values()
            )
            or any(
                isinstance(size, bool) or not isinstance(size, int) or size < 1
                for size in role_sizes.values()
            )
        ):
            raise ValueError("schema-pin")
        schema_canonical_digests = {}
        schema_canonical_sizes = {}
        for server in expected_servers:
            schema, schema_stderr = bounded_command(
                ["/usr/bin/mcporter", "list", server, "--schema"]
            )
            if schema_stderr:
                raise ValueError("schema")
            canonical_schema = _canonicalize_mcporter_schema(schema)
            if len(canonical_schema) != role_sizes[server]:
                raise ValueError("schema")
            schema_digest = hashlib.sha256(canonical_schema).hexdigest()
            if schema_digest != role_pins[server]:
                raise ValueError("schema")
            schema_canonical_digests[server] = schema_digest
            schema_canonical_sizes[server] = len(canonical_schema)
        skill_attested = False
        if role == "devflow-locator":
            root = Path(workspace) / "skills" / "github-evidence"
            if root.is_symlink() or root.resolve(strict=True) != root:
                raise ValueError("skill")
            for relative, digest in PINS.items():
                path = root / relative
                metadata = path.stat()
                if path.is_symlink() or path.resolve(strict=True) != path or not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                    raise ValueError("skill")
            skill_attested = True
        print(canonical({
            "ok": True,
            "role": role,
            "serverNames": expected_servers,
            "skillAttested": skill_attested,
            "mcporterSha256": "ec13274c40bc0c71e73e994cf773b9d3801ce909d38f4b133f11450c9e0c458b",
            "mcporterVersion": "0.9.0",
            "configSha256": config_digest,
            "schemaCanonicalization": MCP_SCHEMA_CANONICALIZATION_ID,
            "schemaCanonicalSha256": schema_canonical_digests,
            "schemaCanonicalBytes": schema_canonical_sizes,
        }))
    except Exception:
        print(canonical({"ok": False, "code": "runtime_preflight_failed"}))
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0)
        signal.signal(signal.SIGALRM, previous_handler)
    return 0

raise SystemExit(main())
'''.strip().replace(
    "__MCP_SCHEMA_CANONICAL_PINS__",
    repr(EXPECTED_MCP_SCHEMA_CANONICAL_SHA256),
).replace(
    "__MCP_SCHEMA_CANONICAL_SIZES__",
    repr(EXPECTED_MCP_SCHEMA_CANONICAL_BYTES),
).replace(
    "__MCP_SCHEMA_CANONICALIZER__",
    inspect.getsource(_canonicalize_mcporter_schema).strip(),
)

REMOTE_STDIN_BOOTSTRAP = r'''
import io
import sys

raw = sys.stdin.buffer.read(650009)
if len(raw) < 8 or len(raw) > 650008:
    raise SystemExit(97)
source_size = int.from_bytes(raw[:4], "big")
input_size = int.from_bytes(raw[4:8], "big")
if not 1 <= source_size <= 400000 or not 0 <= input_size <= 250000:
    raise SystemExit(97)
if len(raw) != 8 + source_size + input_size:
    raise SystemExit(97)
source = raw[8 : 8 + source_size]
arguments = raw[8 + source_size :]
try:
    source_text = source.decode("utf-8")
except UnicodeError:
    raise SystemExit(97) from None
sys.stdin = io.TextIOWrapper(io.BytesIO(arguments), encoding="utf-8")
namespace = {"__name__": "__main__", "__file__": "<devflow-memory-helper>"}
exec(compile(source_text, "<devflow-memory-helper>", "exec"), namespace)
'''.strip()


def _remote_frame(helper: str, input_data: bytes | None) -> bytes:
    try:
        source = helper.encode("utf-8")
    except UnicodeError as exc:
        raise DriverError("remote_source_invalid", "transport") from exc
    arguments = input_data or b""
    if not 1 <= len(source) <= MAX_REMOTE_SOURCE_BYTES:
        raise DriverError("remote_source_invalid", "transport")
    if len(arguments) > MAX_REMOTE_INPUT_BYTES:
        raise DriverError("remote_input_invalid", "transport")
    return (
        len(source).to_bytes(4, "big")
        + len(arguments).to_bytes(4, "big")
        + source
        + arguments
    )


class _CommandRunner:
    """Run kubectl without a shell and never expose captured failure output."""

    def run(
        self,
        arguments: list[str],
        *,
        input_data: bytes | None = None,
        timeout: int = 180,
    ) -> str:
        try:
            returncode, stdout = _remote_run_bounded_process(
                arguments,
                cwd=os.getcwd(),
                input_data=input_data or b"",
                timeout_seconds=timeout,
                max_stdout_bytes=3_300_000,
            )
        except _RemoteError as exc:
            raise DriverError("command_unavailable", "transport") from exc
        if returncode != 0:
            raise DriverError("command_failed", "transport")
        try:
            return stdout.decode("utf-8")
        except UnicodeError as exc:
            raise DriverError("command_output_invalid", "transport") from exc


class KubernetesBackend:
    """Production backend for the fixed, attested DevFlow AgentTeams runtime."""

    def __init__(self, kubectl: str = "kubectl") -> None:
        if (
            not kubectl
            or len(kubectl.encode("utf-8")) > 260
            or CONTROL.search(kubectl) is not None
        ):
            raise DriverError("kubectl_invalid", "input")
        self.kubectl = kubectl
        self.runner = _CommandRunner()
        self._leader: Target | None = None
        self._locator: Target | None = None

    def _kubectl(self, *arguments: str) -> list[str]:
        return [self.kubectl, "--namespace", NAMESPACE, *arguments]

    def _exec(
        self,
        target: Target,
        helper: str,
        helper_arguments: list[str],
        *,
        input_data: bytes | None = None,
        timeout_seconds: int,
    ) -> str:
        command = self._kubectl("exec")
        command.append("--stdin")
        command.extend(
            [
                target.pod_name,
                "--container",
                CONTAINER_NAME,
                "--",
                "python3",
                "-c",
                REMOTE_STDIN_BOOTSTRAP,
                *helper_arguments,
            ]
        )
        encoded = [item.encode("utf-8") for item in command]
        if (
            any(len(item) > MAX_KUBECTL_ARGUMENT_BYTES for item in encoded)
            or sum(len(item) + 1 for item in encoded) > MAX_KUBECTL_ARGV_BYTES
        ):
            raise DriverError("kubectl_argv_too_large", "transport")
        return self.runner.run(
            command,
            input_data=_remote_frame(helper, input_data),
            timeout=timeout_seconds,
        )

    @staticmethod
    def _json_object(text: str, stage: str) -> dict[str, Any]:
        try:
            value = _strict_loads(text)
        except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
            raise DriverError("remote_summary_invalid", stage) from exc
        if not isinstance(value, dict):
            raise DriverError("remote_summary_invalid", stage)
        return value

    def preflight(self) -> RuntimeContext:
        self.runner.run([self.kubectl, "version", "--request-timeout=10s"], timeout=20)
        try:
            team = _strict_loads(
                self.runner.run(
                    self._kubectl("get", "team", TEAM_NAME, "--output", "json"),
                    timeout=30,
                )
            )
            pods = _strict_loads(
                self.runner.run(
                    self._kubectl(
                        "get",
                        "pods",
                        "--selector",
                        f"agentteams.io/team={TEAM_NAME}",
                        "--output",
                        "json",
                    ),
                    timeout=30,
                )
            )
            if not isinstance(team, dict) or not isinstance(pods, dict):
                raise ReconcileError("discovery document is malformed")
            targets = discover_targets(team, pods)
        except (ReconcileError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DriverError("runtime_discovery_failed", "runtime-preflight") from exc
        by_role = {target.role_name: target for target in targets}
        if set(by_role) != {
            "devflow-lead",
            "devflow-triage",
            "devflow-locator",
            "devflow-coder",
            "devflow-tester",
            "devflow-reviewer",
        }:
            raise DriverError("runtime_set_invalid", "runtime-preflight")
        leader = by_role[LEADER_ROLE]
        locator = by_role[LOCATOR_ROLE]
        for target, expected_names, skill_attested in (
            (leader, [TEAMHARNESS_SERVER], False),
            (locator, [GITHUB_SERVER, TEAMHARNESS_SERVER], True),
        ):
            report = self._json_object(
                self._exec(
                    target,
                    REMOTE_PREFLIGHT_HELPER,
                    [target.role_name, target.workspace],
                    timeout_seconds=HOST_PREFLIGHT_TIMEOUT_SECONDS,
                ),
                "runtime-preflight",
            )
            if report != {
                "ok": True,
                "role": target.role_name,
                "serverNames": expected_names,
                "skillAttested": skill_attested,
                "mcporterSha256": EXPECTED_MCPORTER_SHA256,
                "mcporterVersion": EXPECTED_MCPORTER_VERSION,
                "configSha256": _sha256(
                    _canonical_bytes(_normalized_mcporter_config(target.role_name))
                ),
                "schemaCanonicalization": MCP_SCHEMA_CANONICALIZATION_ID,
                "schemaCanonicalSha256": {
                    server: EXPECTED_MCP_SCHEMA_CANONICAL_SHA256[
                        target.role_name
                    ][server]
                    for server in expected_names
                },
                "schemaCanonicalBytes": {
                    server: EXPECTED_MCP_SCHEMA_CANONICAL_BYTES[
                        target.role_name
                    ][server]
                    for server in expected_names
                },
            }:
                raise DriverError("runtime_attestation_failed", "runtime-preflight")
        self._leader = leader
        self._locator = locator
        return RuntimeContext(
            leader_matrix_user_id=leader.matrix_user_id,
            locator_matrix_user_id=locator.matrix_user_id,
        )

    def _target(self, role: str) -> Target:
        target = self._leader if role == LEADER_ROLE else self._locator
        if target is None or target.role_name != role:
            raise DriverError("preflight_required", "transport")
        return target

    def leader_call(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        target = self._target(LEADER_ROLE)
        action = arguments.get("action")
        if not isinstance(action, str):
            raise DriverError("action_invalid", "transport")
        response = self._exec(
            target,
            REMOTE_CONTROL_HELPER,
            [target.role_name, target.workspace, tool, action],
            input_data=_canonical_bytes(arguments),
            timeout_seconds=HOST_CONTROL_TIMEOUT_SECONDS,
        )
        return self._json_object(response, "transport")

    def locator_execute(self, run_id: str, task_id: str) -> dict[str, Any]:
        target = self._target(LOCATOR_ROLE)
        response = self._exec(
            target,
            REMOTE_LOCATOR_HELPER,
            [target.role_name, target.workspace],
            input_data=_canonical_bytes({"runId": run_id, "taskId": task_id}),
            timeout_seconds=HOST_LOCATOR_TIMEOUT_SECONDS,
        )
        value = self._json_object(response, "locator-evidence")
        if value.get("ok") is not True:
            remote_stage = value.get("stage")
            if (
                set(value) != {"ok", "code", "stage"}
                or value.get("ok") is not False
                or value.get("code") != "locator_execution_failed"
                or not isinstance(remote_stage, str)
                or remote_stage not in REMOTE_LOCATOR_FAILURE_STAGE_MAP
            ):
                raise DriverError("remote_summary_invalid", "locator-evidence")
            raise DriverError(
                "locator_execution_failed",
                REMOTE_LOCATOR_FAILURE_STAGE_MAP[remote_stage],
            )
        return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or explicitly execute one fixed AgentTeams GitHub evidence path."
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="contact the fixed cluster and create state; omitted means no-contact plan",
    )
    parser.add_argument(
        "--project-id",
        help=f"fresh id beginning with {PROJECT_PREFIX!r}; required with --execute",
    )
    parser.add_argument(
        "--confirm",
        help="fixed confirmation phrase; required with --execute",
    )
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not args.execute:
            if args.project_id is not None or args.confirm is not None:
                raise DriverError("execute_flag_required", "input")
            result = plan_report()
        else:
            if args.project_id is None or args.confirm is None:
                raise DriverError("execution_arguments_required", "input")
            result = execute_success_path(
                KubernetesBackend(args.kubectl),
                project_id=args.project_id,
                confirmation=args.confirm,
            )
        _assert_public_safe(result)
        print(_canonical_text(result))
        return 0
    except DriverError as exc:
        failure = {"ok": False, "code": exc.code, "stage": exc.stage}
        _assert_public_safe(failure)
        print(_canonical_text(failure), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

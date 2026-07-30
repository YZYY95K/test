"""Strict tests for the Tester-only AgentTeams CI/CD MCP boundary."""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import shutil
import socket
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO, StringIO
from pathlib import Path
from typing import Any

import pytest

from agentteams.cicd import tester_server as cicd
from scripts import install_agentteams_tester_cicd as installer

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "agentteams" / "cicd" / "tester_server.py"
INSTALLER = ROOT / "scripts" / "install_agentteams_tester_cicd.py"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _clear_completed_task_cache() -> Iterator[None]:
    with cicd._COMPLETED_LOCK:
        cicd._COMPLETED_RESULTS.clear()
    yield
    with cicd._COMPLETED_LOCK:
        cicd._COMPLETED_RESULTS.clear()


class _FakeSigner:
    public_key_sha256 = _hash("test-receipt-public-key")

    def sign(self, _value: dict[str, Any]) -> str:
        return cicd._base64url(b"s" * cicd.ED25519_SIGNATURE_BYTES)


def _policy() -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": "1.0",
        "teamName": cicd.TEAM_NAME,
        "serviceIdentity": cicd.SERVICE_IDENTITY,
        "repositoryRoot": str(cicd.REPOSITORY_ROOT),
        "workspaceRoot": str(cicd.WORKSPACE_ROOT),
        "repositoryRevision": "a" * 40,
        "repositoryArchiveSha256": _hash("repository-archive"),
        "repositoryManifestSha256": _hash("repository"),
        "serverSha256": _hash("server"),
        "receiptPublicKeySha256": _FakeSigner.public_key_sha256,
        "testCommands": {
            "focused": ["/opt/devflow/ci/python", "-m", "pytest", "-q", "tests/unit"],
            "full": ["/opt/devflow/ci/python", "-m", "pytest", "-q"],
        },
        "testExecutableSha256": {
            "focused": _hash("test-executable"),
            "full": _hash("test-executable"),
        },
        "networkIsolationPrefix": list(cicd.NETWORK_ISOLATION_PREFIX),
        "networkIsolationExecutableSha256": _hash("unshare"),
        "resourceLimitLauncher": [cicd.PRODUCTION_PRLIMIT.as_posix()],
        "resourceLimitLauncherSha256": _hash("prlimit"),
        "resourceLimitsApplied": True,
        "assignmentSource": cicd.ASSIGNMENT_SOURCE,
        "assignmentSourceLiveAgentTeams": False,
        "dynamicCandidateSupported": False,
        "testPathMutationSupported": False,
        "fixedCandidateSha256": {
            "devflow-demo-focused": _hash("placeholder-focused"),
            "devflow-demo-full": _hash("placeholder-full"),
        },
        "testCompletionPolicy": cicd.TEST_COMPLETION_POLICY,
        "minimumExecutedTests": 1,
        "timeoutSeconds": 60,
        "cpuSeconds": 45,
        "addressSpaceBytes": 512 * 1024 * 1024,
        "maxProcesses": 32,
        "maxOpenFiles": 128,
        "maxOutputBytes": 4096,
        "maxPatchBytes": 64 * 1024,
        "maxPatchFiles": 16,
        "maxFileBytes": 32 * 1024,
        "maxRepositoryFiles": 1000,
        "maxRepositoryBytes": 16 * 1024 * 1024,
        "credentialPolicy": "empty-environment",
        "networkPolicy": "bubblewrap-unshare-all-mask-runtime-credentials",
        "workspaceBinding": "0" * 64,
        "remainingThreat": (
            "Ordinary code is bounded; pod root and kernel compromise remain outside."
        ),
    }
    value["fixedCandidateSha256"] = {
        "devflow-demo-focused": cicd._sha256_bytes(
            cicd._canonical(_candidate(tier="T2"))
        ),
        "devflow-demo-full": cicd._sha256_bytes(
            cicd._canonical(_candidate(tier="T3"))
        ),
    }
    value["workspaceBinding"] = cicd._sha256_bytes(
        cicd._canonical(cicd.policy_binding_body(value))
    )
    return value


def _receipt_policy(policy: dict[str, Any]) -> dict[str, Any]:
    return {
        "schemaVersion": "1.0",
        "algorithm": cicd.TEST_EXECUTION_RECEIPT_ALGORITHM,
        "audience": cicd.TEST_EXECUTION_RECEIPT_AUDIENCE,
        "issuer": cicd.TEST_EXECUTION_RECEIPT_ISSUER,
        "signatureDomain": cicd.TEST_EXECUTION_RECEIPT_SCHEMA,
        "publicKeyPath": cicd.TEAMHARNESS_RECEIPT_PUBLIC_KEY_PATH,
        "publicKeyFileSha256": _hash("receipt-public-key-file"),
        "publicKeySha256": _FakeSigner.public_key_sha256,
        "policyAttestationPath": cicd.TEAMHARNESS_RECEIPT_POLICY_PATH,
        "opensslPath": str(cicd.PRODUCTION_OPENSSL),
        "replayLedgerPath": cicd.TEAMHARNESS_RECEIPT_LEDGER_PATH,
        "replayScope": cicd.TEST_EXECUTION_RECEIPT_REPLAY_SCOPE,
        "replayLedgerPersistentAcrossPodReplacement": False,
        "receiptLifetimeSeconds": cicd.TEST_EXECUTION_RECEIPT_TTL_SECONDS,
        "maxReceiptLifetimeSeconds": cicd.TEST_EXECUTION_RECEIPT_TTL_SECONDS,
        "maxClockSkewSeconds": 5,
        "ciServerSha256": policy["serverSha256"],
        "ciPolicySha256": policy["workspaceBinding"],
        "repositoryArchiveSha256": policy["repositoryArchiveSha256"],
        "repositoryManifestSha256": policy["repositoryManifestSha256"],
        "repositoryRevision": policy["repositoryRevision"],
        "remainingThreat": (
            "The replay ledger is Pod-local; Leader Pod replacement can lose "
            "replay history for at most the 120-second receipt lifetime."
        ),
    }


def _runtime_binding() -> dict[str, Any]:
    return {
        "schemaVersion": "1.0",
        "teamName": cicd.TEAM_NAME,
        "memberName": "member-tester",
        "runtimeName": cicd.TESTER_ROLE,
        "podName": "pod-tester",
        "teamHarnessRole": "worker",
    }


def _candidate(
    *,
    path: str = "src/app.py",
    change_type: str = "modify",
    original: str | None = "old\n",
    new: str | None = "fixed\n",
    tier: str = "T2",
) -> dict[str, Any]:
    allowed = [path]
    boundary = {
        "schema_version": "1.0",
        "located_context_digest": _hash("located"),
        "allowed_files": allowed,
    }
    boundary["scope_digest"] = cicd._sha256_bytes(cicd._canonical(boundary))
    patch = {
        "branch_name": "fix/task-1",
        "changes": [
            {
                "file_path": path,
                "change_type": change_type,
                "original_content": original,
                "new_content": new,
                "diff": cicd._canonical_patch_diff(
                    path,
                    change_type,
                    original,
                    new,
                ),
            }
        ],
        "commit_message": "fix task",
        "description": "minimal fix",
    }
    return {
        "schema_version": "1.2",
        "issue_id": 7,
        "tier": tier,
        "patch": patch,
        "candidate_digest": cicd._sha256_bytes(cicd._canonical(patch)),
        "evidence_boundary": boundary,
        "model_call_attempt": 1,
        "retry_attempt": 1,
        "revision_of": None,
    }


def _assignment(
    policy: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    return {
        "projectId": "project-7",
        "runId": "run-7",
        "issueId": candidate["issue_id"],
        "taskId": (
            "devflow-demo-full"
            if candidate["tier"] in {"T3", "T4", "T5"}
            else "devflow-demo-focused"
        ),
        "revision": policy["repositoryRevision"],
        "workspaceBinding": policy["workspaceBinding"],
        "candidateDigest": candidate["candidate_digest"],
        "fullSuite": candidate["tier"] in {"T3", "T4", "T5"},
    }


def _task_evidence(
    policy: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    assignment = _assignment(policy, candidate)
    envelope = {
        "envelope_version": "1.0",
        "run_id": assignment["runId"],
        "issue_id": assignment["issueId"],
        "task_id": assignment["taskId"],
        "producer": "TeamLeader",
        "consumer": cicd.TESTER_ROLE,
        "skill": cicd.TESTER_SKILL,
        "trace_id": f'{assignment["runId"]}:{assignment["taskId"]}',
        "idempotency_key": (
            f'{assignment["runId"]}:{assignment["taskId"]}:'
            f"{cicd.TESTER_ROLE}:{cicd.TESTER_SKILL}"
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "ready",
        "artifact": {
            "type": "PatchCandidate",
            "schema_version": "1.2",
            "inline": candidate,
            "ref": None,
            "sha256": cicd._sha256_bytes(cicd._canonical(candidate)),
        },
    }
    return {
        "task": {
            "project_id": assignment["projectId"],
            "task_id": assignment["taskId"],
            "assigned_to": cicd.TESTER_ROLE,
            "status": "acknowledged",
        },
        "spec": json.dumps(envelope, sort_keys=True),
    }


def _fixture_task_evidence(
    policy: dict[str, Any],
    task_id: str,
    tier: str,
    *,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    evidence = _task_evidence(policy, _candidate(tier=tier))
    envelope = json.loads(evidence["spec"])
    envelope["task_id"] = task_id
    envelope["trace_id"] = f'{envelope["run_id"]}:{task_id}'
    envelope["idempotency_key"] = (
        f'{envelope["run_id"]}:{task_id}:{cicd.TESTER_ROLE}:{cicd.TESTER_SKILL}'
    )
    if created_at is not None:
        envelope["created_at"] = created_at.isoformat()
    evidence["task"]["task_id"] = task_id
    evidence["spec"] = json.dumps(envelope, sort_keys=True)
    return evidence


def _request(
    policy: dict[str, Any],
) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": cicd.TOOL_NAME,
            "arguments": {
                "taskId": "devflow-demo-focused",
                "revision": policy["repositoryRevision"],
                "workspaceBinding": policy["workspaceBinding"],
            },
        },
    }


@contextlib.contextmanager
def _http_server() -> Iterator[int]:
    server = cicd.BoundedThreadingHTTPServer(
        ("127.0.0.1", 0), cicd.CICDHTTPHandler
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _http_request(
    port: int,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def _mcp_headers(*, protocol: bool = True) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if protocol:
        headers["MCP-Protocol-Version"] = cicd.PROTOCOL_VERSION
    return headers


def _command_outcome(
    *,
    returncode: int = 0,
    passed: int = 1,
    failed: int = 0,
    errors: int = 0,
    skipped: int = 0,
    duration_ms: int = 5,
) -> cicd.CommandOutcome:
    parts = [
        f"{count} {label}"
        for count, label in (
            (passed, "passed"),
            (failed, "failed"),
            (errors, "errors"),
            (skipped, "skipped"),
        )
        if count
    ]
    output = f"{', '.join(parts)} in 0.01s\n"
    evidence = cicd._pytest_terminal_evidence(
        output,
        returncode=returncode,
        minimum_executed=1,
    )
    return cicd.CommandOutcome(
        returncode=returncode,
        output=output,
        duration_ms=duration_ms,
        collected=evidence["collected"],
        executed=evidence["executed"],
        passed=evidence["passed"],
        failed=evidence["failed"],
        errors=evidence["errors"],
        skipped=evidence["skipped"],
        terminal_summary=evidence["summary"],
        terminal_evidence_sha256=evidence["sha256"],
        resource_limits_applied=True,
    )


def _bound_executor(
    candidate: dict[str, Any],
    assignment: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    test_result = {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "duration_ms": 5,
        "results": [
            {
                "name": "server-owned-focused-suite",
                "status": "passed",
                "duration_ms": 5,
                "error_message": None,
                "traceback": None,
            }
        ],
        "baseline_comparison": {
            "baseline_passed": 1,
            "current_passed": 1,
            "new_failures": [],
            "fixed_tests": [],
            "regression": False,
        },
        "integrity_attestation": {
            "schema_version": "1.0",
            "policy": cicd.INTEGRITY_POLICY,
            "policy_digest": cicd.INTEGRITY_POLICY_DIGEST,
            "command_digest": _hash("command"),
            "baseline_manifest_digest": _hash("protected"),
            "candidate_baseline_manifest_digest": _hash("protected"),
            "candidate_pre_run_manifest_digest": _hash("pre"),
            "candidate_post_run_manifest_digest": _hash("pre"),
            "added_tests_manifest_digest": _hash("added"),
            "baseline_protected_file_count": 1,
            "added_test_file_count": 0,
            "full_suite": assignment["fullSuite"],
            "verified": True,
            "isolation_boundary": cicd.ISOLATION_BOUNDARY,
        },
    }
    evidence = cicd._signed_test_evidence(
        test_result,
        assignment,
        candidate,
        policy,
        _FakeSigner(),
        now=1_800_000_000,
        jti="1" * 32,
    )
    return {
        "schema": cicd.RESULT_SCHEMA,
        "artifactType": "TestEvidence",
        "artifactSchemaVersion": "1.0",
        "testEvidence": evidence,
    }


def test_tools_list_exposes_one_fixed_action_without_command_path_or_credentials() -> None:
    policy = _policy()
    response = cicd.handle_request(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        policy=policy,
        runtime_binding=_runtime_binding(),
    )

    assert response is not None
    tools = response["result"]["tools"]
    assert [tool["name"] for tool in tools] == [cicd.TOOL_NAME]
    schema = tools[0]["inputSchema"]
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {
        "taskId",
        "revision",
        "workspaceBinding",
    }
    assert schema["properties"]["revision"]["const"] == policy["repositoryRevision"]
    assert (
        schema["properties"]["workspaceBinding"]["const"]
        == policy["workspaceBinding"]
    )
    serialized = json.dumps(tools)
    for forbidden in ("shell", "environment", "deployment", "repositoryPath"):
        assert f'"{forbidden}"' not in serialized


def test_run_tests_returns_task_revision_workspace_and_candidate_bound_result() -> None:
    policy = _policy()
    candidate = _candidate()
    assignment = _assignment(policy, candidate)

    response = cicd.handle_request(
        _request(policy),
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=_task_evidence(policy, candidate),
        executor=_bound_executor,
    )

    assert response is not None
    assert response["result"]["isError"] is False
    result = response["result"]["structuredContent"]
    assert result["artifactType"] == "TestEvidence"
    evidence = result["testEvidence"]
    assert evidence["revision"] == assignment["revision"]
    assert evidence["workspace_binding"] == assignment["workspaceBinding"]
    assert evidence["candidate_digest"] == candidate["candidate_digest"]
    assert evidence["execution_policy"]["credentials_forwarded"] is False
    assert evidence["execution_policy"]["deployment_tools_exposed"] is False
    receipt = evidence["test_execution_receipt"]
    assert receipt["run_id"] == assignment["runId"]
    assert receipt["task_id"] == assignment["taskId"]
    assert receipt["test_result_digest"] == cicd._sha256_bytes(
        cicd._canonical(evidence["test_result"])
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", "pytest"),
        ("shell", "pytest -q"),
        ("repositoryPath", "/etc"),
        ("outputPath", "../../tmp/result"),
        ("environment", {"TOKEN": "secret"}),
        ("deploy", True),
        ("fullSuite", False),
    ],
)
def test_request_rejects_agent_selected_command_path_env_deploy_and_suite(
    field: str,
    value: Any,
) -> None:
    policy = _policy()
    candidate = _candidate()
    request = _request(policy)
    request["params"]["arguments"][field] = value

    response = cicd.handle_request(
        request,
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=_task_evidence(policy, candidate),
        executor=_bound_executor,
    )

    assert response is not None
    assert response["error"]["code"] == -32602
    assert response["error"]["message"] == "Invalid params"
    assert response["error"]["data"]["reason"] == "arguments_outside_policy"


@pytest.mark.parametrize(
    ("surface", "replacement", "error"),
    [
        ("taskId", "other-task", "teamharness_task_not_authorized"),
        ("revision", "b" * 40, "assignment_revision_mismatch"),
        ("workspaceBinding", "b" * 64, "assignment_workspace_mismatch"),
    ],
)
def test_assignment_must_match_request_binding(
    surface: str,
    replacement: str,
    error: str,
) -> None:
    policy = _policy()
    candidate = _candidate()
    request = _request(policy)
    request["params"]["arguments"][surface] = replacement

    response = cicd.handle_request(
        request,
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=_task_evidence(policy, candidate),
        executor=_bound_executor,
    )

    assert response is not None
    assert response["result"]["isError"] is True
    assert response["result"]["structuredContent"]["error"] == error


def test_teamharness_task_binds_candidate_issue_digest_and_acked_state() -> None:
    policy = _policy()
    candidate = _candidate()
    mutations = ("issue", "digest", "state")
    for mutation in mutations:
        evidence = _task_evidence(policy, candidate)
        envelope = json.loads(evidence["spec"])
        if mutation == "issue":
            envelope["issue_id"] = 8
        elif mutation == "digest":
            envelope["artifact"]["sha256"] = "b" * 64
        else:
            evidence["task"]["status"] = "pending"
        evidence["spec"] = json.dumps(envelope)
        response = cicd.handle_request(
            _request(policy),
            policy=policy,
            runtime_binding=_runtime_binding(),
            assignment=evidence,
            executor=_bound_executor,
        )
        assert response is not None
        assert response["result"]["isError"] is True


def test_teamharness_task_accepts_absent_task_skill_but_rejects_mismatch() -> None:
    policy = _policy()
    candidate = _candidate()
    evidence = _task_evidence(policy, candidate)

    accepted = cicd.handle_request(
        _request(policy),
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=evidence,
        executor=_bound_executor,
    )
    assert accepted is not None
    assert accepted["result"]["isError"] is False

    evidence["task"]["skill"] = "pr-reviewer"
    rejected = cicd.handle_request(
        _request(policy),
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=evidence,
        executor=_bound_executor,
    )
    assert rejected is not None
    assert rejected["result"]["isError"] is True
    assert (
        rejected["result"]["structuredContent"]["error"]
        == "teamharness_task_not_authorized"
    )


def test_teamharness_artifact_accepts_canonical_null_ref_and_rejects_reference() -> None:
    policy = _policy()
    candidate = _candidate()
    evidence = _task_evidence(policy, candidate)
    envelope = json.loads(evidence["spec"])
    assert envelope["artifact"]["ref"] is None

    envelope["artifact"]["ref"] = "shared://attacker-selected-candidate"
    evidence["spec"] = json.dumps(envelope)
    response = cicd.handle_request(
        _request(policy),
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=evidence,
        executor=_bound_executor,
    )
    assert response is not None
    assert response["result"]["isError"] is True
    assert (
        response["result"]["structuredContent"]["error"]
        == "teamharness_candidate_artifact_invalid"
    )


def test_full_suite_is_derived_from_teamharness_candidate_not_agent_input() -> None:
    policy = _policy()
    candidate = _candidate(tier="T3")
    captured: dict[str, Any] = {}

    def executor(
        candidate_value: dict[str, Any],
        assignment: dict[str, Any],
        policy_value: dict[str, Any],
    ) -> dict[str, Any]:
        captured["fullSuite"] = assignment["fullSuite"]
        return _bound_executor(candidate_value, assignment, policy_value)

    request = _request(policy)
    request["params"]["arguments"]["taskId"] = "devflow-demo-full"
    response = cicd.handle_request(
        request,
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=_task_evidence(policy, candidate),
        executor=executor,
    )

    assert response is not None
    assert response["result"]["isError"] is False
    assert captured["fullSuite"] is True


def test_dynamic_t4_candidate_is_rejected_before_execution() -> None:
    policy = _policy()
    candidate = _candidate(tier="T4")
    request = _request(policy)
    request["params"]["arguments"]["taskId"] = "devflow-demo-full"

    response = cicd.handle_request(
        request,
        policy=policy,
        runtime_binding=_runtime_binding(),
        assignment=_task_evidence(policy, candidate),
        executor=lambda *_args, **_kwargs: pytest.fail("dynamic T4 executed"),
    )

    assert response is not None
    assert response["result"]["isError"] is True
    assert response["result"]["structuredContent"]["error"] == (
        "dynamic_candidate_not_supported"
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("credentialPolicy", "inherit-environment"),
        ("networkPolicy", "best-effort"),
        ("networkIsolationPrefix", ["/bin/sh", "-c"]),
        ("timeoutSeconds", 0),
        ("maxPatchBytes", 10 * 1024 * 1024),
        ("serviceIdentity", "attacker.example"),
    ],
)
def test_policy_rejects_weakened_identity_network_credentials_and_limits(
    field: str,
    replacement: Any,
) -> None:
    policy = _policy()
    policy[field] = replacement
    policy["workspaceBinding"] = cicd._sha256_bytes(
        cicd._canonical(cicd.policy_binding_body(policy))
    )

    with pytest.raises(cicd.BoundaryError):
        cicd.validate_policy(policy, verify_files=False)


def test_policy_binding_detects_every_enforcement_field_change() -> None:
    original = _policy()
    for field in cicd.POLICY_FIELDS - {"workspaceBinding", "remainingThreat"}:
        changed = deepcopy(original)
        value = changed[field]
        if isinstance(value, int):
            changed[field] = value + 1
        elif isinstance(value, str):
            changed[field] = value + "x"
        elif isinstance(value, list):
            changed[field] = [*value, "x"]
        else:
            changed[field] = {"changed": True}
        assert cicd._sha256_bytes(
            cicd._canonical(cicd.policy_binding_body(changed))
        ) != original["workspaceBinding"]


def test_candidate_rejects_traversal_out_of_scope_and_secret_content() -> None:
    policy = _policy()
    for candidate in (
        _candidate(path="../outside.py"),
        _candidate(path="src/app.py", new="ghp_" + "A" * 40),
    ):
        with pytest.raises(cicd.BoundaryError):
            cicd._validate_candidate(candidate, policy)

    candidate = _candidate()
    candidate["patch"]["changes"][0]["file_path"] = "src/other.py"
    candidate["candidate_digest"] = cicd._sha256_bytes(
        cicd._canonical(candidate["patch"])
    )
    with pytest.raises(cicd.BoundaryError, match="outside_scope"):
        cicd._validate_candidate(candidate, policy)


@pytest.mark.parametrize(
    "path",
    (
        ".git/config",
        ".devflow/state.json",
        "node_modules/pkg/index.js",
        "src/__pycache__/app.pyc",
        ".pytest_cache/v/cache/nodeids",
    ),
)
def test_candidate_rejects_ignored_or_control_tree_paths(path: str) -> None:
    with pytest.raises(cicd.BoundaryError, match="repository_path_forbidden"):
        cicd._validate_candidate(_candidate(path=path), _policy())


def test_candidate_diff_must_exactly_match_server_recomputation() -> None:
    candidate = _candidate()
    candidate["patch"]["changes"][0]["diff"] += "fabricated\n"
    candidate["candidate_digest"] = cicd._sha256_bytes(
        cicd._canonical(candidate["patch"])
    )

    with pytest.raises(cicd.BoundaryError, match="patch_diff_mismatch"):
        cicd._validate_candidate(candidate, _policy())


@pytest.mark.parametrize(
    "path",
    (
        "pytest.ini",
        "pytest.py",
        "sitecustomize.py",
        "usercustomize.py",
        "tests/conftest.py",
        "tests/test_exit.py",
        "plugins/escape.pth",
    ),
)
def test_candidate_rejects_test_control_files(path: str) -> None:
    policy = _policy()
    candidate = _candidate(
        path=path,
        change_type="create",
        original=None,
        new="[pytest]\naddopts=-x\n",
    )
    candidate["candidate_digest"] = cicd._sha256_bytes(
        cicd._canonical(candidate["patch"])
    )

    with pytest.raises(cicd.BoundaryError, match="test_or_runner_change_forbidden"):
        cicd._validate_candidate(candidate, policy)


def test_import_time_os_exit_test_attack_is_rejected_as_test_mutation() -> None:
    candidate = _candidate(
        path="tests/test_exit.py",
        change_type="create",
        original=None,
        new="import os\nos._exit(0)\n",
    )

    with pytest.raises(cicd.BoundaryError, match="test_or_runner_change_forbidden"):
        cicd._validate_candidate(candidate, _policy())


def test_exit_code_zero_without_pytest_terminal_evidence_is_rejected() -> None:
    with pytest.raises(cicd.BoundaryError, match="test_completion_evidence_missing"):
        cicd._pytest_terminal_evidence(
            "application exited cleanly\n",
            returncode=0,
            minimum_executed=1,
        )


def test_execute_command_uses_fixed_network_prefix_empty_env_and_no_shell(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    policy = _policy()
    captured: dict[str, Any] = {}

    class FakeProcess:
        pid = 123
        returncode = 0

        def communicate(self, timeout: int) -> tuple[str, None]:
            captured["timeout"] = timeout
            return "ok", None

    def fake_popen(command: list[str], **kwargs: Any) -> FakeProcess:
        captured["command"] = command
        captured["kwargs"] = kwargs
        kwargs["stdout"].write(b"1 passed in 0.01s\n")
        kwargs["stdout"].flush()
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-cross")
    result = cicd.execute_command(tmp_path, full_suite=False, policy=policy)

    assert result.returncode == 0
    command = captured["command"]
    assert command[: len(cicd.NETWORK_ISOLATION_PREFIX)] == list(
        cicd.NETWORK_ISOLATION_PREFIX
    )
    assert command[-len(policy["testCommands"]["focused"]) :] == policy[
        "testCommands"
    ]["focused"]
    assert command.count("--clearenv") == 1
    for masked in ("/etc", "/home", "/root", "/run", "/tmp"):
        assert ["--tmpfs", masked] == command[
            command.index(masked) - 1 : command.index(masked) + 1
        ]
    bind_index = command.index("--ro-bind", len(cicd.NETWORK_ISOLATION_PREFIX))
    assert command[bind_index + 1 : bind_index + 3] == [str(tmp_path), str(tmp_path)]
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL
    assert "preexec_fn" not in captured["kwargs"]
    assert captured["kwargs"]["env"] == {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONHASHSEED": "0",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TMPDIR": "/tmp",
    }
    assert "GITHUB_TOKEN" not in captured["kwargs"]["env"]
    assert captured["timeout"] == policy["timeoutSeconds"]


def test_trusted_patcher_can_modify_a_copy_of_read_only_image_source(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    (source / "src").mkdir(parents=True)
    (source / "src/app.py").write_text("old\n", encoding="utf-8")
    (source / "src/app.py").chmod(0o444)
    (source / "src").chmod(0o555)
    source.chmod(0o555)
    policy = _policy()
    candidate = _candidate()

    cicd._copy_repository(source, destination, policy)
    assert stat.S_IMODE((destination / "src").stat().st_mode) == 0o555
    assert stat.S_IMODE((destination / "src/app.py").stat().st_mode) == 0o444
    cicd._make_patch_targets_writable(destination, candidate)
    assert stat.S_IMODE((destination / "src/app.py").stat().st_mode) & stat.S_IWUSR
    cicd._apply_patch(destination, candidate)

    assert (destination / "src/app.py").read_text(encoding="utf-8") == "fixed\n"
    assert (source / "src/app.py").read_text(encoding="utf-8") == "old\n"


@pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("bwrap") is None,
    reason="requires a Linux host with Bubblewrap",
)
def test_linux_bubblewrap_runs_patched_read_only_tree_and_blocks_restore_attack(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "candidate"
    (source / "src").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "src/app.py").write_text("old\n", encoding="utf-8")
    protected = source / "tests/test_app.py"
    protected.write_text("assert True\n", encoding="utf-8")
    (source / "attack.py").write_text(
        """from pathlib import Path
for name in ("tests/test_app.py", "src/app.py", ".pytest_cache/attack"):
    path = Path(name)
    original = path.read_text(encoding="utf-8") if path.exists() else None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("malicious runtime mutation\\n", encoding="utf-8")
        if original is not None:
            path.write_text(original, encoding="utf-8")
    except OSError:
        print(f"{name}:write-blocked")
        continue
    print(f"{name}:write-unexpectedly-succeeded")
    raise SystemExit(9)
print("1 passed in 0.01s")
raise SystemExit(0)
""",
        encoding="utf-8",
    )
    for path in source.rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)
    source.chmod(0o555)
    policy = _policy()
    policy["testCommands"] = {
        "focused": [sys.executable, "attack.py"],
        "full": [sys.executable, "attack.py"],
    }
    candidate = _candidate()
    cicd._copy_repository(source, destination, policy)
    cicd._make_patch_targets_writable(destination, candidate)
    cicd._apply_patch(destination, candidate)

    outcome = cicd.execute_command(destination, full_suite=False, policy=policy)
    if outcome.returncode != 0 and "bwrap:" in outcome.output:
        pytest.skip("Bubblewrap namespaces are disabled by this Linux host")

    assert outcome.returncode == 0, outcome.output
    for name in ("tests/test_app.py", "src/app.py", ".pytest_cache/attack"):
        assert f"{name}:write-blocked" in outcome.output
    assert (destination / "src/app.py").read_text(encoding="utf-8") == "fixed\n"
    assert (destination / "tests/test_app.py").read_text(
        encoding="utf-8"
    ) == "assert True\n"
    assert not (destination / ".pytest_cache").exists()


def test_real_executor_uses_disposable_copies_and_emits_integrity_attestation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    workspace = tmp_path / "workspaces"
    repository.mkdir()
    workspace.mkdir()
    (repository / "src").mkdir()
    (repository / "src/app.py").write_text("old\n", encoding="utf-8")
    (repository / "tests").mkdir()
    (repository / "tests/test_app.py").write_text("assert True\n", encoding="utf-8")
    for path in repository.rglob("*"):
        path.chmod(0o555 if path.is_dir() else 0o444)
    repository.chmod(0o555)
    monkeypatch.setattr(cicd, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(cicd, "WORKSPACE_ROOT", workspace)
    policy = _policy()
    policy["repositoryRoot"] = str(repository)
    policy["workspaceRoot"] = str(workspace)
    manifest = cicd.repository_manifest(
        repository,
        max_files=policy["maxRepositoryFiles"],
        max_bytes=policy["maxRepositoryBytes"],
    )
    policy["repositoryManifestSha256"] = manifest.digest
    policy["workspaceBinding"] = cicd._sha256_bytes(
        cicd._canonical(cicd.policy_binding_body(policy))
    )
    candidate = _candidate()
    assignment = _assignment(policy, candidate)

    def runner(
        root: Path,
        *,
        full_suite: bool,
        policy: dict[str, Any],
    ) -> cicd.CommandOutcome:
        assert full_suite is False
        assert policy["credentialPolicy"] == "empty-environment"
        assert root.parent.parent == workspace
        return _command_outcome()

    result = cicd.run_candidate(
        candidate,
        assignment,
        policy,
        command_runner=runner,
        receipt_signer=_FakeSigner(),
        clock=lambda: 1_800_000_000.0,
        jti_factory=lambda: "2" * 32,
    )

    assert (repository / "src/app.py").read_text(encoding="utf-8") == "old\n"
    assert list(workspace.iterdir()) == []
    evidence = result["testEvidence"]
    test_result = evidence["test_result"]
    assert test_result["passed"] == 1
    attestation = test_result["integrity_attestation"]
    assert attestation["verified"] is True
    assert attestation["full_suite"] is False
    assert attestation["isolation_boundary"] == cicd.ISOLATION_BOUNDARY
    assert evidence["execution_policy"]["credentials_forwarded"] is False
    assert evidence["execution_policy"]["deployment_tools_exposed"] is False
    assert evidence["repository"]["archive_sha256"] == policy[
        "repositoryArchiveSha256"
    ]
    receipt = evidence["test_execution_receipt"]
    assert receipt["test_result_digest"] == cicd._sha256_bytes(
        cicd._canonical(test_result)
    )
    assert receipt["execution_profile"] == "focused"
    assert receipt["jti"] == "2" * 32


def test_real_executor_refuses_candidate_that_modifies_existing_test(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    workspace = tmp_path / "workspaces"
    repository.mkdir()
    workspace.mkdir()
    (repository / "tests").mkdir()
    (repository / "tests/test_app.py").write_text("old\n", encoding="utf-8")
    monkeypatch.setattr(cicd, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(cicd, "WORKSPACE_ROOT", workspace)
    policy = _policy()
    policy["repositoryRoot"] = str(repository)
    policy["workspaceRoot"] = str(workspace)
    policy["repositoryManifestSha256"] = cicd.repository_manifest(
        repository,
        max_files=policy["maxRepositoryFiles"],
        max_bytes=policy["maxRepositoryBytes"],
    ).digest
    policy["workspaceBinding"] = cicd._sha256_bytes(
        cicd._canonical(cicd.policy_binding_body(policy))
    )
    candidate = _candidate(path="tests/test_app.py")
    assignment = _assignment(policy, candidate)

    with pytest.raises(cicd.BoundaryError, match="protected_test"):
        cicd.run_candidate(
            candidate,
            assignment,
            policy,
            command_runner=lambda *_args, **_kwargs: _command_outcome(),
            receipt_signer=_FakeSigner(),
        )
    assert list(workspace.iterdir()) == []


def test_readiness_binds_each_fixed_fixture_filename_task_and_tier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    assignments = tmp_path / "assignments"
    repository.mkdir()
    assignments.mkdir()
    (repository / "README.md").write_text("fixed demo repository\n", encoding="utf-8")
    policy = _policy()
    policy["repositoryManifestSha256"] = cicd.repository_manifest(
        repository,
        max_files=policy["maxRepositoryFiles"],
        max_bytes=policy["maxRepositoryBytes"],
    ).digest
    policy["workspaceBinding"] = cicd._sha256_bytes(
        cicd._canonical(cicd.policy_binding_body(policy))
    )

    focused = _fixture_task_evidence(policy, "devflow-demo-focused", "T2")
    full = _fixture_task_evidence(policy, "devflow-demo-full", "T3")
    for task_id, evidence in (
        ("devflow-demo-focused", focused),
        ("devflow-demo-full", full),
    ):
        (assignments / f"{task_id}.json").write_text(
            json.dumps(evidence, sort_keys=True),
            encoding="utf-8",
        )
        (assignments / f"{task_id}.json").chmod(0o444)
    assignments.chmod(0o555)
    receipt_policy = tmp_path / "test-receipt-policy.json"
    receipt_policy.write_bytes(cicd._canonical(_receipt_policy(policy)))
    receipt_policy.chmod(0o444)
    monkeypatch.setattr(cicd, "ASSIGNMENT_ROOT", assignments)
    monkeypatch.setattr(cicd, "REPOSITORY_ROOT", repository)
    monkeypatch.setattr(cicd, "TEST_RECEIPT_POLICY_PATH", receipt_policy)
    monkeypatch.setattr(cicd, "load_execution_policy", lambda: policy)
    monkeypatch.setattr(
        cicd,
        "OpenSSLEd25519ReceiptSigner",
        lambda *_args, **_kwargs: _FakeSigner(),
    )

    ready = cicd.readiness_attestation()

    assert ready["assignmentSource"] == "image-fixed-demo-fixture/v1"
    assert ready["assignmentSourceLiveAgentTeams"] is False
    assert ready["fixtureTaskIds"] == list(cicd.FIXTURE_TASK_IDS)
    assert ready["replayScope"] == "pod-incarnation"
    assert ready["replayLedgerPersistentAcrossPodReplacement"] is False
    assert ready["receiptLifetimeSeconds"] == 120
    assert "Leader Pod replacement" in ready["remainingThreat"]
    assert ready["assignmentExpiryAction"] == cicd.ASSIGNMENT_EXPIRY_ACTION

    focused_path = assignments / "devflow-demo-focused.json"
    focused_path.chmod(0o644)
    focused_path.write_text(
        json.dumps(full, sort_keys=True),
        encoding="utf-8",
    )
    focused_path.chmod(0o444)
    with pytest.raises(cicd.BoundaryError):
        cicd.readiness_attestation()


def test_receipt_policy_makes_pod_scoped_replay_limit_explicit() -> None:
    policy = _policy()
    receipt = _receipt_policy(policy)

    assert (
        cicd.validate_receipt_policy(
            receipt,
            execution_policy=policy,
            public_key_sha256=_FakeSigner.public_key_sha256,
        )
        == receipt
    )
    for field, value in (
        ("replayScope", "cluster"),
        ("replayLedgerPersistentAcrossPodReplacement", True),
        ("receiptLifetimeSeconds", 121),
    ):
        changed = dict(receipt)
        changed[field] = value
        with pytest.raises(cicd.BoundaryError, match="receipt_policy_binding_invalid"):
            cicd.validate_receipt_policy(
                changed,
                execution_policy=policy,
                public_key_sha256=_FakeSigner.public_key_sha256,
            )


def test_expired_assignment_fails_liveness_and_readiness_to_trigger_restart(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    policy = _policy()
    assignments = tmp_path / "assignments"
    assignments.mkdir()
    expired_at = datetime.now(timezone.utc) - timedelta(
        seconds=cicd.ASSIGNMENT_MAX_AGE_SECONDS + 60
    )
    for task_id, tier in (
        ("devflow-demo-focused", "T2"),
        ("devflow-demo-full", "T3"),
    ):
        path = assignments / f"{task_id}.json"
        path.write_bytes(
            cicd._canonical(
                _fixture_task_evidence(
                    policy,
                    task_id,
                    tier,
                    created_at=expired_at,
                )
            )
        )
        path.chmod(0o444)
    assignments.chmod(0o555)
    monkeypatch.setattr(cicd, "ASSIGNMENT_ROOT", assignments)
    monkeypatch.setattr(cicd, "load_execution_policy", lambda: policy)

    try:
        with pytest.raises(cicd.BoundaryError, match="teamharness_task_spec_stale"):
            cicd.liveness_attestation()
        with _http_server() as port:
            health_status, _, health_body = _http_request(port, "GET", "/healthz")
            ready_status, _, ready_body = _http_request(port, "GET", "/readyz")
        assert health_status == 503
        assert ready_status == 503
        assert json.loads(health_body)["assignmentExpiryAction"] == (
            cicd.ASSIGNMENT_EXPIRY_ACTION
        )
        assert json.loads(ready_body)["assignmentExpiryAction"] == (
            cicd.ASSIGNMENT_EXPIRY_ACTION
        )
    finally:
        for path in assignments.iterdir():
            path.chmod(0o666)
        assignments.chmod(0o777)


def test_streamable_http_is_strict_stateless_mcp_2025_03_26(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    monkeypatch.setattr(cicd, "load_execution_policy", lambda: policy)
    initialize: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": cicd.PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "AgentTeams", "version": "1.0"},
        },
    }

    with _http_server() as port:
        status, response_headers, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(initialize),
            headers=_mcp_headers(protocol=False),
        )
        initialized = json.loads(body)
        assert status == 200
        assert initialized["id"] == "init-1"
        assert initialized["result"]["protocolVersion"] == "2025-03-26"
        assert initialized["result"]["capabilities"] == {
            "tools": {"listChanged": False}
        }
        assert cicd.SERVER_VERSION == "2.1.0"
        assert initialized["result"]["serverInfo"] == {
            "name": cicd.SERVER_NAME,
            "version": "2.1.0",
        }
        assert "Mcp-Session-Id" not in response_headers

        older = deepcopy(initialize)
        older["id"] = "init-older"
        older["params"]["protocolVersion"] = "2024-11-05"
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(older),
            headers=_mcp_headers(protocol=False),
        )
        assert status == 200
        assert json.loads(body)["result"]["protocolVersion"] == cicd.PROTOCOL_VERSION

        tools_list = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(tools_list),
            headers=_mcp_headers(protocol=False),
        )
        assert status == 200
        assert [tool["name"] for tool in json.loads(body)["result"]["tools"]] == [
            cicd.TOOL_NAME
        ]

        unsupported_headers = _mcp_headers(protocol=False)
        unsupported_headers["MCP-Protocol-Version"] = "2024-11-05"
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(tools_list),
            headers=unsupported_headers,
        )
        assert status == 400
        assert json.loads(body)["error"]["data"]["reason"] == "protocol_version_invalid"

        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(tools_list),
            headers=_mcp_headers(),
        )
        assert status == 200
        assert [tool["name"] for tool in json.loads(body)["result"]["tools"]] == [
            cicd.TOOL_NAME
        ]

        unknown = {"jsonrpc": "2.0", "id": "missing", "method": "resources/list"}
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(unknown),
            headers=_mcp_headers(),
        )
        assert status == 200
        assert json.loads(body)["error"]["code"] == -32601

        bad_id = {"jsonrpc": "2.0", "id": True, "method": "ping"}
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(bad_id),
            headers=_mcp_headers(),
        )
        assert status == 200
        assert json.loads(body)["error"]["code"] == -32600

        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(notification),
            headers=_mcp_headers(),
        )
        assert status == 202
        assert body == b""

        batch = [
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
            notification,
        ]
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(batch),
            headers=_mcp_headers(),
        )
        assert status == 200
        assert json.loads(body) == [{"jsonrpc": "2.0", "id": 3, "result": {}}]

        status, headers, _ = _http_request(port, "GET", "/mcp")
        assert status == 405
        assert headers["Allow"] == "POST"

        origin_headers = _mcp_headers()
        origin_headers["Origin"] = "https://attacker.example"
        status, _, body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(tools_list),
            headers=origin_headers,
        )
        assert status == 403
        assert json.loads(body)["error"]["data"]["reason"] == "origin_forbidden"


def test_batch_limits_reject_oversize_and_multiple_side_effects() -> None:
    oversized = [
        {"jsonrpc": "2.0", "id": index, "method": "ping"}
        for index in range(cicd.MAX_BATCH_SIZE + 1)
    ]
    rejected = cicd._dispatch_message(
        oversized,
        handler=lambda _item: pytest.fail("oversized batch dispatched"),
    )
    assert isinstance(rejected, dict)
    assert rejected["error"]["data"]["reason"] == "batch_size_invalid"

    side_effects = [
        {"jsonrpc": "2.0", "id": index, "method": "tools/call"}
        for index in (1, 2)
    ]
    rejected = cicd._dispatch_message(
        side_effects,
        handler=lambda _item: pytest.fail("side-effecting batch dispatched"),
    )
    assert isinstance(rejected, dict)
    assert rejected["error"]["data"]["reason"] == (
        "side_effecting_batch_invalid"
    )


def test_completed_task_replay_returns_same_receipt_without_rerun(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    candidate = _candidate()
    evidence = _task_evidence(policy, candidate)
    executions = 0

    def executor(
        candidate_value: dict[str, Any],
        assignment_value: dict[str, Any],
        policy_value: dict[str, Any],
    ) -> dict[str, Any]:
        nonlocal executions
        executions += 1
        return _bound_executor(candidate_value, assignment_value, policy_value)

    monkeypatch.setattr(
        cicd,
        "probe_teamharness_task",
        lambda _task_id, _policy: evidence,
    )
    first = cicd.handle_request(_request(policy), policy=policy, executor=executor)
    repeated_request = _request(policy)
    repeated_request["id"] = 2
    repeated = cicd.handle_request(
        repeated_request,
        policy=policy,
        executor=executor,
    )

    assert executions == 1
    assert first is not None and repeated is not None
    first_receipt = first["result"]["structuredContent"]["testEvidence"][
        "test_execution_receipt"
    ]
    repeated_receipt = repeated["result"]["structuredContent"]["testEvidence"][
        "test_execution_receipt"
    ]
    assert repeated_receipt == first_receipt
    assert cicd._completed_state() == 1


def test_http_connection_overload_gets_fast_503() -> None:
    class FakeRequest:
        def __init__(self) -> None:
            self.payload = b""
            self.closed = False

        def sendall(self, payload: bytes) -> None:
            self.payload += payload

        def shutdown(self, _direction: int) -> None:
            return

        def close(self) -> None:
            self.closed = True

    server = cicd.BoundedThreadingHTTPServer.__new__(
        cicd.BoundedThreadingHTTPServer
    )
    server._connection_slots = threading.BoundedSemaphore(1)
    assert server._connection_slots.acquire(blocking=False)
    request = FakeRequest()

    server.process_request(request, ("127.0.0.1", 12345))

    assert b" 503 Service Unavailable\r\n" in request.payload
    assert request.closed is True


def test_streamable_http_times_out_partial_request_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cicd, "SOCKET_READ_TIMEOUT_SECONDS", 0.1)
    request = (
        "POST /mcp HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: application/json, text/event-stream\r\n"
        "Content-Type: application/json\r\n"
        f"MCP-Protocol-Version: {cicd.PROTOCOL_VERSION}\r\n"
        "Content-Length: 100\r\n"
        "\r\n"
        "{"
    ).encode("ascii")

    with _http_server() as port, socket.create_connection(
        ("127.0.0.1", port),
        timeout=3,
    ) as connection:
        connection.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks)
    assert b" 408 " in response.split(b"\r\n", 1)[0]
    assert b"request_read_timeout" in response


def test_busy_responses_distinguish_same_task_and_global_inflight_over_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy()
    candidate = _candidate()
    evidence = _task_evidence(policy, candidate)
    entered = threading.Event()
    release = threading.Event()
    first: list[tuple[int, dict[str, str], bytes]] = []

    def blocking_executor(
        candidate_value: dict[str, Any],
        assignment_value: dict[str, Any],
        policy_value: dict[str, Any],
    ) -> dict[str, Any]:
        entered.set()
        assert release.wait(timeout=3)
        return _bound_executor(candidate_value, assignment_value, policy_value)

    monkeypatch.setattr(cicd, "load_execution_policy", lambda: policy)
    monkeypatch.setattr(
        cicd,
        "probe_teamharness_task",
        lambda _task_id, _policy: evidence,
    )
    monkeypatch.setattr(cicd, "run_candidate", blocking_executor)
    body = cicd._canonical(_request(policy))

    with _http_server() as port:
        first_thread = threading.Thread(
            target=lambda: first.append(
                _http_request(
                    port,
                    "POST",
                    "/mcp",
                    body=body,
                    headers=_mcp_headers(),
                )
            )
        )
        first_thread.start()
        assert entered.wait(timeout=3)

        status, _, same_body = _http_request(
            port,
            "POST",
            "/mcp",
            body=body,
            headers=_mcp_headers(),
        )
        other = _request(policy)
        other["params"]["arguments"]["taskId"] = "other-task"
        other["id"] = 3
        other_status, _, other_body = _http_request(
            port,
            "POST",
            "/mcp",
            body=cicd._canonical(other),
            headers=_mcp_headers(),
        )
        release.set()
        first_thread.join(timeout=3)

    assert status == 200
    assert json.loads(same_body)["error"] == {
        "code": -32001,
        "message": "Server busy",
        "data": {"reason": "task_inflight", "server": cicd.SERVER_NAME},
    }
    assert other_status == 200
    assert json.loads(other_body)["error"]["data"]["reason"] == "server_busy"
    assert len(first) == 1
    assert first[0][0] == 200
    assert json.loads(first[0][2])["result"]["isError"] is False
    assert cicd._execution_state() == (0, 1)


def test_server_and_installer_have_no_runtime_dependency_for_help_or_compile() -> None:
    compile_result = subprocess.run(
        [sys.executable, "-S", "-m", "py_compile", str(SERVER)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    help_result = subprocess.run(
        [sys.executable, "-S", str(INSTALLER), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert compile_result.returncode == 0, compile_result.stderr
    assert help_result.returncode == 0, help_result.stderr
    assert "--apply" in help_result.stdout
    assert "--repository-root" not in help_result.stdout
    assert "--workspace-root" not in help_result.stdout


def test_installer_accepts_fixed_argv_policy_and_rejects_shell_or_eval() -> None:
    commands = installer._commands(
        json.dumps(
            {
                "focused": ["/opt/devflow/ci/python", "-m", "pytest", "-q", "tests/unit"],
                "full": ["/opt/devflow/ci/python", "-m", "pytest", "-q"],
            }
        )
    )

    assert set(commands) == {"focused", "full"}
    for invalid in (
        {"focused": ["/bin/sh", "-c", "pytest"], "full": ["/bin/sh", "-c", "pytest"]},
        {
            "focused": ["/usr/bin/python3", "-c", "print('unsafe')"],
            "full": ["/usr/bin/python3", "-m", "pytest"],
        },
        {"focused": ["/usr/bin/pytest"], "full": ["/usr/bin/pytest"], "extra": []},
    ):
        with pytest.raises(installer.InstallError):
            installer._commands(json.dumps(invalid))


def test_installer_apply_fails_before_mutation_without_exact_confirmation() -> None:
    completed = subprocess.run(
        [sys.executable, str(INSTALLER), "--apply"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "requires exact confirmation" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_legacy_worker_installer_cannot_apply_or_claim_compliance() -> None:
    checked = subprocess.run(
        [sys.executable, str(INSTALLER)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    applied = subprocess.run(
        [
            sys.executable,
            str(INSTALLER),
            "--apply",
            "--confirm",
            installer.CONFIRMATION,
            "--expected-source-sha256",
            "a" * 64,
            "--revision",
            "b" * 40,
            "--repository-archive-sha256",
            "c" * 64,
            "--test-commands-json",
            json.dumps(
                {
                    "focused": ["/usr/bin/python3", "-m", "pytest", "-q", "tests"],
                    "full": ["/usr/bin/python3", "-m", "pytest", "-q"],
                }
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    for completed in (checked, applied):
        assert completed.returncode == 1
        assert "reconcile_agentteams_tester_cicd.py" in completed.stderr
        assert "Traceback" not in completed.stderr


def test_stdio_mcp_positive_path_lists_and_calls_only_run_tests() -> None:
    policy = _policy()
    candidate = _candidate()
    task = _task_evidence(policy, candidate)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        _request(policy),
    ]
    source = BytesIO(
        b"".join(cicd._canonical(request) + b"\n" for request in requests)
    )
    output = StringIO()

    def handler(request: dict[str, Any]) -> dict[str, Any] | None:
        return cicd.handle_request(
            request,
            policy=policy,
            runtime_binding=_runtime_binding(),
            assignment=task,
            executor=_bound_executor,
        )

    assert cicd.serve_stdio(source, output, handler=handler) == 0
    responses = [json.loads(line) for line in output.getvalue().splitlines()]

    assert [tool["name"] for tool in responses[0]["result"]["tools"]] == [
        cicd.TOOL_NAME
    ]
    assert responses[1]["result"]["isError"] is False
    assert (
        responses[1]["result"]["structuredContent"]["testEvidence"]["candidate_digest"]
        == candidate["candidate_digest"]
    )


def test_stdio_mcp_rejects_duplicate_json_and_unknown_tool_without_crashing() -> None:
    policy = _policy()
    candidate = _candidate()
    source = BytesIO(
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}\n'
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        b'"params":{"name":"deploy","arguments":{}}}\n'
    )
    output = StringIO()

    def handler(request: dict[str, Any]) -> dict[str, Any] | None:
        return cicd.handle_request(
            request,
            policy=policy,
            runtime_binding=_runtime_binding(),
            assignment=_task_evidence(policy, candidate),
            executor=_bound_executor,
        )

    assert cicd.serve_stdio(source, output, handler=handler) == 0
    responses = [json.loads(line) for line in output.getvalue().splitlines()]

    assert len(responses) == 2
    assert responses[0]["error"]["code"] == -32700
    assert responses[0]["error"]["data"]["reason"] == "parse_error"
    assert responses[1]["error"]["code"] == -32602
    assert responses[1]["error"]["data"]["reason"] == "forbidden_tool"

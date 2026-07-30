"""Cryptographic and replay tests for Tester CI execution receipts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

from agentteams.cicd import tester_server as cicd

ROOT = Path(__file__).resolve().parents[1]


def _guard_module() -> ModuleType:
    path = ROOT / "agentteams" / "teamharness" / "guarded_server.py"
    spec = importlib.util.spec_from_file_location(
        "devflow_test_receipt_guarded_server",
        path,
    )
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


def _reservation_fixture(
    tmp_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str | int], datetime]:
    ledger = tmp_path / "reservation-ledger.json"
    ledger.write_text(
        json.dumps(
            {"schemaVersion": GUARD.TEST_RECEIPT_LEDGER_SCHEMA, "reservations": {}},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    ledger.chmod(0o600)
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    return (
        {"replayLedgerPath": str(ledger), "maxClockSkewSeconds": 5},
        {"run_id": "run-1", "task_id": "task-1"},
        {
            "jti": "1" * 32,
            "exp": int(now.timestamp()) + 120,
            "receiptSha256": _sha("receipt"),
        },
        now,
    )


def test_receipt_reservation_commits_exact_binding_once(tmp_path: Path) -> None:
    policy, source, verified, now = _reservation_fixture(tmp_path)
    request_digest = _sha("accept-request")
    result_digest = _sha("accept-result")
    authoritative_digest = _sha("authoritative-result")
    response_digest = _sha("upstream-response")
    ledger = Path(policy["replayLedgerPath"])

    with GUARD._ledger_lock(ledger):
        state, pending = GUARD._reserve_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=request_digest,
            accept_result_sha256=result_digest,
            now=now,
        )
        assert state == "new"
        assert pending["state"] == "pending"
        committed = GUARD._commit_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=request_digest,
            accept_result_sha256=result_digest,
            authoritative_result_sha256=authoritative_digest,
            upstream_response_sha256=response_digest,
            now=now,
        )
        assert committed["state"] == "committed"

    with GUARD._ledger_lock(ledger):
        state, replay = GUARD._reserve_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=request_digest,
            accept_result_sha256=result_digest,
            now=now,
        )
        assert state == "committed"
        assert replay["authoritativeResultSha256"] == authoritative_digest
        with pytest.raises(
            GUARD.GuardPolicyError,
            match="test_receipt_reservation_conflict",
        ):
            GUARD._reserve_test_execution_receipt_in_locked_ledger(
                policy,
                source,
                verified,
                accept_request_sha256=_sha("different-request"),
                accept_result_sha256=result_digest,
                now=now,
            )


def test_receipt_reservation_release_requires_owner_or_orphan(
    tmp_path: Path,
) -> None:
    policy, source, verified, now = _reservation_fixture(tmp_path)
    request_digest = _sha("accept-request")
    result_digest = _sha("accept-result")
    ledger = Path(policy["replayLedgerPath"])

    with GUARD._ledger_lock(ledger):
        _state, pending = GUARD._reserve_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=request_digest,
            accept_result_sha256=result_digest,
            now=now,
        )
        with pytest.raises(
            GUARD.GuardPolicyError,
            match="test_receipt_reservation_busy",
        ):
            GUARD._release_test_execution_receipt_in_locked_ledger(
                policy,
                source,
                verified,
                accept_request_sha256=request_digest,
                accept_result_sha256=result_digest,
                owner_id=_sha("not-the-owner"),
                now=now,
            )
        GUARD._release_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=request_digest,
            accept_result_sha256=result_digest,
            owner_id=pending["ownerId"],
            now=now,
        )
        state, _replacement = GUARD._reserve_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=request_digest,
            accept_result_sha256=result_digest,
            now=now,
        )
        assert state == "new"


class _AcceptanceUpstream:
    def __init__(self, task: dict[str, Any], project: dict[str, Any]) -> None:
        self.task = json.loads(json.dumps(task))
        self.project = json.loads(json.dumps(project))
        self.mode = "success"
        self.delay = 0.0
        self.accept_calls = 0
        self._lock = threading.Lock()

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        params = request.get("params", {})
        arguments = params.get("arguments", {})
        payload = arguments.get("payload", {})
        if isinstance(payload, str):
            payload = json.loads(payload)
        action = arguments.get("action")
        if params.get("name") == "taskflow" and action == "check_task":
            with self._lock:
                task = json.loads(json.dumps(self.task))
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps({"ok": True, "task": task}),
                        }
                    ]
                },
            }
        if params.get("name") == "projectflow" and action == "resolve_project":
            with self._lock:
                project = json.loads(json.dumps(self.project))
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "ok": True,
                    "tool": "projectflow",
                    "action": action,
                    "project": project,
                },
            }
        if params.get("name") == "projectflow" and action == "accept_task_result":
            with self._lock:
                self.accept_calls += 1
                mode = self.mode
                delay = self.delay
            if delay:
                time.sleep(delay)
            if mode == "fail-before-mutation":
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "result": {
                        "ok": False,
                        "tool": "projectflow",
                        "action": action,
                        "error": "fixture upstream failure",
                    },
                }
            if mode == "raise-before-mutation":
                raise OSError("fixture upstream transport failure")
            task_id = str(payload["taskId"])
            result_status = str(payload["resultStatus"])
            with self._lock:
                node = next(
                    item
                    for item in self.project["tasks"]
                    if item["task_id"] == task_id
                )
                node["status"] = "blocked" if mode == "conflict" else "completed"
                if mode != "conflict":
                    self.project["requester_report"] = {
                        "pending": True,
                        "reason": "task_result_accepted",
                        "task_id": task_id,
                        "result_status": result_status,
                        "summary": str(payload.get("summary") or ""),
                        "report_path": (
                            f"shared/projects/{self.project['project_id']}/result.md"
                        ),
                    }
                project = json.loads(json.dumps(self.project))
            if mode == "raise-after-mutation":
                raise OSError("fixture response lost after mutation")
            if mode == "response-lost":
                return None
            return {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "result": {
                    "ok": True,
                    "tool": "projectflow",
                    "action": action,
                    "project": project,
                },
            }
        raise AssertionError(f"unexpected upstream request: {params.get('name')} {action}")


def _acceptance_fixture(
    tmp_path: Path,
) -> tuple[
    _AcceptanceUpstream,
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    now = datetime.now(timezone.utc)
    ledger = tmp_path / "acceptance-reservation-ledger.json"
    ledger.write_text(
        json.dumps(
            {"schemaVersion": GUARD.TEST_RECEIPT_LEDGER_SCHEMA, "reservations": {}},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    ledger.chmod(0o600)
    task = {
        "task_id": "task-1",
        "project_id": "project-1",
        "assigned_to": "devflow-tester",
        "status": "submitted",
        "result_status": "SUCCESS",
        "summary": "tests passed",
        "deliverables": ["shared/tasks/task-1/result.handoff.json"],
    }
    project = {
        "project_id": "project-1",
        "source": "operator-driven",
        "status": "active",
        "tasks": [{"task_id": "task-1", "status": "submitted"}],
    }
    upstream = _AcceptanceUpstream(task, project)
    policy = {"replayLedgerPath": str(ledger), "maxClockSkewSeconds": 5}
    source = {"run_id": "run-1", "task_id": "task-1"}
    verified: dict[str, str | int] = {
        "jti": "2" * 32,
        "exp": int(now.timestamp()) + 120,
        "receiptSha256": _sha("acceptance-receipt"),
    }
    context = {
        "policy": policy,
        "source": source,
        "verified": verified,
        "validatedAt": now,
    }
    arguments = {
        "action": "accept_task_result",
        "payload": {
            "projectId": "project-1",
            "taskId": "task-1",
            "accepted": True,
            "resultStatus": "SUCCESS",
            "summary": "verified by TeamLeader",
        },
        "workspaceDir": str(tmp_path),
    }
    request = {
        "jsonrpc": "2.0",
        "id": 71,
        "method": "tools/call",
        "params": {"name": "projectflow", "arguments": arguments},
    }
    binding = {
        "riskTier": "T2",
        "source": "operator-driven",
        "incarnation": _sha("incarnation"),
        "audience": "test-audience",
        "approvalDomain": _sha("approval-domain"),
        "policyKeySha256": _sha("policy-key"),
        "projectBindingDigest": _sha("project-binding"),
    }
    contract = GUARD._test_receipt_accept_contract(arguments, task)
    return upstream, request, arguments, binding, context, contract


def _execute_acceptance_fixture(
    fixture: tuple[
        _AcceptanceUpstream,
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ],
) -> dict[str, Any]:
    _upstream, request, arguments, binding, context, contract = fixture
    return cast(
        dict[str, Any],
        GUARD._execute_test_receipt_acceptance(
            request,
            request["id"],
            arguments,
            arguments["workspaceDir"],
            binding,
            context,
            contract,
        ),
    )


def test_handle_request_routes_verified_receipt_through_reservation_protocol(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream, request, _arguments, binding, context, _contract = fixture
    monkeypatch.setattr(GUARD, "upstream", upstream)
    monkeypatch.setattr(
        GUARD,
        "runtime_identity",
        lambda: {
            "role": "leader",
            "runtimeName": "devflow-lead",
            "matrixUserId": "@devflow-lead:matrix.test",
        },
    )
    monkeypatch.setattr(GUARD, "_workspace_path", lambda: tmp_path)
    manifest = tmp_path / "install-manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(GUARD, "INSTALL_MANIFEST", manifest)
    monkeypatch.setattr(GUARD, "_approval_policy", lambda _manifest: {"test": True})
    monkeypatch.setattr(
        GUARD,
        "_verified_project_binding",
        lambda *_args, **_kwargs: (binding, json.loads(json.dumps(upstream.project))),
    )

    def verified_transition(
        _arguments: dict[str, Any],
        _probe: dict[str, Any],
        _task: dict[str, Any],
        _identity: dict[str, str],
        *,
        test_receipt_context: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        assert test_receipt_context is not None
        test_receipt_context.update(context)
        return {"schema": "devflow.agentteams.skill-validation/v1"}

    monkeypatch.setattr(GUARD, "_verify_skill_transition", verified_transition)

    response = GUARD.handle_request(request)

    assert response is not None
    payload = GUARD._action_payload(response)
    assert payload is not None
    assert payload["ok"] is True, payload
    assert upstream.accept_calls == 1
    ledger = json.loads(Path(context["policy"]["replayLedgerPath"]).read_text())
    assert next(iter(ledger["reservations"].values()))["state"] == "committed"


@pytest.mark.parametrize("failure_mode", ["fail-before-mutation", "raise-before-mutation"])
def test_acceptance_failure_releases_receipt_for_exact_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_mode: str
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream = fixture[0]
    monkeypatch.setattr(GUARD, "upstream", upstream)
    upstream.mode = failure_mode

    with pytest.raises(GUARD.GuardPolicyError, match="test_receipt_upstream_not_applied"):
        _execute_acceptance_fixture(fixture)
    ledger = json.loads(Path(fixture[4]["policy"]["replayLedgerPath"]).read_text())
    assert ledger["reservations"] == {}

    upstream.mode = "success"
    response = _execute_acceptance_fixture(fixture)
    assert GUARD._action_payload(response)["ok"] is True
    assert upstream.accept_calls == 2


@pytest.mark.parametrize("loss_mode", ["response-lost", "raise-after-mutation"])
def test_acceptance_response_loss_commits_and_retry_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, loss_mode: str
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream = fixture[0]
    monkeypatch.setattr(GUARD, "upstream", upstream)
    upstream.mode = loss_mode

    first = _execute_acceptance_fixture(fixture)
    upstream.project["requester_report"]["pending"] = False
    upstream.project["requester_report"]["sent_at"] = "2030-01-01T00:00:00Z"
    second = _execute_acceptance_fixture(fixture)

    assert GUARD._action_payload(first)["ok"] is True
    assert GUARD._action_payload(second)["idempotent"] is True
    assert upstream.accept_calls == 1
    ledger = json.loads(Path(fixture[4]["policy"]["replayLedgerPath"]).read_text())
    assert next(iter(ledger["reservations"].values()))["state"] == "committed"


def test_committed_receipt_conflicting_accept_request_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream, request, arguments, binding, context, _contract = fixture
    monkeypatch.setattr(GUARD, "upstream", upstream)
    _execute_acceptance_fixture(fixture)
    conflicting_arguments = json.loads(json.dumps(arguments))
    conflicting_arguments["payload"]["summary"] = "different acceptance summary"
    conflicting_request = dict(request)
    conflicting_request["params"] = {
        "name": "projectflow",
        "arguments": conflicting_arguments,
    }
    conflicting_contract = GUARD._test_receipt_accept_contract(
        conflicting_arguments,
        upstream.task,
    )

    with pytest.raises(
        GUARD.GuardPolicyError, match="test_receipt_reservation_conflict"
    ):
        GUARD._execute_test_receipt_acceptance(
            conflicting_request,
            conflicting_request["id"],
            conflicting_arguments,
            conflicting_arguments["workspaceDir"],
            binding,
            context,
            conflicting_contract,
        )

    assert upstream.accept_calls == 1


def test_concurrent_same_receipt_performs_only_one_upstream_accept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream = fixture[0]
    monkeypatch.setattr(GUARD, "upstream", upstream)
    upstream.delay = 0.15

    def attempt() -> str:
        try:
            _execute_acceptance_fixture(fixture)
            return "ok"
        except (GUARD.GuardPolicyError, ValueError) as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _index: attempt(), range(2)))

    assert "ok" in outcomes
    assert upstream.accept_calls == 1


def test_concurrent_conflicting_receipt_requests_perform_one_upstream_accept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream, request, arguments, binding, context, _contract = fixture
    monkeypatch.setattr(GUARD, "upstream", upstream)
    upstream.delay = 0.15
    conflicting_arguments = json.loads(json.dumps(arguments))
    conflicting_arguments["payload"]["summary"] = "concurrent conflicting summary"
    conflicting_request = dict(request)
    conflicting_request["params"] = {
        "name": "projectflow",
        "arguments": conflicting_arguments,
    }
    conflicting_contract = GUARD._test_receipt_accept_contract(
        conflicting_arguments,
        upstream.task,
    )

    def exact_attempt() -> str:
        try:
            _execute_acceptance_fixture(fixture)
            return "ok"
        except (GUARD.GuardPolicyError, ValueError) as exc:
            return str(exc)

    def conflicting_attempt() -> str:
        try:
            GUARD._execute_test_receipt_acceptance(
                conflicting_request,
                conflicting_request["id"],
                conflicting_arguments,
                conflicting_arguments["workspaceDir"],
                binding,
                context,
                conflicting_contract,
            )
            return "ok"
        except (GUARD.GuardPolicyError, ValueError) as exc:
            return str(exc)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(exact_attempt), pool.submit(conflicting_attempt)]
        outcomes = [future.result() for future in futures]

    assert "ok" in outcomes
    assert upstream.accept_calls == 1


def test_conflicting_authoritative_result_retains_pending_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream = fixture[0]
    monkeypatch.setattr(GUARD, "upstream", upstream)
    upstream.mode = "conflict"

    with pytest.raises(
        GUARD.GuardPolicyError, match="test_receipt_authoritative_conflict"
    ):
        _execute_acceptance_fixture(fixture)
    upstream.mode = "success"
    with pytest.raises(
        GUARD.GuardPolicyError, match="test_receipt_authoritative_conflict"
    ):
        _execute_acceptance_fixture(fixture)

    assert upstream.accept_calls == 1
    ledger = json.loads(Path(fixture[4]["policy"]["replayLedgerPath"]).read_text())
    assert next(iter(ledger["reservations"].values()))["state"] == "pending"


def test_expired_crash_reservation_releases_and_retries_submitted_task(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _acceptance_fixture(tmp_path)
    upstream, _request, _arguments, _binding, context, contract = fixture
    monkeypatch.setattr(GUARD, "upstream", upstream)
    policy = context["policy"]
    source = context["source"]
    verified = context["verified"]
    ledger_path = Path(policy["replayLedgerPath"])
    now = datetime.now(timezone.utc)
    with GUARD._ledger_lock(ledger_path):
        _state, _record = GUARD._reserve_test_execution_receipt_in_locked_ledger(
            policy,
            source,
            verified,
            accept_request_sha256=contract["acceptRequestSha256"],
            accept_result_sha256=contract["acceptResultSha256"],
            now=now,
        )
        ledger = GUARD._read_test_receipt_ledger(ledger_path)
        record = ledger["reservations"][verified["jti"]]
        record["reservedAt"] = int(now.timestamp()) - 60
        record["leaseExpiresAt"] = int(now.timestamp()) - 30
        GUARD._write_ledger(ledger_path, ledger)

    response = _execute_acceptance_fixture(fixture)

    assert GUARD._action_payload(response)["ok"] is True
    assert upstream.accept_calls == 1


def _openssl() -> Path:
    discovered = shutil.which("openssl")
    candidates = [
        Path(discovered) if discovered else None,
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path("/usr/bin/openssl"),
    ]
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    pytest.skip("OpenSSL with Ed25519 support is unavailable")


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_sha(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _key_pair(root: Path, label: str) -> tuple[Path, Path, Path, str]:
    openssl = _openssl()
    private_key = root / f"{label}-private.pem"
    public_key = root / f"{label}-public.pem"
    generated = subprocess.run(
        [str(openssl), "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        capture_output=True,
        check=False,
    )
    if generated.returncode != 0:
        pytest.skip("OpenSSL cannot generate Ed25519 fixtures")
    exported = subprocess.run(
        [
            str(openssl),
            "pkey",
            "-in",
            str(private_key),
            "-pubout",
            "-out",
            str(public_key),
        ],
        capture_output=True,
        check=False,
    )
    assert exported.returncode == 0
    private_key.chmod(0o400)
    public_der = subprocess.run(
        [
            str(openssl),
            "pkey",
            "-pubin",
            "-in",
            str(public_key),
            "-outform",
            "DER",
        ],
        capture_output=True,
        check=True,
    ).stdout
    return openssl, private_key, public_key, hashlib.sha256(public_der).hexdigest()


def _candidate() -> dict[str, Any]:
    patch = {
        "branch_name": "devflow/issue-17",
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
        "description": "Correct the bounded arithmetic defect.",
    }
    scope = {
        "schema_version": "1.0",
        "located_context_digest": _sha("located-context"),
        "allowed_files": ["calculator.py"],
    }
    return {
        "schema_version": "1.2",
        "issue_id": 17,
        "tier": "T2",
        "patch": patch,
        "candidate_digest": _canonical_sha(patch),
        "evidence_boundary": {
            **scope,
            "scope_digest": _canonical_sha(scope),
        },
        "model_call_attempt": 1,
        "retry_attempt": 1,
        "revision_of": None,
    }


def _test_result() -> dict[str, Any]:
    return {
        "total": 1,
        "passed": 1,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "duration_ms": 7,
        "results": [
            {
                "name": "server-owned-focused-suite",
                "status": "passed",
                "duration_ms": 7,
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
            "command_digest": _sha("command"),
            "baseline_manifest_digest": _sha("baseline"),
            "candidate_baseline_manifest_digest": _sha("baseline"),
            "candidate_pre_run_manifest_digest": _sha("candidate-tests"),
            "candidate_post_run_manifest_digest": _sha("candidate-tests"),
            "added_tests_manifest_digest": _sha("added-tests"),
            "baseline_protected_file_count": 1,
            "added_test_file_count": 0,
            "full_suite": False,
            "verified": True,
            "isolation_boundary": cicd.ISOLATION_BOUNDARY,
        },
    }


def _fixture(
    tmp_path: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], datetime]:
    openssl, private_key, public_key, key_digest = _key_pair(tmp_path, "receipt")
    now = datetime(2030, 1, 1, 0, 0, 30, tzinfo=timezone.utc)
    workspace_binding = _sha("ci-policy")
    server_digest = _sha("ci-server")
    archive_digest = _sha("repository-archive")
    manifest_digest = _sha("repository-manifest")
    revision = "a" * 40
    ci_policy = {
        "repositoryArchiveSha256": archive_digest,
        "repositoryManifestSha256": manifest_digest,
        "serverSha256": server_digest,
        "timeoutSeconds": 60,
        "resourceLimitsApplied": True,
        "resourceLimitLauncherSha256": _sha("resource-limit-launcher"),
        "dynamicCandidateSupported": False,
        "testPathMutationSupported": False,
        "testCompletionPolicy": cicd.TEST_COMPLETION_POLICY,
        "minimumExecutedTests": 1,
        "remainingThreat": (
            "Worker code is separated; CI pod root, node root, and kernel remain threats."
        ),
    }
    candidate = _candidate()
    assignment = {
        "projectId": "project-17",
        "runId": "run-17",
        "issueId": 17,
        "taskId": "task-17-test",
        "revision": revision,
        "workspaceBinding": workspace_binding,
        "candidateDigest": candidate["candidate_digest"],
        "fullSuite": False,
    }
    signer = cicd.OpenSSLEd25519ReceiptSigner(
        private_key,
        openssl_path=openssl,
    )
    assert signer.public_key_sha256 == key_digest
    inline = cicd._signed_test_evidence(
        _test_result(),
        assignment,
        candidate,
        ci_policy,
        signer,
        now=int(now.timestamp()),
        jti="1" * 32,
    )
    source = {
        "envelope_version": "1.0",
        "run_id": assignment["runId"],
        "issue_id": assignment["issueId"],
        "task_id": assignment["taskId"],
        "producer": "TeamLeader",
        "consumer": "TesterAgent",
        "skill": "test-runner",
        "trace_id": f'{assignment["runId"]}:{assignment["taskId"]}',
        "idempotency_key": "unused-in-direct-verifier",
        "created_at": (now - timedelta(seconds=5)).isoformat(),
        "status": "ready",
        "artifact": {
            "type": "PatchCandidate",
            "schema_version": "1.2",
            "inline": candidate,
            "sha256": _canonical_sha(candidate),
        },
    }
    ledger = tmp_path / "test-receipt-ledger.json"
    ledger.write_text(
        json.dumps(
            {"schemaVersion": GUARD.TEST_RECEIPT_LEDGER_SCHEMA, "reservations": {}},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    ledger.chmod(0o600)
    policy_path = tmp_path / "test-receipt-policy.json"
    policy = {
        "schemaVersion": "1.0",
        "algorithm": GUARD.TEST_RECEIPT_ALGORITHM,
        "audience": GUARD.TEST_RECEIPT_AUDIENCE,
        "issuer": GUARD.TEST_RECEIPT_ISSUER,
        "signatureDomain": GUARD.TEST_RECEIPT_SCHEMA,
        "publicKeyPath": str(public_key),
        "publicKeyFileSha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "publicKeySha256": key_digest,
        "policyAttestationPath": str(policy_path),
        "opensslPath": str(openssl),
        "replayLedgerPath": str(ledger),
        "replayScope": GUARD.TEST_RECEIPT_REPLAY_SCOPE,
        "replayLedgerPersistentAcrossPodReplacement": (
            GUARD.TEST_RECEIPT_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        ),
        "receiptLifetimeSeconds": GUARD.TEST_RECEIPT_LIFETIME_SECONDS,
        "maxReceiptLifetimeSeconds": GUARD.TEST_RECEIPT_LIFETIME_SECONDS,
        "maxClockSkewSeconds": 5,
        "ciServerSha256": server_digest,
        "ciPolicySha256": workspace_binding,
        "repositoryArchiveSha256": archive_digest,
        "repositoryManifestSha256": manifest_digest,
        "repositoryRevision": revision,
        "remainingThreat": (
            "The key is absent from Workers; CI pod root, node root, and kernel "
            "remain threats. The replay ledger is Pod-local; Leader Pod replacement "
            "can lose replay history for the 120-second receipt lifetime."
        ),
    }
    policy_path.write_text(json.dumps(policy, sort_keys=True), encoding="utf-8")
    return policy, source, inline, now


def test_fixed_policy_verifies_signature_and_consumes_jti_once(tmp_path: Path) -> None:
    policy, source, inline, now = _fixture(tmp_path)
    manifest = {
        "sourcePolicy": "test-only",
        "testExecutionReceiptPolicy": policy,
    }

    assert GUARD._test_execution_receipt_policy(manifest) == policy
    verified = GUARD._verify_test_execution_receipt(
        policy,
        source,
        inline,
        now=now,
    )
    GUARD._consume_test_execution_receipt(
        policy,
        source,
        verified,
        now=now,
    )
    with pytest.raises(GUARD.GuardPolicyError, match="test_receipt_replayed"):
        GUARD._consume_test_execution_receipt(
            policy,
            source,
            verified,
            now=now,
        )


def test_missing_production_policy_attestation_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _source, _inline, _now = _fixture(tmp_path)
    missing_policy = tmp_path / "missing-production-policy.json"
    monkeypatch.setattr(GUARD, "PRODUCTION_TEST_RECEIPT_POLICY", missing_policy)
    policy.update(
        publicKeyPath=str(GUARD.PRODUCTION_TEST_RECEIPT_PUBLIC_KEY),
        policyAttestationPath=str(missing_policy),
        replayLedgerPath=str(GUARD.PRODUCTION_TEST_RECEIPT_LEDGER),
        opensslPath=str(GUARD.PRODUCTION_OPENSSL),
    )
    manifest = {
        "sourcePolicy": "production-pinned",
        "testExecutionReceiptPolicy": policy,
        "testExecutionReceiptPolicyPath": str(missing_policy),
        "testExecutionReceiptPolicySha256": "a" * 64,
        "testExecutionReceiptPublicKeyPath": str(
            GUARD.PRODUCTION_TEST_RECEIPT_PUBLIC_KEY
        ),
        "testExecutionReceiptPublicKeyFileSha256": policy[
            "publicKeyFileSha256"
        ],
    }

    assert GUARD._test_execution_receipt_policy(manifest) is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda policy, source, inline: source.update(task_id="other-task"),
        lambda policy, source, inline: inline.update(revision="b" * 40),
        lambda policy, source, inline: inline["repository"].update(
            archive_sha256=_sha("other-repository")
        ),
        lambda policy, source, inline: source["artifact"]["inline"].update(
            candidate_digest=_sha("other-candidate")
        ),
        lambda policy, source, inline: source["artifact"]["inline"]["patch"][
            "changes"
        ][0].update(new_content="def add(a, b):\n    return a + b + 0\n"),
        lambda policy, source, inline: source["artifact"]["inline"][
            "evidence_boundary"
        ].update(allowed_files=["calculator.py", "other.py"]),
        lambda policy, source, inline: source["artifact"].update(
            sha256=_sha("other-source-artifact")
        ),
        lambda policy, source, inline: policy.update(repositoryRevision="b" * 40),
        lambda policy, source, inline: inline["test_result"].update(duration_ms=99),
        lambda policy, source, inline: inline.update(execution_profile="full"),
        lambda policy, source, inline: policy.update(ciPolicySha256=_sha("other-policy")),
        lambda policy, source, inline: inline["test_execution_receipt"].update(
            signature=(
                ("A" if inline["test_execution_receipt"]["signature"][0] != "A" else "B")
                + inline["test_execution_receipt"]["signature"][1:]
            )
        ),
    ],
    ids=[
        "cross-task",
        "cross-revision",
        "cross-repository",
        "cross-candidate",
        "cross-patch-content",
        "cross-evidence-scope",
        "cross-source-artifact",
        "cross-policy-revision",
        "cross-result",
        "cross-profile",
        "cross-policy",
        "fake-signature",
    ],
)
def test_receipt_rejects_every_cross_boundary_or_fake_signature(
    tmp_path: Path,
    mutation: Any,
) -> None:
    policy, source, inline, now = _fixture(tmp_path)
    mutation(policy, source, inline)

    with pytest.raises(GUARD.GuardPolicyError):
        GUARD._verify_test_execution_receipt(
            policy,
            source,
            inline,
            now=now,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda candidate: candidate["patch"]["changes"][0].update(
            new_content="def add(a, b):\n    return a + b + 0\n"
        ),
        lambda candidate: candidate["evidence_boundary"].update(
            allowed_files=["calculator.py", "other.py"]
        ),
    ],
    ids=["patch-digest-drift", "scope-digest-drift"],
)
def test_receipt_rejects_canonical_source_with_unbound_candidate_lineage(
    tmp_path: Path,
    mutation: Any,
) -> None:
    policy, source, inline, now = _fixture(tmp_path)
    candidate = source["artifact"]["inline"]
    mutation(candidate)
    # Keep the outer source artifact canonical: the inner patch/scope lineage
    # check must independently reject this drift.
    source["artifact"]["sha256"] = _canonical_sha(candidate)

    with pytest.raises(
        GUARD.GuardPolicyError,
        match="test_receipt_source_lineage_invalid",
    ):
        GUARD._verify_test_execution_receipt(
            policy,
            source,
            inline,
            now=now,
        )


def test_receipt_rejects_a_different_canonical_patch_even_with_fresh_digest(
    tmp_path: Path,
) -> None:
    policy, source, inline, now = _fixture(tmp_path)
    candidate = source["artifact"]["inline"]
    candidate["patch"]["changes"][0]["new_content"] = (
        "def add(a, b):\n    return a + b + 0\n"
    )
    candidate["candidate_digest"] = _canonical_sha(candidate["patch"])
    source["artifact"]["sha256"] = _canonical_sha(candidate)

    with pytest.raises(GUARD.GuardPolicyError, match="test_receipt_binding_invalid"):
        GUARD._verify_test_execution_receipt(
            policy,
            source,
            inline,
            now=now,
        )


def test_receipt_rejects_expired_evidence(tmp_path: Path) -> None:
    policy, source, inline, now = _fixture(tmp_path)

    with pytest.raises(GUARD.GuardPolicyError, match="test_receipt_expired"):
        GUARD._verify_test_execution_receipt(
            policy,
            source,
            inline,
            now=now + timedelta(minutes=10),
        )


def test_receipt_rejects_a_different_fixed_deployment_key(tmp_path: Path) -> None:
    policy, source, inline, now = _fixture(tmp_path)
    openssl, _private_key, public_key, key_digest = _key_pair(tmp_path, "other")
    policy["publicKeyPath"] = str(public_key)
    policy["publicKeyFileSha256"] = hashlib.sha256(public_key.read_bytes()).hexdigest()
    policy["publicKeySha256"] = key_digest
    policy["opensslPath"] = str(openssl)

    with pytest.raises(GUARD.GuardPolicyError):
        GUARD._verify_test_execution_receipt(
            policy,
            source,
            inline,
            now=now,
        )


def test_private_key_path_is_ci_only_and_not_a_worker_configuration_surface() -> None:
    source = (ROOT / "agentteams/cicd/tester_server.py").read_text(encoding="utf-8")
    skill = (ROOT / "skills/test-runner/SKILL.md").read_text(encoding="utf-8")

    assert cicd.TEST_EXECUTION_RECEIPT_PRIVATE_KEY.as_posix().startswith(
        "/var/run/secrets/"
    )
    assert "DEVFLOW_TEST_RECEIPT_PRIVATE_KEY" not in source
    assert "Never mount it\nin the Tester Worker" in skill
    assert "same UID/root" in skill

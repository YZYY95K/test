"""Capability-gated GitHub delegation tests for the TeamHarness guard."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
import types
import uuid
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "agentteams" / "teamharness" / "guarded_server.py"
NOW = dt.datetime(2026, 7, 27, 12, 0, tzinfo=dt.timezone.utc)
REVISION = "a" * 40
TOKEN_MARKER = "token-material-must-not-escape"
TEST_TASK_ROOM_ID = "!" + "task" + ":" + "matrix.test"
TEST_BOUND_ROOM_ID = "!" + "bounded" + ":" + "matrix.test"
TEST_APPROVAL_DOMAIN = "d" * 64
TEST_POLICY_KEY_SHA256 = "e" * 64


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _request_document(**updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": "devflow.github-assignment-request/v1",
        "run_id": "run-1",
        "issue_id": 7,
        "task_id": "7-locate",
        "trace_id": "run-1:7-locate",
        "idempotency_key": ("run-1:7-locate:devflow-locator:github-evidence"),
        "repository": {"owner": "example", "repo": "repo"},
        "revision": REVISION,
        "paths": ["README.md", "src/app.py"],
    }
    value.update(updates)
    return value


def _task_request(
    *,
    spec: str | None = None,
    task_id: str = "7-locate",
    assigned_to: str = "devflow-locator",
    action: str = "delegate_task",
    extra_arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "projectId": "project-7",
        "taskId": task_id,
        "assignedTo": assigned_to,
        "roomId": TEST_TASK_ROOM_ID,
        "spec": spec if spec is not None else _canonical(_request_document()).decode("utf-8"),
    }
    arguments: dict[str, Any] = {"action": action, "payload": payload}
    if extra_arguments:
        arguments.update(extra_arguments)
    return {
        "jsonrpc": "2.0",
        "id": 41,
        "method": "tools/call",
        "params": {"name": "taskflow", "arguments": arguments},
    }


def _issuer_response(
    scope: dict[str, Any],
    *,
    claim_updates: dict[str, Any] | None = None,
    response_updates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    issued = int(NOW.timestamp()) - 1
    expires = issued + 120
    claims: dict[str, Any] = {
        "schema": "devflow.github-content-capability/v2",
        **scope,
        "iat": issued,
        "exp": expires,
        "jti": "b" * 32,
    }
    if claim_updates:
        claims.update(claim_updates)
    capability = f"{_b64url(_canonical(claims))}.{_b64url(b's' * 32)}"
    response: dict[str, Any] = {
        "schema": "devflow.github-content-capability/v2",
        "capability": capability,
        "expires_at": claims["exp"],
        "jti": claims["jti"],
    }
    if response_updates:
        response.update(response_updates)
    return response


class _FakeIssuer:
    def __init__(
        self,
        *,
        claim_updates: dict[str, Any] | None = None,
        response_updates: dict[str, Any] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.claim_updates = claim_updates
        self.response_updates = response_updates
        self.failure = failure
        self.calls = 0
        self.scope: dict[str, Any] | None = None
        self.token_sha256 = ""

    def issue(self, scope: dict[str, Any], bearer_token: str) -> dict[str, Any]:
        self.calls += 1
        self.scope = scope
        self.token_sha256 = hashlib.sha256(bearer_token.encode("ascii")).hexdigest()
        if self.failure is not None:
            raise self.failure
        return _issuer_response(
            scope,
            claim_updates=self.claim_updates,
            response_updates=self.response_updates,
        )


def _load_guard(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    role: str = "leader",
    patch_workspace: bool = True,
) -> Any:
    upstream = types.ModuleType("server")
    upstream_any: Any = upstream
    upstream_any.list_tools = lambda: [
        {
            "name": "taskflow",
            "description": "upstream task flow",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "spec": {"type": "string"},
                    "assignedTo": {"type": "string"},
                },
                "additionalProperties": True,
            },
        }
    ]

    def handle_request(request: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"ok": True, "upstreamRequest": request},
        }

    upstream_any.handle_request = handle_request
    monkeypatch.setitem(sys.modules, "server", upstream)
    name = f"teamharness_guard_fixture_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(name, GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)
    identity = {
        "role": role,
        "runtimeName": ("devflow-lead" if role == "leader" else "devflow-locator"),
        "matrixUserId": (
            "@devflow-lead:matrix.test" if role == "leader" else "@devflow-locator:matrix.test"
        ),
        "hostname": "pod-fixture",
        "teamName": "devflow-swe",
        "memberName": "member-fixture",
        "podName": "pod-fixture",
    }
    monkeypatch.setattr(module, "runtime_identity", lambda: identity)
    if patch_workspace:
        monkeypatch.setattr(module, "_workspace_path", lambda: tmp_path)
    return module


def _token_file(tmp_path: Path, payload: str = TOKEN_MARKER) -> Path:
    path = tmp_path / "projected-token"
    path.write_text(payload, encoding="ascii")
    path.chmod(0o444)
    return path


def _call(
    guard: Any,
    request: dict[str, Any],
    issuer: _FakeIssuer,
    token_path: Path,
) -> dict[str, Any]:
    response = guard.handle_request(
        request,
        github_issuer=issuer,
        github_clock=lambda: NOW,
        github_token_path=token_path,
    )
    assert isinstance(response, dict)
    return response


def _error(response: dict[str, Any]) -> str:
    payload = json.loads(response["result"]["content"][0]["text"])
    return str(payload["error"])


def test_skill_validator_pins_match_exact_packaged_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)

    assert set(guard.SKILL_VALIDATOR_FILES) == set(guard.SKILL_VALIDATION_POLICIES)
    for skill, files in guard.SKILL_VALIDATOR_FILES.items():
        assert set(files) == {
            "scripts/validate.py",
            "scripts/_contract.py",
            "references/contract.yaml",
        }
        for relative, expected in files.items():
            data = (ROOT / "skills" / skill / relative).read_bytes()
            assert expected == (len(data), hashlib.sha256(data).hexdigest())


def test_valid_request_becomes_complete_canonical_handoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer()
    token_path = _token_file(tmp_path)

    response = _call(
        guard,
        _task_request(extra_arguments={"tokenPath": "/tmp/attacker"}),
        issuer,
        token_path,
    )

    assert issuer.calls == 1
    assert issuer.scope == {
        "run_id": "run-1",
        "task_id": "7-locate",
        "trace_id": "run-1:7-locate",
        "owner": "example",
        "repo": "repo",
        "revision": REVISION,
        "paths": ["README.md", "src/app.py"],
    }
    assert issuer.token_sha256 == hashlib.sha256(TOKEN_MARKER.encode("ascii")).hexdigest()
    upstream_arguments = response["result"]["upstreamRequest"]["params"]["arguments"]
    spec = upstream_arguments["payload"]["spec"]
    assert upstream_arguments["spec"] == spec
    assert spec == _canonical(json.loads(spec)).decode("utf-8")
    envelope = json.loads(spec)
    assert set(envelope) == {
        "envelope_version",
        "run_id",
        "issue_id",
        "task_id",
        "producer",
        "consumer",
        "skill",
        "trace_id",
        "idempotency_key",
        "created_at",
        "status",
        "artifact",
    }
    assert envelope["producer"] == "devflow-lead"
    assert envelope["consumer"] == "devflow-locator"
    assert envelope["skill"] == "github-evidence"
    assert envelope["created_at"] == "2026-07-27T12:00:00Z"
    inline = envelope["artifact"]["inline"]
    assert envelope["artifact"]["sha256"] == hashlib.sha256(_canonical(inline)).hexdigest()


def test_ordinary_non_github_task_passes_without_token_or_issuer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer(failure=AssertionError("issuer must not be called"))
    request = _task_request(
        spec="Inspect the regression and return exact test evidence.",
        assigned_to="devflow-tester",
    )

    response = _call(guard, request, issuer, tmp_path / "missing-token")

    assert issuer.calls == 0
    arguments = response["result"]["upstreamRequest"]["params"]["arguments"]
    assert arguments["payload"]["spec"] == (
        "Inspect the regression and return exact test evidence."
    )


@pytest.mark.parametrize(
    ("tool_request", "expected"),
    [
        (
            _task_request(assigned_to="devflow-coder"),
            "github_assignment_scope_mismatch",
        ),
        (
            _task_request(task_id="wrong-task"),
            "github_assignment_scope_mismatch",
        ),
        (
            _task_request(action="check_task"),
            "github_assignment_scope_mismatch",
        ),
    ],
)
def test_github_schema_never_passes_wrong_target_or_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tool_request: dict[str, Any],
    expected: str,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer()

    response = _call(guard, tool_request, issuer, _token_file(tmp_path))

    assert _error(response) == expected
    assert issuer.calls == 0


def test_worker_cannot_forward_github_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path, role="worker")
    issuer = _FakeIssuer()

    response = _call(
        guard,
        _task_request(action="ack_task"),
        issuer,
        _token_file(tmp_path),
    )

    assert _error(response) == "github_assignment_scope_mismatch"
    assert issuer.calls == 0


@pytest.mark.parametrize(
    "spec",
    [
        (
            '{"schema":"devflow.github-assignment-request/v1",'
            '"schema":"devflow.github-assignment-request/v1"}'
        ),
        _canonical(_request_document(unexpected=True)).decode("utf-8"),
        _canonical(_request_document(schema="devflow.github-assignment-request/v2")).decode(
            "utf-8"
        ),
        _canonical(_request_document(paths=["src/app.py", "README.md"])).decode("utf-8"),
        json.dumps(_request_document(), indent=2),
    ],
)
def test_duplicate_unknown_or_noncanonical_request_json_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spec: str,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer()

    response = _call(guard, _task_request(spec=spec), issuer, _token_file(tmp_path))

    assert _error(response) == "github_assignment_invalid"
    assert issuer.calls == 0


@pytest.mark.parametrize("failure", ["empty", "writable", "symlink"])
def test_token_file_is_nonempty_nonwritable_and_not_attacker_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer()
    token_path = tmp_path / "token"
    if failure == "empty":
        token_path.write_bytes(b"")
        token_path.chmod(0o444)
    elif failure == "writable":
        token_path.write_text(TOKEN_MARKER, encoding="ascii")
        token_path.chmod(0o666)
    else:
        target = _token_file(tmp_path)
        try:
            os.symlink(target, token_path)
        except OSError:
            pytest.skip("symbolic links are unavailable")

    response = _call(guard, _task_request(), issuer, token_path)

    assert _error(response) == "github_service_account_token_invalid"
    assert issuer.calls == 0


def test_projected_token_accepts_a_resolved_parent_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    real_mount = tmp_path / "run" / "secrets" / "agentteams"
    timestamp = real_mount / "..2026_07_27_00_00_00"
    timestamp.mkdir(parents=True)
    token = timestamp / "token"
    token.write_text(TOKEN_MARKER, encoding="ascii")
    token.chmod(0o444)
    try:
        os.symlink(timestamp.name, real_mount / "..data", target_is_directory=True)
        os.symlink("..data/token", real_mount / "token")
        alias_mount = tmp_path / "var-run-secrets-agentteams"
        os.symlink(real_mount, alias_mount, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")
    projected = alias_mount / "token"
    monkeypatch.setattr(guard, "PRODUCTION_SERVICE_ACCOUNT_TOKEN", projected)

    assert guard._service_account_token(projected) == TOKEN_MARKER


def test_issuer_failure_is_stable_and_scrubs_sensitive_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer(failure=RuntimeError(TOKEN_MARKER))

    response = _call(guard, _task_request(), issuer, _token_file(tmp_path))

    rendered = json.dumps(response, sort_keys=True)
    assert _error(response) == "github_issuer_unavailable"
    assert TOKEN_MARKER not in rendered
    assert "capability" not in rendered


@pytest.mark.parametrize(
    "claim_updates",
    [
        {"run_id": "other-run"},
        {"task_id": "other-task"},
        {"trace_id": "run-1:other-task"},
        {"repo": "different"},
        {"paths": ["README.md"]},
    ],
)
def test_issuer_scope_mismatch_fails_before_upstream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claim_updates: dict[str, Any],
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    issuer = _FakeIssuer(claim_updates=claim_updates)

    response = _call(guard, _task_request(), issuer, _token_file(tmp_path))

    assert _error(response) == "github_issuer_scope_mismatch"


@pytest.mark.parametrize(
    "issuer",
    [
        _FakeIssuer(response_updates={"unexpected": True}),
        _FakeIssuer(response_updates={"schema": "unknown/v1"}),
        _FakeIssuer(response_updates={"capability": "malformed"}),
        _FakeIssuer(response_updates={"expires_at": True}),
        _FakeIssuer(claim_updates={"exp": int(NOW.timestamp()) - 1}),
    ],
)
def test_malformed_issuer_response_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    issuer: _FakeIssuer,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)

    response = _call(guard, _task_request(), issuer, _token_file(tmp_path))

    assert _error(response) == "github_issuer_response_invalid"


def test_leader_tools_list_exposes_exact_request_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)

    response = guard.handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})

    taskflow = response["result"]["tools"][0]
    description = taskflow["inputSchema"]["properties"]["spec"]["description"]
    assert "devflow.github-assignment-request/v1" in description
    assert "Unknown or duplicate fields fail closed" in description
    assert "devflow-locator" in description
    assert "token path" in description


class _MatrixReader:
    def __init__(self, state: dict[str, Any]) -> None:
        self.state = state
        self.room_id = ""

    def read(self, room_id: str) -> dict[str, Any]:
        self.room_id = room_id
        return self.state


def _matrix_state(
    members: dict[str, str],
    *,
    join_rule: str = "invite",
) -> dict[str, Any]:
    return {
        "joinRules": {"join_rule": join_rule},
        "members": {
            "chunk": [
                {
                    "state_key": user_id,
                    "content": {"membership": membership},
                }
                for user_id, membership in members.items()
            ]
        },
    }


def _room_response(invites: list[str]) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 9,
        "result": {
            "ok": True,
            "tool": "roomflow",
            "action": "create_task_room",
            "roomId": TEST_BOUND_ROOM_ID,
            "content": {
                "preset": "trusted_private_chat",
                "invite": invites,
            },
        },
    }


def _project_binding(guard: Any) -> dict[str, Any]:
    binding = {
        "riskTier": "T2",
        "createdTargetDigest": "a" * 64,
        "source": "operator-driven",
        "incarnation": "b" * 64,
        "audience": guard.APPROVAL_AUDIENCE,
        "approvalDomain": TEST_APPROVAL_DOMAIN,
        "policyKeySha256": TEST_POLICY_KEY_SHA256,
    }
    binding["projectBindingDigest"] = guard._project_binding_digest(
        "project-7", binding
    )
    return binding


def test_private_room_result_is_actual_state_attestation_not_full_member_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    locator = "@devflow-locator:matrix.test"
    leader = "@devflow-lead:matrix.test"
    reader = _MatrixReader(_matrix_state({leader: "join", locator: "invite"}))

    upstream_response = _room_response([locator])
    upstream_response["debug"] = TOKEN_MARKER
    upstream_response["result"]["debug"] = TOKEN_MARKER
    response = guard._attest_task_room_response(
        upstream_response,
        identity=guard.runtime_identity(),
        project_id="project-7",
        invitees=[locator],
        binding=_project_binding(guard),
        state_reader=reader,
    )

    result = response["result"]
    assert result["private"] is True
    assert result["invite"] == result["members"] == [locator]
    assert result["membershipProjection"] == (
        "non-creator-requested-worker-invitees"
    )
    assert result["creator"] == leader
    assert result["joinRule"] == "invite"
    assert result["membershipStateVerified"] is True
    assert result["authorizedMemberCount"] == 2
    assert re.fullmatch(r"[0-9a-f]{64}", result["authorizedMembersSha256"])
    assert result["binding"]["riskTierAuthority"] == "root-only-approval-ledger"
    assert reader.room_id == TEST_BOUND_ROOM_ID
    assert TOKEN_MARKER not in json.dumps(response, sort_keys=True)


@pytest.mark.parametrize(
    "state",
    [
        _matrix_state(
            {
                "@devflow-lead:matrix.test": "join",
                "@devflow-locator:matrix.test": "invite",
                "@unexpected:matrix.test": "join",
            }
        ),
        _matrix_state(
            {
                "@devflow-lead:matrix.test": "join",
                "@devflow-locator:matrix.test": "invite",
            },
            join_rule="public",
        ),
    ],
)
def test_room_attestation_rejects_public_or_extra_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: dict[str, Any],
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    locator = "@devflow-locator:matrix.test"

    with pytest.raises(guard.GuardPolicyError):
        guard._attest_task_room_response(
            _room_response([locator]),
            identity=guard.runtime_identity(),
            project_id="project-7",
            invitees=[locator],
            binding=_project_binding(guard),
            state_reader=_MatrixReader(state),
        )


def test_room_request_shape_rejects_admin_override_and_non_array_invite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    identity = guard.runtime_identity()
    with pytest.raises(guard.GuardPolicyError, match="task_room_invite_invalid"):
        guard._task_room_invitees(
            {
                "payload": {
                    "projectId": "project-7",
                    "invite": "@devflow-locator:matrix.test",
                }
            },
            identity,
        )
    with pytest.raises(
        guard.GuardPolicyError,
        match="task_room_security_override_forbidden",
    ):
        guard._task_room_invitees(
            {
                "payload": {
                    "projectId": "project-7",
                    "invite": ["@devflow-locator:matrix.test"],
                    "admin": "@attacker:matrix.test",
                }
            },
            identity,
        )


def test_room_request_accepts_only_exact_same_homeserver_devflow_worker_roster(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    identity = guard.runtime_identity()
    workers = [
        "@devflow-triage:matrix.test",
        "@devflow-locator:matrix.test",
        "@devflow-coder:matrix.test",
        "@devflow-tester:matrix.test",
        "@devflow-reviewer:matrix.test",
    ]

    assert guard._task_room_invitees(
        {"payload": {"projectId": "project-7", "invite": workers}},
        identity,
    ) == workers

    for invalid in (
        [workers[0], workers[0]],
        ["@unknown-worker:matrix.test"],
        ["@devflow-coder:foreign.test"],
        workers + ["@devflow-locator:matrix.test"],
    ):
        with pytest.raises(
            guard.GuardPolicyError,
            match="task_room_invite_invalid",
        ):
            guard._task_room_invitees(
                {"payload": {"projectId": "project-7", "invite": invalid}},
                identity,
            )


def test_private_room_attestation_accepts_exact_multi_worker_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    leader = "@devflow-lead:matrix.test"
    workers = [
        "@devflow-triage:matrix.test",
        "@devflow-locator:matrix.test",
        "@devflow-coder:matrix.test",
        "@devflow-tester:matrix.test",
        "@devflow-reviewer:matrix.test",
    ]
    state = {leader: "join", **{worker: "invite" for worker in workers}}

    response = guard._attest_task_room_response(
        _room_response(workers),
        identity=guard.runtime_identity(),
        project_id="project-7",
        invitees=workers,
        binding=_project_binding(guard),
        state_reader=_MatrixReader(_matrix_state(state)),
    )

    assert response["result"]["members"] == workers
    assert response["result"]["authorizedMemberCount"] == 6
    assert response["result"]["membershipStateVerified"] is True


def test_create_task_room_handler_binds_project_and_verified_matrix_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    locator = "@devflow-locator:matrix.test"
    leader = "@devflow-lead:matrix.test"
    binding = _project_binding(guard)
    calls = 0

    monkeypatch.setattr(guard, "_load_object", lambda _path: {})
    monkeypatch.setattr(
        guard,
        "_approval_policy",
        lambda _manifest: {
            "ledgerPath": "fixed",
            "audience": guard.APPROVAL_AUDIENCE,
            "approvalDomain": TEST_APPROVAL_DOMAIN,
            "policyKeySha256": TEST_POLICY_KEY_SHA256,
        },
    )

    def verified(*_args: Any, **_kwargs: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        return binding, {"project_id": "project-7", "source": "operator-driven"}

    def room_create(_request: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _room_response([locator])

    monkeypatch.setattr(guard, "_verified_project_binding", verified)
    monkeypatch.setattr(guard.upstream, "handle_request", room_create)
    reader = _MatrixReader(_matrix_state({leader: "join", locator: "invite"}))

    response = guard.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "roomflow",
                "arguments": {
                    "action": "create_task_room",
                    "payload": {
                        "projectId": "project-7",
                        "source": "operator-driven",
                        "invite": [locator],
                    },
                },
            },
        },
        matrix_state_reader=reader,
    )

    assert response["result"]["private"] is True
    assert response["result"]["members"] == [locator]
    assert response["result"]["binding"] == guard._project_binding_attestation(binding)
    assert calls == 1


def test_legacy_project_ledger_entry_upgrades_without_schema_break(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    ledger_path = tmp_path / "approval-ledger.json"
    ledger_path.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "projects": {
                    "project-7": {
                        "riskTier": "T2",
                        "createdTargetDigest": "a" * 64,
                    }
                },
                "usedNonces": {},
            }
        ),
        encoding="utf-8",
    )
    ledger_path.chmod(0o600)

    upgraded = guard._upgrade_legacy_project_binding(
        {
            "ledgerPath": str(ledger_path),
            "audience": guard.APPROVAL_AUDIENCE,
            "approvalDomain": TEST_APPROVAL_DOMAIN,
            "policyKeySha256": TEST_POLICY_KEY_SHA256,
        },
        "project-7",
        "operator-driven",
    )

    persisted = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert persisted["schemaVersion"] == "1.0"
    assert set(persisted) == {"schemaVersion", "projects", "usedNonces"}
    assert upgraded["source"] == "operator-driven"
    assert re.fullmatch(r"[0-9a-f]{64}", upgraded["incarnation"])
    assert re.fullmatch(r"[0-9a-f]{64}", upgraded["projectBindingDigest"])
    assert upgraded["approvalDomain"] == TEST_APPROVAL_DOMAIN


def test_duplicate_or_oversized_payload_json_fails_before_upstream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    with pytest.raises(guard.GuardPolicyError, match="payload_invalid"):
        guard._payload_object({"payload": '{"projectId":"a","projectId":"b"}'})
    with pytest.raises(guard.GuardPolicyError, match="payload_too_large"):
        guard._payload_object({"payload": "x" * (guard.MAX_PAYLOAD_BYTES + 1)})


def test_submit_conflict_rechecks_and_rejects_changed_current_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path, role="worker")
    calls = 0

    def changing_probe(request: dict[str, Any]) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        summary = "original" if calls == 1 else "changed concurrently"
        task = {
            "task_id": "task-7",
            "assigned_to": "devflow-locator",
            "status": "submitted",
            "result_status": "SUCCESS",
            "summary": summary,
            "deliverables": ["shared/tasks/task-7/result.md"],
        }
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {"type": "text", "text": json.dumps({"task": task})}
                ]
            },
        }

    monkeypatch.setattr(guard.upstream, "handle_request", changing_probe)
    response = guard.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 17,
            "method": "tools/call",
            "params": {
                "name": "taskflow",
                "arguments": {
                    "action": "submit_task",
                    "payload": {
                        "taskId": "task-7",
                        "status": "SUCCESS",
                        "summary": "different retry",
                        "deliverables": ["shared/tasks/task-7/result.md"],
                    },
                },
            },
        }
    )

    assert _error(response) == "task_state_changed"
    assert calls == 2


def test_filesync_push_rejects_symlink_anywhere_in_recursive_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    workspace = tmp_path / "role-workspace"
    source = workspace / "shared/projects/project-7"
    source.mkdir(parents=True)
    external = tmp_path / "external.txt"
    external.write_text("outside\n", encoding="utf-8")
    try:
        (source / "linked.txt").symlink_to(external)
    except OSError:
        pytest.skip("host does not permit test symlinks")

    with pytest.raises(guard.GuardPolicyError, match="filesync_symlink_forbidden"):
        guard._prepare_filesync_path(
            workspace,
            "push",
            "shared/projects/project-7/",
            False,
        )


@pytest.mark.parametrize("action", ["push", "pull"])
def test_filesync_rejects_symlinked_shared_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    workspace = tmp_path / "role-workspace"
    workspace.mkdir()
    external = tmp_path / "external-shared"
    (external / "projects/project-7").mkdir(parents=True)
    try:
        (workspace / "shared").symlink_to(external, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit test directory symlinks")

    with pytest.raises(guard.GuardPolicyError):
        guard._prepare_filesync_path(
            workspace,
            action,
            "shared/projects/project-7/",
            False,
        )


def test_filesync_push_detects_target_replacement_after_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    workspace = tmp_path / "role-workspace"
    source = workspace / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "result.md").write_text("before\n", encoding="utf-8")
    attestation = guard._prepare_filesync_path(
        workspace,
        "push",
        "shared/projects/project-7/",
        False,
    )
    original = source.with_name("project-7-original")
    source.rename(original)
    source.mkdir()
    (source / "result.md").write_text("replacement\n", encoding="utf-8")

    with pytest.raises(guard.GuardPolicyError, match="filesync_path_replaced"):
        guard._verify_filesync_path(attestation)


def test_filesync_pull_detects_parent_replacement_after_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    workspace = tmp_path / "role-workspace"
    parent = workspace / "shared/tasks"
    parent.mkdir(parents=True)
    attestation = guard._prepare_filesync_path(
        workspace,
        "pull",
        "shared/tasks/task-7/result.md",
        False,
    )
    original = parent.with_name("tasks-original")
    parent.rename(original)
    parent.mkdir()
    (parent / "task-7").mkdir()
    (parent / "task-7/result.md").write_text("replacement\n", encoding="utf-8")

    with pytest.raises(guard.GuardPolicyError, match="filesync_path_replaced"):
        guard._verify_filesync_path(attestation)


def _upstream_filesync_response(
    workspace: Path,
    action: str,
    path: str,
    **updates: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "ok": True,
        "tool": "filesync",
        "action": action,
        "kind": path.split("/", 1)[0],
        "path": path,
        "localPath": str(workspace.joinpath(*path.rstrip("/").split("/"))),
    }
    if action == "push":
        payload["exclude"] = []
    payload.update(updates)
    return {"jsonrpc": "2.0", "id": 41, "result": payload}


def test_filesync_push_rejects_hardlinked_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    original = source / "result.md"
    original.write_text("bounded\n", encoding="utf-8")
    try:
        os.link(original, source / "result-copy.md")
    except OSError:
        pytest.skip("host does not permit hardlink fixtures")

    with pytest.raises(guard.GuardPolicyError, match="filesync_hardlink_forbidden"):
        guard._prepare_filesync_path(
            tmp_path,
            "push",
            "shared/projects/project-7/",
            False,
        )


def test_filesync_push_tree_applies_segment_allowlist_to_descendants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "bad name.md").write_text("bounded\n", encoding="utf-8")

    with pytest.raises(guard.GuardPolicyError, match="filesync_tree_entry_invalid"):
        guard._prepare_filesync_path(
            tmp_path,
            "push",
            "shared/projects/project-7/",
            False,
        )


def test_filesync_push_tree_enforces_total_byte_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    monkeypatch.setattr(guard, "FILESYNC_MAX_TREE_BYTES", 4)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "result.md").write_bytes(b"12345")

    with pytest.raises(guard.GuardPolicyError, match="filesync_tree_too_large"):
        guard._prepare_filesync_path(
            tmp_path,
            "push",
            "shared/projects/project-7/",
            False,
        )


def test_filesync_push_tree_enforces_readback_object_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    monkeypatch.setattr(guard, "FILESYNC_MAX_PUSH_OBJECTS", 1)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "one.md").write_text("one\n", encoding="utf-8")
    (source / "two.md").write_text("two\n", encoding="utf-8")

    with pytest.raises(guard.GuardPolicyError, match="filesync_tree_too_large"):
        guard._prepare_filesync_path(
            tmp_path,
            "push",
            "shared/projects/project-7/",
            False,
        )


def test_filesync_push_detects_in_place_content_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    result = source / "result.md"
    result.write_text("before\n", encoding="utf-8")
    attestation = guard._prepare_filesync_path(
        tmp_path,
        "push",
        "shared/projects/project-7/",
        False,
    )
    result.write_text("after!\n", encoding="utf-8")

    with pytest.raises(guard.GuardPolicyError, match="filesync_path_replaced"):
        guard._verify_filesync_path(attestation)


def test_filesync_pull_requires_a_provable_target_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    target = tmp_path / "shared/tasks/task-7/result.md"
    target.parent.mkdir(parents=True)
    target.write_text("already here\n", encoding="utf-8")
    attestation = guard._prepare_filesync_path(
        tmp_path,
        "pull",
        "shared/tasks/task-7/result.md",
        False,
    )

    with pytest.raises(guard.GuardPolicyError, match="filesync_pull_unverified"):
        guard._verify_filesync_path(attestation)


@pytest.mark.parametrize(
    ("action", "updates"),
    [
        ("list", {}),
        ("stat", {}),
        ("push", {"exclude": None}),
        ("push", {"exclude": ["*"]}),
    ],
)
def test_filesync_success_responses_require_action_specific_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    action: str,
    updates: dict[str, Any],
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    path = "shared/projects/project-7/" if action != "stat" else "shared/result.md"
    response = _upstream_filesync_response(tmp_path, action, path, **updates)

    with pytest.raises(guard.GuardPolicyError, match="filesync_response_invalid"):
        guard._attest_filesync_response(
            response,
            action=action,
            path=path,
            workspace=tmp_path,
            dry_run=False,
        )


@pytest.mark.parametrize(
    "entries",
    [
        ["safe", "bad\x1bcontrol"],
        ["x" * 2_049],
    ],
)
def test_filesync_list_response_rejects_unsafe_or_oversized_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    entries: list[str],
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    path = "shared/projects/project-7/"
    response = _upstream_filesync_response(
        tmp_path,
        "list",
        path,
        entries=entries,
    )

    with pytest.raises(guard.GuardPolicyError, match="filesync_response_invalid"):
        guard._attest_filesync_response(
            response,
            action="list",
            path=path,
            workspace=tmp_path,
            dry_run=False,
        )


@pytest.mark.parametrize(
    ("limit_name", "limit", "entries"),
    [
        ("FILESYNC_MAX_LIST_ENTRIES", 1, ["one", "two"]),
        ("FILESYNC_MAX_LIST_BYTES", 5, ["one", "two"]),
    ],
)
def test_filesync_list_response_enforces_count_and_aggregate_byte_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
    entries: list[str],
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    monkeypatch.setattr(guard, limit_name, limit)
    path = "shared/projects/project-7/"
    response = _upstream_filesync_response(
        tmp_path,
        "list",
        path,
        entries=entries,
    )

    with pytest.raises(guard.GuardPolicyError, match="filesync_response_invalid"):
        guard._attest_filesync_response(
            response,
            action="list",
            path=path,
            workspace=tmp_path,
            dry_run=False,
        )


def test_filesync_push_readback_stats_every_expected_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "meta.json").write_text("{}\n", encoding="utf-8")
    nested = source / "tasks/task-7"
    nested.mkdir(parents=True)
    (nested / "result.md").write_text("done\n", encoding="utf-8")
    attestation = guard._prepare_filesync_path(
        tmp_path,
        "push",
        "shared/projects/project-7/",
        False,
    )
    probed: list[str] = []

    def stat_response(request: dict[str, Any]) -> dict[str, Any]:
        arguments = request["params"]["arguments"]
        assert arguments["action"] == "stat"
        assert arguments["workspaceDir"] == str(tmp_path)
        probed.append(str(arguments["path"]))
        return _upstream_filesync_response(
            tmp_path,
            "stat",
            str(arguments["path"]),
            exists=True,
        )

    monkeypatch.setattr(guard.upstream, "handle_request", stat_response)

    assert guard._verify_filesync_push_readback(41, attestation) == 2
    assert probed == list(attestation.push_objects)
    assert probed == [
        "shared/projects/project-7/meta.json",
        "shared/projects/project-7/tasks/task-7/result.md",
    ]


def test_filesync_push_readback_fails_when_any_object_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "meta.json").write_text("{}\n", encoding="utf-8")
    (source / "result.md").write_text("done\n", encoding="utf-8")
    attestation = guard._prepare_filesync_path(
        tmp_path,
        "push",
        "shared/projects/project-7/",
        False,
    )

    def stat_response(request: dict[str, Any]) -> dict[str, Any]:
        object_path = str(request["params"]["arguments"]["path"])
        return _upstream_filesync_response(
            tmp_path,
            "stat",
            object_path,
            exists=not object_path.endswith("result.md"),
        )

    monkeypatch.setattr(guard.upstream, "handle_request", stat_response)

    with pytest.raises(guard.GuardPolicyError, match="filesync_push_readback_failed"):
        guard._verify_filesync_push_readback(41, attestation)


def test_filesync_handler_never_returns_push_success_without_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path)
    source = tmp_path / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "result.md").write_text("done\n", encoding="utf-8")
    actions: list[str] = []

    def filesync_response(request: dict[str, Any]) -> dict[str, Any]:
        arguments = request["params"]["arguments"]
        action = str(arguments["action"])
        path = str(arguments["path"])
        actions.append(action)
        if action == "push":
            return _upstream_filesync_response(tmp_path, action, path)
        return _upstream_filesync_response(tmp_path, action, path, exists=False)

    monkeypatch.setattr(guard.upstream, "handle_request", filesync_response)
    response = guard.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "filesync",
                "arguments": {
                    "action": "push",
                    "path": "shared/projects/project-7/",
                },
            },
        }
    )

    assert isinstance(response, dict)
    assert _error(response) == "filesync_push_readback_failed"
    assert actions == ["push", "stat"]


@pytest.mark.parametrize(
    "workspace_value",
    [
        "/root/hiclaw-fs/agents/other-runtime",
        "/root/hiclaw-fs/agents/..",
    ],
)
def test_production_workspace_path_is_exactly_bound_to_runtime_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workspace_value: str,
) -> None:
    guard = _load_guard(monkeypatch, tmp_path, patch_workspace=False)
    monkeypatch.setattr(guard, "PRODUCTION_MODE", True)
    monkeypatch.setattr(guard, "PRODUCTION_WORKSPACE_ROOT", Path("/root/hiclaw-fs/agents"))
    monkeypatch.setattr(
        guard,
        "_load_object",
        lambda _path: {
            "workspacePath": workspace_value,
            "runtimeIdentity": {"runtimeName": "devflow-lead"},
        },
    )

    with pytest.raises(ValueError, match="runtime role root"):
        guard._workspace_path()


def test_production_workspace_path_accepts_only_existing_exact_real_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path, patch_workspace=False)
    expected_root = tmp_path / "agents"
    expected_workspace = expected_root / "devflow-lead"
    expected_workspace.mkdir(parents=True)
    monkeypatch.setattr(guard, "PRODUCTION_MODE", True)
    monkeypatch.setattr(guard, "PRODUCTION_WORKSPACE_ROOT", expected_root)
    monkeypatch.setattr(
        guard,
        "_load_object",
        lambda _path: {
            "workspacePath": str(expected_workspace),
            "runtimeIdentity": {"runtimeName": "devflow-lead"},
        },
    )

    assert guard._workspace_path() == expected_workspace


def test_production_workspace_path_rejects_symlinked_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _load_guard(monkeypatch, tmp_path, patch_workspace=False)
    real_root = tmp_path / "real-agents"
    real_workspace = real_root / "devflow-lead"
    real_workspace.mkdir(parents=True)
    linked_parent = tmp_path / "linked"
    try:
        linked_parent.symlink_to(real_root, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit test directory symlinks")
    expected_root = linked_parent
    expected_workspace = expected_root / "devflow-lead"
    monkeypatch.setattr(guard, "PRODUCTION_MODE", True)
    monkeypatch.setattr(guard, "PRODUCTION_WORKSPACE_ROOT", expected_root)
    monkeypatch.setattr(
        guard,
        "_load_object",
        lambda _path: {
            "workspacePath": str(expected_workspace),
            "runtimeIdentity": {"runtimeName": "devflow-lead"},
        },
    )

    with pytest.raises(ValueError, match="real role directory"):
        guard._workspace_path()

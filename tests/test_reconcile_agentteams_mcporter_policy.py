"""Fail-closed tests for the fixed DevFlow mcporter policy reconciler."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts import reconcile_agentteams_mcporter_policy as policy_reconciler
from scripts import teamharness_openclaw
from scripts.reconcile_agentteams_mcporter_policy import (
    CICD_SERVER,
    CICD_URL,
    DEVFLOW_SERVER,
    DEVFLOW_URL,
    LEADER_ROLE,
    LOCATOR_ROLE,
    REMOTE_HELPER,
    STALE_SERVER,
    STALE_URL,
    TEAMHARNESS_APPROVAL_AUDIENCE,
    TEAMHARNESS_APPROVAL_LEDGER_PATH,
    TEAMHARNESS_APPROVAL_POLICY_PATH,
    TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH,
    TEAMHARNESS_CORE_ARTIFACTS,
    TEAMHARNESS_GITHUB_RECEIPT_AUDIENCE,
    TEAMHARNESS_GITHUB_RECEIPT_POLICY_FIELDS,
    TEAMHARNESS_GITHUB_RECEIPT_POLICY_PATH,
    TEAMHARNESS_GITHUB_RECEIPT_PUBLIC_KEY_PATH,
    TEAMHARNESS_GITHUB_RECEIPT_SIGNATURE_DOMAIN,
    TEAMHARNESS_LEADER_ARTIFACTS,
    TEAMHARNESS_LOCATOR_ARTIFACTS,
    TEAMHARNESS_OPENSSL_PATH,
    TEAMHARNESS_POLICY_FIELDS,
    TEAMHARNESS_UPSTREAM_SERVER_PATH,
    TESTER_ROLE,
    PolicyError,
    SubprocessRunner,
    _evaluate_config,
    _expected_cicd_entry,
    _expected_teamharness_entry,
    _trusted_fixed_file,
    _validate_runtime_attestation,
    reconcile,
)
from scripts.reconcile_teamharness_openclaw import (
    EXPECTED_ROLES,
    NAMESPACE,
    RUNTIME_LABEL,
    TEAM_LABEL,
    TEAM_NAME,
    WORKER_LABEL,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile_agentteams_mcporter_policy.py"
SECRET_SENTINEL = "credential-value-must-not-leak"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _bearer(url: str, *, token: str = SECRET_SENTINEL) -> dict[str, Any]:
    return {
        "url": url,
        "transport": "http",
        "headers": {"Authorization": f"Bearer {token}"},
    }


def _config(
    role: str,
    *,
    stale: bool = False,
    extra: tuple[str, Any] | None = None,
) -> dict[str, Any]:
    servers: dict[str, Any] = {"teamharness": _expected_teamharness_entry()}
    if role == LOCATOR_ROLE:
        servers[DEVFLOW_SERVER] = _bearer(DEVFLOW_URL)
    elif role == TESTER_ROLE:
        servers[CICD_SERVER] = _expected_cicd_entry()
    if stale:
        servers[STALE_SERVER] = _bearer(STALE_URL)
    if extra is not None:
        servers[extra[0]] = extra[1]
    return {"mcpServers": servers}


def _runtime_attestation(
    role: str,
) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any], dict[str, str]]:
    teamharness_role = "leader" if role == LEADER_ROLE else "worker"
    runtime_binding = {
        "schemaVersion": "1.0",
        "teamName": TEAM_NAME,
        "memberName": f"member-{role}",
        "runtimeName": role,
        "podName": f"pod-{role}",
        "teamHarnessRole": teamharness_role,
    }
    manifest: dict[str, Any] = {
        "schemaVersion": "1.0",
        "sourcePolicy": "production-pinned",
        "role": teamharness_role,
        "runtimeIdentity": {
            "runtimeName": role,
            "hostname": runtime_binding["podName"],
        },
        "runtimeBinding": runtime_binding,
    }
    artifacts = list(TEAMHARNESS_CORE_ARTIFACTS)
    if role == LEADER_ROLE:
        artifacts.extend(TEAMHARNESS_LEADER_ARTIFACTS)
    digests = {name: _hash(name) for name, _path, _path_field, _sha_field in artifacts}
    for name, path, path_field, sha_field in artifacts:
        manifest[path_field] = path
        manifest[sha_field] = digests[name]

    if role != LEADER_ROLE:
        return manifest, None, runtime_binding, digests

    policy: dict[str, Any] = {
        "schemaVersion": "1.1",
        "algorithm": "Ed25519",
        "audience": TEAMHARNESS_APPROVAL_AUDIENCE,
        "approvalDomain": _hash("approval-domain"),
        "guardSha256": digests["guard"],
        "adapterSha256": digests["adapter"],
        "policyAttestationPath": TEAMHARNESS_APPROVAL_POLICY_PATH,
        "publicKeyPath": TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH,
        "publicKeySha256": digests["approvalPublicKey"],
        "policyKeySha256": digests["approvalPublicKey"],
        "serverSha256": digests["server"],
        "ledgerPath": TEAMHARNESS_APPROVAL_LEDGER_PATH,
        "opensslPath": TEAMHARNESS_OPENSSL_PATH,
        "maxApprovalLifetimeSeconds": 900,
        "remainingThreat": "fixed artifacts must be mounted read-only",
    }
    assert set(policy) == TEAMHARNESS_POLICY_FIELDS
    manifest["approvalPolicy"] = policy
    return manifest, policy, runtime_binding, digests


def _locator_runtime_attestation() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, str],
]:
    manifest, _policy, runtime_binding, digests = _runtime_attestation(
        LOCATOR_ROLE
    )
    for name, path, path_field, sha_field in TEAMHARNESS_LOCATOR_ARTIFACTS:
        digests[name] = _hash(name)
        manifest[path_field] = path
        manifest[sha_field] = digests[name]
    receipt_policy: dict[str, Any] = {
        "schemaVersion": "1.0",
        "algorithm": "Ed25519",
        "audience": TEAMHARNESS_GITHUB_RECEIPT_AUDIENCE,
        "signatureDomain": TEAMHARNESS_GITHUB_RECEIPT_SIGNATURE_DOMAIN,
        "consumerRuntimeName": LOCATOR_ROLE,
        "publicKeyPath": TEAMHARNESS_GITHUB_RECEIPT_PUBLIC_KEY_PATH,
        "publicKeySha256": _hash("github-receipt-key-id"),
        "publicKeyFileSha256": digests["githubReceiptPublicKey"],
        "policyPath": TEAMHARNESS_GITHUB_RECEIPT_POLICY_PATH,
        "opensslPath": TEAMHARNESS_OPENSSL_PATH,
    }
    assert set(receipt_policy) == TEAMHARNESS_GITHUB_RECEIPT_POLICY_FIELDS
    manifest["githubReceiptPolicy"] = receipt_policy
    manifest["githubReceiptKeyIdSha256"] = receipt_policy["publicKeySha256"]
    return manifest, receipt_policy, runtime_binding, digests


def _team() -> dict[str, Any]:
    roles = sorted(EXPECTED_ROLES)
    return {
        "apiVersion": "agentteams.io/v1beta1",
        "kind": "Team",
        "metadata": {"name": TEAM_NAME, "namespace": NAMESPACE},
        "spec": {
            "leader": {"name": "devflow-lead"},
            "workers": [{"name": role} for role in roles if role != "devflow-lead"],
        },
        "status": {
            "members": [
                {
                    "name": f"member-{index}",
                    "runtimeName": role,
                    "matrixUserID": f"@{role}:matrix.example",
                }
                for index, role in enumerate(roles)
            ]
        },
    }


def _pod(member: str, role: str, *, ready: bool = True) -> dict[str, Any]:
    spec: dict[str, Any] = {"containers": [{"name": "worker"}]}
    if role == "devflow-lead":
        spec = {
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
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"pod-{role}",
            "namespace": NAMESPACE,
            "labels": {
                TEAM_LABEL: TEAM_NAME,
                RUNTIME_LABEL: "openclaw",
                WORKER_LABEL: member,
            },
        },
        "spec": spec,
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"name": "worker", "ready": ready}],
        },
    }


def _pods(team: dict[str, Any] | None = None) -> dict[str, Any]:
    team = team or _team()
    return {
        "apiVersion": "v1",
        "kind": "PodList",
        "items": [
            _pod(member["name"], member["runtimeName"]) for member in team["status"]["members"]
        ],
    }


class _FakeRunner:
    def __init__(
        self,
        team: dict[str, Any] | None = None,
        pods: dict[str, Any] | None = None,
        *,
        drift_roles: set[str] | None = None,
    ) -> None:
        self.team = team or _team()
        self.pods = pods or _pods(self.team)
        self.drift_roles = set(drift_roles or set())
        self.calls: list[list[str]] = []

    def run(self, args: list[str]) -> str:
        self.calls.append(list(args))
        if "get" in args and "team" in args:
            return json.dumps(self.team)
        if "get" in args and "pods" in args:
            return json.dumps(self.pods)
        if "exec" not in args:
            return ""
        action, role = args[-5], args[-4]
        desired_names = ["teamharness"]
        if role == LOCATOR_ROLE:
            desired_names.append(DEVFLOW_SERVER)
        elif role == TESTER_ROLE:
            desired_names.append(CICD_SERVER)
        desired_names.sort()
        drift = role in self.drift_roles and action == "check"
        desired_digest = _hash(f"desired:{role}")
        return json.dumps(
            {
                "ok": True,
                "role": role,
                "liveDigest": _hash(f"live:{role}") if drift else desired_digest,
                "desiredDigest": desired_digest,
                "remoteDigest": _hash(f"remote:{role}") if drift else desired_digest,
                "liveServerNames": (
                    sorted([*desired_names, STALE_SERVER]) if drift else desired_names
                ),
                "desiredServerNames": desired_names,
                "remoteServerNames": (
                    sorted([*desired_names, STALE_SERVER]) if drift else desired_names
                ),
                "needsApply": drift,
                "applied": action == "apply",
            }
        )


def _helper_calls(runner: _FakeRunner, action: str) -> list[list[str]]:
    return [args for args in runner.calls if "exec" in args and args[-5] == action]


def test_policy_accepts_exact_role_surfaces_and_removes_only_known_stale() -> None:
    locator_text = json.dumps(_config(LOCATOR_ROLE, stale=True))
    current, desired, names, desired_names, desired_bytes = _evaluate_config(
        locator_text,
        LOCATOR_ROLE,
        require_complete=True,
    )
    worker = _evaluate_config(
        json.dumps(_config("devflow-coder")),
        "devflow-coder",
        require_complete=True,
    )

    assert current != desired
    assert names == [DEVFLOW_SERVER, STALE_SERVER, "teamharness"]
    assert desired_names == [DEVFLOW_SERVER, "teamharness"]
    assert set(json.loads(desired_bytes)["mcpServers"]) == {
        DEVFLOW_SERVER,
        "teamharness",
    }
    assert worker[0] == worker[1]
    assert worker[2] == ["teamharness"]


def test_tester_alone_receives_exact_credential_free_cicd_entry() -> None:
    tester = _evaluate_config(
        json.dumps(_config(TESTER_ROLE)),
        TESTER_ROLE,
        require_complete=True,
    )
    desired = json.loads(tester[4])

    assert tester[0] == tester[1]
    assert tester[2] == [CICD_SERVER, "teamharness"]
    assert desired["mcpServers"][CICD_SERVER] == _expected_cicd_entry()
    assert "env" not in desired["mcpServers"][CICD_SERVER]
    assert set(desired["mcpServers"][CICD_SERVER]) == {
        "transport",
        "url",
    }
    assert desired["mcpServers"][CICD_SERVER]["url"] == CICD_URL

    for role in EXPECTED_ROLES - {TESTER_ROLE}:
        misplaced = _config(role, extra=(CICD_SERVER, _expected_cicd_entry()))
        with pytest.raises(PolicyError):
            _evaluate_config(json.dumps(misplaced), role, require_complete=True)


def test_tester_first_install_treats_missing_fixed_http_entry_as_repairable_drift() -> None:
    current, desired, names, desired_names, desired_bytes = _evaluate_config(
        json.dumps({"mcpServers": {"teamharness": _expected_teamharness_entry()}}),
        TESTER_ROLE,
        require_complete=False,
    )

    assert current != desired
    assert names == ["teamharness"]
    assert desired_names == [CICD_SERVER, "teamharness"]
    assert json.loads(desired_bytes)["mcpServers"][CICD_SERVER] == {
        "transport": "http",
        "url": CICD_URL,
    }


@pytest.mark.parametrize(
    "entry",
    [
        {
            "command": "/bin/sh",
            "args": ["-c", "pytest"],
            "transport": "stdio",
        },
        {
            **_expected_cicd_entry(),
            "env": {"TOKEN": SECRET_SENTINEL},
        },
        {
            **_expected_cicd_entry(),
            "args": ["/tmp/agent-selected.py"],
        },
        {
            **_expected_cicd_entry(),
            "transport": "stdio",
        },
        {
            **_expected_cicd_entry(),
            "url": "http://wrong.agentteams-system.svc.cluster.local:8080/mcp",
        },
    ],
)
def test_tester_cicd_entry_rejects_shell_credentials_paths_and_transport(
    entry: dict[str, Any],
) -> None:
    value = _config(TESTER_ROLE)
    value["mcpServers"][CICD_SERVER] = entry

    with pytest.raises(PolicyError, match="CI/CD"):
        _evaluate_config(json.dumps(value), TESTER_ROLE, require_complete=True)


def test_policy_rejects_arbitrary_program_and_inline_token_regression() -> None:
    value = _config("devflow-coder")
    value["mcpServers"]["teamharness"] = {
        "command": "arbitrary-executable",
        "args": ["--unsafe"],
        "transport": "stdio",
        "env": {"TOKEN": SECRET_SENTINEL},
    }

    with pytest.raises(PolicyError):
        _evaluate_config(
            json.dumps(value),
            "devflow-coder",
            require_complete=True,
        )


@pytest.mark.parametrize(
    ("field", "replacement", "message"),
    [
        ("command", "python3", "executable"),
        ("args", [".teamharness/mcp/guarded_server.py"], "guard path"),
        ("args", [TEAMHARNESS_UPSTREAM_SERVER_PATH], "guard path"),
        ("transport", "sse", "transport"),
        (
            "env",
            {"TEAMHARNESS_SHARED_DIR": "/tmp/shared"},
            "environment",
        ),
        (
            "env",
            {
                "TEAMHARNESS_SHARED_DIR": "/root/hiclaw-fs/shared",
                "API_TOKEN": SECRET_SENTINEL,
            },
            "environment",
        ),
    ],
)
def test_policy_rejects_teamharness_execution_surface_drift(
    field: str,
    replacement: Any,
    message: str,
) -> None:
    value = _config("devflow-coder")
    value["mcpServers"]["teamharness"][field] = replacement

    with pytest.raises(PolicyError, match=message):
        _evaluate_config(
            json.dumps(value),
            "devflow-coder",
            require_complete=True,
        )


def test_policy_rejects_unknown_teamharness_field() -> None:
    value = _config("devflow-coder")
    value["mcpServers"]["teamharness"]["cwd"] = "/tmp"

    with pytest.raises(PolicyError, match="schema"):
        _evaluate_config(
            json.dumps(value),
            "devflow-coder",
            require_complete=True,
        )


def test_runtime_attestation_accepts_exact_worker_and_leader_surfaces() -> None:
    for role in ("devflow-coder", LEADER_ROLE):
        manifest, policy, runtime_binding, digests = _runtime_attestation(role)
        _validate_runtime_attestation(
            manifest,
            policy,
            runtime_binding,
            role,
            digests,
        )


def test_runtime_attestation_accepts_only_exact_locator_receipt_trust() -> None:
    manifest, receipt_policy, runtime_binding, digests = (
        _locator_runtime_attestation()
    )
    _validate_runtime_attestation(
        manifest,
        None,
        runtime_binding,
        LOCATOR_ROLE,
        digests,
        receipt_policy,
    )

    for field, replacement in (
        ("signatureDomain", "attacker-domain"),
        ("publicKeySha256", "0" * 64),
        ("publicKeyFileSha256", "0" * 64),
    ):
        changed_manifest = deepcopy(manifest)
        changed_policy = deepcopy(receipt_policy)
        changed_policy[field] = replacement
        changed_manifest["githubReceiptPolicy"] = changed_policy
        with pytest.raises(PolicyError, match="receipt policy"):
            _validate_runtime_attestation(
                changed_manifest,
                None,
                runtime_binding,
                LOCATOR_ROLE,
                digests,
                changed_policy,
            )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("schemaVersion", "1.0"),
        ("audience", "wrong-audience"),
        ("approvalDomain", "A" * 64),
        ("policyKeySha256", "0" * 64),
    ],
)
def test_runtime_attestation_rejects_weakened_v1_1_approval_binding(
    field: str,
    replacement: str,
) -> None:
    manifest, policy, runtime_binding, digests = _runtime_attestation(LEADER_ROLE)
    assert policy is not None
    policy[field] = replacement
    manifest["approvalPolicy"] = policy

    with pytest.raises(PolicyError, match="approval policy"):
        _validate_runtime_attestation(
            manifest,
            policy,
            runtime_binding,
            LEADER_ROLE,
            digests,
        )


def test_actual_teamharness_policy_matches_reconciler_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_public_key = tmp_path / "external-approval.pub"
    source_public_key.write_bytes(b"test-only-ed25519-public-key-fixture\n")
    installed_public_key = tmp_path / "etc" / "approval-ed25519.pub"
    approval_ledger = tmp_path / "var" / "approval-ledger.json"
    openssl_path = tmp_path / "usr" / "openssl"
    monkeypatch.setattr(
        teamharness_openclaw,
        "_validate_ed25519_public_key",
        lambda *_args: None,
    )

    guard_digest = _hash("guard")
    adapter_digest = _hash("adapter")
    server_digest = _hash("server")
    approval_domain = _hash("deployment-approval-domain")
    policy = teamharness_openclaw._install_approval_policy(
        source_public_key,
        approval_domain,
        installed_public_key,
        approval_ledger,
        openssl_path,
        guard_digest,
        adapter_digest,
        server_digest,
    )
    approval_policy = installed_public_key.with_name("approval-policy.json")
    leader_artifacts = (
        (
            "approvalPolicy",
            str(approval_policy),
            "approvalPolicyPath",
            "approvalPolicySha256",
        ),
        (
            "approvalPublicKey",
            str(installed_public_key),
            "approvalPublicKeyPath",
            "approvalPublicKeySha256",
        ),
    )
    monkeypatch.setattr(
        policy_reconciler,
        "TEAMHARNESS_LEADER_ARTIFACTS",
        leader_artifacts,
    )
    monkeypatch.setattr(
        policy_reconciler,
        "TEAMHARNESS_APPROVAL_POLICY_PATH",
        str(approval_policy),
    )
    monkeypatch.setattr(
        policy_reconciler,
        "TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH",
        str(installed_public_key),
    )
    monkeypatch.setattr(
        policy_reconciler,
        "TEAMHARNESS_APPROVAL_LEDGER_PATH",
        str(approval_ledger),
    )
    monkeypatch.setattr(
        policy_reconciler,
        "TEAMHARNESS_OPENSSL_PATH",
        str(openssl_path),
    )

    runtime_binding = {
        "schemaVersion": "1.0",
        "teamName": TEAM_NAME,
        "memberName": "member-devflow-lead",
        "runtimeName": LEADER_ROLE,
        "podName": "pod-devflow-lead",
        "teamHarnessRole": "leader",
    }
    digests = {
        "guard": guard_digest,
        "adapter": adapter_digest,
        "server": server_digest,
        "runtimeBinding": _hash("runtime-binding"),
        "approvalPolicy": hashlib.sha256(approval_policy.read_bytes()).hexdigest(),
        "approvalPublicKey": hashlib.sha256(
            installed_public_key.read_bytes()
        ).hexdigest(),
    }
    manifest: dict[str, Any] = {
        "schemaVersion": "1.0",
        "sourcePolicy": "production-pinned",
        "role": "leader",
        "runtimeIdentity": {
            "runtimeName": LEADER_ROLE,
            "hostname": runtime_binding["podName"],
        },
        "runtimeBinding": runtime_binding,
        "approvalPolicy": policy,
    }
    artifacts = list(TEAMHARNESS_CORE_ARTIFACTS) + list(leader_artifacts)
    for name, path, path_field, sha_field in artifacts:
        manifest[path_field] = path
        manifest[sha_field] = digests[name]

    policy_reconciler._validate_runtime_attestation(
        manifest,
        policy,
        runtime_binding,
        LEADER_ROLE,
        digests,
    )


def test_runtime_attestation_rejects_path_swap() -> None:
    manifest, policy, runtime_binding, digests = _runtime_attestation("devflow-coder")
    manifest["guardPath"] = "/root/hiclaw-fs/agents/devflow-coder/guarded_server.py"

    with pytest.raises(PolicyError, match="path or digest"):
        _validate_runtime_attestation(
            manifest,
            policy,
            runtime_binding,
            "devflow-coder",
            digests,
        )


def test_trusted_file_rejects_noncanonical_realpath(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    trusted = tmp_path / "trusted"
    workspace.mkdir()
    trusted.mkdir()
    (trusted / "alias-parent").mkdir()
    artifact = trusted / "guarded_server.py"
    artifact.write_text("trusted", encoding="utf-8")
    noncanonical = trusted / "alias-parent" / ".." / artifact.name

    with pytest.raises(PolicyError, match="unsafe"):
        _trusted_fixed_file(str(noncanonical), str(workspace))


def test_trusted_file_rejects_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    trusted = tmp_path / "trusted"
    workspace.mkdir()
    trusted.mkdir()
    artifact = trusted / "guarded_server.py"
    artifact.write_text("trusted", encoding="utf-8")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == artifact or original_is_symlink(path),
    )

    with pytest.raises(PolicyError, match="unsafe"):
        _trusted_fixed_file(str(artifact), str(workspace))


@pytest.mark.parametrize("artifact", ["guard", "adapter", "server", "runtimeBinding"])
def test_runtime_attestation_rejects_core_digest_mismatch(artifact: str) -> None:
    manifest, policy, runtime_binding, digests = _runtime_attestation("devflow-coder")
    digests[artifact] = _hash(f"tampered-{artifact}")

    with pytest.raises(PolicyError, match="digest mismatch"):
        _validate_runtime_attestation(
            manifest,
            policy,
            runtime_binding,
            "devflow-coder",
            digests,
        )


def test_runtime_attestation_rejects_adapter_policy_pin_mismatch() -> None:
    manifest, policy, runtime_binding, digests = _runtime_attestation(LEADER_ROLE)
    assert policy is not None
    policy["adapterSha256"] = _hash("tampered-adapter-policy-pin")
    manifest["approvalPolicy"] = policy

    with pytest.raises(PolicyError, match="approval policy"):
        _validate_runtime_attestation(
            manifest,
            policy,
            runtime_binding,
            LEADER_ROLE,
            digests,
        )


def test_policy_rejects_missing_required_and_unknown_entries() -> None:
    missing: dict[str, Any] = {"mcpServers": {}}
    unknown = _config("devflow-coder", extra=("filesystem", {"command": "fs"}))
    misplaced_devflow = _config(
        "devflow-coder",
        extra=(DEVFLOW_SERVER, _bearer(DEVFLOW_URL)),
    )

    with pytest.raises(PolicyError, match="missing"):
        _evaluate_config(json.dumps(missing), "devflow-coder", require_complete=True)
    for value in (unknown, misplaced_devflow):
        with pytest.raises(PolicyError):
            _evaluate_config(
                json.dumps(value),
                "devflow-coder",
                require_complete=True,
            )


def test_policy_migrates_only_exact_legacy_teamharness_entry() -> None:
    role = "devflow-coder"
    legacy = {
        "mcpServers": {
            "teamharness": {
                "command": "python3",
                "args": [
                    f"/root/hiclaw-fs/agents/{role}/.teamharness/mcp/guarded_server.py"
                ],
                "transport": "stdio",
                "env": {
                    "AGENTTEAMS_AGENT_ROLE": "worker",
                    "TEAMHARNESS_RUNTIME_CONFIG": (
                        f"/root/hiclaw-fs/agents/{role}/runtime/runtime.json"
                    ),
                    "TEAMHARNESS_SHARED_DIR": "/root/hiclaw-fs/shared",
                },
            }
        }
    }

    evaluated = _evaluate_config(json.dumps(legacy), role, require_complete=False)
    desired = json.loads(evaluated[4])

    assert desired["mcpServers"]["teamharness"] == _expected_teamharness_entry()
    assert evaluated[0] != evaluated[1]
    with pytest.raises(PolicyError, match="executable"):
        _evaluate_config(json.dumps(legacy), role, require_complete=True)

    legacy["mcpServers"]["teamharness"]["command"] = "arbitrary-python"
    with pytest.raises(PolicyError, match="executable"):
        _evaluate_config(json.dumps(legacy), role, require_complete=False)


@pytest.mark.parametrize(
    "entry",
    [
        _bearer("http://wrong.example/mcp"),
        _bearer(STALE_URL) | {"transport": "sse"},
        _bearer(STALE_URL) | {"extra": True},
        {"url": STALE_URL, "transport": "http", "headers": {}},
        {
            "url": STALE_URL,
            "transport": "http",
            "headers": {"Authorization": "Basic value"},
        },
    ],
)
def test_policy_refuses_non_exact_stale_github_entry(entry: dict[str, Any]) -> None:
    value = _config("devflow-coder", extra=(STALE_SERVER, entry))

    with pytest.raises(PolicyError, match="exact removable"):
        _evaluate_config(
            json.dumps(value),
            "devflow-coder",
            require_complete=True,
        )


def test_policy_rejects_duplicate_json_fields() -> None:
    duplicate = '{"mcpServers":{},"mcpServers":{}}'

    with pytest.raises(PolicyError, match="duplicate"):
        _evaluate_config(duplicate, "devflow-coder", require_complete=True)


@pytest.mark.parametrize("failure", ["missing", "duplicate", "unready"])
def test_reconcile_rejects_incomplete_or_unready_six_pod_set(failure: str) -> None:
    team = _team()
    pods = _pods(team)
    if failure == "missing":
        pods["items"].pop()
    elif failure == "duplicate":
        pods["items"][-1] = deepcopy(pods["items"][0])
        pods["items"][-1]["metadata"]["name"] = "pod-duplicate"
    else:
        pods["items"][0]["status"]["conditions"][0]["status"] = "False"
        pods["items"][0]["status"]["containerStatuses"][0]["ready"] = False
    runner = _FakeRunner(team, pods)

    with pytest.raises(RuntimeError):
        reconcile(runner)
    assert not _helper_calls(runner, "check")
    assert not _helper_calls(runner, "apply")


def test_default_check_preflights_six_roles_and_never_applies() -> None:
    runner = _FakeRunner(drift_roles={"devflow-coder", LOCATOR_ROLE})

    reports = reconcile(runner)

    assert len(reports) == 6
    names_by_role = {
        report.target.role_name: report.desired_names for report in reports
    }
    assert names_by_role[TESTER_ROLE] == (CICD_SERVER, "teamharness")
    assert names_by_role[LOCATOR_ROLE] == (DEVFLOW_SERVER, "teamharness")
    assert all(
        CICD_SERVER not in names
        for role, names in names_by_role.items()
        if role != TESTER_ROLE
    )
    assert len(_helper_calls(runner, "check")) == 6
    assert not _helper_calls(runner, "apply")
    assert sum(report.needs_apply for report in reports) == 2


def test_apply_starts_only_after_every_preflight_and_updates_drifted_roles() -> None:
    runner = _FakeRunner(drift_roles={"devflow-coder", LOCATOR_ROLE})

    reports = reconcile(runner, apply=True)

    checks = _helper_calls(runner, "check")
    applies = _helper_calls(runner, "apply")
    assert len(checks) == 6
    assert len(applies) == 2
    assert max(runner.calls.index(call) for call in checks) < min(
        runner.calls.index(call) for call in applies
    )
    assert all(not report.needs_apply for report in reports)
    assert {args[-4] for args in applies} == {"devflow-coder", LOCATOR_ROLE}
    assert all(re.fullmatch(r"[0-9a-f]{64}", args[-2]) for args in applies)
    assert all(re.fullmatch(r"[0-9a-f]{64}", args[-1]) for args in applies)


def test_compliant_apply_is_idempotent_and_performs_no_remote_write() -> None:
    runner = _FakeRunner()

    reports = reconcile(runner, apply=True)

    assert len(reports) == 6
    assert not _helper_calls(runner, "apply")


def test_subprocess_failure_never_includes_remote_credentials() -> None:
    runner = SubprocessRunner()
    command = [
        sys.executable,
        "-c",
        (
            "import sys; "
            f"sys.stdout.write({SECRET_SENTINEL!r}); "
            f"sys.stderr.write({SECRET_SENTINEL!r}); "
            "raise SystemExit(1)"
        ),
    ]

    with pytest.raises(PolicyError) as captured:
        runner.run(command)
    assert SECRET_SENTINEL not in str(captured.value)


def test_remote_helper_keeps_sensitive_work_inside_pod() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "os.replace(staged, live_path)" in REMOTE_HELPER
    assert '"--config-dir"' in REMOTE_HELPER
    assert '"AGENTTEAMS_FS_ACCESS_KEY"' in REMOTE_HELPER
    assert '"AGENTTEAMS_FS_SECRET_KEY"' in REMOTE_HELPER
    assert 'os.O_WRONLY | os.O_CREAT | os.O_EXCL' in REMOTE_HELPER
    assert "MC_BINARY_SHA256" in REMOTE_HELPER
    assert "authoritative_config_is_absent" in REMOTE_HELPER
    assert "Only an entirely empty, successful listing" in REMOTE_HELPER
    assert "stdout=subprocess.DEVNULL" in REMOTE_HELPER
    assert "stderr=subprocess.DEVNULL" in REMOTE_HELPER
    assert "verified[0] != live[1]" in REMOTE_HELPER
    assert "_validate_runtime_trust(workspace, role)" in REMOTE_HELPER
    assert "_validate_cicd_runtime(workspace, role)" not in REMOTE_HELPER
    assert CICD_URL in REMOTE_HELPER
    assert "receipt-ed25519.pem" not in REMOTE_HELPER
    assert "path.is_symlink()" in REMOTE_HELPER
    assert "path.resolve(strict=True)" in REMOTE_HELPER
    assert TEAMHARNESS_UPSTREAM_SERVER_PATH in REMOTE_HELPER
    assert "adapterSha256" in REMOTE_HELPER
    assert "Authorization" not in json.dumps(
        {
            "liveDigest": _hash("live"),
            "serverNames": ["teamharness"],
        }
    )
    for verb in ("apply", "create", "patch", "auth"):
        assert f'_kubectl(kubectl, "{verb}"' not in text
    assert "get secret" not in text.lower()
    assert SECRET_SENTINEL not in text


def test_help_runs_without_site_packages_and_defaults_to_check() -> None:
    completed = subprocess.run(
        [sys.executable, "-S", str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--apply" in completed.stdout
    assert "--namespace" not in completed.stdout
    assert "--team" not in completed.stdout

    helper_compile = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "from scripts.reconcile_agentteams_mcporter_policy import "
                "REMOTE_HELPER; compile(REMOTE_HELPER, '<remote-helper>', 'exec')"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert helper_compile.returncode == 0, helper_compile.stderr

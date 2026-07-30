"""Fail-closed tests for host-side TeamHarness reconciliation."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import subprocess
import sys
import tarfile
from copy import deepcopy
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from scripts.reconcile_teamharness_openclaw import (
    EXPECTED_ROLES,
    NAMESPACE,
    TEAM_LABEL,
    TEAM_NAME,
    UPSTREAM_AGENTTEAMS_COMMIT,
    WORKER_LABEL,
    ReconcileError,
    Target,
    _tar_runtime_config,
    discover_targets,
    reconcile,
    validate_sources,
)
from scripts.reconcile_teamharness_openclaw import (
    UPSTREAM_FILE_SHA256 as RECONCILE_SOURCE_HASHES,
)
from scripts.teamharness_openclaw import UPSTREAM_FILE_SHA256

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile_teamharness_openclaw.py"
TEST_APPROVAL_DOMAIN = "d" * 64


def _team() -> dict[str, Any]:
    roles = sorted(EXPECTED_ROLES)
    workers = [role for role in roles if role != "devflow-lead"]
    return {
        "apiVersion": "agentteams.io/v1beta1",
        "kind": "Team",
        "metadata": {"name": TEAM_NAME, "namespace": NAMESPACE},
        "spec": {
            "leader": {"name": "devflow-lead"},
            "workers": [{"name": role} for role in workers],
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


def _pod(member_name: str, role: str, *, ready: bool = True) -> dict[str, Any]:
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
            "name": f"agentteams-worker-{role}",
            "namespace": NAMESPACE,
            "labels": {
                TEAM_LABEL: TEAM_NAME,
                "agentteams.io/runtime": "openclaw",
                WORKER_LABEL: member_name,
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


def test_discovery_accepts_generic_core_v1_list_from_kubectl() -> None:
    pods = _pods()
    pods["kind"] = "List"

    targets = discover_targets(_team(), pods)

    assert {target.role_name for target in targets} == EXPECTED_ROLES


@pytest.mark.parametrize(
    ("api_version", "kind"),
    [("v2", "List"), ("v1", "UnknownList")],
)
def test_discovery_rejects_non_core_or_unknown_collection_kind(api_version: str, kind: str) -> None:
    pods = _pods()
    pods["apiVersion"] = api_version
    pods["kind"] = kind

    with pytest.raises(ReconcileError, match="Pod discovery response is malformed"):
        discover_targets(_team(), pods)


def _write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _public_key_fixture(
    root: Path,
    *,
    name: str = "approval-ed25519.pub",
    key_bytes: bytes = bytes(range(1, 33)),
) -> Path:
    path = root / name
    der = bytes.fromhex("302a300506032b6570032100") + key_bytes
    path.write_bytes(
        b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) + b"\n-----END PUBLIC KEY-----\n"
    )
    return path


def _receipt_public_key_fixture(root: Path) -> Path:
    return _public_key_fixture(
        root,
        name="github-receipt-ed25519.pub",
        key_bytes=bytes(range(32, 0, -1)),
    )


def _test_receipt_trust_fixture(root: Path) -> tuple[Path, Path]:
    public_key = _public_key_fixture(
        root,
        name="test-receipt-ed25519.pub",
        key_bytes=bytes(range(33, 65)),
    )
    der = base64.b64decode(public_key.read_text(encoding="ascii").splitlines()[1])
    policy = {
        "algorithm": "Ed25519",
        "audience": "devflow-teamharness",
        "ciPolicySha256": "1" * 64,
        "ciServerSha256": "2" * 64,
        "issuer": "devflow-tester-cicd",
        "maxClockSkewSeconds": 5,
        "maxReceiptLifetimeSeconds": 120,
        "opensslPath": "/usr/bin/openssl",
        "policyAttestationPath": (
            "/etc/devflow/teamharness/test-receipt-policy.json"
        ),
        "publicKeyFileSha256": hashlib.sha256(public_key.read_bytes()).hexdigest(),
        "publicKeyPath": "/etc/devflow/teamharness/test-receipt-ed25519.pub",
        "publicKeySha256": hashlib.sha256(der).hexdigest(),
        "remainingThreat": (
            "A container or node root compromise remains in scope. The replay "
            "ledger is Pod-local; Leader Pod replacement can lose replay history "
            "for the 120-second receipt lifetime."
        ),
        "replayLedgerPath": (
            "/var/lib/devflow/teamharness/test-receipt-ledger.json"
        ),
        "replayScope": "pod-incarnation",
        "replayLedgerPersistentAcrossPodReplacement": False,
        "receiptLifetimeSeconds": 120,
        "repositoryArchiveSha256": "3" * 64,
        "repositoryManifestSha256": "4" * 64,
        "repositoryRevision": "5" * 40,
        "schemaVersion": "1.0",
        "signatureDomain": "devflow.test-execution-receipt/v1",
    }
    policy_path = root / "test-receipt-policy.json"
    policy_path.write_bytes(
        json.dumps(
            policy,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    return public_key, policy_path


def _source_fixture(root: Path) -> tuple[Path, tuple[str, ...], dict[str, str]]:
    repo = root / "AgentTeams"
    relative_files = (
        "plugin.yaml",
        "mcp/server.py",
        "mcp/message_tool.py",
        "mcp/roomflow_tool.py",
        "prompts/team/TEAMS.md",
        "skills/team/task-execution/SKILL.md",
    )
    plugin = repo / "plugins/teamharness"
    for index, relative in enumerate(relative_files):
        _write(plugin / relative, f"fixture-{index}\n".encode())
    policy = {
        relative: hashlib.sha256((plugin / relative).read_bytes()).hexdigest()
        for relative in UPSTREAM_FILE_SHA256
    }
    tracked = tuple(f"plugins/teamharness/{relative}" for relative in relative_files)
    return repo, tracked, policy


class _FakeRunner:
    def __init__(
        self,
        team: dict[str, Any],
        pods: dict[str, Any],
        tracked: tuple[str, ...],
        *,
        commit: str = UPSTREAM_AGENTTEAMS_COMMIT,
        drift: str = "",
    ) -> None:
        self.team = team
        self.pods = pods
        self.tracked = tracked
        self.commit = commit
        self.drift = drift
        self.calls: list[tuple[list[str], bytes | None]] = []

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        self.calls.append((list(args), input_data))
        if args[0] == "git" and "rev-parse" in args:
            return f"{self.commit}\n"
        if args[0] == "git" and "status" in args:
            return self.drift
        if args[0] == "git" and "ls-files" in args:
            return "\x00".join(self.tracked) + "\x00"
        if "get" in args and "team" in args:
            return json.dumps(self.team)
        if "get" in args and "pods" in args:
            return json.dumps(self.pods)
        return ""


def test_discovers_exactly_six_ready_roles_and_maps_leader() -> None:
    targets = discover_targets(_team(), _pods())

    assert {target.role_name for target in targets} == EXPECTED_ROLES
    assert len(targets) == 6
    assert (
        next(target for target in targets if target.role_name == "devflow-lead").teamharness_role
        == "leader"
    )
    assert all(
        target.teamharness_role == "worker"
        for target in targets
        if target.role_name != "devflow-lead"
    )
    assert all(target.workspace.endswith(target.role_name) for target in targets)
    assert all(target.matrix_user_id == f"@{target.role_name}:matrix.example" for target in targets)


def test_discovery_rejects_matrix_identity_for_another_runtime() -> None:
    team = _team()
    team["status"]["members"][0]["matrixUserID"] = "@another-runtime:matrix.example"

    with pytest.raises(ReconcileError, match="Matrix identity"):
        discover_targets(team, _pods(team))


def test_staged_runtime_config_is_credential_free_simple_yaml() -> None:
    target = Target(
        "devflow-locator",
        "devflow-locator",
        "@devflow-locator:matrix.example",
        "agentteams-worker-devflow-locator",
    )

    archive, digest = _tar_runtime_config(target)

    with tarfile.open(fileobj=BytesIO(archive), mode="r:") as stream:
        member = stream.getmember("runtime-config.yaml")
        extracted = stream.extractfile(member)
        assert extracted is not None
        payload = extracted.read()
    assert hashlib.sha256(payload).hexdigest() == digest
    assert payload.decode("utf-8") == (
        "role: worker\n"
        "runtimeName: devflow-locator\n"
        "matrixUserId: @devflow-locator:matrix.example\n"
    )
    assert b"credential" not in payload.lower()


def test_discovery_requires_explicit_member_to_runtime_binding() -> None:
    team = _team()
    del team["status"]["members"][0]["runtimeName"]

    with pytest.raises(ReconcileError, match="Team status runtime name"):
        discover_targets(team, _pods())


@pytest.mark.parametrize(
    "drift",
    ["audience", "service-account", "mount", "automount", "expiration"],
)
def test_discovery_requires_fixed_rotating_leader_issuer_token(drift: str) -> None:
    pods = _pods()
    leader = next(
        pod for pod in pods["items"] if pod["metadata"]["name"] == "agentteams-worker-devflow-lead"
    )
    spec = leader["spec"]
    if drift == "audience":
        spec["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"]["audience"] = (
            "untrusted-audience"
        )
    elif drift == "service-account":
        spec["serviceAccountName"] = "default"
    elif drift == "mount":
        spec["containers"][0]["volumeMounts"][0]["mountPath"] = "/tmp/token"
    elif drift == "automount":
        spec["automountServiceAccountToken"] = True
    else:
        spec["volumes"][0]["projected"]["sources"][0]["serviceAccountToken"][
            "expirationSeconds"
        ] = 7200

    with pytest.raises(ReconcileError, match="issuer token projection"):
        discover_targets(_team(), pods)


def test_discovery_can_scope_out_unrelated_github_issuer_token() -> None:
    pods = _pods()
    leader = next(
        pod
        for pod in pods["items"]
        if pod["metadata"]["name"] == "agentteams-worker-devflow-lead"
    )
    leader["spec"]["volumes"][0]["projected"]["sources"][0][
        "serviceAccountToken"
    ]["audience"] = "untrusted-audience"

    targets = discover_targets(
        _team(), pods, require_github_issuer_token=False
    )

    assert {target.role_name for target in targets} == EXPECTED_ROLES


@pytest.mark.parametrize("failure", ["missing", "duplicate", "unready", "unexpected"])
def test_discovery_rejects_missing_duplicate_unready_or_unknown_role(
    failure: str,
) -> None:
    team = _team()
    pods = _pods(team)
    if failure == "missing":
        pods["items"].pop()
    elif failure == "duplicate":
        pods["items"][-1] = deepcopy(pods["items"][0])
        pods["items"][-1]["metadata"]["name"] = "pod-duplicate"
    elif failure == "unready":
        pods["items"][0]["status"]["conditions"][0]["status"] = "False"
        pods["items"][0]["status"]["containerStatuses"][0]["ready"] = False
    else:
        pods["items"][0]["metadata"]["labels"][WORKER_LABEL] = "unknown-member"

    with pytest.raises(ReconcileError):
        discover_targets(team, pods)


def test_source_validation_pins_commit_clean_tree_and_all_critical_hashes(
    tmp_path: Path,
) -> None:
    assert RECONCILE_SOURCE_HASHES == UPSTREAM_FILE_SHA256
    repo, tracked, policy = _source_fixture(tmp_path)
    runner = _FakeRunner(_team(), _pods(), tracked)
    test_receipt_key, test_receipt_policy = _test_receipt_trust_fixture(tmp_path)

    bundle = validate_sources(
        runner,
        repo,
        ROOT,
        _public_key_fixture(tmp_path),
        _receipt_public_key_fixture(tmp_path),
        test_receipt_key,
        test_receipt_policy,
        _test_hash_policy=policy,
    )

    assert set(bundle.plugin_hashes) == {
        item.removeprefix("plugins/teamharness/") for item in tracked
    }
    assert set(bundle.overlay_hashes) == {
        "scripts/teamharness_openclaw.py",
        "agentteams/teamharness/guarded_server.py",
    }
    assert bundle.test_receipt_public_key == test_receipt_key.read_bytes()
    assert bundle.test_receipt_policy == test_receipt_policy.read_bytes()
    assert len(
        {
            bundle.approval_public_key,
            bundle.github_receipt_public_key,
            bundle.test_receipt_public_key,
        }
    ) == 3
    assert sum(1 for args, _ in runner.calls if "status" in args) == 2


@pytest.mark.parametrize("failure", ["commit", "tree", "hash"])
def test_source_validation_rejects_upstream_drift(
    tmp_path: Path,
    failure: str,
) -> None:
    repo, tracked, policy = _source_fixture(tmp_path)
    runner = _FakeRunner(
        _team(),
        _pods(),
        tracked,
        commit="0" * 40 if failure == "commit" else UPSTREAM_AGENTTEAMS_COMMIT,
        drift=" M plugins/teamharness/plugin.yaml\n" if failure == "tree" else "",
    )
    if failure == "hash":
        _write(repo / "plugins/teamharness/mcp/server.py", b"drift\n")
    test_receipt_key, test_receipt_policy = _test_receipt_trust_fixture(tmp_path)

    with pytest.raises(ReconcileError):
        validate_sources(
            runner,
            repo,
            ROOT,
            _public_key_fixture(tmp_path),
            _receipt_public_key_fixture(tmp_path),
            test_receipt_key,
            test_receipt_policy,
            _test_hash_policy=policy,
        )


def test_source_validation_rejects_test_receipt_key_policy_mismatch(
    tmp_path: Path,
) -> None:
    repo, tracked, policy = _source_fixture(tmp_path)
    runner = _FakeRunner(_team(), _pods(), tracked)
    test_receipt_key, test_receipt_policy = _test_receipt_trust_fixture(tmp_path)
    value = json.loads(test_receipt_policy.read_text(encoding="utf-8"))
    value["publicKeyFileSha256"] = "0" * 64
    test_receipt_policy.write_bytes(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )

    with pytest.raises(ReconcileError, match="key binding"):
        validate_sources(
            runner,
            repo,
            ROOT,
            _public_key_fixture(tmp_path),
            _receipt_public_key_fixture(tmp_path),
            test_receipt_key,
            test_receipt_policy,
            _test_hash_policy=policy,
        )


def test_reconcile_preflights_all_roles_then_stages_installs_and_verifies(
    tmp_path: Path,
) -> None:
    team = _team()
    pods = _pods(team)
    repo, tracked, policy = _source_fixture(tmp_path)
    runner = _FakeRunner(team, pods, tracked)
    test_receipt_key, test_receipt_policy = _test_receipt_trust_fixture(tmp_path)

    targets = reconcile(
        runner,
        kubectl="kubectl",
        agentteams_repo=repo,
        approval_public_key=_public_key_fixture(tmp_path),
        approval_domain=TEST_APPROVAL_DOMAIN,
        github_receipt_public_key=_receipt_public_key_fixture(tmp_path),
        test_receipt_public_key=test_receipt_key,
        test_receipt_policy=test_receipt_policy,
        devflow_repo=ROOT,
        _test_hash_policy=policy,
    )

    assert len(targets) == 6
    tar_calls = [
        (index, args, payload)
        for index, (args, payload) in enumerate(runner.calls)
        if payload is not None
    ]
    assert len(tar_calls) == 30
    assert all(payload for _, _, payload in tar_calls)
    assert all("--stdin" in args for _, args, _ in tar_calls)
    install_calls = [
        (index, args)
        for index, (args, _) in enumerate(runner.calls)
        if "teamharness_openclaw.py" in " ".join(args) and "install" in args
    ]
    verify_calls = [
        (index, args)
        for index, (args, _) in enumerate(runner.calls)
        if "teamharness_openclaw.py" in " ".join(args) and "verify" in args
    ]
    assert len(install_calls) == len(verify_calls) == 6
    assert max(index for index, _, _ in tar_calls) < min(index for index, _ in install_calls)
    for target in targets:
        install_index = next(index for index, args in install_calls if target.pod_name in args)
        verify_index = next(index for index, args in verify_calls if target.pod_name in args)
        assert install_index < verify_index
    leader = next(args for _, args in install_calls if "agentteams-worker-devflow-lead" in args)
    assert leader[leader.index("--role") + 1] == "leader"
    for _, args in install_calls:
        if "agentteams-worker-devflow-lead" not in args:
            assert args[args.index("--role") + 1] == "worker"
        assert "--replace" in args
        assert "--runtime-binding" in args
        runtime_config = args[args.index("--runtime-config") + 1]
        assert runtime_config.endswith("/identity/runtime-config.yaml")
    assert "--approval-public-key" in leader
    assert leader[leader.index("--approval-domain") + 1] == TEST_APPROVAL_DOMAIN
    for _, args in install_calls:
        if "agentteams-worker-devflow-lead" not in args:
            assert "--approval-domain" not in args
    locator = next(
        args
        for _, args in install_calls
        if "agentteams-worker-devflow-locator" in args
    )
    assert "--github-receipt-public-key" in locator
    for _, args in install_calls:
        if "agentteams-worker-devflow-locator" not in args:
            assert "--github-receipt-public-key" not in args
        assert "--test-receipt-public-key" in args
        assert "--test-receipt-policy" in args
        assert not any("PRIVATE KEY" in argument for argument in args)


def test_reconcile_rejects_ambiguous_approval_domain_before_kubernetes(
    tmp_path: Path,
) -> None:
    runner = _FakeRunner(_team(), _pods(), ())
    test_receipt_key, test_receipt_policy = _test_receipt_trust_fixture(tmp_path)

    with pytest.raises(ReconcileError, match="approval domain"):
        reconcile(
            runner,
            kubectl="kubectl",
            agentteams_repo=tmp_path,
            approval_public_key=_public_key_fixture(tmp_path),
            approval_domain="shared-domain",
            github_receipt_public_key=_receipt_public_key_fixture(tmp_path),
            test_receipt_public_key=test_receipt_key,
            test_receipt_policy=test_receipt_policy,
            devflow_repo=ROOT,
            _test_hash_policy={},
        )

    assert runner.calls == []


def test_script_never_mutates_rbac_or_contains_credentials() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "UPSTREAM_AGENTTEAMS_COMMIT" in text
    assert "expected exactly six active OpenClaw role Pods" in text
    assert "pods/exec" in text
    assert 'test -f "$expected/openclaw.json"' in text
    assert 'test -f "$expected/runtime/runtime.json"' not in text
    assert not re.search(r"\bkubectl\b.*\b(?:apply|create|patch|auth)\b", text)
    for forbidden in (
        "ghp_",
        "accessToken",
        "gatewayKey",
        "AGENTTEAMS_WORKER_MATRIX_TOKEN",
        "AGENTTEAMS_WORKER_GATEWAY_KEY",
        "set -x",
    ):
        assert forbidden not in text


def test_script_help_runs_without_site_packages() -> None:
    completed = subprocess.run(
        [sys.executable, "-S", str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--agentteams-repo" in completed.stdout

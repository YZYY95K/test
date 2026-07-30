"""Fail-closed tests for the isolated Tester CI MCP reconciler."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import reconcile_agentteams_tester_cicd as reconciler
from scripts.reconcile_agentteams_tester_cicd import (
    APP_NAME,
    CONFIRMATION,
    PRIVATE_KEY_PATH,
    SECRET_NAME,
    SERVICE_URL,
    SOURCE_PATH,
    TESTER_ROLE,
    TOOL_NAME,
    DesiredState,
    ReconcileError,
    SourceAttestation,
    TrustMaterial,
    _endpoint_check,
    _secret_isolation,
    attest_source,
    desired_state,
    load_public_key,
    reconcile,
)
from scripts.reconcile_teamharness_openclaw import (
    RUNTIME_LABEL,
    TEAM_LABEL,
    TEAM_NAME,
    WORKER_LABEL,
    Target,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile_agentteams_tester_cicd.py"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _source() -> SourceAttestation:
    return SourceAttestation(
        revision="a" * 40,
        archive_sha256=_hash("archive"),
        tree_sha256=_hash("tree"),
        server_sha256=_hash("server"),
        file_count=12,
    )


def _trust(source: SourceAttestation | None = None) -> TrustMaterial:
    source = source or _source()
    public_key = (
        "-----BEGIN PUBLIC KEY-----\n"
        + base64.b64encode(reconciler.ED25519_SPKI_PREFIX + b"K" * 32).decode("ascii")
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")
    public_key_sha256 = hashlib.sha256(
        reconciler.ED25519_SPKI_PREFIX + b"K" * 32
    ).hexdigest()
    execution_policy: dict[str, Any] = {
        "schemaVersion": "1.0",
        "teamName": TEAM_NAME,
        "serviceIdentity": reconciler.SERVICE_IDENTITY,
        "repositoryRoot": reconciler.REPOSITORY_ROOT,
        "workspaceRoot": reconciler.WORKSPACE_ROOT,
        "repositoryRevision": source.revision,
        "repositoryArchiveSha256": source.archive_sha256,
        "repositoryManifestSha256": source.tree_sha256,
        "serverSha256": source.server_sha256,
        "receiptPublicKeySha256": public_key_sha256,
        "testCommands": {
            "focused": ["/usr/local/bin/python3.12", "-m", "pytest", "-q", "tests"],
            "full": ["/usr/local/bin/python3.12", "-m", "pytest", "-q"],
        },
        "testExecutableSha256": {
            "focused": _hash("python"),
            "full": _hash("python"),
        },
        "networkIsolationPrefix": list(reconciler.NETWORK_PREFIX),
        "networkIsolationExecutableSha256": _hash("bwrap"),
        "resourceLimitLauncher": ["/usr/bin/prlimit"],
        "resourceLimitLauncherSha256": _hash("prlimit"),
        "resourceLimitsApplied": True,
        "assignmentSource": reconciler.ASSIGNMENT_SOURCE,
        "assignmentSourceLiveAgentTeams": False,
        "dynamicCandidateSupported": False,
        "testPathMutationSupported": False,
        "fixedCandidateSha256": {
            task_id: _hash(task_id) for task_id in reconciler.FIXTURE_TASK_IDS
        },
        "testCompletionPolicy": reconciler.TEST_COMPLETION_POLICY,
        "minimumExecutedTests": 1,
        "timeoutSeconds": 600,
        "cpuSeconds": 600,
        "addressSpaceBytes": 2 * 1024 * 1024 * 1024,
        "maxProcesses": 64,
        "maxOpenFiles": 512,
        "maxOutputBytes": 16 * 1024,
        "maxPatchBytes": 1024 * 1024,
        "maxPatchFiles": 64,
        "maxFileBytes": 2 * 1024 * 1024,
        "maxRepositoryFiles": 100_000,
        "maxRepositoryBytes": 1024 * 1024 * 1024,
        "credentialPolicy": "empty-environment",
        "networkPolicy": reconciler.NETWORK_POLICY,
        "workspaceBinding": "0" * 64,
        "remainingThreat": "Pod root, kernel and cluster control plane remain trusted.",
    }
    execution_policy["workspaceBinding"] = reconciler._execution_policy_binding(
        execution_policy
    )
    receipt_policy = {
        "schemaVersion": "1.0",
        "algorithm": "Ed25519",
        "audience": reconciler.RECEIPT_AUDIENCE,
        "issuer": reconciler.RECEIPT_ISSUER,
        "signatureDomain": reconciler.RECEIPT_DOMAIN,
        "publicKeyPath": reconciler.TEAMHARNESS_PUBLIC_KEY_PATH,
        "publicKeyFileSha256": hashlib.sha256(public_key).hexdigest(),
        "publicKeySha256": public_key_sha256,
        "policyAttestationPath": reconciler.TEAMHARNESS_POLICY_PATH,
        "opensslPath": "/usr/bin/openssl",
        "replayLedgerPath": reconciler.TEAMHARNESS_LEDGER_PATH,
        "replayScope": reconciler.REPLAY_SCOPE,
        "replayLedgerPersistentAcrossPodReplacement": (
            reconciler.REPLAY_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        ),
        "receiptLifetimeSeconds": reconciler.RECEIPT_LIFETIME_SECONDS,
        "maxReceiptLifetimeSeconds": 120,
        "maxClockSkewSeconds": 5,
        "ciServerSha256": source.server_sha256,
        "ciPolicySha256": execution_policy["workspaceBinding"],
        "repositoryArchiveSha256": source.archive_sha256,
        "repositoryManifestSha256": source.tree_sha256,
        "repositoryRevision": source.revision,
        "remainingThreat": (
            "CI root, kernel and TeamHarness verifier remain trusted. The replay "
            "ledger is Pod-local; Leader Pod replacement can lose replay history "
            "for the 120-second receipt lifetime."
        ),
    }
    return TrustMaterial(
        public_key=public_key,
        public_key_sha256=public_key_sha256,
        public_key_file_sha256=hashlib.sha256(public_key).hexdigest(),
        execution_policy=execution_policy,
        execution_policy_sha256=execution_policy["workspaceBinding"],
        receipt_policy=receipt_policy,
        receipt_policy_sha256=hashlib.sha256(
            reconciler._canonical(receipt_policy)
        ).hexdigest(),
    )


def _desired() -> DesiredState:
    source = _source()
    return desired_state(
        source=source,
        trust=_trust(source),
        image="registry.example/devflow/tester-cicd@sha256:" + "b" * 64,
    )


def _resource(desired: DesiredState, kind: str, name: str) -> dict[str, Any]:
    return next(
        value
        for value in desired.resources
        if value["kind"] == kind and value["metadata"]["name"] == name
    )


def _target() -> Target:
    return Target(
        role_name=TESTER_ROLE,
        member_name=TESTER_ROLE,
        matrix_user_id="@devflow-tester:example.invalid",
        pod_name="agentteams-worker-devflow-tester",
    )


def _targets() -> tuple[Target, ...]:
    roles = (
        "devflow-coder",
        "devflow-lead",
        "devflow-locator",
        "devflow-reviewer",
        "devflow-tester",
        "devflow-triage",
    )
    return tuple(
        Target(
            role_name=role,
            member_name=f"member-{role}",
            matrix_user_id=f"@{role}:example.invalid",
            pod_name=f"agentteams-worker-{role}",
        )
        for role in roles
    )


def test_desired_state_is_external_digest_pinned_and_secret_is_ci_only() -> None:
    desired = _desired()
    deployment = _resource(desired, "Deployment", APP_NAME)
    service = _resource(desired, "Service", APP_NAME)
    default_deny = _resource(desired, "NetworkPolicy", f"{APP_NAME}-default-deny")
    tester_only = _resource(desired, "NetworkPolicy", f"{APP_NAME}-tester-only")
    pod_spec = deployment["spec"]["template"]["spec"]
    container = pod_spec["containers"][0]

    assert "@sha256:" in container["image"]
    assert container["args"] == [
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "8080",
    ]
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert container["securityContext"]["runAsNonRoot"] is True
    assert container["securityContext"]["runAsUser"] == reconciler.SERVICE_UID
    assert pod_spec["securityContext"]["fsGroup"] == reconciler.SERVICE_GID
    assert pod_spec["automountServiceAccountToken"] is False
    assert "initContainers" not in pod_spec
    signing = next(
        volume for volume in pod_spec["volumes"] if volume["name"] == "receipt-signing-key"
    )
    assert signing["secret"] == {
        "secretName": SECRET_NAME,
        "defaultMode": 0o440,
        "items": [{"key": "receipt-ed25519.pem", "path": "receipt-ed25519.pem"}],
    }
    assert service["spec"]["type"] == "ClusterIP"
    assert default_deny["spec"] == {
        "podSelector": {"matchLabels": deployment["metadata"]["labels"]},
        "policyTypes": ["Ingress", "Egress"],
    }
    ingress = tester_only["spec"]["ingress"][0]["from"]
    assert ingress == [
        {
            "podSelector": {
                "matchLabels": {
                    TEAM_LABEL: TEAM_NAME,
                    WORKER_LABEL: TESTER_ROLE,
                    RUNTIME_LABEL: "openclaw",
                }
            }
        }
    ]
    serialized = json.dumps(list(desired.resources), sort_keys=True)
    assert "PRIVATE KEY" not in serialized
    assert PRIVATE_KEY_PATH in serialized
    execution_mount = next(
        mount
        for mount in container["volumeMounts"]
        if mount.get("mountPath") == reconciler.EXECUTION_POLICY_PATH
    )
    receipt_mount = next(
        mount
        for mount in container["volumeMounts"]
        if mount.get("mountPath") == reconciler.CI_RECEIPT_POLICY_PATH
    )
    assert execution_mount["subPath"] == "execution-policy.json"
    assert receipt_mount["subPath"] == "test-receipt-policy.json"
    assignment_mount = next(
        mount
        for mount in container["volumeMounts"]
        if mount.get("mountPath") == reconciler.ASSIGNMENT_ROOT
    )
    assert "readOnly" not in assignment_mount
    config = _resource(desired, "ConfigMap", desired.config_map_name)
    assert config["data"]["assignment-source"] == reconciler.ASSIGNMENT_SOURCE
    assert json.loads(config["data"]["fixture-task-ids"]) == list(
        reconciler.FIXTURE_TASK_IDS
    )
    assert config["data"]["live-agentteams-task-projection"] == "false"


class _LiveResourceRunner:
    def __init__(self, desired: DesiredState, *, add_initializer: bool = False) -> None:
        self.resources = {
            (
                reconciler._resource_type(resource["kind"]),
                resource["metadata"]["name"],
            ): deepcopy(resource)
            for resource in desired.resources
        }
        if add_initializer:
            deployment = self.resources[("deployment", APP_NAME)]
            deployment["spec"]["template"]["spec"]["initContainers"] = [
                {"name": "unexpected-root-init"}
            ]

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        assert input_data is None
        index = args.index("get")
        return json.dumps(self.resources[(args[index + 1], args[index + 2])])


def test_live_resource_readback_requires_no_initializer() -> None:
    desired = _desired()

    assert reconciler._live_resources(
        _LiveResourceRunner(desired),
        "kubectl",
        desired,
    ) == (True, True)
    assert reconciler._live_resources(
        _LiveResourceRunner(desired, add_initializer=True),
        "kubectl",
        desired,
    ) == (True, False)


@pytest.mark.parametrize(
    "image",
    (
        "registry.example/devflow/tester-cicd:latest",
        "registry.example/devflow/tester-cicd@sha256:short",
        "https://registry.example/devflow/tester-cicd@sha256:" + "b" * 64,
    ),
)
def test_desired_state_rejects_unpinned_or_ambiguous_image(image: str) -> None:
    with pytest.raises(ReconcileError, match="image"):
        desired_state(
            source=_source(),
            trust=_trust(),
            image=image,
        )


def test_public_key_accepts_only_canonical_ed25519_spki(tmp_path: Path) -> None:
    path = tmp_path / "receipt.pub"
    payload = _trust().public_key
    path.write_bytes(payload)

    checked, digest = load_public_key(path)

    assert checked == payload
    assert digest == hashlib.sha256(
        reconciler.ED25519_SPKI_PREFIX + b"K" * 32
    ).hexdigest()
    private_header = "-----BEGIN " + "PRIVATE KEY-----"
    private_footer = "-----END " + "PRIVATE KEY-----"
    path.write_text(f"{private_header}\nnot-a-key\n{private_footer}\n")
    with pytest.raises(ReconcileError, match="public key"):
        load_public_key(path)


class _GitRunner:
    def __init__(self, root: Path, *, dirty: bool = False, mode: str = "100644") -> None:
        self.root = root
        self.dirty = dirty
        self.mode = mode

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        assert input_data is None
        if "rev-parse" in args:
            return "a" * 40 + "\n"
        if "status" in args:
            return " M changed\0" if self.dirty else ""
        if "ls-files" in args:
            return (
                f"{self.mode} {'1' * 40} 0\t{SOURCE_PATH}\0"
                f"100644 {'2' * 40} 0\tREADME.md\0"
            )
        raise AssertionError(args)


def _fake_repository(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    server = tmp_path.joinpath(*SOURCE_PATH.split("/"))
    server.parent.mkdir(parents=True)
    server.write_text("print('fixed')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("release\n", encoding="utf-8")
    return tmp_path
def test_source_attestation_is_deterministic_and_rejects_dirty_or_link_index(
    tmp_path: Path,
) -> None:
    repository = _fake_repository(tmp_path)
    first = attest_source(_GitRunner(repository), repository)
    second = attest_source(_GitRunner(repository), repository)

    assert first == second
    assert first.revision == "a" * 40
    assert first.file_count == 2
    with pytest.raises(ReconcileError, match="clean"):
        attest_source(_GitRunner(repository, dirty=True), repository)
    with pytest.raises(ReconcileError, match="link"):
        attest_source(_GitRunner(repository, mode="120000"), repository)


def _ci_pod(*, name: str = "devflow-tester-cicd-pod") -> dict[str, Any]:
    deployment = _resource(_desired(), "Deployment", APP_NAME)
    return {
        "metadata": {
            "name": name,
            "labels": deployment["metadata"]["labels"],
        },
        "spec": deepcopy(deployment["spec"]["template"]["spec"]),
    }


def _ci_workloads(desired: DesiredState) -> dict[str, Any]:
    return {
        "items": [deepcopy(_resource(desired, "Deployment", APP_NAME))],
    }


def test_secret_isolation_rejects_any_worker_or_second_consumer() -> None:
    worker = {
        "metadata": {"name": "agentteams-worker-devflow-tester", "labels": {}},
        "spec": {
            "containers": [{"name": "worker", "env": []}],
            "volumes": [{"name": "bad", "secret": {"secretName": SECRET_NAME}}],
        },
    }
    empty = _secret_isolation({"items": []}, require_ci_pod=False)
    assert empty.no_unexpected_secret_consumer is True
    assert empty.observed_single_signing_secret_consumer is False
    observed = _secret_isolation({"items": [_ci_pod()]}, require_ci_pod=True)
    assert observed.no_unexpected_secret_consumer is True
    assert observed.observed_single_signing_secret_consumer is True
    observed_with_template = _secret_isolation(
        {"items": [_ci_pod()]},
        require_ci_pod=True,
        namespace_workloads=_ci_workloads(_desired()),
    )
    assert observed_with_template.observed_single_signing_secret_consumer is True
    with pytest.raises(ReconcileError, match="multiple"):
        _secret_isolation(
            {"items": [_ci_pod(name="ci-one"), _ci_pod(name="ci-two")]},
            require_ci_pod=True,
        )
    init_exposed = _ci_pod()
    init_exposed["spec"]["initContainers"] = [
        {
            "name": "fixture",
            "env": [],
            "volumeMounts": [{
            "name": "key",
            "mountPath": "/tmp/receipt.pem",
            "readOnly": True,
            }],
        }
    ]
    with pytest.raises(ReconcileError, match="isolated"):
        _secret_isolation({"items": [init_exposed]}, require_ci_pod=True)
    ephemeral_exposed = _ci_pod()
    ephemeral_exposed["spec"]["ephemeralContainers"] = [
        {
            "name": "debugger",
            "env": [],
            "volumeMounts": [
                {
                    "name": "key",
                    "mountPath": "/tmp/debug-receipt.pem",
                    "readOnly": True,
                }
            ],
        }
    ]
    with pytest.raises(ReconcileError, match="isolated"):
        _secret_isolation({"items": [ephemeral_exposed]}, require_ci_pod=True)
    other_template = {
        "kind": "Job",
        "metadata": {"name": "secret-reader"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "reader", "env": []}],
                    "volumes": [
                        {"name": "key", "secret": {"secretName": SECRET_NAME}}
                    ],
                }
            }
        },
    }
    with pytest.raises(ReconcileError, match="workload template"):
        _secret_isolation(
            {"items": [_ci_pod()]},
            require_ci_pod=True,
            namespace_workloads={
                "items": [
                    *_ci_workloads(_desired())["items"],
                    other_template,
                ]
            },
        )
    with pytest.raises(ReconcileError, match="outside"):
        _secret_isolation({"items": [worker]}, require_ci_pod=True)


class _EndpointRunner:
    def __init__(self, desired: DesiredState) -> None:
        self.desired = desired
        self.calls: list[list[str]] = []

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        assert input_data is None
        self.calls.append(args)
        ready = {
            "ok": True,
            "server": reconciler.SERVER_NAME,
            "transport": "streamable-http",
            "protocolVersion": reconciler.PROTOCOL_VERSION,
            "stateless": False,
            "mcpSessionsSupported": False,
            "repositoryRevision": self.desired.source.revision,
            "repositoryArchiveSha256": self.desired.source.archive_sha256,
            "serverSha256": self.desired.source.server_sha256,
            "executionPolicySha256": self.desired.trust.execution_policy_sha256,
            "receiptPublicKeySha256": self.desired.trust.public_key_sha256,
            "receiptPolicySha256": self.desired.trust.receipt_policy_sha256,
            "receiptIssuer": reconciler.RECEIPT_ISSUER,
            "receiptLifetimeSeconds": reconciler.RECEIPT_LIFETIME_SECONDS,
            "replayScope": reconciler.REPLAY_SCOPE,
            "replayLedgerPersistentAcrossPodReplacement": False,
            "remainingThreat": self.desired.trust.receipt_policy["remainingThreat"],
            "privateKeyLoaded": True,
            "credentialsForwarded": False,
            "repositoryMode": reconciler.REPOSITORY_MODE,
            "testCommandSource": reconciler.TEST_COMMAND_SOURCE,
            "assignmentSource": reconciler.ASSIGNMENT_SOURCE,
            "assignmentSourceLiveAgentTeams": False,
            "dynamicCandidateSupported": False,
            "testPathMutationSupported": False,
            "testCompletionPolicy": reconciler.TEST_COMPLETION_POLICY,
            "minimumExecutedTests": 1,
            "resourceLimitsApplied": True,
            "runAsUser": reconciler.SERVICE_UID,
            "runAsGroup": reconciler.SERVICE_GID,
            "httpCallerAuthentication": "network-policy-only-no-mtls-or-spiffe",
            "testerIdentityAuthenticatedByService": False,
            "deploymentBlockers": [
                "application-layer-mtls-or-spiffe-not-configured",
                "live-agentteams-task-projection-not-configured",
                "end-to-end-consumer-replay-flow-not-exercised",
                "task-result-cache-not-persistent-across-container-restart",
            ],
            "taskReplayCacheScope": "container-incarnation",
            "endToEndReady": False,
            "taskExecutionSemantics": (
                "single-execution-per-task-per-container-incarnation-cached-response"
            ),
            "fixtureTaskIds": list(reconciler.FIXTURE_TASK_IDS),
            "assignmentFresh": True,
            "assignmentMaxAgeSeconds": 86_400,
            "assignmentExpiryAction": (
                "fail-liveness-and-readiness-refresh-on-container-restart"
            ),
            "inflightExecutions": 0,
            "maxConcurrentExecutions": 1,
            "completedTaskCount": 0,
        }
        tool = {
            "name": TOOL_NAME,
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "taskId": {"type": "string"},
                    "revision": {"type": "string"},
                    "workspaceBinding": {"type": "string"},
                },
                "required": ["taskId", "revision", "workspaceBinding"],
            },
        }
        return json.dumps(
            {
                "ready": ready,
                "toolsList": {
                    "jsonrpc": "2.0",
                    "id": "list",
                    "result": {"tools": [tool]},
                },
                "deploymentPreflightReady": True,
            }
        )


def _receipt_readback(desired: DesiredState) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schemaVersion": "devflow.teamharness.test-receipt-readback/v1",
        "sourcePolicy": "production-pinned",
        "manifestPolicyPath": reconciler.TEAMHARNESS_POLICY_PATH,
        "manifestPolicySha256": desired.trust.receipt_policy_sha256,
        "manifestPublicKeyPath": reconciler.TEAMHARNESS_PUBLIC_KEY_PATH,
        "manifestPublicKeyFileSha256": desired.trust.public_key_file_sha256,
        "replayScope": reconciler.REPLAY_SCOPE,
        "replayLedgerPersistentAcrossPodReplacement": (
            reconciler.REPLAY_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        ),
        "receiptLifetimeSeconds": reconciler.RECEIPT_LIFETIME_SECONDS,
        "policyFileSha256": desired.trust.receipt_policy_sha256,
        "publicKeyFileSha256": desired.trust.public_key_file_sha256,
        "policyMatchesManifest": True,
        "policyCanonical": True,
        "ledgerSchemaVersion": "devflow.test-execution-receipt-ledger/v1",
        "ledgerUsedJtisObject": True,
        "ledgerEntryCount": 0,
        "publicKeyPemOnly": True,
    }
    for prefix, mode in (
        ("manifest", 0o444),
        ("publicKey", 0o444),
        ("policy", 0o444),
        ("ledger", 0o600),
    ):
        value.update(
            {
                f"{prefix}Regular": True,
                f"{prefix}Links": 1,
                f"{prefix}Uid": 0,
                f"{prefix}Gid": 0,
                f"{prefix}Mode": mode,
            }
        )
    return value


class _TeamHarnessVerifierRunner:
    def __init__(self, desired: DesiredState, *, corrupt_role: str | None = None) -> None:
        self.desired = desired
        self.corrupt_role = corrupt_role
        self.calls: list[list[str]] = []

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        assert input_data is None
        self.calls.append(args)
        if reconciler.TEAMHARNESS_ADAPTER_PATH in args:
            return json.dumps(
                [
                    {"name": "manifest-hashes", "ok": True, "detail": "fixed"},
                    {
                        "name": "test-execution-receipt-policy",
                        "ok": True,
                        "detail": "public verifier policy and ledger verified",
                    },
                ]
            )
        if reconciler.TEAMHARNESS_RECEIPT_READBACK in args:
            value = _receipt_readback(self.desired)
            pod_name = args[args.index("exec") + 1]
            if self.corrupt_role and pod_name.endswith(self.corrupt_role):
                value["ledgerMode"] = 0o644
            return json.dumps(value)
        raise AssertionError(args)


def test_teamharness_receipt_readback_requires_all_six_public_verifiers() -> None:
    desired = _desired()
    targets = _targets()
    runner = _TeamHarnessVerifierRunner(desired)

    roles = reconciler._teamharness_receipt_verifier_roles(
        runner,
        "kubectl",
        targets,
        desired,
    )

    assert roles == tuple(target.role_name for target in targets)
    assert len(runner.calls) == 12
    assert all(PRIVATE_KEY_PATH not in args for args in runner.calls)
    assert all(SECRET_NAME not in args for args in runner.calls)
    assert sum(
        reconciler.TEAMHARNESS_ADAPTER_PATH in args for args in runner.calls
    ) == 6

    drifted = _TeamHarnessVerifierRunner(desired, corrupt_role="devflow-reviewer")
    drifted_roles = reconciler._teamharness_receipt_verifier_roles(
        drifted,
        "kubectl",
        targets,
        desired,
    )
    assert "devflow-reviewer" not in drifted_roles
    assert len(drifted_roles) == 5


class _NetworkDenyRunner:
    def __init__(self, *, reachable_role: str | None = None) -> None:
        self.reachable_role = reachable_role
        self.calls: list[list[str]] = []

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        assert input_data is None
        self.calls.append(args)
        pod_name = args[args.index("exec") + 1]
        blocked = not (
            self.reachable_role and pod_name.endswith(self.reachable_role)
        )
        return json.dumps({"blocked": blocked, "serviceUrl": reconciler.READY_URL})


def test_network_policy_probe_observes_tester_positive_elsewhere_and_five_denials() -> None:
    targets = _targets()
    runner = _NetworkDenyRunner()

    denied = reconciler._network_policy_denied_roles(
        runner,
        "kubectl",
        targets,
    )

    assert set(denied) == {
        target.role_name for target in targets if target.role_name != TESTER_ROLE
    }
    assert len(runner.calls) == 5
    assert all("agentteams-worker-devflow-tester" not in call for call in runner.calls)
    reachable = _NetworkDenyRunner(reachable_role="devflow-lead")
    assert "devflow-lead" not in reconciler._network_policy_denied_roles(
        reachable,
        "kubectl",
        targets,
    )


def test_endpoint_check_executes_only_in_tester_and_accepts_one_tool() -> None:
    desired = _desired()
    runner = _EndpointRunner(desired)

    assert _endpoint_check(runner, "kubectl", _target(), desired) == (TOOL_NAME,)

    assert len(runner.calls) == 1
    command = runner.calls[0]
    assert "agentteams-worker-devflow-tester" in command
    assert SERVICE_URL in command
    assert SECRET_NAME not in command


def test_reconcile_default_check_never_applies_when_resources_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desired = _desired()
    calls: list[str] = []
    monkeypatch.setattr(
        reconciler,
        "_discover",
        lambda _runner, _kubectl: (
            _target(),
            _targets(),
            {"items": []},
            {"items": []},
        ),
    )
    monkeypatch.setattr(
        reconciler,
        "_teamharness_receipt_verifier_roles",
        lambda *_args, **_kwargs: tuple(target.role_name for target in _targets()),
    )
    monkeypatch.setattr(
        reconciler,
        "_live_resources",
        lambda _runner, _kubectl, _desired: (False, False),
    )
    monkeypatch.setattr(
        reconciler,
        "_apply_resources",
        lambda *_args, **_kwargs: calls.append("apply"),
    )

    report = reconcile(SimpleNamespace(), desired)

    assert report.needs_apply is True
    assert report.applied is False
    assert calls == []


def test_reconcile_never_claims_end_to_end_when_one_role_lacks_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desired = _desired()
    targets = _targets()
    monkeypatch.setattr(
        reconciler,
        "_discover",
        lambda _runner, _kubectl: (
            _target(),
            targets,
            {"items": [_ci_pod()]},
            _ci_workloads(desired),
        ),
    )
    monkeypatch.setattr(
        reconciler,
        "_teamharness_receipt_verifier_roles",
        lambda *_args, **_kwargs: tuple(
            target.role_name
            for target in targets
            if target.role_name != "devflow-reviewer"
        ),
    )
    monkeypatch.setattr(
        reconciler,
        "_live_resources",
        lambda *_args, **_kwargs: (True, True),
    )
    monkeypatch.setattr(
        reconciler,
        "_endpoint_check",
        lambda *_args, **_kwargs: (TOOL_NAME,),
    )
    monkeypatch.setattr(
        reconciler,
        "_policy_check",
        lambda *_args, **_kwargs: SimpleNamespace(needs_apply=False),
    )
    monkeypatch.setattr(
        reconciler,
        "_network_policy_denied_roles",
        lambda *_args, **_kwargs: tuple(
            target.role_name
            for target in targets
            if target.role_name != TESTER_ROLE
        ),
    )

    report = reconcile(SimpleNamespace(), desired)

    assert report.ci_service_verified is False
    assert report.deployment_preflight_ready is True
    assert report.needs_apply is False
    assert report.teamharness_receipt_verifier_verified is False
    assert report.end_to_end_ready is False


def test_reconcile_apply_requires_every_post_apply_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    desired = _desired()
    state = {"applied": False}
    monkeypatch.setattr(
        reconciler,
        "_discover",
        lambda _runner, _kubectl: (
            _target(),
            _targets(),
            {"items": [_ci_pod()]} if state["applied"] else {"items": []},
            _ci_workloads(desired) if state["applied"] else {"items": []},
        ),
    )
    monkeypatch.setattr(
        reconciler,
        "_teamharness_receipt_verifier_roles",
        lambda *_args, **_kwargs: tuple(target.role_name for target in _targets()),
    )
    monkeypatch.setattr(
        reconciler,
        "_live_resources",
        lambda _runner, _kubectl, _desired: (
            (True, True) if state["applied"] else (False, False)
        ),
    )

    def apply_resources(*_args: Any, **_kwargs: Any) -> None:
        state["applied"] = True

    monkeypatch.setattr(reconciler, "_apply_resources", apply_resources)
    monkeypatch.setattr(
        reconciler,
        "_endpoint_check",
        lambda *_args, **_kwargs: (TOOL_NAME,),
    )
    monkeypatch.setattr(
        reconciler,
        "_policy_check",
        lambda *_args, **_kwargs: SimpleNamespace(needs_apply=False),
    )
    monkeypatch.setattr(
        reconciler,
        "_network_policy_denied_roles",
        lambda *_args, **_kwargs: tuple(
            target.role_name
            for target in _targets()
            if target.role_name != TESTER_ROLE
        ),
    )

    report = reconcile(SimpleNamespace(), desired, apply=True)

    assert report.applied is True
    assert report.needs_apply is False
    assert report.observed_single_secret_consumer is True
    assert report.ci_service_verified is False
    assert report.deployment_preflight_ready is True
    assert report.network_policy_tester_access_observed is True
    assert report.network_policy_other_roles_denied_observed is True
    assert report.teamharness_receipt_verifier_verified is True
    assert report.end_to_end_ready is False
    assert report.replay_scope == "pod-incarnation"
    assert report.replay_ledger_persistent_across_pod_replacement is False
    assert report.receipt_lifetime_seconds == 120


def test_cli_apply_refuses_before_any_cluster_or_source_access_without_confirmation() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            str(SCRIPT),
            "--apply",
            "--image",
            "registry.example/devflow/tester-cicd@sha256:" + "b" * 64,
            "--execution-policy",
            "missing-execution-policy.json",
            "--receipt-policy",
            "missing-receipt-policy.json",
            "--receipt-public-key",
            "missing.pub",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "exact confirmation" in completed.stderr
    assert CONFIRMATION not in completed.stderr
    assert "Traceback" not in completed.stderr


def test_observed_single_secret_consumer_is_not_reported_as_mount_acl() -> None:
    report = SimpleNamespace(
        resources_verified=True,
        observed_single_secret_consumer=True,
    )

    assert reconciler._secret_mount_acl_enforced(report) is False

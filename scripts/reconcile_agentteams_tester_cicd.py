#!/usr/bin/env python3
"""Reconcile the isolated AgentTeams Tester CI MCP service.

The CI executor is deliberately a separate Deployment.  Its Ed25519 signing
key is referenced from a pre-created Secret that is mounted only in the main
CI signer container; neither the init container nor any AgentTeams Worker
receives the private key.  Tester reaches one
ClusterIP Streamable HTTP endpoint, while NetworkPolicy denies every other
ingress source.

Check mode is the default and performs no mutation.  Apply requires an exact
confirmation.  It never creates, reads, copies, or prints a Secret value.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import stat
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from scripts import reconcile_agentteams_mcporter_policy as mcporter_policy
    from scripts.reconcile_teamharness_openclaw import (
        CONTAINER_NAME,
        NAMESPACE,
        RUNTIME_LABEL,
        TEAM_LABEL,
        TEAM_NAME,
        WORKER_LABEL,
        Target,
        discover_targets,
    )
except ModuleNotFoundError:  # pragma: no cover - direct ``python -S`` execution
    import reconcile_agentteams_mcporter_policy as mcporter_policy  # type: ignore[no-redef]
    from reconcile_teamharness_openclaw import (  # type: ignore[no-redef]
        CONTAINER_NAME,
        NAMESPACE,
        RUNTIME_LABEL,
        TEAM_LABEL,
        TEAM_NAME,
        WORKER_LABEL,
        Target,
        discover_targets,
    )

__all__ = [
    "CONTAINER_NAME",
    "NAMESPACE",
    "RUNTIME_LABEL",
    "TEAM_LABEL",
    "TEAM_NAME",
    "WORKER_LABEL",
    "Target",
]

TESTER_ROLE = "devflow-tester"
SERVER_NAME = "devflow-cicd"
TOOL_NAME = "run_tests"
CONFIRMATION = "RECONCILE_ISOLATED_AGENTTEAMS_TESTER_CICD"
APP_NAME = "devflow-tester-cicd"
WORKLOAD_TEMPLATE_RESOURCES = (
    "deployments,statefulsets,daemonsets,jobs,cronjobs"
)
SERVICE_ACCOUNT = APP_NAME
SERVICE_NAME = APP_NAME
DEPLOYMENT_NAME = APP_NAME
SECRET_NAME = "devflow-test-receipt-signing"
SECRET_KEY = "receipt-ed25519.pem"
PRIVATE_KEY_PATH = "/var/run/secrets/devflow-test-receipt/receipt-ed25519.pem"
TEAMHARNESS_PUBLIC_KEY_PATH = "/etc/devflow/teamharness/test-receipt-ed25519.pub"
TEAMHARNESS_POLICY_PATH = "/etc/devflow/teamharness/test-receipt-policy.json"
TEAMHARNESS_LEDGER_PATH = "/var/lib/devflow/teamharness/test-receipt-ledger.json"
TEAMHARNESS_ADAPTER_PATH = "/opt/devflow/teamharness/teamharness_openclaw.py"
TEAMHARNESS_MANIFEST_PATH = "/etc/devflow/teamharness/install-manifest.json"
REPLAY_SCOPE = "pod-incarnation"
REPLAY_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT = False
RECEIPT_LIFETIME_SECONDS = 120
SERVICE_URL = (
    "http://devflow-tester-cicd.agentteams-system.svc.cluster.local:8080/mcp"
)
READY_URL = (
    "http://devflow-tester-cicd.agentteams-system.svc.cluster.local:8080/readyz"
)
RECEIPT_AUDIENCE = "devflow-teamharness"
RECEIPT_DOMAIN = "devflow.test-execution-receipt/v1"
RECEIPT_ISSUER = "devflow-tester-cicd"
RECEIPT_POLICY_SCHEMA = "1.0"
SERVICE_IDENTITY = "devflow-tester-cicd.agentteams-system.svc.cluster.local"
EXECUTION_POLICY_PATH = "/etc/devflow/agentteams-cicd/policy.json"
CI_RECEIPT_POLICY_PATH = "/etc/devflow/agentteams-cicd/test-receipt-policy.json"
REPOSITORY_ROOT = "/var/lib/devflow/agentteams-cicd/repository"
WORKSPACE_ROOT = "/var/lib/devflow/agentteams-cicd/workspaces"
ASSIGNMENT_ROOT = "/var/lib/devflow/agentteams-cicd/assignments"
ASSIGNMENT_SOURCE = "image-fixed-demo-fixture/v1"
REPOSITORY_MODE = "image-fixed-clean-commit-fixture/v1"
TEST_COMMAND_SOURCE = "image-policy-fixed-argv/v1"
FIXTURE_TASK_IDS = ("devflow-demo-focused", "devflow-demo-full")
MATERIALIZER_PATH = "/opt/devflow/agentteams-cicd/materialize_demo_assignments.py"
SERVICE_UID = 10_001
SERVICE_GID = 10_001
PROTOCOL_VERSION = "2025-03-26"
TEST_COMPLETION_POLICY = "fixed-candidate-pytest-terminal-summary/v1"
NETWORK_POLICY = "bubblewrap-unshare-all-mask-runtime-credentials"
NETWORK_PREFIX = (
    "/usr/bin/bwrap",
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    "--cap-drop",
    "ALL",
    "--ro-bind",
    "/",
    "/",
    "--tmpfs",
    "/etc",
    "--tmpfs",
    "/home",
    "--tmpfs",
    "/root",
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/tmp",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
)
EXECUTION_POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "teamName",
        "serviceIdentity",
        "repositoryRoot",
        "workspaceRoot",
        "repositoryRevision",
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
        "serverSha256",
        "receiptPublicKeySha256",
        "testCommands",
        "testExecutableSha256",
        "networkIsolationPrefix",
        "networkIsolationExecutableSha256",
        "resourceLimitLauncher",
        "resourceLimitLauncherSha256",
        "resourceLimitsApplied",
        "assignmentSource",
        "assignmentSourceLiveAgentTeams",
        "dynamicCandidateSupported",
        "testPathMutationSupported",
        "fixedCandidateSha256",
        "testCompletionPolicy",
        "minimumExecutedTests",
        "timeoutSeconds",
        "cpuSeconds",
        "addressSpaceBytes",
        "maxProcesses",
        "maxOpenFiles",
        "maxOutputBytes",
        "maxPatchBytes",
        "maxPatchFiles",
        "maxFileBytes",
        "maxRepositoryFiles",
        "maxRepositoryBytes",
        "credentialPolicy",
        "networkPolicy",
        "workspaceBinding",
        "remainingThreat",
    }
)
RECEIPT_POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "algorithm",
        "audience",
        "issuer",
        "signatureDomain",
        "publicKeyPath",
        "publicKeyFileSha256",
        "publicKeySha256",
        "policyAttestationPath",
        "opensslPath",
        "replayLedgerPath",
        "replayScope",
        "replayLedgerPersistentAcrossPodReplacement",
        "receiptLifetimeSeconds",
        "maxReceiptLifetimeSeconds",
        "maxClockSkewSeconds",
        "ciServerSha256",
        "ciPolicySha256",
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
        "repositoryRevision",
        "remainingThreat",
    }
)
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$"
)
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_FILES = 100_000
MAX_OUTPUT_BYTES = 1024 * 1024
SOURCE_PATH = "agentteams/cicd/tester_server.py"
TEAMHARNESS_RECEIPT_READBACK = r"""
import hashlib
import json
import stat
import sys
from pathlib import Path

manifest_path, public_key_path, policy_path, ledger_path = map(Path, sys.argv[1:])

def metadata(path):
    value = path.lstat()
    return {
        "regular": stat.S_ISREG(value.st_mode),
        "links": value.st_nlink,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "mode": stat.S_IMODE(value.st_mode),
    }

manifest_bytes = manifest_path.read_bytes()
public_key_bytes = public_key_path.read_bytes()
policy_bytes = policy_path.read_bytes()
ledger_bytes = ledger_path.read_bytes()
manifest = json.loads(manifest_bytes.decode("utf-8"))
policy = json.loads(policy_bytes.decode("utf-8"))
ledger = json.loads(ledger_bytes.decode("utf-8"))
used_jtis = ledger.get("usedJtis") if isinstance(ledger, dict) else None
value = {
    "schemaVersion": "devflow.teamharness.test-receipt-readback/v1",
    "sourcePolicy": manifest.get("sourcePolicy"),
    "manifestPolicyPath": manifest.get("testExecutionReceiptPolicyPath"),
    "manifestPolicySha256": manifest.get("testExecutionReceiptPolicySha256"),
    "manifestPublicKeyPath": manifest.get("testExecutionReceiptPublicKeyPath"),
    "manifestPublicKeyFileSha256": manifest.get(
        "testExecutionReceiptPublicKeyFileSha256"
    ),
    "replayScope": manifest.get("testExecutionReceiptReplayScope"),
    "replayLedgerPersistentAcrossPodReplacement": manifest.get(
        "testExecutionReceiptReplayLedgerPersistentAcrossPodReplacement"
    ),
    "receiptLifetimeSeconds": manifest.get("testExecutionReceiptLifetimeSeconds"),
    "policyFileSha256": hashlib.sha256(policy_bytes).hexdigest(),
    "publicKeyFileSha256": hashlib.sha256(public_key_bytes).hexdigest(),
    "policyMatchesManifest": manifest.get("testExecutionReceiptPolicy") == policy,
    "policyCanonical": policy_bytes == json.dumps(
        policy,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8"),
    "ledgerSchemaVersion": ledger.get("schemaVersion")
    if isinstance(ledger, dict)
    else None,
    "ledgerUsedJtisObject": isinstance(used_jtis, dict),
    "ledgerEntryCount": len(used_jtis) if isinstance(used_jtis, dict) else -1,
    "publicKeyPemOnly": public_key_bytes.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    and public_key_bytes.endswith(b"-----END PUBLIC KEY-----\n")
    and b"PRIVATE KEY" not in public_key_bytes,
}
for prefix, path in (
    ("manifest", manifest_path),
    ("publicKey", public_key_path),
    ("policy", policy_path),
    ("ledger", ledger_path),
):
    for name, item in metadata(path).items():
        value[prefix + name[0].upper() + name[1:]] = item
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
""".strip()


class ReconcileError(RuntimeError):
    """A source, identity, manifest, isolation, or readback gate failed."""


class Runner(Protocol):
    def run(self, args: list[str], *, input_data: bytes | None = None) -> str: ...


class SubprocessRunner:
    """Run fixed argument vectors without a shell or failed-command output."""

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        try:
            completed = subprocess.run(
                args,
                input=input_data,
                capture_output=True,
                check=False,
                text=input_data is None,
                timeout=240,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReconcileError("required command could not complete") from exc
        stdout = completed.stdout
        payload = stdout if isinstance(stdout, bytes) else stdout.encode("utf-8")
        if completed.returncode != 0:
            raise ReconcileError("required command failed without a success claim")
        if len(payload) > MAX_OUTPUT_BYTES:
            raise ReconcileError("required command output exceeded the public bound")
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReconcileError("required command returned non-UTF-8 output") from exc


@dataclass(frozen=True)
class TrackedFile:
    relative: str
    path: Path
    digest: str
    size: int
    mode: int


@dataclass(frozen=True)
class SourceAttestation:
    revision: str
    archive_sha256: str
    tree_sha256: str
    server_sha256: str
    file_count: int


@dataclass(frozen=True)
class TrustMaterial:
    public_key: bytes
    public_key_sha256: str
    public_key_file_sha256: str
    execution_policy: dict[str, Any]
    execution_policy_sha256: str
    receipt_policy: dict[str, Any]
    receipt_policy_sha256: str


@dataclass(frozen=True)
class DesiredState:
    resources: tuple[dict[str, Any], ...]
    config_map_name: str
    image: str
    source: SourceAttestation
    trust: TrustMaterial


@dataclass(frozen=True)
class SecretIsolationStatus:
    no_unexpected_secret_consumer: bool
    observed_single_signing_secret_consumer: bool


@dataclass(frozen=True)
class Report:
    applied: bool
    image: str
    repository_revision: str
    repository_archive_sha256: str
    server_sha256: str
    receipt_public_key_sha256: str
    receipt_policy_sha256: str
    execution_policy_sha256: str
    resources_verified: bool
    no_unexpected_secret_consumer: bool
    observed_single_secret_consumer: bool
    endpoint_verified: bool
    mcporter_policy_verified: bool
    ci_service_verified: bool
    deployment_preflight_ready: bool
    teamharness_receipt_verifier_verified: bool
    teamharness_receipt_verifier_roles: tuple[str, ...]
    end_to_end_ready: bool
    replay_scope: str
    replay_ledger_persistent_across_pod_replacement: bool
    receipt_lifetime_seconds: int
    network_policy_declared_and_readback: bool
    network_policy_tester_access_observed: bool
    network_policy_other_roles_denied_observed: bool
    network_policy_denied_roles: tuple[str, ...]
    tool_names: tuple[str, ...]
    needs_apply: bool


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReconcileError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ReconcileError("non-standard JSON scalar")


def _json_object(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ReconcileError(f"{label} returned malformed JSON") from exc
    if not isinstance(value, dict):
        raise ReconcileError(f"{label} returned a non-object")
    return value


def _safe_git_path(value: str) -> str:
    if not value or "\\" in value or CONTROL.search(value) is not None:
        raise ReconcileError("tracked path is unsafe")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ReconcileError("tracked path is unsafe")
    return value


def _tracked_files(
    runner: Runner,
    repository: Path,
) -> tuple[str, tuple[TrackedFile, ...]]:
    requested = repository
    try:
        root = requested.resolve(strict=True)
    except OSError as exc:
        raise ReconcileError("release repository is unavailable") from exc
    if requested.is_symlink() or not root.is_dir() or not (root / ".git").is_dir():
        raise ReconcileError("release repository root is outside policy")
    revision = runner.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD^{commit}"]
    ).strip()
    if REVISION.fullmatch(revision) is None:
        raise ReconcileError("release revision is not a full 40-hex commit")
    if runner.run(
        [
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "-z",
        ]
    ):
        raise ReconcileError("release repository must be completely clean")
    raw_index = runner.run(["git", "-C", str(root), "ls-files", "--stage", "-z"])
    files: list[TrackedFile] = []
    seen: set[str] = set()
    total = 0
    for record in raw_index.split("\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split("\t", 1)
            mode_text, object_id, stage = header.split(" ")
        except ValueError as exc:
            raise ReconcileError("git index output is malformed") from exc
        relative = _safe_git_path(raw_path)
        if (
            mode_text not in {"100644", "100755"}
            or re.fullmatch(r"[0-9a-f]{40,64}", object_id) is None
            or stage != "0"
            or relative in seen
        ):
            raise ReconcileError("git index contains a link, special entry, or conflict")
        path = root.joinpath(*PurePosixPath(relative).parts)
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
            payload = path.read_bytes()
        except OSError as exc:
            raise ReconcileError("tracked source changed during validation") from exc
        if (
            path.is_symlink()
            or resolved != path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size != len(payload)
            or len(payload) > MAX_FILE_BYTES
        ):
            raise ReconcileError("tracked source contains a link or special file")
        total += len(payload)
        if len(files) >= MAX_FILES or total > MAX_ARCHIVE_BYTES:
            raise ReconcileError("release repository exceeds the archive bound")
        seen.add(relative)
        files.append(
            TrackedFile(
                relative=relative,
                path=path,
                digest=_sha256(payload),
                size=len(payload),
                mode=0o555 if mode_text == "100755" else 0o444,
            )
        )
    if SOURCE_PATH not in seen:
        raise ReconcileError("release repository lacks the CI server source")
    return revision, tuple(sorted(files, key=lambda item: item.relative))


def _archive(files: tuple[TrackedFile, ...]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for item in files:
            try:
                metadata = item.path.lstat()
                payload = item.path.read_bytes()
            except OSError as exc:
                raise ReconcileError("tracked source changed while archiving") from exc
            if (
                item.path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or len(payload) != item.size
                or _sha256(payload) != item.digest
            ):
                raise ReconcileError("tracked source changed while archiving")
            info = tarfile.TarInfo(item.relative)
            info.size = len(payload)
            info.mode = item.mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(payload))
    result = buffer.getvalue()
    if len(result) > MAX_ARCHIVE_BYTES:
        raise ReconcileError("release archive exceeds the bound")
    return result


def attest_source(runner: Runner, repository: Path) -> SourceAttestation:
    revision, files = _tracked_files(runner, repository)
    archive = _archive(files)
    tree = [{"path": item.relative, "sha256": item.digest} for item in files]
    server = next(item for item in files if item.relative == SOURCE_PATH)
    return SourceAttestation(
        revision=revision,
        archive_sha256=_sha256(archive),
        tree_sha256=_sha256(_canonical(tree)),
        server_sha256=server.digest,
        file_count=len(files),
    )


def load_public_key(path: Path) -> tuple[bytes, str]:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
        payload = resolved.read_bytes()
        lines = payload.decode("ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ReconcileError("receipt public key is unavailable or non-ASCII") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or len(lines) != 3
        or lines[0] != "-----BEGIN PUBLIC KEY-----"
        or lines[2] != "-----END PUBLIC KEY-----"
    ):
        raise ReconcileError("receipt public key is not a canonical public key")
    try:
        der = base64.b64decode(lines[1], validate=True)
    except ValueError as exc:
        raise ReconcileError("receipt public key base64 is invalid") from exc
    canonical = (
        f"-----BEGIN PUBLIC KEY-----\n{base64.b64encode(der).decode('ascii')}\n"
        "-----END PUBLIC KEY-----\n"
    ).encode("ascii")
    if payload != canonical or len(der) != 44 or not der.startswith(ED25519_SPKI_PREFIX):
        raise ReconcileError("receipt public key is not canonical Ed25519 SPKI")
    return payload, _sha256(der)


def _canonical_policy(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
        payload = resolved.read_bytes()
    except OSError as exc:
        raise ReconcileError(f"{label} is unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 1 <= len(payload) <= 128 * 1024
    ):
        raise ReconcileError(f"{label} file is outside policy")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ReconcileError(f"{label} is malformed") from exc
    if not isinstance(value, dict) or payload != _canonical(value):
        raise ReconcileError(f"{label} is not canonical JSON")
    return value, payload


def _fixed_command(value: Any) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= 64
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > 1024
            or "\x00" in item
            for item in value
        )
        or not PurePosixPath(value[0]).is_absolute()
        or "\\" in value[0]
    ):
        raise ReconcileError("execution policy command is invalid")
    executable = PurePosixPath(value[0]).name.lower()
    if executable in {
        "bash",
        "cmd",
        "cmd.exe",
        "dash",
        "fish",
        "powershell",
        "pwsh",
        "sh",
        "zsh",
    }:
        raise ReconcileError("execution policy command is invalid")
    if executable.startswith(("python", "pypy")) and "-c" in value[1:]:
        raise ReconcileError("execution policy command is invalid")
    if executable in {"node", "nodejs"} and any(
        argument in {"-e", "--eval"} for argument in value[1:]
    ):
        raise ReconcileError("execution policy command is invalid")
    return list(value)


def _execution_policy_binding(policy: dict[str, Any]) -> str:
    body = {
        key: policy[key]
        for key in sorted(EXECUTION_POLICY_FIELDS - {"workspaceBinding", "remainingThreat"})
    }
    return _sha256(_canonical(body))


def trust_material(
    *,
    source: SourceAttestation,
    public_key_path: Path,
    execution_policy_path: Path,
    receipt_policy_path: Path,
) -> TrustMaterial:
    public_key, public_key_sha256 = load_public_key(public_key_path)
    public_key_file_sha256 = _sha256(public_key)
    execution, _execution_bytes = _canonical_policy(
        execution_policy_path,
        "execution policy",
    )
    if (
        set(execution) != EXECUTION_POLICY_FIELDS
        or execution.get("schemaVersion") != "1.0"
        or execution.get("teamName") != TEAM_NAME
        or execution.get("serviceIdentity") != SERVICE_IDENTITY
        or execution.get("repositoryRoot") != REPOSITORY_ROOT
        or execution.get("workspaceRoot") != WORKSPACE_ROOT
        or execution.get("repositoryRevision") != source.revision
        or execution.get("repositoryArchiveSha256") != source.archive_sha256
        or execution.get("repositoryManifestSha256") != source.tree_sha256
        or execution.get("serverSha256") != source.server_sha256
        or execution.get("receiptPublicKeySha256") != public_key_sha256
        or execution.get("networkIsolationPrefix") != list(NETWORK_PREFIX)
        or execution.get("resourceLimitLauncher") != ["/usr/bin/prlimit"]
        or execution.get("resourceLimitsApplied") is not True
        or execution.get("assignmentSource") != ASSIGNMENT_SOURCE
        or execution.get("assignmentSourceLiveAgentTeams") is not False
        or execution.get("dynamicCandidateSupported") is not False
        or execution.get("testPathMutationSupported") is not False
        or execution.get("testCompletionPolicy") != TEST_COMPLETION_POLICY
        or execution.get("credentialPolicy") != "empty-environment"
        or execution.get("networkPolicy") != NETWORK_POLICY
        or not isinstance(execution.get("remainingThreat"), str)
        or not execution["remainingThreat"]
    ):
        raise ReconcileError("execution policy identity or source binding is invalid")
    commands = execution.get("testCommands")
    executable_digests = execution.get("testExecutableSha256")
    if (
        not isinstance(commands, dict)
        or set(commands) != {"focused", "full"}
        or not isinstance(executable_digests, dict)
        or set(executable_digests) != {"focused", "full"}
    ):
        raise ReconcileError("execution policy command map is invalid")
    for suite in ("focused", "full"):
        _fixed_command(commands[suite])
        if (
            not isinstance(executable_digests[suite], str)
            or DIGEST.fullmatch(executable_digests[suite]) is None
        ):
            raise ReconcileError("execution policy executable digest is invalid")
    for field in (
        "networkIsolationExecutableSha256",
        "resourceLimitLauncherSha256",
        "workspaceBinding",
    ):
        if not isinstance(execution.get(field), str) or DIGEST.fullmatch(execution[field]) is None:
            raise ReconcileError("execution policy digest is invalid")
    fixed_candidates = execution.get("fixedCandidateSha256")
    minimum_executed = execution.get("minimumExecutedTests")
    if (
        not isinstance(fixed_candidates, dict)
        or set(fixed_candidates) != set(FIXTURE_TASK_IDS)
        or any(
            not isinstance(value, str) or DIGEST.fullmatch(value) is None
            for value in fixed_candidates.values()
        )
        or isinstance(minimum_executed, bool)
        or not isinstance(minimum_executed, int)
        or not 1 <= minimum_executed <= 10_000
    ):
        raise ReconcileError("fixed candidate execution policy is invalid")
    limits = {
        "timeoutSeconds": (1, 900),
        "cpuSeconds": (1, 900),
        "addressSpaceBytes": (64 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
        "maxProcesses": (1, 256),
        "maxOpenFiles": (16, 4096),
        "maxOutputBytes": (1024, 64 * 1024),
        "maxPatchBytes": (1024, 4 * 1024 * 1024),
        "maxPatchFiles": (1, 256),
        "maxFileBytes": (1024, 8 * 1024 * 1024),
        "maxRepositoryFiles": (1, 200_000),
        "maxRepositoryBytes": (1024, 2 * 1024 * 1024 * 1024),
    }
    for field, (minimum, maximum) in limits.items():
        value = execution.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ReconcileError("execution policy resource limit is invalid")
    execution_policy_sha256 = _execution_policy_binding(execution)
    if execution["workspaceBinding"] != execution_policy_sha256:
        raise ReconcileError("execution policy binding is invalid")

    receipt, receipt_bytes = _canonical_policy(receipt_policy_path, "receipt policy")
    if (
        set(receipt) != RECEIPT_POLICY_FIELDS
        or receipt.get("schemaVersion") != RECEIPT_POLICY_SCHEMA
        or receipt.get("algorithm") != "Ed25519"
        or receipt.get("audience") != RECEIPT_AUDIENCE
        or receipt.get("issuer") != RECEIPT_ISSUER
        or receipt.get("signatureDomain") != RECEIPT_DOMAIN
        or receipt.get("publicKeyPath") != TEAMHARNESS_PUBLIC_KEY_PATH
        or receipt.get("publicKeyFileSha256") != public_key_file_sha256
        or receipt.get("publicKeySha256") != public_key_sha256
        or receipt.get("policyAttestationPath") != TEAMHARNESS_POLICY_PATH
        or receipt.get("opensslPath") != "/usr/bin/openssl"
        or receipt.get("replayLedgerPath") != TEAMHARNESS_LEDGER_PATH
        or receipt.get("replayScope") != REPLAY_SCOPE
        or receipt.get("replayLedgerPersistentAcrossPodReplacement")
        is not REPLAY_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        or receipt.get("receiptLifetimeSeconds") != RECEIPT_LIFETIME_SECONDS
        or receipt.get("maxReceiptLifetimeSeconds") != 120
        or receipt.get("maxClockSkewSeconds") != 5
        or receipt.get("ciServerSha256") != source.server_sha256
        or receipt.get("ciPolicySha256") != execution_policy_sha256
        or receipt.get("repositoryArchiveSha256") != source.archive_sha256
        or receipt.get("repositoryManifestSha256") != source.tree_sha256
        or receipt.get("repositoryRevision") != source.revision
        or not isinstance(receipt.get("remainingThreat"), str)
        or not receipt["remainingThreat"]
        or "pod replacement" not in receipt["remainingThreat"].lower()
        or "120" not in receipt["remainingThreat"]
    ):
        raise ReconcileError("receipt policy identity or release binding is invalid")
    return TrustMaterial(
        public_key=public_key,
        public_key_sha256=public_key_sha256,
        public_key_file_sha256=public_key_file_sha256,
        execution_policy=execution,
        execution_policy_sha256=execution_policy_sha256,
        receipt_policy=receipt,
        receipt_policy_sha256=_sha256(receipt_bytes),
    )


def _metadata(name: str, *, labels: dict[str, str] | None = None) -> dict[str, Any]:
    value: dict[str, Any] = {"name": name, "namespace": NAMESPACE}
    if labels:
        value["labels"] = labels
    return value


def desired_state(
    *,
    source: SourceAttestation,
    trust: TrustMaterial,
    image: str,
) -> DesiredState:
    if IMAGE.fullmatch(image) is None:
        raise ReconcileError("CI image must use an exact sha256 digest reference")
    release_digest = _sha256(
        _canonical(
            {
                "image": image,
                "repositoryRevision": source.revision,
                "repositoryArchiveSha256": source.archive_sha256,
                "serverSha256": source.server_sha256,
                "receiptPublicKeySha256": trust.public_key_sha256,
                "receiptPolicySha256": trust.receipt_policy_sha256,
                "executionPolicySha256": trust.execution_policy_sha256,
            }
        )
    )
    config_map_name = f"{APP_NAME}-{release_digest[:16]}"
    labels = {
        "app.kubernetes.io/name": APP_NAME,
        "app.kubernetes.io/component": "isolated-ci-mcp",
    }
    annotations = {
        "devflow.io/release-digest": release_digest,
        "devflow.io/repository-revision": source.revision,
        "devflow.io/repository-archive-sha256": source.archive_sha256,
        "devflow.io/server-sha256": source.server_sha256,
        "devflow.io/receipt-public-key-sha256": trust.public_key_sha256,
        "devflow.io/receipt-public-key-file-sha256": trust.public_key_file_sha256,
        "devflow.io/receipt-policy-sha256": trust.receipt_policy_sha256,
        "devflow.io/execution-policy-sha256": trust.execution_policy_sha256,
        "devflow.io/assignment-source": ASSIGNMENT_SOURCE,
        "devflow.io/live-agentteams-task-projection": "false",
    }
    config = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": _metadata(config_map_name, labels=labels),
        "immutable": True,
        "data": {
            "receipt-ed25519.pub": trust.public_key.decode("ascii"),
            "receipt-public-key-file-sha256": trust.public_key_file_sha256,
            "test-receipt-policy.json": _canonical(trust.receipt_policy).decode("utf-8"),
            "execution-policy.json": _canonical(trust.execution_policy).decode("utf-8"),
            "repository-revision": source.revision,
            "repository-archive-sha256": source.archive_sha256,
            "repository-tree-sha256": source.tree_sha256,
            "server-sha256": source.server_sha256,
            "execution-policy-sha256": trust.execution_policy_sha256,
            "service-url": SERVICE_URL,
            "assignment-source": ASSIGNMENT_SOURCE,
            "fixture-task-ids": _canonical(list(FIXTURE_TASK_IDS)).decode("utf-8"),
            "live-agentteams-task-projection": "false",
            "repository-mode": REPOSITORY_MODE,
            "test-command-source": TEST_COMMAND_SOURCE,
        },
    }
    service_account = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": _metadata(SERVICE_ACCOUNT, labels=labels),
        "automountServiceAccountToken": False,
    }
    container = {
        "name": "ci-mcp",
        "image": image,
        "imagePullPolicy": "IfNotPresent",
        "args": [
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
        ],
        "ports": [{"name": "mcp-http", "containerPort": 8080, "protocol": "TCP"}],
        "readinessProbe": {
            "httpGet": {"path": "/readyz", "port": "mcp-http"},
            "periodSeconds": 5,
            "timeoutSeconds": 2,
            "failureThreshold": 6,
        },
        "livenessProbe": {
            "httpGet": {"path": "/healthz", "port": "mcp-http"},
            "periodSeconds": 10,
            "timeoutSeconds": 2,
            "failureThreshold": 3,
        },
        "resources": {
            "requests": {"cpu": "100m", "memory": "128Mi"},
            "limits": {"cpu": "2", "memory": "2Gi"},
        },
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": SERVICE_UID,
            "runAsGroup": SERVICE_GID,
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [
            {
                "name": "receipt-signing-key",
                "mountPath": PRIVATE_KEY_PATH,
                "subPath": SECRET_KEY,
                "readOnly": True,
            },
            {
                "name": "release-config",
                "mountPath": EXECUTION_POLICY_PATH,
                "subPath": "execution-policy.json",
                "readOnly": True,
            },
            {
                "name": "release-config",
                "mountPath": CI_RECEIPT_POLICY_PATH,
                "subPath": "test-receipt-policy.json",
                "readOnly": True,
            },
            {
                "name": "assignments",
                "mountPath": ASSIGNMENT_ROOT,
            },
            {
                "name": "workspaces",
                "mountPath": "/var/lib/devflow/agentteams-cicd/workspaces",
            },
            {"name": "temporary", "mountPath": "/tmp"},
        ],
    }
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": _metadata(DEPLOYMENT_NAME, labels=labels),
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels, "annotations": annotations},
                "spec": {
                    "serviceAccountName": SERVICE_ACCOUNT,
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": SERVICE_UID,
                        "runAsGroup": SERVICE_GID,
                        "fsGroup": SERVICE_GID,
                        "fsGroupChangePolicy": "OnRootMismatch",
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [container],
                    "volumes": [
                        {
                            "name": "receipt-signing-key",
                            "secret": {
                                "secretName": SECRET_NAME,
                                "defaultMode": 0o440,
                                "items": [{"key": SECRET_KEY, "path": SECRET_KEY}],
                            },
                        },
                        {"name": "release-config", "configMap": {"name": config_map_name, "defaultMode": 0o444}},
                        {"name": "workspaces", "emptyDir": {"sizeLimit": "2Gi"}},
                        {"name": "assignments", "emptyDir": {"sizeLimit": "1Mi"}},
                        {"name": "temporary", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}},
                    ],
                },
            },
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": _metadata(SERVICE_NAME, labels=labels),
        "spec": {
            "type": "ClusterIP",
            "selector": labels,
            "ports": [{"name": "mcp-http", "port": 8080, "targetPort": "mcp-http", "protocol": "TCP"}],
        },
    }
    default_deny = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(f"{APP_NAME}-default-deny", labels=labels),
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
        },
    }
    tester_only = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": _metadata(f"{APP_NAME}-tester-only", labels=labels),
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress", "Egress"],
            "ingress": [
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {
                                    TEAM_LABEL: TEAM_NAME,
                                    WORKER_LABEL: TESTER_ROLE,
                                    RUNTIME_LABEL: "openclaw",
                                }
                            }
                        }
                    ],
                    "ports": [{"protocol": "TCP", "port": 8080}],
                }
            ],
            "egress": [],
        },
    }
    return DesiredState(
        resources=(config, service_account, deployment, service, default_deny, tester_only),
        config_map_name=config_map_name,
        image=image,
        source=source,
        trust=trust,
    )


def _kubectl(kubectl: str, *args: str) -> list[str]:
    return [kubectl, "--namespace", NAMESPACE, *args]


def _exec(kubectl: str, target: Target, *args: str) -> list[str]:
    return _kubectl(
        kubectl,
        "exec",
        target.pod_name,
        "--container",
        CONTAINER_NAME,
        "--",
        *args,
    )


def _receipt_readback_matches(
    value: Any,
    desired: DesiredState,
) -> bool:
    fields = {
        "schemaVersion",
        "sourcePolicy",
        "manifestPolicyPath",
        "manifestPolicySha256",
        "manifestPublicKeyPath",
        "manifestPublicKeyFileSha256",
        "replayScope",
        "replayLedgerPersistentAcrossPodReplacement",
        "receiptLifetimeSeconds",
        "policyFileSha256",
        "publicKeyFileSha256",
        "policyMatchesManifest",
        "policyCanonical",
        "ledgerSchemaVersion",
        "ledgerUsedJtisObject",
        "ledgerEntryCount",
        "publicKeyPemOnly",
        *(
            f"{prefix}{suffix}"
            for prefix in ("manifest", "publicKey", "policy", "ledger")
            for suffix in ("Regular", "Links", "Uid", "Gid", "Mode")
        ),
    }
    if not isinstance(value, dict) or set(value) != fields:
        return False
    if (
        value.get("schemaVersion")
        != "devflow.teamharness.test-receipt-readback/v1"
        or value.get("sourcePolicy") != "production-pinned"
        or value.get("manifestPolicyPath") != TEAMHARNESS_POLICY_PATH
        or value.get("manifestPolicySha256")
        != desired.trust.receipt_policy_sha256
        or value.get("policyFileSha256") != desired.trust.receipt_policy_sha256
        or value.get("manifestPublicKeyPath") != TEAMHARNESS_PUBLIC_KEY_PATH
        or value.get("manifestPublicKeyFileSha256")
        != desired.trust.public_key_file_sha256
        or value.get("publicKeyFileSha256")
        != desired.trust.public_key_file_sha256
        or value.get("replayScope") != REPLAY_SCOPE
        or value.get("replayLedgerPersistentAcrossPodReplacement")
        is not REPLAY_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        or value.get("receiptLifetimeSeconds") != RECEIPT_LIFETIME_SECONDS
        or value.get("policyMatchesManifest") is not True
        or value.get("policyCanonical") is not True
        or value.get("ledgerSchemaVersion")
        != "devflow.test-execution-receipt-ledger/v1"
        or value.get("ledgerUsedJtisObject") is not True
        or value.get("publicKeyPemOnly") is not True
    ):
        return False
    entry_count = value.get("ledgerEntryCount")
    if (
        isinstance(entry_count, bool)
        or not isinstance(entry_count, int)
        or not 0 <= entry_count <= 100_000
    ):
        return False
    for prefix in ("manifest", "publicKey", "policy", "ledger"):
        if (
            value.get(f"{prefix}Regular") is not True
            or value.get(f"{prefix}Links") != 1
            or value.get(f"{prefix}Uid") != 0
            or value.get(f"{prefix}Gid") != 0
        ):
            return False
    for prefix in ("manifest", "publicKey", "policy"):
        mode = value.get(f"{prefix}Mode")
        if isinstance(mode, bool) or not isinstance(mode, int) or mode & 0o022:
            return False
    return value.get("ledgerMode") == 0o600


def _teamharness_receipt_verifier_roles(
    runner: Runner,
    kubectl: str,
    targets: tuple[Target, ...],
    desired: DesiredState,
) -> tuple[str, ...]:
    """Read back only public verifier facts after the installed adapter passes."""

    verified: list[str] = []
    for target in targets:
        try:
            checks = json.loads(
                runner.run(
                    _exec(
                        kubectl,
                        target,
                        "python3",
                        TEAMHARNESS_ADAPTER_PATH,
                        "verify",
                        "--workspace",
                        target.workspace,
                        "--role",
                        target.teamharness_role,
                    )
                )
            )
            if (
                not isinstance(checks, list)
                or not checks
                or any(
                    not isinstance(check, dict)
                    or set(check) != {"name", "ok", "detail"}
                    or check.get("ok") is not True
                    for check in checks
                )
                or sum(
                    check.get("name") == "test-execution-receipt-policy"
                    for check in checks
                )
                != 1
            ):
                continue
            readback = json.loads(
                runner.run(
                    _exec(
                        kubectl,
                        target,
                        "python3",
                        "-S",
                        "-c",
                        TEAMHARNESS_RECEIPT_READBACK,
                        TEAMHARNESS_MANIFEST_PATH,
                        TEAMHARNESS_PUBLIC_KEY_PATH,
                        TEAMHARNESS_POLICY_PATH,
                        TEAMHARNESS_LEDGER_PATH,
                    )
                )
            )
        except (OSError, RuntimeError, UnicodeError, ValueError):
            continue
        if _receipt_readback_matches(readback, desired):
            verified.append(target.role_name)
    return tuple(verified)


def _contains(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and _contains(actual[key], value)
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) == len(expected) and all(
            _contains(item, wanted) for item, wanted in zip(actual, expected, strict=True)
        )
    return bool(actual == expected)


def _resource_identity(resource: dict[str, Any]) -> tuple[str, str]:
    metadata = resource.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("name"), str):
        raise ReconcileError("desired resource identity is malformed")
    return str(resource.get("kind")), metadata["name"]


def _resource_type(kind: str) -> str:
    mapping = {
        "ConfigMap": "configmap",
        "ServiceAccount": "serviceaccount",
        "Deployment": "deployment",
        "Service": "service",
        "NetworkPolicy": "networkpolicy",
    }
    try:
        return mapping[kind]
    except KeyError as exc:
        raise ReconcileError("desired resource kind is outside policy") from exc


def _live_resources(
    runner: Runner,
    kubectl: str,
    desired: DesiredState,
) -> tuple[bool, bool]:
    all_present = True
    all_compliant = True
    for resource in desired.resources:
        kind, name = _resource_identity(resource)
        text = runner.run(
            _kubectl(
                kubectl,
                "get",
                _resource_type(kind),
                name,
                "--ignore-not-found=true",
                "--output",
                "json",
            )
        )
        if not text.strip():
            all_present = False
            all_compliant = False
            continue
        live = _json_object(text, f"live {kind}/{name}")
        if kind == "ConfigMap":
            compliant = (
                live.get("immutable") is True
                and live.get("data") == resource.get("data")
                and not live.get("binaryData")
            )
        elif kind == "ServiceAccount":
            compliant = live.get("automountServiceAccountToken") is False
        elif kind == "Service":
            compliant = _contains(live.get("spec"), resource.get("spec"))
        elif kind == "NetworkPolicy":
            compliant = live.get("spec") == resource.get("spec")
        elif kind == "Deployment":
            live_spec = live.get("spec")
            wanted_spec = resource.get("spec")
            compliant = _contains(live_spec, wanted_spec)
            if isinstance(live_spec, dict):
                template_spec = live_spec.get("template", {}).get("spec", {})
                compliant = bool(
                    compliant
                    and isinstance(template_spec, dict)
                    and len(template_spec.get("containers", [])) == 1
                    and len(template_spec.get("initContainers", [])) == 0
                    and not template_spec.get("hostNetwork")
                    and not template_spec.get("hostPID")
                    and not template_spec.get("hostIPC")
                )
        else:  # pragma: no cover - guarded by _resource_type
            compliant = False
        all_compliant = all_compliant and compliant
    return all_present, all_compliant


def _pod_references_secret(pod: dict[str, Any], secret_name: str) -> bool:
    spec = pod.get("spec")
    if not isinstance(spec, dict):
        raise ReconcileError("Pod spec is malformed")
    volumes = spec.get("volumes", [])
    if not isinstance(volumes, list):
        raise ReconcileError("Pod volumes are malformed")
    for volume in volumes:
        if not isinstance(volume, dict):
            raise ReconcileError("Pod volume is malformed")
        secret = volume.get("secret")
        if isinstance(secret, dict) and secret.get("secretName") == secret_name:
            return True
        projected = volume.get("projected")
        sources = projected.get("sources", []) if isinstance(projected, dict) else []
        if not isinstance(sources, list):
            raise ReconcileError("Pod projected volume is malformed")
        if any(
            isinstance(source, dict)
            and isinstance(source.get("secret"), dict)
            and source["secret"].get("name") == secret_name
            for source in sources
        ):
            return True
    image_pull_secrets = spec.get("imagePullSecrets", [])
    if not isinstance(image_pull_secrets, list):
        raise ReconcileError("Pod image pull Secrets are malformed")
    if any(
        isinstance(reference, dict) and reference.get("name") == secret_name
        for reference in image_pull_secrets
    ):
        return True
    containers_raw = spec.get("containers", [])
    init_containers_raw = spec.get("initContainers", [])
    ephemeral_containers_raw = spec.get("ephemeralContainers", [])
    if (
        not isinstance(containers_raw, list)
        or not isinstance(init_containers_raw, list)
        or not isinstance(ephemeral_containers_raw, list)
    ):
        raise ReconcileError("Pod containers are malformed")
    containers = [
        *containers_raw,
        *init_containers_raw,
        *ephemeral_containers_raw,
    ]
    for container in containers:
        if not isinstance(container, dict):
            raise ReconcileError("Pod container is malformed")
        environment = container.get("env", [])
        environment_from = container.get("envFrom", [])
        if not isinstance(environment, list) or not isinstance(environment_from, list):
            raise ReconcileError("Pod container environment is malformed")
        for env in environment:
            reference = env.get("valueFrom", {}).get("secretKeyRef", {}) if isinstance(env, dict) else {}
            if isinstance(reference, dict) and reference.get("name") == secret_name:
                return True
        for env_from in environment_from:
            reference = env_from.get("secretRef", {}) if isinstance(env_from, dict) else {}
            if isinstance(reference, dict) and reference.get("name") == secret_name:
                return True
    return False


def _discover(
    runner: Runner,
    kubectl: str,
) -> tuple[Target, tuple[Target, ...], dict[str, Any], dict[str, Any]]:
    runner.run([kubectl, "version", "--request-timeout=10s"])
    team_text = runner.run(
        _kubectl(kubectl, "get", "team", TEAM_NAME, "--output", "json")
    )
    team_pods_text = runner.run(
        _kubectl(
            kubectl,
            "get",
            "pods",
            "--selector",
            f"{TEAM_LABEL}={TEAM_NAME},{RUNTIME_LABEL}=openclaw",
            "--output",
            "json",
        )
    )
    namespace_pods_text = runner.run(_kubectl(kubectl, "get", "pods", "--output", "json"))
    namespace_workloads_text = runner.run(
        _kubectl(
            kubectl,
            "get",
            WORKLOAD_TEMPLATE_RESOURCES,
            "--output",
            "json",
        )
    )
    try:
        team = json.loads(team_text)
        team_pods = json.loads(team_pods_text)
        namespace_pods = json.loads(namespace_pods_text)
        namespace_workloads = json.loads(namespace_workloads_text)
        targets = discover_targets(team, team_pods, require_github_issuer_token=False)
    except (json.JSONDecodeError, RuntimeError, ValueError) as exc:
        raise ReconcileError("fixed AgentTeams target discovery failed") from exc
    tester = [target for target in targets if target.role_name == TESTER_ROLE]
    if (
        len(tester) != 1
        or not isinstance(namespace_pods, dict)
        or not isinstance(namespace_workloads, dict)
    ):
        raise ReconcileError("exactly one Ready Tester Pod is required")
    return tester[0], tuple(targets), namespace_pods, namespace_workloads


def _workload_pod_spec(workload: dict[str, Any]) -> dict[str, Any]:
    kind = workload.get("kind")
    spec = workload.get("spec")
    if not isinstance(spec, dict):
        raise ReconcileError("namespace workload spec is malformed")
    if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
        template = spec.get("template")
    elif kind == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = (
            job_template.get("spec") if isinstance(job_template, dict) else None
        )
        template = job_spec.get("template") if isinstance(job_spec, dict) else None
    else:
        raise ReconcileError("namespace workload kind is outside the observed set")
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        raise ReconcileError("namespace workload Pod template is malformed")
    return pod_spec


def _secret_isolation(
    namespace_pods: dict[str, Any],
    *,
    require_ci_pod: bool,
    namespace_workloads: dict[str, Any] | None = None,
) -> SecretIsolationStatus:
    items = namespace_pods.get("items")
    if not isinstance(items, list):
        raise ReconcileError("namespace Pod discovery is malformed")
    consumers: list[dict[str, Any]] = []
    for pod in items:
        if not isinstance(pod, dict):
            raise ReconcileError("namespace Pod item is malformed")
        if _pod_references_secret(pod, SECRET_NAME):
            consumers.append(pod)
    workload_items = (namespace_workloads or {"items": []}).get("items")
    if not isinstance(workload_items, list):
        raise ReconcileError("namespace workload discovery is malformed")
    allowed_templates = 0
    for workload in workload_items:
        if not isinstance(workload, dict):
            raise ReconcileError("namespace workload item is malformed")
        pod_spec = _workload_pod_spec(workload)
        if not _pod_references_secret({"spec": pod_spec}, SECRET_NAME):
            continue
        metadata = workload.get("metadata")
        if (
            workload.get("kind") != "Deployment"
            or not isinstance(metadata, dict)
            or metadata.get("name") != DEPLOYMENT_NAME
        ):
            raise ReconcileError(
                "receipt signing Secret appears in another workload template"
            )
        allowed_templates += 1
    if allowed_templates > 1:
        raise ReconcileError("receipt signing Secret has duplicate CI templates")
    if (
        consumers
        and namespace_workloads is not None
        and require_ci_pod
        and allowed_templates != 1
    ):
        raise ReconcileError("receipt signing Secret CI template is not observed")
    if not consumers:
        return SecretIsolationStatus(
            no_unexpected_secret_consumer=True,
            observed_single_signing_secret_consumer=False,
        )
    if len(consumers) != 1:
        raise ReconcileError("receipt signing Secret has multiple Pod consumers")
    for pod in consumers:
        metadata = pod.get("metadata")
        spec = pod.get("spec")
        labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
        if (
            not isinstance(labels, dict)
            or labels.get("app.kubernetes.io/name") != APP_NAME
            or labels.get("app.kubernetes.io/component") != "isolated-ci-mcp"
            or not isinstance(spec, dict)
            or spec.get("serviceAccountName") != SERVICE_ACCOUNT
            or spec.get("automountServiceAccountToken") is not False
            or spec.get("securityContext")
            != {
                "runAsNonRoot": True,
                "runAsUser": SERVICE_UID,
                "runAsGroup": SERVICE_GID,
                "fsGroup": SERVICE_GID,
                "fsGroupChangePolicy": "OnRootMismatch",
                "seccompProfile": {"type": "RuntimeDefault"},
            }
        ):
            raise ReconcileError("receipt signing Secret is visible outside the CI Pod")
        volumes = spec.get("volumes", [])
        containers = spec.get("containers", [])
        init_containers = spec.get("initContainers", [])
        ephemeral_containers = spec.get("ephemeralContainers", [])
        if (
            not isinstance(volumes, list)
            or not isinstance(containers, list)
            or not isinstance(init_containers, list)
            or not isinstance(ephemeral_containers, list)
        ):
            raise ReconcileError("receipt signing Secret Pod wiring is malformed")
        secret_volumes = {
            volume.get("name")
            for volume in volumes
            if isinstance(volume, dict)
            and isinstance(volume.get("name"), str)
            and isinstance(volume.get("secret"), dict)
            and volume["secret"].get("secretName") == SECRET_NAME
        }
        secret_definitions = [
            volume["secret"]
            for volume in volumes
            if isinstance(volume, dict)
            and volume.get("name") in secret_volumes
            and isinstance(volume.get("secret"), dict)
        ]
        mounts: list[tuple[str, dict[str, Any]]] = []
        for current in [*containers, *init_containers, *ephemeral_containers]:
            if not isinstance(current, dict) or not isinstance(
                current.get("volumeMounts", []), list
            ):
                raise ReconcileError("receipt signing Secret Pod wiring is malformed")
            for mount in current.get("volumeMounts", []):
                if isinstance(mount, dict) and mount.get("name") in secret_volumes:
                    mounts.append((str(current.get("name", "")), mount))
        ci_container = containers[0] if len(containers) == 1 else None
        if (
            len(secret_volumes) != 1
            or secret_definitions
            != [
                {
                    "secretName": SECRET_NAME,
                    "defaultMode": 0o440,
                    "items": [{"key": SECRET_KEY, "path": SECRET_KEY}],
                }
            ]
            or not isinstance(ci_container, dict)
            or ci_container.get("name") != "ci-mcp"
            or ci_container.get("securityContext")
            != {
                "runAsNonRoot": True,
                "runAsUser": SERVICE_UID,
                "runAsGroup": SERVICE_GID,
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
            }
            or init_containers
            or ephemeral_containers
            or mounts
            != [
            (
                "ci-mcp",
                {
                    "name": next(iter(secret_volumes)),
                    "mountPath": PRIVATE_KEY_PATH,
                    "subPath": SECRET_KEY,
                    "readOnly": True,
                },
            )
            ]
        ):
            raise ReconcileError(
                "receipt signing Secret is not isolated to the CI signer"
            )
    return SecretIsolationStatus(
        no_unexpected_secret_consumer=True,
        observed_single_signing_secret_consumer=True,
    )


REMOTE_HTTP_CHECK = f"""
import json, sys, urllib.error, urllib.request
service_url, ready_url = sys.argv[1:]
if service_url != {SERVICE_URL!r} or ready_url != {READY_URL!r}:
    raise SystemExit(2)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
opener = urllib.request.build_opener(NoRedirect)
def read_json(response):
    body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024 or response.geturl() not in {{service_url, ready_url}}:
        raise SystemExit(3)
    media = response.headers.get_content_type()
    if media == 'application/json':
        return json.loads(body)
    if media == 'text/event-stream':
        values = []
        for line in body.decode('utf-8').splitlines():
            if line.startswith('data:'):
                values.append(json.loads(line[5:].strip()))
        if len(values) != 1: raise SystemExit(3)
        return values[0]
    raise SystemExit(3)
with opener.open(urllib.request.Request(ready_url, method='GET'), timeout=10) as response:
    if response.status != 200: raise SystemExit(3)
    ready = read_json(response)
headers = {{'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}}
def post(payload, session=None):
    current = dict(headers)
    if session: current['Mcp-Session-Id'] = session
    request = urllib.request.Request(service_url, data=json.dumps(payload, sort_keys=True, separators=(',', ':')).encode(), headers=current, method='POST')
    with opener.open(request, timeout=15) as response:
        if response.status not in {{200, 202}}: raise SystemExit(3)
        session_id = response.headers.get('Mcp-Session-Id') or session
        if response.status == 202: return None, session_id
        return read_json(response), session_id
initialized, session = post({{'jsonrpc':'2.0','id':'init','method':'initialize','params':{{'protocolVersion':{PROTOCOL_VERSION!r},'capabilities':{{}},'clientInfo':{{'name':'devflow-deployment-check','version':'1.0'}}}}}})
if not isinstance(initialized, dict) or initialized.get('id') != 'init' or initialized.get('result', {{}}).get('protocolVersion') != {PROTOCOL_VERSION!r}: raise SystemExit(3)
post({{'jsonrpc':'2.0','method':'notifications/initialized','params':{{}}}}, session)
listed, session = post({{'jsonrpc':'2.0','id':'list','method':'tools/list','params':{{}}}}, session)
if not isinstance(listed, dict) or listed.get('id') != 'list': raise SystemExit(3)
print(json.dumps({{'ready':ready,'toolsList':listed,'deploymentPreflightReady':True}}, sort_keys=True, separators=(',', ':')))
""".strip()

REMOTE_NETWORK_DENY_CHECK = f"""
import json, sys, urllib.error, urllib.request
url = sys.argv[1]
if url != {READY_URL!r}:
    raise SystemExit(2)
request = urllib.request.Request(url, method='GET')
try:
    with urllib.request.urlopen(request, timeout=5) as response:
        response.read(1)
except urllib.error.HTTPError:
    blocked = False
except (urllib.error.URLError, TimeoutError, OSError):
    blocked = True
else:
    blocked = False
print(json.dumps({{'blocked': blocked, 'serviceUrl': url}}, sort_keys=True, separators=(',', ':')))
""".strip()


def _endpoint_check(
    runner: Runner,
    kubectl: str,
    target: Target,
    desired: DesiredState,
) -> tuple[str, ...]:
    value = _json_object(
        runner.run(
            _exec(
                kubectl,
                target,
                "/usr/bin/python3",
                "-c",
                REMOTE_HTTP_CHECK,
                SERVICE_URL,
                READY_URL,
            )
        ),
        "isolated CI endpoint check",
    )
    if (
        set(value) != {"ready", "toolsList", "deploymentPreflightReady"}
        or value.get("deploymentPreflightReady") is not True
    ):
        raise ReconcileError("isolated CI endpoint returned an invalid envelope")
    ready = value.get("ready")
    expected_ready = {
        "ok": True,
        "server": SERVER_NAME,
        "transport": "streamable-http",
        "protocolVersion": PROTOCOL_VERSION,
        "stateless": False,
        "mcpSessionsSupported": False,
        "repositoryRevision": desired.source.revision,
        "repositoryArchiveSha256": desired.source.archive_sha256,
        "serverSha256": desired.source.server_sha256,
        "executionPolicySha256": desired.trust.execution_policy_sha256,
        "receiptPublicKeySha256": desired.trust.public_key_sha256,
        "receiptPolicySha256": desired.trust.receipt_policy_sha256,
        "receiptIssuer": RECEIPT_ISSUER,
        "receiptLifetimeSeconds": RECEIPT_LIFETIME_SECONDS,
        "replayScope": REPLAY_SCOPE,
        "replayLedgerPersistentAcrossPodReplacement": False,
        "remainingThreat": desired.trust.receipt_policy["remainingThreat"],
        "privateKeyLoaded": True,
        "credentialsForwarded": False,
        "repositoryMode": REPOSITORY_MODE,
        "testCommandSource": TEST_COMMAND_SOURCE,
        "assignmentSource": ASSIGNMENT_SOURCE,
        "assignmentSourceLiveAgentTeams": False,
        "dynamicCandidateSupported": False,
        "testPathMutationSupported": False,
        "testCompletionPolicy": TEST_COMPLETION_POLICY,
        "minimumExecutedTests": desired.trust.execution_policy[
            "minimumExecutedTests"
        ],
        "resourceLimitsApplied": True,
        "runAsUser": SERVICE_UID,
        "runAsGroup": SERVICE_GID,
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
        "fixtureTaskIds": list(FIXTURE_TASK_IDS),
        "assignmentFresh": True,
        "assignmentMaxAgeSeconds": 86_400,
        "assignmentExpiryAction": (
            "fail-liveness-and-readiness-refresh-on-container-restart"
        ),
        "maxConcurrentExecutions": 1,
    }
    if not isinstance(ready, dict):
        raise ReconcileError("isolated CI readiness attestation mismatch")
    dynamic = {
        "inflightExecutions": ready.get("inflightExecutions"),
        "completedTaskCount": ready.get("completedTaskCount"),
    }
    inflight = dynamic["inflightExecutions"]
    completed = dynamic["completedTaskCount"]
    static_ready = {
        key: value for key, value in ready.items() if key not in dynamic
    }
    if (
        static_ready != expected_ready
        or not isinstance(inflight, int)
        or isinstance(inflight, bool)
        or inflight < 0
        or inflight > 1
        or not isinstance(completed, int)
        or isinstance(completed, bool)
        or completed < 0
    ):
        raise ReconcileError("isolated CI readiness attestation mismatch")
    listed = value.get("toolsList")
    result = listed.get("result") if isinstance(listed, dict) else None
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list) or len(tools) != 1 or not isinstance(tools[0], dict):
        raise ReconcileError("isolated CI must expose exactly one MCP tool")
    tool = tools[0]
    schema = tool.get("inputSchema")
    if (
        tool.get("name") != TOOL_NAME
        or not isinstance(schema, dict)
        or schema.get("type") != "object"
        or schema.get("additionalProperties") is not False
        or set(schema.get("properties", {})) != {"taskId", "revision", "workspaceBinding"}
        or set(schema.get("required", [])) != {"taskId", "revision", "workspaceBinding"}
    ):
        raise ReconcileError("isolated CI run_tests schema is outside policy")
    return (TOOL_NAME,)


def _network_policy_denied_roles(
    runner: Runner,
    kubectl: str,
    targets: tuple[Target, ...],
) -> tuple[str, ...]:
    """Observe failed service connections from every non-Tester role Pod."""

    denied: list[str] = []
    for target in targets:
        if target.role_name == TESTER_ROLE:
            continue
        try:
            value = _json_object(
                runner.run(
                    _exec(
                        kubectl,
                        target,
                        "/usr/bin/python3",
                        "-c",
                        REMOTE_NETWORK_DENY_CHECK,
                        READY_URL,
                    )
                ),
                "NetworkPolicy negative probe",
            )
        except (OSError, RuntimeError, UnicodeError, ValueError):
            continue
        if value == {"blocked": True, "serviceUrl": READY_URL}:
            denied.append(target.role_name)
    return tuple(denied)


def _policy_check(
    runner: Runner,
    kubectl: str,
    target: Target,
    *,
    apply: bool,
) -> mcporter_policy.Report:
    preflight = mcporter_policy._parse_report(
        runner.run(mcporter_policy._exec_helper(kubectl, target, "check")),
        target,
        applied=False,
    )
    if not apply or not preflight.needs_apply:
        return preflight
    final = mcporter_policy._parse_report(
        runner.run(
            mcporter_policy._exec_helper(
                kubectl,
                target,
                "apply",
                preflight.live_digest,
                preflight.remote_digest,
            )
        ),
        target,
        applied=True,
    )
    if (
        final.needs_apply
        or final.live_digest != final.desired_digest
        or final.remote_digest != final.desired_digest
        or final.live_names != final.desired_names
        or final.remote_names != final.desired_names
    ):
        raise ReconcileError("Tester mcporter policy post-apply check failed")
    return final


def _apply_resources(
    runner: Runner,
    kubectl: str,
    desired: DesiredState,
) -> None:
    document = {
        "apiVersion": "v1",
        "kind": "List",
        "items": list(desired.resources),
    }
    runner.run(
        _kubectl(
            kubectl,
            "apply",
            "--server-side=true",
            "--field-manager=devflow-tester-cicd-reconciler",
            "--filename=-",
        ),
        input_data=_canonical(document) + b"\n",
    )
    runner.run(
        _kubectl(
            kubectl,
            "rollout",
            "status",
            f"deployment/{DEPLOYMENT_NAME}",
            "--timeout=180s",
        )
    )


def reconcile(
    runner: Runner,
    desired: DesiredState,
    *,
    kubectl: str = "kubectl",
    apply: bool = False,
) -> Report:
    target, targets, namespace_pods, namespace_workloads = _discover(
        runner,
        kubectl,
    )
    verifier_roles = _teamharness_receipt_verifier_roles(
        runner,
        kubectl,
        targets,
        desired,
    )
    teamharness_verified = (
        len(verifier_roles) == len(targets)
        and set(verifier_roles) == {item.role_name for item in targets}
    )
    resources_present, resources_verified = _live_resources(
        runner,
        kubectl,
        desired,
    )
    secret_status = _secret_isolation(
        namespace_pods,
        require_ci_pod=resources_present,
        namespace_workloads=namespace_workloads,
    )
    endpoint_verified = False
    policy_verified = False
    network_denied_roles: tuple[str, ...] = ()
    network_other_roles_denied = False
    tool_names: tuple[str, ...] = ()
    if (
        resources_verified
        and secret_status.no_unexpected_secret_consumer
        and secret_status.observed_single_signing_secret_consumer
    ):
        tool_names = _endpoint_check(runner, kubectl, target, desired)
        endpoint_verified = tool_names == (TOOL_NAME,)
        if endpoint_verified:
            network_denied_roles = _network_policy_denied_roles(
                runner,
                kubectl,
                targets,
            )
            expected_denied_roles = {
                item.role_name
                for item in targets
                if item.role_name != TESTER_ROLE
            }
            network_other_roles_denied = (
                len(network_denied_roles) == len(expected_denied_roles)
                and set(network_denied_roles) == expected_denied_roles
            )
        policy_verified = not _policy_check(
            runner,
            kubectl,
            target,
            apply=False,
        ).needs_apply
    deployment_preflight_ready = (
        resources_verified
        and secret_status.no_unexpected_secret_consumer
        and secret_status.observed_single_signing_secret_consumer
        and endpoint_verified
        and network_other_roles_denied
        and policy_verified
    )
    needs_apply = not deployment_preflight_ready
    applied = False
    if apply and not teamharness_verified:
        raise ReconcileError(
            "TeamHarness receipt verifier precondition failed on one or more roles"
        )
    if apply and needs_apply:
        _apply_resources(runner, kubectl, desired)
        target, targets, namespace_pods, namespace_workloads = _discover(
            runner,
            kubectl,
        )
        verifier_roles = _teamharness_receipt_verifier_roles(
            runner,
            kubectl,
            targets,
            desired,
        )
        teamharness_verified = (
            len(verifier_roles) == len(targets)
            and set(verifier_roles) == {item.role_name for item in targets}
        )
        if not teamharness_verified:
            raise ReconcileError(
                "TeamHarness receipt verifier failed post-apply readback"
            )
        resources_present, resources_verified = _live_resources(
            runner,
            kubectl,
            desired,
        )
        if not resources_present or not resources_verified:
            raise ReconcileError("isolated CI resources failed post-apply readback")
        secret_status = _secret_isolation(
            namespace_pods,
            require_ci_pod=True,
            namespace_workloads=namespace_workloads,
        )
        tool_names = _endpoint_check(runner, kubectl, target, desired)
        endpoint_verified = tool_names == (TOOL_NAME,)
        network_denied_roles = _network_policy_denied_roles(
            runner,
            kubectl,
            targets,
        )
        expected_denied_roles = {
            item.role_name for item in targets if item.role_name != TESTER_ROLE
        }
        network_other_roles_denied = (
            len(network_denied_roles) == len(expected_denied_roles)
            and set(network_denied_roles) == expected_denied_roles
        )
        policy_verified = not _policy_check(
            runner,
            kubectl,
            target,
            apply=True,
        ).needs_apply
        deployment_preflight_ready = (
            resources_verified
            and secret_status.no_unexpected_secret_consumer
            and secret_status.observed_single_signing_secret_consumer
            and endpoint_verified
            and network_other_roles_denied
            and policy_verified
        )
        needs_apply = not deployment_preflight_ready
        applied = True
        if needs_apply:
            raise ReconcileError("isolated CI post-apply verification failed")
    # This reconciler proves deployment preconditions only.  It does not run a
    # real run_tests -> signed receipt -> Leader accept -> replay rejection flow.
    ci_service_verified = False
    end_to_end_ready = False
    return Report(
        applied=applied,
        image=desired.image,
        repository_revision=desired.source.revision,
        repository_archive_sha256=desired.source.archive_sha256,
        server_sha256=desired.source.server_sha256,
        receipt_public_key_sha256=desired.trust.public_key_sha256,
        receipt_policy_sha256=desired.trust.receipt_policy_sha256,
        execution_policy_sha256=desired.trust.execution_policy_sha256,
        resources_verified=resources_verified,
        no_unexpected_secret_consumer=(
            secret_status.no_unexpected_secret_consumer
        ),
        observed_single_secret_consumer=(
            secret_status.observed_single_signing_secret_consumer
        ),
        endpoint_verified=endpoint_verified,
        mcporter_policy_verified=policy_verified,
        ci_service_verified=ci_service_verified,
        deployment_preflight_ready=deployment_preflight_ready,
        teamharness_receipt_verifier_verified=teamharness_verified,
        teamharness_receipt_verifier_roles=verifier_roles,
        end_to_end_ready=end_to_end_ready,
        replay_scope=REPLAY_SCOPE,
        replay_ledger_persistent_across_pod_replacement=(
            REPLAY_LEDGER_PERSISTENT_ACROSS_POD_REPLACEMENT
        ),
        receipt_lifetime_seconds=RECEIPT_LIFETIME_SECONDS,
        network_policy_declared_and_readback=resources_verified,
        network_policy_tester_access_observed=endpoint_verified,
        network_policy_other_roles_denied_observed=network_other_roles_denied,
        network_policy_denied_roles=network_denied_roles,
        tool_names=tool_names,
        needs_apply=needs_apply,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check or reconcile the isolated AgentTeams Tester CI MCP."
    )
    parser.add_argument("--apply", action="store_true", help="apply after read-only preflight")
    parser.add_argument("--confirm", help="exact apply confirmation")
    parser.add_argument("--repository", type=Path, default=ROOT, help="clean release repository")
    parser.add_argument("--image", required=True, help="immutable CI image digest reference")
    parser.add_argument(
        "--execution-policy",
        type=Path,
        required=True,
        help="canonical public policy extracted from the immutable CI image",
    )
    parser.add_argument(
        "--receipt-policy",
        type=Path,
        required=True,
        help="canonical public receipt policy extracted from the immutable CI image",
    )
    parser.add_argument(
        "--receipt-public-key",
        type=Path,
        required=True,
        help="canonical Ed25519 public key; private key is never accepted",
    )
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    return parser


def _secret_mount_acl_enforced(_report: object) -> bool:
    """Return the deliberately conservative Secret-mount ACL conclusion.

    Resource readback can establish the currently observed consumer set, but
    it cannot prevent a namespace principal from creating a later Pod that
    references the Secret.  This may become true only after a separate,
    verified admission/RBAC control is added.
    """

    return False


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.apply:
            if args.confirm != CONFIRMATION:
                raise ReconcileError("apply requires the exact confirmation")
        elif args.confirm is not None:
            raise ReconcileError("check mode does not accept apply confirmation")
        runner = SubprocessRunner()
        source = attest_source(runner, args.repository)
        trust = trust_material(
            source=source,
            public_key_path=args.receipt_public_key,
            execution_policy_path=args.execution_policy,
            receipt_policy_path=args.receipt_policy,
        )
        desired = desired_state(
            source=source,
            trust=trust,
            image=args.image,
        )
        report = reconcile(
            runner,
            desired,
            kubectl=args.kubectl,
            apply=args.apply,
        )
    except (ReconcileError, OSError, RuntimeError, UnicodeError, ValueError, tarfile.TarError) as exc:
        print(f"error: isolated Tester CI reconciliation failed safely: {exc}", file=sys.stderr)
        return 1
    summary = {
        "applied": report.applied,
        "ciServiceVerified": report.ci_service_verified,
        "deploymentPreflightReady": report.deployment_preflight_ready,
        "cniConnectivityProbed": (
            report.network_policy_tester_access_observed
            and report.network_policy_other_roles_denied_observed
        ),
        "endToEndReady": report.end_to_end_ready,
        "endpointVerified": report.endpoint_verified,
        "executionPolicySha256": report.execution_policy_sha256,
        "image": report.image,
        "mcporterPolicyVerified": report.mcporter_policy_verified,
        "needsApply": report.needs_apply,
        "needsTeamHarnessReconcile": (
            not report.teamharness_receipt_verifier_verified
        ),
        "namespace": NAMESPACE,
        "networkPolicyDeniedRoles": list(report.network_policy_denied_roles),
        "networkPolicyObjectReadbackVerified": (
            report.network_policy_declared_and_readback
        ),
        "networkPolicyOtherRolesDeniedObserved": (
            report.network_policy_other_roles_denied_observed
        ),
        "networkPolicyTesterAccessObserved": (
            report.network_policy_tester_access_observed
        ),
        "observedSingleSigningSecretConsumer": (
            report.observed_single_secret_consumer
        ),
        "noUnexpectedSecretConsumer": report.no_unexpected_secret_consumer,
        "privateKeyMountObservedOnWorker": False,
        "receiptPolicySha256": report.receipt_policy_sha256,
        "receiptPublicKeySha256": report.receipt_public_key_sha256,
        "receiptLifetimeSeconds": report.receipt_lifetime_seconds,
        "replayLedgerPersistentAcrossPodReplacement": (
            report.replay_ledger_persistent_across_pod_replacement
        ),
        "replayScope": report.replay_scope,
        "repositoryArchiveSha256": report.repository_archive_sha256,
        "repositoryRevision": report.repository_revision,
        "resourcesVerified": report.resources_verified,
        "serverSha256": report.server_sha256,
        "serviceUrl": SERVICE_URL,
        "secretMountAclEnforced": _secret_mount_acl_enforced(report),
        "secretMountRemainingThreat": (
            "A principal allowed to create or mutate Pods in this namespace can "
            "mount the signing Secret after this observed-state check."
        ),
        "signingSecretReadByReconciler": False,
        "team": TEAM_NAME,
        "teamHarnessReceiptVerifierRoles": list(
            report.teamharness_receipt_verifier_roles
        ),
        "teamHarnessReceiptVerifierVerified": (
            report.teamharness_receipt_verifier_verified
        ),
        "testerPodLocalInstall": False,
        "httpCallerAuthentication": "network-policy-only-no-mtls-or-spiffe",
        "applicationLayerTesterIdentityAuthVerified": False,
        "deploymentBlockers": [
            "application-layer-mtls-or-spiffe-not-configured",
            "live-agentteams-task-projection-not-configured",
            "end-to-end-consumer-replay-flow-not-exercised",
            "task-result-cache-not-persistent-across-container-restart",
        ],
        "toolNames": list(report.tool_names),
        "verified": report.end_to_end_ready,
        "workspacePersistence": "ephemeral-per-execution-by-design",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Finalize immutable Tester CI policy files inside the image build.

The host cannot know the SHA-256 of the image's Python and Bubblewrap
executables.  This build-only utility computes those digests after the pinned
base image and packages exist, binds them to the clean repository attestation,
then writes canonical read-only execution and receipt policies.  It never
accepts or reads the receipt private key.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

SERVER_PATH = Path("/opt/devflow/agentteams-cicd/tester_server.py")
REPOSITORY_ROOT = Path("/var/lib/devflow/agentteams-cicd/repository")
WORKSPACE_ROOT = Path("/var/lib/devflow/agentteams-cicd/workspaces")
PUBLIC_KEY_PATH = Path("/opt/devflow/build/receipt-ed25519.pub")
RELEASE_TEMPLATE_PATH = Path("/opt/devflow/build/release-template.json")
EXECUTION_POLICY_PATH = Path("/etc/devflow/agentteams-cicd/policy.json")
RECEIPT_POLICY_PATH = Path("/etc/devflow/agentteams-cicd/test-receipt-policy.json")
RELEASE_PATH = Path("/etc/devflow/agentteams-cicd/release.json")
DEMO_ASSIGNMENT_TEMPLATE_ROOT = Path(
    "/opt/devflow/agentteams-cicd/demo-assignment-templates"
)
PYTHON_PATH = Path("/usr/local/bin/python3.12")
BWRAP_PATH = Path("/usr/bin/bwrap")
OPENSSL_PATH = Path("/usr/bin/openssl")
PRLIMIT_PATH = Path("/usr/bin/prlimit")
TEAM_NAME = "devflow-swe"
SERVICE_IDENTITY = "devflow-tester-cicd.agentteams-system.svc.cluster.local"
RECEIPT_AUDIENCE = "devflow-teamharness"
RECEIPT_ISSUER = "devflow-tester-cicd"
RECEIPT_DOMAIN = "devflow.test-execution-receipt/v1"
TEAMHARNESS_PUBLIC_KEY_PATH = "/etc/devflow/teamharness/test-receipt-ed25519.pub"
TEAMHARNESS_POLICY_PATH = "/etc/devflow/teamharness/test-receipt-policy.json"
TEAMHARNESS_LEDGER_PATH = "/var/lib/devflow/teamharness/test-receipt-ledger.json"
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
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
RELEASE_TEMPLATE_FIELDS = frozenset(
    {
        "schemaVersion",
        "repositoryRevision",
        "repositoryArchiveSha256",
        "repositoryManifestSha256",
        "serverSha256",
        "receiptPublicKeyFileSha256",
        "receiptPublicKeySha256",
    }
)
DEMO_ASSIGNMENT_SOURCE = "image-fixed-demo-fixture/v1"
DEMO_ASSIGNMENT_TASKS = (
    ("devflow-demo-focused", 9001, "T2", "devflow_demo_focused.txt"),
    ("devflow-demo-full", 9002, "T3", "devflow_demo_full.txt"),
)


class FinalizeError(RuntimeError):
    """The image cannot truthfully bind its fixed runtime."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        if (
            path.is_symlink()
            or resolved != path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or metadata.st_uid != 0
        ):
            raise FinalizeError("image runtime file is outside policy")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise FinalizeError("image runtime file is unavailable") from exc
    return digest.hexdigest()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FinalizeError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise FinalizeError("non-standard JSON scalar")


def _read_canonical(path: Path, fields: frozenset[str], label: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        payload = resolved.read_bytes()
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FinalizeError(f"{label} is unavailable or malformed") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not isinstance(value, dict)
        or set(value) != fields
        or payload != _canonical(value)
    ):
        raise FinalizeError(f"{label} is outside policy")
    return value


def _public_key() -> tuple[str, str]:
    try:
        payload = PUBLIC_KEY_PATH.read_bytes()
        lines = payload.decode("ascii").splitlines()
        der = base64.b64decode(lines[1], validate=True)
    except (OSError, UnicodeError, ValueError, IndexError) as exc:
        raise FinalizeError("receipt public key is malformed") from exc
    canonical = (
        f"-----BEGIN PUBLIC KEY-----\n{base64.b64encode(der).decode('ascii')}\n"
        "-----END PUBLIC KEY-----\n"
    ).encode("ascii")
    if (
        lines[:1] != ["-----BEGIN PUBLIC KEY-----"]
        or lines[2:] != ["-----END PUBLIC KEY-----"]
        or payload != canonical
        or len(der) != 44
        or not der.startswith(ED25519_SPKI_PREFIX)
    ):
        raise FinalizeError("receipt public key is not canonical Ed25519 SPKI")
    return _sha256(payload), _sha256(der)


def execution_policy(
    release: dict[str, Any],
    *,
    python_sha256: str,
    bwrap_sha256: str,
    prlimit_sha256: str,
) -> dict[str, Any]:
    focused = [
        str(PYTHON_PATH),
        "-m",
        "pytest",
        "-q",
        "tests/test_agentteams_tester_cicd.py",
        "tests/test_agentteams_tester_cicd_image.py",
        "tests/test_reconcile_agentteams_tester_cicd.py",
        "tests/test_reconcile_agentteams_mcporter_policy.py",
        "tests/test_teamharness_test_execution_receipt.py",
    ]
    full = [str(PYTHON_PATH), "-m", "pytest", "-q"]
    fixed_candidates = {
        task_id: _sha256(
            _canonical(
                _demo_candidate(
                    task_id=task_id,
                    issue_id=issue_id,
                    tier=tier,
                    path=path,
                    repository_revision=release["repositoryRevision"],
                )
            )
        )
        for task_id, issue_id, tier, path in DEMO_ASSIGNMENT_TASKS
    }
    policy: dict[str, Any] = {
        "schemaVersion": "1.0",
        "teamName": TEAM_NAME,
        "serviceIdentity": SERVICE_IDENTITY,
        "repositoryRoot": str(REPOSITORY_ROOT),
        "workspaceRoot": str(WORKSPACE_ROOT),
        "repositoryRevision": release["repositoryRevision"],
        "repositoryArchiveSha256": release["repositoryArchiveSha256"],
        "repositoryManifestSha256": release["repositoryManifestSha256"],
        "serverSha256": release["serverSha256"],
        "receiptPublicKeySha256": release["receiptPublicKeySha256"],
        "testCommands": {"focused": focused, "full": full},
        "testExecutableSha256": {
            "focused": python_sha256,
            "full": python_sha256,
        },
        "networkIsolationPrefix": list(NETWORK_PREFIX),
        "networkIsolationExecutableSha256": bwrap_sha256,
        "resourceLimitLauncher": ["/usr/bin/prlimit"],
        "resourceLimitLauncherSha256": prlimit_sha256,
        "resourceLimitsApplied": True,
        "assignmentSource": DEMO_ASSIGNMENT_SOURCE,
        "assignmentSourceLiveAgentTeams": False,
        "dynamicCandidateSupported": False,
        "testPathMutationSupported": False,
        "fixedCandidateSha256": fixed_candidates,
        "testCompletionPolicy": "fixed-candidate-pytest-terminal-summary/v1",
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
        "networkPolicy": "bubblewrap-unshare-all-mask-runtime-credentials",
        "workspaceBinding": "0" * 64,
        "remainingThreat": (
            "Ordinary Agent and repository code are bounded; CI image, cluster "
            "control plane, node-root, kernel and namespace-isolator compromise "
            "remain outside this claim."
        ),
    }
    body = {
        key: policy[key]
        for key in sorted(EXECUTION_POLICY_FIELDS - {"workspaceBinding", "remainingThreat"})
    }
    policy["workspaceBinding"] = _sha256(_canonical(body))
    if set(policy) != EXECUTION_POLICY_FIELDS:
        raise FinalizeError("generated execution policy fields drifted")
    return policy


def receipt_policy(release: dict[str, Any], execution: dict[str, Any]) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "schemaVersion": "1.0",
        "algorithm": "Ed25519",
        "audience": RECEIPT_AUDIENCE,
        "issuer": RECEIPT_ISSUER,
        "signatureDomain": RECEIPT_DOMAIN,
        "publicKeyPath": TEAMHARNESS_PUBLIC_KEY_PATH,
        "publicKeyFileSha256": release["receiptPublicKeyFileSha256"],
        "publicKeySha256": release["receiptPublicKeySha256"],
        "policyAttestationPath": TEAMHARNESS_POLICY_PATH,
        "opensslPath": str(OPENSSL_PATH),
        "replayLedgerPath": TEAMHARNESS_LEDGER_PATH,
        "replayScope": "pod-incarnation",
        "replayLedgerPersistentAcrossPodReplacement": False,
        "receiptLifetimeSeconds": 120,
        "maxReceiptLifetimeSeconds": 120,
        "maxClockSkewSeconds": 5,
        "ciServerSha256": release["serverSha256"],
        "ciPolicySha256": execution["workspaceBinding"],
        "repositoryArchiveSha256": release["repositoryArchiveSha256"],
        "repositoryManifestSha256": release["repositoryManifestSha256"],
        "repositoryRevision": release["repositoryRevision"],
        "remainingThreat": (
            "CI image, cluster control plane, kernel, receipt signing service, "
            "and TeamHarness verifier compromise remain outside this claim. "
            "The replay ledger is Pod-local; Leader Pod replacement can lose "
            "replay history and permit a duplicate receipt until its 120-second "
            "lifetime expires."
        ),
    }
    if set(policy) != RECEIPT_POLICY_FIELDS:
        raise FinalizeError("generated receipt policy fields drifted")
    return policy


def _demo_candidate(
    *,
    task_id: str,
    issue_id: int,
    tier: str,
    path: str,
    repository_revision: str,
) -> dict[str, Any]:
    """Build one harmless, image-fixed candidate for the finals runtime demo."""

    located_context_digest = _sha256(
        _canonical(
            {
                "source": DEMO_ASSIGNMENT_SOURCE,
                "taskId": task_id,
                "repositoryRevision": repository_revision,
            }
        )
    )
    boundary: dict[str, Any] = {
        "schema_version": "1.0",
        "located_context_digest": located_context_digest,
        "allowed_files": [path],
    }
    boundary["scope_digest"] = _sha256(_canonical(boundary))
    marker = f"DevFlow fixed AgentTeams CI fixture: {task_id}\n"
    diff = "".join(
        difflib.unified_diff(
            [],
            marker.splitlines(keepends=True),
            fromfile=f"a/{path}",
            tofile=f"b/{path}",
            lineterm="\n",
        )
    )
    patch = {
        "branch_name": f"demo/{task_id}",
        "changes": [
            {
                "file_path": path,
                "change_type": "create",
                "original_content": None,
                "new_content": marker,
                "diff": diff,
            }
        ],
        "commit_message": f"demo: execute {task_id}",
        "description": (
            "Image-fixed finals fixture proving server-owned assignment, "
            "suite selection, isolation, and receipt issuance."
        ),
    }
    return {
        "schema_version": "1.2",
        "issue_id": issue_id,
        "tier": tier,
        "patch": patch,
        "candidate_digest": _sha256(_canonical(patch)),
        "evidence_boundary": boundary,
        "model_call_attempt": 1,
        "retry_attempt": 1,
        "revision_of": None,
    }


def demo_assignment_templates(
    execution: dict[str, Any],
) -> tuple[dict[str, Any], ...]:
    """Return templates whose timestamps refresh at every container start."""

    values: list[dict[str, Any]] = []
    for task_id, issue_id, tier, path in DEMO_ASSIGNMENT_TASKS:
        candidate = _demo_candidate(
            task_id=task_id,
            issue_id=issue_id,
            tier=tier,
            path=path,
            repository_revision=execution["repositoryRevision"],
        )
        run_id = f"run-{task_id}"
        envelope = {
            "envelope_version": "1.0",
            "run_id": run_id,
            "issue_id": issue_id,
            "task_id": task_id,
            "producer": "TeamLeader",
            "consumer": "devflow-tester",
            "skill": "test-runner",
            "trace_id": f"{run_id}:{task_id}",
            "idempotency_key": (
                f"{run_id}:{task_id}:devflow-tester:test-runner"
            ),
            "created_at": "__MATERIALIZED_AT__",
            "status": "ready",
            "artifact": {
                "type": "PatchCandidate",
                "schema_version": "1.2",
                "inline": candidate,
                "ref": None,
                "sha256": _sha256(_canonical(candidate)),
            },
        }
        values.append(
            {
                "schemaVersion": "1.0",
                "source": DEMO_ASSIGNMENT_SOURCE,
                "taskId": task_id,
                "evidenceTemplate": {
                    "task": {
                        "project_id": "devflow-ci-fixed-demo",
                        "task_id": task_id,
                        "assigned_to": "devflow-tester",
                        "status": "acknowledged",
                        "skill": "test-runner",
                    },
                    "envelope": envelope,
                },
            }
        )
    if {
        value["taskId"] for value in values
    } != {task_id for task_id, *_rest in DEMO_ASSIGNMENT_TASKS}:
        raise FinalizeError("fixed assignment template identity drifted")
    if execution.get("testCommands") is None:
        raise FinalizeError("fixed assignment templates lack a suite policy")
    return tuple(values)


def _load_server() -> Any:
    spec = importlib.util.spec_from_file_location("_devflow_image_cicd", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise FinalizeError("CI server source cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise FinalizeError("CI server source cannot be loaded") from exc
    return module


def _write(path: Path, value: dict[str, Any]) -> bytes:
    payload = _canonical(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o444,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        path.unlink(missing_ok=True)
        raise
    os.chmod(path, 0o444)
    return payload


def finalize() -> dict[str, Any]:
    release = _read_canonical(
        RELEASE_TEMPLATE_PATH,
        RELEASE_TEMPLATE_FIELDS,
        "release template",
    )
    key_file_sha256, key_sha256 = _public_key()
    if (
        release.get("schemaVersion") != "1.0"
        or release.get("receiptPublicKeyFileSha256") != key_file_sha256
        or release.get("receiptPublicKeySha256") != key_sha256
        or release.get("serverSha256") != _sha256_file(SERVER_PATH)
    ):
        raise FinalizeError("release template source binding is invalid")
    server = _load_server()
    if frozenset(getattr(server, "POLICY_FIELDS", ())) != EXECUTION_POLICY_FIELDS:
        raise FinalizeError("CI server execution policy schema drifted")
    manifest = server.repository_manifest(
        REPOSITORY_ROOT,
        max_files=100_000,
        max_bytes=1024 * 1024 * 1024,
    )
    if manifest.digest != release.get("repositoryManifestSha256"):
        raise FinalizeError("image repository differs from the release manifest")
    execution = execution_policy(
        release,
        python_sha256=_sha256_file(PYTHON_PATH),
        bwrap_sha256=_sha256_file(BWRAP_PATH),
        prlimit_sha256=_sha256_file(PRLIMIT_PATH),
    )
    receipt = receipt_policy(release, execution)
    execution_bytes = _write(EXECUTION_POLICY_PATH, execution)
    receipt_bytes = _write(RECEIPT_POLICY_PATH, receipt)
    assignment_templates = demo_assignment_templates(execution)
    assignment_template_digests: dict[str, str] = {}
    for template in assignment_templates:
        task_id = template["taskId"]
        candidate = template["evidenceTemplate"]["envelope"]["artifact"]["inline"]
        fixture_path = candidate["patch"]["changes"][0]["file_path"]
        if REPOSITORY_ROOT.joinpath(*fixture_path.split("/")).exists():
            raise FinalizeError("fixed assignment path already exists in repository")
        if server._validate_candidate(candidate, execution) != candidate:
            raise FinalizeError("CI server rejected a fixed assignment candidate")
        payload = _write(
            DEMO_ASSIGNMENT_TEMPLATE_ROOT / f"{task_id}.template.json",
            template,
        )
        assignment_template_digests[task_id] = _sha256(payload)
    # A build must never receive the runtime receipt private key.  The build
    # independently hashes every fixed executable and repository file above,
    # while the server repeats its full private-key-aware validation at runtime.
    checked = server.validate_policy(execution, verify_files=False)
    if checked != execution:
        raise FinalizeError("CI server rejected the generated execution policy")
    final_release = {
        **release,
        "serviceIdentity": SERVICE_IDENTITY,
        "executionPolicySha256": execution["workspaceBinding"],
        "executionPolicyFileSha256": _sha256(execution_bytes),
        "receiptPolicySha256": _sha256(receipt_bytes),
        "assignmentSource": DEMO_ASSIGNMENT_SOURCE,
        "assignmentTemplateSha256": _sha256(
            _canonical(assignment_template_digests)
        ),
        "fixtureTaskIds": sorted(assignment_template_digests),
        "liveAgentTeamsTaskProjection": False,
    }
    _write(RELEASE_PATH, final_release)
    return {
        "executionPolicySha256": execution["workspaceBinding"],
        "receiptPolicySha256": _sha256(receipt_bytes),
        "assignmentSource": DEMO_ASSIGNMENT_SOURCE,
        "assignmentTemplateSha256": final_release["assignmentTemplateSha256"],
        "fixtureTaskIds": final_release["fixtureTaskIds"],
        "liveAgentTeamsTaskProjection": False,
        "repositoryRevision": release["repositoryRevision"],
        "serverSha256": release["serverSha256"],
        "verified": True,
    }


def main() -> int:
    try:
        result = finalize()
    except (FinalizeError, OSError, RuntimeError, ValueError) as exc:
        print(f"error: Tester CI image finalization failed safely: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

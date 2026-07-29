"""Reconcile role-scoped DevFlow Skills in live and authoritative workspaces.

The fixed six-role Team is discovered through the same Ready-Pod and runtime
identity gates as the other AgentTeams reconcilers. Check mode is read-only
with respect to both Skill stores and uses only a private ephemeral mc config.
Apply mode removes disallowed members of the fixed seven-Skill DevFlow set and
replaces stale allowed trees only with the role's source-attested, digest-pinned
current release archive. MinIO replacement is an explicitly non-atomic S3 tree update
protected by durable staging, backup, and phase-manifest recovery; the later
local exchange is atomic. AgentTeams built-in and unknown Skills are never
deletion targets.

Remote object keys and local files are parsed inside each Pod. The host sees
only fixed Skill names, counts, booleans, and concurrency digests; it never
receives file content, object-store configuration, or credentials.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib
import inspect
import io
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

try:
    from scripts.build_agentteams_package import (
        MAX_ARCHIVE_BYTES,
        MAX_SOURCE_FILE_BYTES,
        PACKAGE_VERSION,
        expected_payload_files,
    )
    from scripts.reconcile_agentteams_controller_cache import (
        ControllerCacheError,
        ControllerReconcileResult,
        discover_controller,
        reconcile_controller_authority,
    )
    from scripts.reconcile_agentteams_mcporter_policy import (
        DIGEST,
        LEADER_ROLE,
        RUNTIME_BINDING_FIELDS,
        TEAMHARNESS_APPROVAL_LEDGER_PATH,
        TEAMHARNESS_APPROVAL_POLICY_PATH,
        TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH,
        TEAMHARNESS_CORE_ARTIFACTS,
        TEAMHARNESS_LEADER_ARTIFACTS,
        TEAMHARNESS_MANIFEST_PATH,
        TEAMHARNESS_OPENSSL_PATH,
        TEAMHARNESS_POLICY_FIELDS,
        TEAMHARNESS_SHARED_DIR,
        PolicyError,
        _read_strict_json,
        _sha256_file,
        _trusted_fixed_directory,
        _trusted_fixed_file,
        _validate_runtime_attestation,
        _validate_runtime_trust,
    )
    from scripts.reconcile_agentteams_packages import (
        Archive,
        PackagePublishError,
        load_archives,
    )
    from scripts.reconcile_teamharness_openclaw import (
        CONTAINER_NAME,
        EXPECTED_ROLES,
        NAMESPACE,
        RUNTIME_LABEL,
        TEAM_LABEL,
        TEAM_NAME,
        Target,
        discover_targets,
    )
except ModuleNotFoundError:  # pragma: no cover - direct ``python -S`` execution
    from build_agentteams_package import (  # type: ignore[no-redef]
        MAX_ARCHIVE_BYTES,
        MAX_SOURCE_FILE_BYTES,
        PACKAGE_VERSION,
        expected_payload_files,
    )
    from reconcile_agentteams_controller_cache import (  # type: ignore[no-redef]
        ControllerCacheError,
        ControllerReconcileResult,
        discover_controller,
        reconcile_controller_authority,
    )
    from reconcile_agentteams_mcporter_policy import (  # type: ignore[no-redef]
        DIGEST,
        LEADER_ROLE,
        RUNTIME_BINDING_FIELDS,
        TEAMHARNESS_APPROVAL_LEDGER_PATH,
        TEAMHARNESS_APPROVAL_POLICY_PATH,
        TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH,
        TEAMHARNESS_CORE_ARTIFACTS,
        TEAMHARNESS_LEADER_ARTIFACTS,
        TEAMHARNESS_MANIFEST_PATH,
        TEAMHARNESS_OPENSSL_PATH,
        TEAMHARNESS_POLICY_FIELDS,
        TEAMHARNESS_SHARED_DIR,
        PolicyError,
        _read_strict_json,
        _sha256_file,
        _trusted_fixed_directory,
        _trusted_fixed_file,
        _validate_runtime_attestation,
        _validate_runtime_trust,
    )
    from reconcile_agentteams_packages import (  # type: ignore[no-redef]
        Archive,
        PackagePublishError,
        load_archives,
    )
    from reconcile_teamharness_openclaw import (  # type: ignore[no-redef]
        CONTAINER_NAME,
        EXPECTED_ROLES,
        NAMESPACE,
        RUNTIME_LABEL,
        TEAM_LABEL,
        TEAM_NAME,
        Target,
        discover_targets,
    )

ROLE_SKILLS: dict[str, tuple[str, ...]] = {
    "devflow-lead": (),
    "devflow-triage": ("issue-classifier",),
    "devflow-locator": ("code-root-cause", "github-evidence"),
    "devflow-coder": ("patch-generator",),
    "devflow-tester": ("test-runner",),
    "devflow-reviewer": ("pr-reviewer", "experience-distiller"),
}
RELEASE_ARCHIVE_DIGESTS = {
    "devflow-lead": "82ffe34e3f02162febe4d1e88c5ed68b4676d4917007d6f8a2cf13e0cb9741a5",
    "devflow-triage": "d5297a1741b0279310dc1adbe36cc02c5c33c8cf5897f4ea1532b4761f21630f",
    "devflow-locator": "cab3503cd3100bf42238cf3b53ad65deca95e9e9e6b99551a81bb0f506daf54b",
    "devflow-coder": "a54c323f4599899b8bee7950a759ec0e9cd0c56ae27fd091e559853ed9d41b16",
    "devflow-tester": "684de72825bb0fdc9a0435c7e568934ce85dc8a37d30e17aa67d1eb7d3833563",
    "devflow-reviewer": "e3d5513508f49b288384fbf47b746dbb52760de997388450f5636c640895842a",
}
ALL_DEVFLOW_SKILLS = frozenset(skill for skills in ROLE_SKILLS.values() for skill in skills)
COMMON_SKILL_FILES = frozenset(
    {
        "SKILL.md",
        "agents/openai.yaml",
        "references/contract.yaml",
        "references/examples.md",
        "scripts/_contract.py",
        "scripts/validate.py",
    }
)
SKILL_EXTRA_FILES: dict[str, frozenset[str]] = {
    "github-evidence": frozenset({"scripts/authorize_tool.py"}),
}
EXPECTED_SKILL_FILES = {
    skill: tuple(sorted(COMMON_SKILL_FILES | SKILL_EXTRA_FILES.get(skill, frozenset())))
    for skill in ALL_DEVFLOW_SKILLS
}
EXPECTED_PACKAGE_FILES = {role: tuple(sorted(expected_payload_files(role))) for role in ROLE_SKILLS}
PACKAGE_MANIFEST_FIELDS = frozenset(
    {"version", "role", "skills", "source", "worker", "files", "manifest_sha256"}
)
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
MC_ENTRY_FIELDS = frozenset(
    {
        "etag",
        "key",
        "lastModified",
        "size",
        "status",
        "storageClass",
        "type",
        "url",
        "versionOrdinal",
    }
)
MAX_LOCAL_ENTRIES = 100_000
MAX_LOCAL_FILE_BYTES = 64 * 1024 * 1024
MAX_LOCAL_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MOUNTINFO_BYTES = 4 * 1024 * 1024
MAX_REMOTE_OBJECTS = 100_000
MAX_REMOTE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MC_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_HOST_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_KUBECTL_ARGUMENT_BYTES = 4_096
MAX_KUBECTL_ARGV_BYTES = 16_384
MAX_REMOTE_HELPER_SOURCE_BYTES = 400_000
MAX_REMOTE_PARAMETERS_BYTES = 128 * 1024
REMOTE_READ_TIMEOUT_SECONDS = 30.0
REMOTE_COMMAND_TIMEOUT_SECONDS = 45.0
APPLY_HELPER_MAX_SECONDS = 900.0
HOST_HELPER_MARGIN_SECONDS = 60.0
LEASE_RECOVERY_MARGIN_SECONDS = 120
HOST_COMMAND_TIMEOUT_SECONDS = APPLY_HELPER_MAX_SECONDS + HOST_HELPER_MARGIN_SECONDS
MC_BINARY_PATH = "/usr/local/bin/mc.bin"
MC_BINARY_SHA256 = "01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891"
MC_BINARY_VERSION = (
    "mc.bin version RELEASE.2025-08-13T08-35-41Z "
    "(commit-id=7394ce0dd2a80935aded936b09fa12cbb3cb8096)"
)
MC_ENDPOINT = "http://agentteams-hiclaw-minio.agentteams-system.svc.cluster.local:9000"
MC_ALIAS = "agentteams"
MC_STORAGE_PREFIX = "agentteams/agentteams-storage"
MC_CONFIG_VERSION = "10"
MC_API = "S3v4"
MC_PATH = "auto"
MC_CONFIG_DIRECTORY: str | None = None
REMOTE_TRANSACTION_DIRECTORY = ".devflow-role-skill-transactions"
REMOTE_TRANSACTION_SCHEMA_VERSION = 1
REMOTE_TRANSACTION_PHASES = frozenset({"staging", "replacing", "committed"})
REMOTE_TRANSACTION_FIELDS = frozenset(
    {
        "schemaVersion",
        "transactionId",
        "role",
        "skill",
        "phase",
        "releaseManifestSha256",
        "newTree",
        "oldTree",
        "manifestSha256",
    }
)
REMOTE_TRANSACTION_TREE_FIELDS = frozenset({"present", "files"})
REMOTE_TRANSACTION_FILE_FIELDS = frozenset({"size", "sha256"})
MAX_TRANSACTION_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_REMOTE_FRAME_BYTES = (
    12 + MAX_REMOTE_HELPER_SOURCE_BYTES + MAX_REMOTE_PARAMETERS_BYTES + MAX_ARCHIVE_BYTES
)
WORKER_ENTRYPOINT_PATH = "/opt/hiclaw/scripts/worker-entrypoint.sh"
WORKER_ENTRYPOINT_SHA256 = "1ffd46d9a386a4b2f05299b39ed5d02c946dbf743749e83342cdf330ca8c37e4"
SYNC_SETTLE_SECONDS = 6.0
SYNC_LEASE_SECONDS = int(HOST_COMMAND_TIMEOUT_SECONDS) + LEASE_RECOVERY_MARGIN_SECONDS
CONTROLLER_RECONCILE_STABILITY_SECONDS = 430.0
SECRET_PATTERNS = (
    rb"gh[pousr]_[A-Za-z0-9]{30,}",
    rb"sk-[A-Za-z0-9_-]{20,}",
    rb"AKIA[0-9A-Z]{16}",
    rb"(?i)Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}",
    (
        rb"(?i)(?:api[_-]?key|access[_-]?key|client[_-]?secret|password|token)"
        rb"[ \t]*[:=][ \t]*(?:['\"][A-Za-z0-9._~+/=-]{12,}['\"]|"
        rb"[A-Za-z0-9_+/=-]{24,})"
    ),
    rb"-----BEGIN [A-Z ]*PRIVATE KEY-----",
)
HIGH_ENTROPY_TOKEN = rb"(?<![A-Za-z0-9])[A-Za-z0-9._-]{40,}(?![A-Za-z0-9])"
SUMMARY_FIELDS = frozenset(
    {
        "ok",
        "role",
        "allowedSkills",
        "localKnownSkills",
        "remoteKnownSkills",
        "localRemove",
        "remoteRemove",
        "remoteSync",
        "localRefresh",
        "localCount",
        "remoteCount",
        "localSnapshot",
        "remoteSnapshot",
        "needsApply",
        "applied",
    }
)

if (
    set(ROLE_SKILLS) != set(EXPECTED_ROLES)
    or set(RELEASE_ARCHIVE_DIGESTS) != set(ROLE_SKILLS)
    or len(ALL_DEVFLOW_SKILLS) != 7
):
    raise RuntimeError("fixed role-Skill policy disagrees with the fixed Team")
if any(
    {
        f"skills/{skill}/{relative}"
        for skill in ROLE_SKILLS[role]
        for relative in EXPECTED_SKILL_FILES[skill]
    }
    != {name for name in EXPECTED_PACKAGE_FILES[role] if name.startswith("skills/")}
    for role in ROLE_SKILLS
):
    raise RuntimeError("fixed role-Skill file policy disagrees with package contract")
if (
    max(REMOTE_READ_TIMEOUT_SECONDS, REMOTE_COMMAND_TIMEOUT_SECONDS)
    >= APPLY_HELPER_MAX_SECONDS
    or HOST_COMMAND_TIMEOUT_SECONDS
    < APPLY_HELPER_MAX_SECONDS + HOST_HELPER_MARGIN_SECONDS
    or SYNC_LEASE_SECONDS
    < HOST_COMMAND_TIMEOUT_SECONDS + LEASE_RECOVERY_MARGIN_SECONDS
):
    raise RuntimeError("role Skill helper, host, and lease timeout budgets are inconsistent")


class RoleSkillError(RuntimeError):
    """Discovery, filesystem, object-key, concurrency, or verification failure."""


@contextmanager
def _remote_helper_deadline() -> Iterator[None]:
    """Bound one in-Pod helper below the host timeout with cleanup headroom."""

    alarm = getattr(signal, "SIGALRM", None)
    real_timer = getattr(signal, "ITIMER_REAL", None)
    get_handler: Any = getattr(signal, "getsignal", None)
    set_handler: Any = getattr(signal, "signal", None)
    set_timer: Any = getattr(signal, "setitimer", None)
    if (
        not isinstance(alarm, int)
        or not isinstance(real_timer, int)
        or not callable(get_handler)
        or not callable(set_handler)
        or not callable(set_timer)
    ):
        raise RoleSkillError("remote helper deadline primitive is unavailable")

    def expired(_signum: int, _frame: Any) -> None:
        raise RoleSkillError("remote helper exceeded its execution budget")

    previous_handler = get_handler(alarm)
    handler_installed = False
    try:
        set_handler(alarm, expired)
        handler_installed = True
        previous_timer = set_timer(real_timer, APPLY_HELPER_MAX_SECONDS)
        if previous_timer != (0.0, 0.0):
            raise RoleSkillError("remote helper inherited an unexpected deadline")
        yield
    except OSError as exc:
        raise RoleSkillError("remote helper deadline could not be enforced") from exc
    finally:
        if handler_installed:
            with suppress(OSError, ValueError):
                set_timer(real_timer, 0.0)
            with suppress(OSError, ValueError):
                set_handler(alarm, previous_handler)


@dataclass(frozen=True)
class RoleRelease:
    """One source-verified role archive and its minimal remote policy spec."""

    role: str
    archive: bytes
    archive_digest: str
    manifest_digest: str
    spec_json: str


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RoleSkillError("duplicate JSON field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise RoleSkillError("non-standard JSON scalar")


def _canonical_digest(value: Any) -> str:
    material = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _release_spec_digest(value: dict[str, Any]) -> str:
    return _canonical_digest({key: item for key, item in value.items() if key != "releaseSha256"})


def _role_release_from_archive(archive: Archive) -> RoleRelease:
    if (
        archive.role not in ROLE_SKILLS
        or archive.digest != RELEASE_ARCHIVE_DIGESTS[archive.role]
        or hashlib.sha256(archive.data).hexdigest() != archive.digest
    ):
        raise RoleSkillError("trusted role archive identity is invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(archive.data)) as package:
            content = {info.filename: package.read(info) for info in package.infolist()}
        manifest = json.loads(
            content["manifest.json"],
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (KeyError, OSError, UnicodeError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise RoleSkillError("trusted role archive could not be decoded") from exc
    if not isinstance(manifest, dict):
        raise RoleSkillError("trusted role archive manifest is malformed")
    package_digests = manifest.get("files")
    manifest_digest = manifest.get("manifest_sha256")
    if (
        not isinstance(package_digests, dict)
        or set(package_digests) != set(EXPECTED_PACKAGE_FILES[archive.role])
        or not isinstance(manifest_digest, str)
        or DIGEST.fullmatch(manifest_digest) is None
    ):
        raise RoleSkillError("trusted role archive manifest is outside release policy")
    package_files: dict[str, dict[str, Any]] = {}
    for name in EXPECTED_PACKAGE_FILES[archive.role]:
        data = content.get(name)
        digest = package_digests.get(name)
        if (
            not isinstance(data, bytes)
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            or hashlib.sha256(data).hexdigest() != digest
        ):
            raise RoleSkillError("trusted role archive file digest mismatch")
        package_files[name] = {"sha256": digest, "size": len(data)}
    skills = {
        skill: {
            relative: package_files[f"skills/{skill}/{relative}"]
            for relative in EXPECTED_SKILL_FILES[skill]
        }
        for skill in ROLE_SKILLS[archive.role]
    }
    spec: dict[str, Any] = {
        "archiveSha256": archive.digest,
        "manifestSha256": manifest_digest,
        "packageFiles": package_files,
        "role": archive.role,
        "skills": skills,
        "version": PACKAGE_VERSION,
    }
    spec["releaseSha256"] = _release_spec_digest(spec)
    return RoleRelease(
        role=archive.role,
        archive=archive.data,
        archive_digest=archive.digest,
        manifest_digest=manifest_digest,
        spec_json=json.dumps(spec, sort_keys=True, separators=(",", ":")),
    )


def load_role_releases(directory: Path) -> dict[str, RoleRelease]:
    """Load all six immutable archives and re-attest them to repository source."""

    try:
        archives = load_archives(directory)
    except PackagePublishError as exc:
        raise RoleSkillError("trusted role release loading failed") from exc
    releases = {archive.role: _role_release_from_archive(archive) for archive in archives}
    if set(releases) != set(ROLE_SKILLS):
        raise RoleSkillError("trusted role release set is incomplete")
    return releases


def _validate_role_releases(releases: dict[str, RoleRelease]) -> None:
    if set(releases) != set(ROLE_SKILLS):
        raise RoleSkillError("trusted role release set is incomplete")
    for role in ROLE_SKILLS:
        release = releases[role]
        spec = _parse_release_spec(release.spec_json, role)
        if (
            release.role != role
            or release.archive_digest != RELEASE_ARCHIVE_DIGESTS[role]
            or release.archive_digest != spec["archiveSha256"]
            or release.manifest_digest != spec["manifestSha256"]
            or hashlib.sha256(release.archive).hexdigest() != release.archive_digest
        ):
            raise RoleSkillError("trusted role release identity changed")


def _parse_release_spec(text: str, role: str) -> dict[str, Any]:
    if role not in ROLE_SKILLS or len(text.encode("utf-8")) > 128 * 1024:
        raise RoleSkillError("role release specification is outside policy")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RoleSkillError("role release specification is malformed") from exc
    fields = {
        "archiveSha256",
        "manifestSha256",
        "packageFiles",
        "releaseSha256",
        "role",
        "skills",
        "version",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RoleSkillError("role release specification schema is invalid")
    if (
        value.get("role") != role
        or value.get("version") != PACKAGE_VERSION
        or value.get("archiveSha256") != RELEASE_ARCHIVE_DIGESTS[role]
        or any(
            not isinstance(value.get(field), str) or DIGEST.fullmatch(value[field]) is None
            for field in ("archiveSha256", "manifestSha256", "releaseSha256")
        )
        or value["releaseSha256"] != _release_spec_digest(value)
    ):
        raise RoleSkillError("role release specification identity is invalid")
    package_files = value.get("packageFiles")
    skills = value.get("skills")
    if (
        not isinstance(package_files, dict)
        or set(package_files) != set(EXPECTED_PACKAGE_FILES[role])
        or not isinstance(skills, dict)
        or set(skills) != set(ROLE_SKILLS[role])
    ):
        raise RoleSkillError("role release specification file set is invalid")
    for name, record in package_files.items():
        if (
            not isinstance(name, str)
            or not isinstance(record, dict)
            or set(record) != {"sha256", "size"}
            or not isinstance(record.get("sha256"), str)
            or DIGEST.fullmatch(record["sha256"]) is None
            or isinstance(record.get("size"), bool)
            or not isinstance(record.get("size"), int)
            or not 0 <= record["size"] <= MAX_SOURCE_FILE_BYTES
        ):
            raise RoleSkillError("role release specification file record is invalid")
    for skill, expected_relatives in (
        (skill, EXPECTED_SKILL_FILES[skill]) for skill in ROLE_SKILLS[role]
    ):
        declared = skills.get(skill)
        if not isinstance(declared, dict) or set(declared) != set(expected_relatives):
            raise RoleSkillError("role release specification Skill tree is invalid")
        for relative in expected_relatives:
            if declared[relative] != package_files[f"skills/{skill}/{relative}"]:
                raise RoleSkillError("role release specification digests disagree")
    return value


def _safe_component(value: str) -> bool:
    return (
        value not in {"", ".", ".."}
        and SAFE_COMPONENT.fullmatch(value) is not None
        and not value.startswith("-")
    )


def _change_time_ns(metadata: os.stat_result) -> int:
    return int(getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns))


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        _change_time_ns(metadata),
    )


def _canonical_directory(path: Path, label: str) -> tuple[Path, os.stat_result]:
    if not path.is_absolute():
        raise RoleSkillError(f"{label} must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise RoleSkillError(f"{label} is missing or unreadable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink() or resolved != path:
        raise RoleSkillError(f"{label} is not one canonical directory")
    return path, metadata


def _validate_mountinfo(text: str, root: Path) -> None:
    root_posix = PurePosixPath(root.as_posix())
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields[6:]:
            raise RoleSkillError("mount boundary metadata is malformed")
        encoded = fields[4]
        decoded = re.sub(
            r"\\([0-7]{3})",
            lambda match: chr(int(match.group(1), 8)),
            encoded,
        )
        if "\\" in decoded:
            raise RoleSkillError("mount boundary metadata has an unsafe escape")
        mountpoint = PurePosixPath(decoded)
        if not mountpoint.is_absolute():
            raise RoleSkillError("mount boundary metadata has a relative path")
        try:
            mountpoint.relative_to(root_posix)
        except ValueError:
            continue
        raise RoleSkillError("skills root or tree contains a mount boundary")


def _reject_nested_mounts(root: Path) -> None:
    """Reject bind/FUSE mount injection at or below a canonical Skill root."""

    if os.name != "posix":
        return
    mountinfo = Path("/proc/self/mountinfo")
    try:
        with mountinfo.open("rb") as stream:
            payload = stream.read(MAX_MOUNTINFO_BYTES + 1)
    except OSError as exc:
        raise RoleSkillError("mount boundary metadata is unavailable") from exc
    if len(payload) > MAX_MOUNTINFO_BYTES:
        raise RoleSkillError("mount boundary metadata exceeds its limit")
    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise RoleSkillError("mount boundary metadata is not UTF-8") from exc
    _validate_mountinfo(text, root)


def _secret_shaped(data: bytes) -> bool:
    if any(re.search(pattern, data) is not None for pattern in SECRET_PATTERNS):
        return True
    for match in re.finditer(HIGH_ENTROPY_TOKEN, data):
        token = match.group(0)
        if (
            any(65 <= byte <= 90 for byte in token)
            and any(97 <= byte <= 122 for byte in token)
            and any(48 <= byte <= 57 for byte in token)
            and len(set(token)) >= 10
        ):
            return True
    return False


def _read_regular_file(
    path: Path,
    *,
    root: Path,
    root_device: int,
    scan_secrets: bool,
) -> bytes:
    try:
        path.relative_to(root)
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except (OSError, ValueError) as exc:
        raise RoleSkillError("Skill file escaped its canonical root") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or resolved != path
        or before.st_dev != root_device
        or before.st_nlink != 1
        or before.st_size > MAX_LOCAL_FILE_BYTES
    ):
        raise RoleSkillError("Skill file is not one bounded canonical regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            raise RoleSkillError("Skill file changed before it could be read")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(MAX_LOCAL_FILE_BYTES + 1)
        after = path.lstat()
        if (
            len(data) > MAX_LOCAL_FILE_BYTES
            or len(data) != before.st_size
            or _stat_identity(after) != _stat_identity(before)
            or path.resolve(strict=True) != path
            or path.is_symlink()
        ):
            raise RoleSkillError("Skill file changed while it was read")
    except OSError as exc:
        raise RoleSkillError("Skill file cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if scan_secrets and _secret_shaped(data):
        raise RoleSkillError("allowed Skill contains secret-shaped content")
    return data


def _snapshot_local_once(skills_root: Path) -> dict[str, Any]:
    root, root_metadata = _canonical_directory(skills_root, "skills root")
    _reject_nested_mounts(root)
    root_device = root_metadata.st_dev
    records: list[tuple[Any, ...]] = []
    skill_records: dict[str, list[tuple[Any, ...]]] = {}
    stable_skill_records: dict[str, list[tuple[Any, ...]]] = {}
    files: dict[str, list[str]] = {}
    file_digests: dict[str, dict[str, str]] = {}
    file_modes: dict[str, dict[str, int]] = {}
    directories: dict[str, list[str]] = {}
    directory_modes: dict[str, dict[str, int]] = {}
    entry_count = 0
    total_bytes = 0
    try:
        top_entries = sorted(os.scandir(root), key=lambda entry: entry.name)
    except OSError as exc:
        raise RoleSkillError("skills root cannot be enumerated") from exc
    for top in top_entries:
        if not _safe_component(top.name):
            raise RoleSkillError("skills root contains an unsafe Skill name")
        top_path = Path(top.path)
        try:
            # DirEntry.stat() reports zeroed device/inode fields on supported
            # Windows Python builds.  Re-stat the exact entry path so the
            # identity and same-device checks use authoritative metadata on
            # every platform (the remote helper runs this same code on Linux).
            top_metadata = top_path.lstat()
        except OSError as exc:
            raise RoleSkillError("Skill metadata cannot be read") from exc
        if (
            top.is_symlink()
            or not stat.S_ISDIR(top_metadata.st_mode)
            or top_metadata.st_dev != root_device
        ):
            raise RoleSkillError("every skills-root entry must be a local directory")
        if top_path.resolve(strict=True) != top_path:
            raise RoleSkillError("Skill directory escapes its canonical root")
        skill_records[top.name] = []
        stable_skill_records[top.name] = []
        files[top.name] = []
        file_digests[top.name] = {}
        file_modes[top.name] = {}
        directories[top.name] = []
        directory_modes[top.name] = {}
        pending = [top_path]
        while pending:
            directory = pending.pop()
            try:
                directory.relative_to(root)
                directory_metadata = directory.lstat()
                directory_resolved = directory.resolve(strict=True)
            except (OSError, ValueError) as exc:
                raise RoleSkillError("Skill directory escaped its canonical root") from exc
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or directory.is_symlink()
                or directory_resolved != directory
                or directory_metadata.st_dev != root_device
            ):
                raise RoleSkillError("Skill tree contains an unsafe directory")
            relative_directory = directory.relative_to(root).as_posix()
            directory_record = (
                "directory",
                relative_directory,
                directory_metadata.st_dev,
                directory_metadata.st_ino,
                directory_metadata.st_mode,
                directory_metadata.st_nlink,
                directory_metadata.st_mtime_ns,
                _change_time_ns(directory_metadata),
            )
            records.append(directory_record)
            skill_records[top.name].append(directory_record)
            stable_skill_records[top.name].append(
                (
                    "directory",
                    relative_directory,
                    directory_metadata.st_dev,
                    directory_metadata.st_ino,
                    directory_metadata.st_mode,
                    directory_metadata.st_nlink,
                )
            )
            skill_directory = directory.relative_to(top_path).as_posix()
            directories[top.name].append(skill_directory)
            directory_modes[top.name][skill_directory] = stat.S_IMODE(directory_metadata.st_mode)
            entry_count += 1
            if entry_count > MAX_LOCAL_ENTRIES:
                raise RoleSkillError("Skill tree exceeds the entry limit")
            try:
                children = sorted(os.scandir(directory), key=lambda entry: entry.name)
            except OSError as exc:
                raise RoleSkillError("Skill directory cannot be enumerated") from exc
            for child in children:
                if not _safe_component(child.name):
                    raise RoleSkillError("Skill tree contains an unsafe path component")
                child_path = Path(child.path)
                try:
                    child_metadata = child_path.lstat()
                except OSError as exc:
                    raise RoleSkillError("Skill entry metadata cannot be read") from exc
                if child.is_symlink() or stat.S_ISLNK(child_metadata.st_mode):
                    raise RoleSkillError("Skill tree contains a symbolic link")
                if child_metadata.st_dev != root_device:
                    raise RoleSkillError("Skill tree crosses a filesystem boundary")
                if stat.S_ISDIR(child_metadata.st_mode):
                    pending.append(child_path)
                    continue
                if not stat.S_ISREG(child_metadata.st_mode):
                    raise RoleSkillError("Skill tree contains a special file")
                data = _read_regular_file(
                    child_path,
                    root=root,
                    root_device=root_device,
                    scan_secrets=False,
                )
                relative = child_path.relative_to(root).as_posix()
                file_record = (
                    "file",
                    relative,
                    child_metadata.st_dev,
                    child_metadata.st_ino,
                    child_metadata.st_mode,
                    child_metadata.st_nlink,
                    len(data),
                    child_metadata.st_mtime_ns,
                    _change_time_ns(child_metadata),
                    hashlib.sha256(data).hexdigest(),
                )
                records.append(file_record)
                skill_records[top.name].append(file_record)
                stable_skill_records[top.name].append(
                    (
                        "file",
                        relative,
                        child_metadata.st_dev,
                        child_metadata.st_ino,
                        child_metadata.st_mode,
                        child_metadata.st_nlink,
                        len(data),
                        hashlib.sha256(data).hexdigest(),
                    )
                )
                skill_relative = child_path.relative_to(top_path).as_posix()
                files[top.name].append(skill_relative)
                file_digests[top.name][skill_relative] = hashlib.sha256(data).hexdigest()
                file_modes[top.name][skill_relative] = stat.S_IMODE(child_metadata.st_mode)
                entry_count += 1
                total_bytes += len(data)
                if entry_count > MAX_LOCAL_ENTRIES or total_bytes > MAX_LOCAL_TOTAL_BYTES:
                    raise RoleSkillError("Skill tree exceeds the bounded snapshot limits")
    all_skills = tuple(sorted(skill_records))
    known = tuple(sorted(set(all_skills) & ALL_DEVFLOW_SKILLS))
    return {
        "digest": _canonical_digest(records),
        "known": known,
        "all": all_skills,
        "skillDigests": {skill: _canonical_digest(skill_records[skill]) for skill in all_skills},
        "stableSkillDigests": {
            skill: _canonical_digest(stable_skill_records[skill]) for skill in all_skills
        },
        "files": {skill: tuple(sorted(files[skill])) for skill in all_skills},
        "fileDigests": {
            skill: {name: file_digests[skill][name] for name in sorted(file_digests[skill])}
            for skill in all_skills
        },
        "fileModes": {
            skill: {name: file_modes[skill][name] for name in sorted(file_modes[skill])}
            for skill in all_skills
        },
        "directories": {skill: tuple(sorted(directories[skill])) for skill in all_skills},
        "directoryModes": {
            skill: {name: directory_modes[skill][name] for name in sorted(directory_modes[skill])}
            for skill in all_skills
        },
    }


def _audit_local_skills(skills_root: Path, role: str) -> dict[str, Any]:
    if role not in ROLE_SKILLS:
        raise RoleSkillError("role is outside the fixed Team")
    first = _snapshot_local_once(skills_root)
    second = _snapshot_local_once(skills_root)
    if first != second:
        raise RoleSkillError("local Skill tree changed during preflight")
    return first


def _validate_remote_key(key: Any) -> tuple[str, ...]:
    if not isinstance(key, str) or not key or len(key) > 4096:
        raise RoleSkillError("object listing contains an invalid key")
    if "\\" in key or key.startswith("/") or key.endswith("/"):
        raise RoleSkillError("object listing contains an unsafe key")
    path = PurePosixPath(key)
    parts = tuple(key.split("/"))
    if (
        path.is_absolute()
        or path.as_posix() != key
        or any(not _safe_component(part) for part in parts)
    ):
        raise RoleSkillError("object listing contains an unsafe key")
    return parts


def _parse_remote_listing(text: str, role: str) -> dict[str, Any]:
    if role not in ROLE_SKILLS or len(text.encode("utf-8")) > MAX_MC_OUTPUT_BYTES:
        raise RoleSkillError("object listing is outside policy")
    records: dict[str, tuple[Any, ...]] = {}
    skill_records: dict[str, list[tuple[Any, ...]]] = {}
    files: dict[str, list[str]] = {}
    file_sizes: dict[str, dict[str, int]] = {}
    total_bytes = 0
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) > MAX_REMOTE_OBJECTS:
        raise RoleSkillError("object listing exceeds the object limit")
    for line in lines:
        try:
            value = json.loads(
                line,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise RoleSkillError("object listing returned malformed JSON") from exc
        if not isinstance(value, dict) or set(value) != MC_ENTRY_FIELDS:
            raise RoleSkillError("object listing schema is outside policy")
        key = value.get("key")
        if not isinstance(key, str):
            raise RoleSkillError("object listing contains an invalid key")
        parts = _validate_remote_key(key)
        size = value.get("size")
        version_ordinal = value.get("versionOrdinal")
        if (
            value.get("status") != "success"
            or value.get("type") != "file"
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or isinstance(version_ordinal, bool)
            or not isinstance(version_ordinal, (int, str))
            or not isinstance(value.get("etag"), str)
            or not value.get("etag")
            or not isinstance(value.get("lastModified"), str)
            or not value.get("lastModified")
            or not isinstance(value.get("storageClass"), str)
            or not isinstance(value.get("url"), str)
        ):
            raise RoleSkillError("object listing entry is outside policy")
        if key in records:
            raise RoleSkillError("object listing contains a duplicate key")
        total_bytes += size
        if total_bytes > MAX_REMOTE_TOTAL_BYTES:
            raise RoleSkillError("object listing exceeds the byte limit")
        if len(parts) < 2:
            raise RoleSkillError("skills object key does not identify a regular file")
        record = (
            key,
            size,
            value["etag"],
            value["lastModified"],
            value["storageClass"],
            version_ordinal,
        )
        records[key] = record
        skill_records.setdefault(parts[0], []).append(record)
        relative = "/".join(parts[1:])
        files.setdefault(parts[0], []).append(relative)
        file_sizes.setdefault(parts[0], {})[relative] = size
    all_skills = tuple(sorted(skill_records))
    known = tuple(sorted(set(all_skills) & ALL_DEVFLOW_SKILLS))
    ordered_records = [records[key] for key in sorted(records)]
    return {
        "digest": _canonical_digest(ordered_records),
        "known": known,
        "all": all_skills,
        "skillDigests": {
            skill: _canonical_digest(sorted(skill_records[skill])) for skill in all_skills
        },
        "files": {skill: tuple(sorted(files[skill])) for skill in all_skills},
        "fileSizes": {
            skill: {name: file_sizes[skill][name] for name in sorted(file_sizes[skill])}
            for skill in all_skills
        },
    }


def _validate_storage_prefix(value: str) -> str:
    if not value or value != value.rstrip("/") or len(value) > 1024:
        raise RoleSkillError("storage prefix is missing or non-canonical")
    parts = value.split("/")
    if len(parts) < 2 or any(not _safe_component(part) for part in parts):
        raise RoleSkillError("storage prefix is not one fixed mc alias/path")
    return value


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        with suppress(OSError):
            process.kill()
    with suppress(OSError, subprocess.TimeoutExpired):
        process.wait(timeout=5)


def _run_bounded_process(
    args: list[str],
    *,
    max_output_bytes: int,
    timeout_seconds: float,
    label: str,
    input_data: bytes | None = None,
) -> bytes:
    """Run one fixed argv with bounded output, duration, and optional stdin."""

    if (
        not args
        or any(not isinstance(item, str) or not item for item in args)
        or isinstance(max_output_bytes, bool)
        or not 0 <= max_output_bytes <= MAX_MC_OUTPUT_BYTES
        or timeout_seconds <= 0
        or input_data is not None
        and len(input_data) > MAX_REMOTE_FRAME_BYTES
    ):
        raise RoleSkillError(f"{label} invocation is outside policy")
    process: subprocess.Popen[bytes] | None = None
    input_stream: Any = None
    result: list[bytes | BaseException] = []
    try:
        if input_data is not None:
            input_stream = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115
            input_stream.write(input_data)
            input_stream.flush()
            input_stream.seek(0)
        process = subprocess.Popen(
            args,
            stdin=input_stream if input_stream is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if process.stdout is None:  # pragma: no cover - PIPE invariant
            raise RoleSkillError(f"{label} output pipe was unavailable")
        stream = process.stdout

        def bounded_reader() -> None:
            try:
                result.append(stream.read(max_output_bytes + 1))
            except (OSError, ValueError) as exc:  # pragma: no cover - defensive pipe failure
                result.append(exc)

        reader = threading.Thread(target=bounded_reader, daemon=True)
        reader.start()
        reader.join(timeout=timeout_seconds)
        if reader.is_alive():
            _stop_process(process)
            reader.join(timeout=5)
            raise RoleSkillError(f"{label} timed out")
        if len(result) != 1 or isinstance(result[0], BaseException):
            raise RoleSkillError(f"{label} output could not be read")
        data = result[0]
        if not isinstance(data, bytes):  # pragma: no cover - narrowed above
            raise RoleSkillError(f"{label} output could not be read")
        if len(data) > max_output_bytes:
            _stop_process(process)
            raise RoleSkillError(f"{label} output exceeded its limit")
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _stop_process(process)
            raise RoleSkillError(f"{label} timed out") from exc
        if returncode != 0:
            raise RoleSkillError(f"{label} failed")
        return data
    except OSError as exc:
        raise RoleSkillError(f"{label} command could not start") from exc
    finally:
        if process is not None:
            _stop_process(process)
        if input_stream is not None:
            input_stream.close()


def _mc_command(*args: str) -> list[str]:
    if MC_CONFIG_DIRECTORY is None:
        # Unit-level helpers retain a dependency-injection seam.  The remote
        # entry point always initializes a pinned binary and isolated config.
        return ["mc", *args]
    return [MC_BINARY_PATH, "--config-dir", MC_CONFIG_DIRECTORY, *args]


def _validate_mc_binary() -> None:
    path = Path(MC_BINARY_PATH)
    parent, parent_metadata = _canonical_directory(path.parent, "mc binary directory")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise RoleSkillError("pinned mc binary is missing") from exc
    if (
        path.parent != parent
        or not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or path.resolve(strict=True) != path
        or metadata.st_dev != parent_metadata.st_dev
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o711
    ):
        raise RoleSkillError("pinned mc binary metadata is outside policy")
    data = _read_regular_file(
        path,
        root=parent,
        root_device=parent_metadata.st_dev,
        scan_secrets=False,
    )
    if hashlib.sha256(data).hexdigest() != MC_BINARY_SHA256:
        raise RoleSkillError("pinned mc binary digest mismatch")
    version = _run_bounded_process(
        [MC_BINARY_PATH, "--version"],
        max_output_bytes=4096,
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        label="mc version attestation",
    )
    try:
        first_line = version.decode("utf-8").splitlines()[0]
    except (UnicodeError, IndexError) as exc:
        raise RoleSkillError("mc version attestation was malformed") from exc
    if first_line != MC_BINARY_VERSION:
        raise RoleSkillError("mc version attestation mismatch")


def _validate_mc_alias(prefix: str, access_key: str, secret_key: str) -> None:
    prefix = _validate_storage_prefix(prefix)
    if prefix.split("/", 1)[0] != MC_ALIAS or MC_CONFIG_DIRECTORY is None:
        raise RoleSkillError("isolated mc alias is outside policy")
    output = _run_bounded_process(
        _mc_command("alias", "list", MC_ALIAS, "--json"),
        max_output_bytes=64 * 1024,
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        label="mc alias attestation",
    )
    try:
        value = json.loads(
            output,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RoleSkillError("mc alias attestation was malformed") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"URL", "accessKey", "alias", "api", "path", "secretKey", "src", "status"}
        or value.get("status") != "success"
        or value.get("alias") != MC_ALIAS
        or value.get("URL") != MC_ENDPOINT
        or value.get("accessKey") != access_key
        or value.get("secretKey") != secret_key
        or value.get("api") != MC_API
        or value.get("path") != MC_PATH
    ):
        raise RoleSkillError("mc alias attestation mismatch")


def _write_isolated_mc_config(
    config_directory: Path,
    endpoint: str,
    access_key: str,
    secret_key: str,
) -> None:
    """Create mc's private config without placing credentials in process argv."""

    config, config_metadata = _canonical_directory(
        config_directory,
        "isolated mc config directory",
    )
    document = {
        "version": MC_CONFIG_VERSION,
        "aliases": {
            MC_ALIAS: {
                "url": endpoint,
                "accessKey": access_key,
                "secretKey": secret_key,
                "api": MC_API,
                "path": MC_PATH,
            }
        },
    }
    payload = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if not 1 <= len(payload) <= 16 * 1024:
        raise RoleSkillError("isolated mc config is outside policy")
    path = config / "config.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        metadata = path.lstat()
        if (
            path.is_symlink()
            or path.resolve(strict=True) != path
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_dev != config_metadata.st_dev
            or metadata.st_uid != config_metadata.st_uid
            or metadata.st_gid != config_metadata.st_gid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
            or _read_regular_file(
                path,
                root=config,
                root_device=config_metadata.st_dev,
                scan_secrets=False,
            )
            != payload
        ):
            raise RoleSkillError("isolated mc config did not stabilize")
    except (OSError, RoleSkillError) as exc:
        with suppress(OSError):
            path.unlink()
        if isinstance(exc, RoleSkillError):
            raise
        raise RoleSkillError("isolated mc config could not be created") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _initialize_mc_client(prefix: str, config_directory: Path) -> tuple[str, str]:
    global MC_CONFIG_DIRECTORY

    prefix = _validate_storage_prefix(prefix)
    if prefix != MC_STORAGE_PREFIX:
        raise RoleSkillError("storage prefix does not match the pinned authoritative root")
    endpoint = os.environ.get("AGENTTEAMS_FS_ENDPOINT", "")
    access_key = os.environ.get("AGENTTEAMS_FS_ACCESS_KEY", "")
    secret_key = os.environ.get("AGENTTEAMS_FS_SECRET_KEY", "")
    if (
        endpoint != MC_ENDPOINT
        or not 1 <= len(access_key) <= 4096
        or not 1 <= len(secret_key) <= 4096
        or "\x00" in access_key
        or "\x00" in secret_key
    ):
        raise RoleSkillError("object-store endpoint or credentials are outside policy")
    config, metadata = _canonical_directory(config_directory, "isolated mc config directory")
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or any(config.iterdir())
    ):
        raise RoleSkillError("isolated mc config directory is outside policy")
    _validate_mc_binary()
    MC_CONFIG_DIRECTORY = str(config)
    _write_isolated_mc_config(config, endpoint, access_key, secret_key)
    _validate_mc_alias(prefix, access_key, secret_key)
    return access_key, secret_key


def _mc_listing(prefix: str, role: str) -> str:
    prefix = _validate_storage_prefix(prefix)
    if role not in ROLE_SKILLS:
        raise RoleSkillError("object listing role is outside the fixed Team")
    # The terminal slash is a security boundary.  MinIO recursively lists by
    # raw object-key prefix; without it, ``skills-backup`` is also in scope.
    role_root = f"{prefix}/agents/{role}/skills/"
    output = _run_bounded_process(
        _mc_command("ls", "--recursive", "--json", role_root),
        max_output_bytes=MAX_MC_OUTPUT_BYTES,
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        label="object listing",
    )
    try:
        return output.decode("utf-8")
    except UnicodeError as exc:
        raise RoleSkillError("object listing was not UTF-8") from exc


def _audit_remote_skills(prefix: str, role: str) -> dict[str, Any]:
    first = _parse_remote_listing(_mc_listing(prefix, role), role)
    second = _parse_remote_listing(_mc_listing(prefix, role), role)
    if first != second:
        raise RoleSkillError("authoritative Skill objects changed during preflight")
    return first


def _read_remote_object(source: str, expected_size: int) -> bytes:
    if (
        not source
        or source.startswith("-")
        or isinstance(expected_size, bool)
        or not 0 <= expected_size <= MAX_SOURCE_FILE_BYTES
    ):
        raise RoleSkillError("remote object read target is outside policy")
    data = _run_bounded_process(
        _mc_command("cat", source),
        max_output_bytes=expected_size,
        timeout_seconds=REMOTE_READ_TIMEOUT_SECONDS,
        label="remote object read",
    )
    if len(data) != expected_size:
        raise RoleSkillError("remote object size changed during verification")
    return data


def _remote_transaction_root(prefix: str, role: str, skill: str) -> str:
    prefix = _validate_storage_prefix(prefix)
    if role not in ROLE_SKILLS or skill not in ROLE_SKILLS[role]:
        raise RoleSkillError("remote transaction target is outside role policy")
    return f"{prefix}/agents/{role}/{REMOTE_TRANSACTION_DIRECTORY}/{skill}"


def _mc_transaction_listing(prefix: str, role: str, skill: str) -> str:
    root = _remote_transaction_root(prefix, role, skill)
    output = _run_bounded_process(
        _mc_command("ls", "--recursive", "--json", f"{root}/"),
        max_output_bytes=MAX_MC_OUTPUT_BYTES,
        timeout_seconds=REMOTE_COMMAND_TIMEOUT_SECONDS,
        label="transaction object listing",
    )
    try:
        return output.decode("utf-8")
    except UnicodeError as exc:
        raise RoleSkillError("transaction object listing was not UTF-8") from exc


def _parse_transaction_listing(text: str, role: str, skill: str) -> dict[str, Any]:
    if (
        role not in ROLE_SKILLS
        or skill not in ROLE_SKILLS[role]
        or len(text.encode("utf-8")) > MAX_MC_OUTPUT_BYTES
    ):
        raise RoleSkillError("transaction object listing is outside policy")
    records: dict[str, tuple[Any, ...]] = {}
    sizes: dict[str, int] = {}
    total_bytes = 0
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) > MAX_REMOTE_OBJECTS:
        raise RoleSkillError("transaction object listing exceeds the object limit")
    for line in lines:
        try:
            value = json.loads(
                line,
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise RoleSkillError("transaction object listing returned malformed JSON") from exc
        if not isinstance(value, dict) or set(value) != MC_ENTRY_FIELDS:
            raise RoleSkillError("transaction object listing schema is outside policy")
        key = value.get("key")
        if not isinstance(key, str):
            raise RoleSkillError("transaction object listing entry is outside policy")
        parts = _validate_remote_key(key)
        size = value.get("size")
        version_ordinal = value.get("versionOrdinal")
        if (
            value.get("status") != "success"
            or value.get("type") != "file"
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or isinstance(version_ordinal, bool)
            or not isinstance(version_ordinal, (int, str))
            or not isinstance(value.get("etag"), str)
            or not value.get("etag")
            or not isinstance(value.get("lastModified"), str)
            or not value.get("lastModified")
            or not isinstance(value.get("storageClass"), str)
            or not isinstance(value.get("url"), str)
            or key in records
            or not (
                key == "manifest.json"
                or len(parts) >= 2
                and parts[0] in {"staging", "backup"}
            )
        ):
            raise RoleSkillError("transaction object listing entry is outside policy")
        total_bytes += size
        if total_bytes > MAX_REMOTE_TOTAL_BYTES:
            raise RoleSkillError("transaction object listing exceeds the byte limit")
        record = (
            key,
            size,
            value["etag"],
            value["lastModified"],
            value["storageClass"],
            version_ordinal,
        )
        records[key] = record
        sizes[key] = size
    return {
        "digest": _canonical_digest([records[key] for key in sorted(records)]),
        "paths": tuple(sorted(records)),
        "sizes": {key: sizes[key] for key in sorted(sizes)},
    }


def _audit_remote_transaction(prefix: str, role: str, skill: str) -> dict[str, Any]:
    first = _parse_transaction_listing(_mc_transaction_listing(prefix, role, skill), role, skill)
    second = _parse_transaction_listing(_mc_transaction_listing(prefix, role, skill), role, skill)
    if first != second:
        raise RoleSkillError("remote transaction changed during preflight")
    return first


def _audit_remote_transactions(prefix: str, role: str) -> dict[str, dict[str, Any]]:
    if role not in ROLE_SKILLS:
        raise RoleSkillError("remote transaction role is outside policy")
    first = {
        skill: _audit_remote_transaction(prefix, role, skill)
        for skill in sorted(ROLE_SKILLS[role])
    }
    second = {
        skill: _audit_remote_transaction(prefix, role, skill)
        for skill in sorted(ROLE_SKILLS[role])
    }
    if first != second:
        raise RoleSkillError("remote transactions changed during role preflight")
    return first


def _remote_skill_matches_release(
    prefix: str,
    role: str,
    skill: str,
    remote: dict[str, Any],
    expected: dict[str, Any],
) -> bool:
    if role not in ROLE_SKILLS or skill not in ROLE_SKILLS[role]:
        raise RoleSkillError("remote release verification is outside role policy")
    prefix = _validate_storage_prefix(prefix)
    observed_files = remote["files"].get(skill, ())
    if set(observed_files) != set(expected):
        return False
    observed_sizes = remote["fileSizes"].get(skill, {})
    if any(observed_sizes.get(name) != expected[name]["size"] for name in expected):
        return False
    for relative in sorted(expected):
        source = f"{prefix}/agents/{role}/skills/{skill}/{relative}"
        data = _read_remote_object(source, expected[relative]["size"])
        if hashlib.sha256(data).hexdigest() != expected[relative]["sha256"]:
            return False
    return True


def _expected_skill_directories(relative_files: tuple[str, ...]) -> tuple[str, ...]:
    directories = {"."}
    for relative in relative_files:
        parts = relative.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    return tuple(sorted(directories))


def _local_skill_matches_release(
    local: dict[str, Any],
    skill: str,
    expected: dict[str, Any],
) -> bool:
    expected_files = tuple(sorted(expected))
    return (
        skill in local["all"]
        and local["files"].get(skill) == expected_files
        and local["directories"].get(skill) == _expected_skill_directories(expected_files)
        and local["fileDigests"].get(skill)
        == {name: expected[name]["sha256"] for name in expected_files}
        and local["fileModes"].get(skill) == {name: 0o644 for name in expected_files}
        and local["directoryModes"].get(skill)
        == {name: 0o755 for name in _expected_skill_directories(expected_files)}
    )


def _state(workspace: str, role: str, release: dict[str, Any]) -> dict[str, Any]:
    if role not in ROLE_SKILLS:
        raise RoleSkillError("role is outside the fixed Team")
    workspace_path = Path(workspace)
    _validate_runtime_trust(workspace, role)
    local = _audit_local_skills(workspace_path / "skills", role)
    prefix = _validate_storage_prefix(os.environ.get("AGENTTEAMS_STORAGE_PREFIX", ""))
    remote = _audit_remote_skills(prefix, role)
    transactions = _audit_remote_transactions(prefix, role)
    allowed = tuple(sorted(ROLE_SKILLS[role]))
    local_refresh: list[str] = []
    remote_refresh: list[str] = []
    for skill in allowed:
        expected = release["skills"][skill]
        if not _local_skill_matches_release(local, skill, expected):
            local_refresh.append(skill)
        if not _remote_skill_matches_release(
            prefix,
            role,
            skill,
            remote,
            expected,
        ):
            remote_refresh.append(skill)
        if transactions[skill]["paths"] and skill not in remote_refresh:
            remote_refresh.append(skill)
    local_after = _audit_local_skills(workspace_path / "skills", role)
    remote_after = _audit_remote_skills(prefix, role)
    transactions_after = _audit_remote_transactions(prefix, role)
    if (
        local_after != local
        or remote_after != remote
        or transactions_after != transactions
    ):
        raise RoleSkillError("role Skill state changed during content verification")
    _validate_runtime_trust(workspace, role)
    local_remove = tuple(sorted(set(local["known"]) - set(allowed)))
    remote_remove = tuple(sorted(set(remote["known"]) - set(allowed)))
    local_refresh_names = tuple(sorted(local_refresh))
    remote_refresh_names = tuple(sorted(remote_refresh))
    return {
        "allowed": allowed,
        "local": local,
        "remote": remote,
        "remoteSnapshot": _canonical_digest(
            [
                remote["digest"],
                *(
                    (skill, transactions[skill]["digest"])
                    for skill in sorted(transactions)
                ),
            ]
        ),
        "transactions": transactions,
        "localRemove": local_remove,
        "remoteRemove": remote_remove,
        "localRefresh": local_refresh_names,
        "remoteSync": remote_refresh_names,
        "needsApply": bool(
            local_remove or remote_remove or local_refresh_names or remote_refresh_names
        ),
        "prefix": prefix,
        "release": release,
    }


def _run_quiet(args: list[str], label: str) -> None:
    try:
        completed = subprocess.run(
            args,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=REMOTE_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise RoleSkillError(f"{label} timed out") from exc
    except OSError as exc:
        raise RoleSkillError(f"{label} command could not start") from exc
    if completed.returncode != 0:
        raise RoleSkillError(f"{label} command failed")


def _remove_remote_skill(prefix: str, role: str, skill: str) -> None:
    if role not in ROLE_SKILLS or skill not in ALL_DEVFLOW_SKILLS or skill in ROLE_SKILLS[role]:
        raise RoleSkillError("remote deletion target is outside role policy")
    prefix = _validate_storage_prefix(prefix)
    # MinIO's recursive remove uses the supplied string as an S3 key prefix.
    # Bound the final Skill component so ``<skill>-backup`` is never matched.
    remote_skill = f"{prefix}/agents/{role}/skills/{skill}/"
    _run_quiet(
        _mc_command("rm", "--recursive", "--force", "--", remote_skill),
        "object deletion",
    )


def _load_release_archive(
    data: bytes,
    release: dict[str, Any],
    role: str,
) -> dict[str, dict[str, bytes]]:
    if (
        role not in ROLE_SKILLS
        or len(data) > MAX_ARCHIVE_BYTES
        or hashlib.sha256(data).hexdigest() != release["archiveSha256"]
    ):
        raise RoleSkillError("role release archive digest mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            infos = package.infolist()
            names = [info.filename for info in infos]
            expected_names = sorted({"manifest.json", *release["packageFiles"]})
            if names != expected_names or len(names) != len(set(names)) or package.comment:
                raise RoleSkillError("role release archive entries are ambiguous")
            for info in infos:
                parts = info.filename.split("/")
                if (
                    any(not _safe_component(part) for part in parts)
                    or info.is_dir()
                    or info.create_system != 3
                    or info.external_attr != (stat.S_IFREG | 0o644) << 16
                    or info.extra
                    or info.comment
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.file_size > MAX_SOURCE_FILE_BYTES
                ):
                    raise RoleSkillError("role release archive contains an unsafe entry")
            content = {info.filename: package.read(info) for info in infos}
        manifest = json.loads(
            content["manifest.json"],
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except RoleSkillError:
        raise
    except (KeyError, OSError, UnicodeError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        raise RoleSkillError("role release archive is malformed") from exc
    expected_digests = {name: record["sha256"] for name, record in release["packageFiles"].items()}
    if (
        not isinstance(manifest, dict)
        or set(manifest) != PACKAGE_MANIFEST_FIELDS
        or manifest.get("version") != PACKAGE_VERSION
        or manifest.get("role") != role
        or manifest.get("skills") != list(ROLE_SKILLS[role])
        or manifest.get("files") != expected_digests
        or manifest.get("manifest_sha256") != release["manifestSha256"]
        or _canonical_digest(
            {key: item for key, item in manifest.items() if key != "manifest_sha256"}
        )
        != release["manifestSha256"]
    ):
        raise RoleSkillError("role release manifest attestation failed")
    for name, record in release["packageFiles"].items():
        payload = content.get(name)
        if (
            not isinstance(payload, bytes)
            or len(payload) != record["size"]
            or hashlib.sha256(payload).hexdigest() != record["sha256"]
            or _secret_shaped(payload)
        ):
            raise RoleSkillError("role release payload attestation failed")
    return {
        skill: {
            relative: content[f"skills/{skill}/{relative}"]
            for relative in EXPECTED_SKILL_FILES[skill]
        }
        for skill in ROLE_SKILLS[role]
    }


def _transaction_file_map(value: Any, label: str) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise RoleSkillError(f"remote transaction {label} is malformed")
    result: dict[str, dict[str, Any]] = {}
    for relative, record in value.items():
        if (
            not isinstance(relative, str)
            or not _validate_remote_key(relative)
            or not isinstance(record, dict)
            or set(record) != REMOTE_TRANSACTION_FILE_FIELDS
            or isinstance(record.get("size"), bool)
            or not isinstance(record.get("size"), int)
            or not 0 <= record["size"] <= MAX_SOURCE_FILE_BYTES
            or not isinstance(record.get("sha256"), str)
            or DIGEST.fullmatch(record["sha256"]) is None
        ):
            raise RoleSkillError(f"remote transaction {label} is malformed")
        result[relative] = {"size": record["size"], "sha256": record["sha256"]}
    return {relative: result[relative] for relative in sorted(result)}


def _transaction_tree(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REMOTE_TRANSACTION_TREE_FIELDS:
        raise RoleSkillError(f"remote transaction {label} is malformed")
    present = value.get("present")
    files = _transaction_file_map(value.get("files"), label)
    if not isinstance(present, bool) or present is not bool(files):
        raise RoleSkillError(f"remote transaction {label} is malformed")
    return {"present": present, "files": files}


def _transaction_manifest_bytes(
    transaction_id: str,
    role: str,
    skill: str,
    phase: str,
    release_manifest_digest: str,
    new_tree: dict[str, Any],
    old_tree: dict[str, Any] | None,
) -> bytes:
    if (
        DIGEST.fullmatch(transaction_id) is None
        or role not in ROLE_SKILLS
        or skill not in ROLE_SKILLS[role]
        or phase not in REMOTE_TRANSACTION_PHASES
        or DIGEST.fullmatch(release_manifest_digest) is None
        or phase == "staging"
        and old_tree is not None
        or phase != "staging"
        and old_tree is None
    ):
        raise RoleSkillError("remote transaction manifest is outside policy")
    body: dict[str, Any] = {
        "schemaVersion": REMOTE_TRANSACTION_SCHEMA_VERSION,
        "transactionId": transaction_id,
        "role": role,
        "skill": skill,
        "phase": phase,
        "releaseManifestSha256": release_manifest_digest,
        "newTree": _transaction_tree(new_tree, "new tree"),
        "oldTree": None if old_tree is None else _transaction_tree(old_tree, "old tree"),
    }
    body["manifestSha256"] = _canonical_digest(body)
    data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(data) > MAX_TRANSACTION_MANIFEST_BYTES:
        raise RoleSkillError("remote transaction manifest exceeds its byte limit")
    return data


def _parse_transaction_manifest(
    data: bytes,
    role: str,
    skill: str,
    release_manifest_digest: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    if not 0 < len(data) <= MAX_TRANSACTION_MANIFEST_BYTES:
        raise RoleSkillError("remote transaction manifest is outside policy")
    try:
        value = json.loads(
            data,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RoleSkillError("remote transaction manifest is malformed") from exc
    if (
        not isinstance(value, dict)
        or set(value) != REMOTE_TRANSACTION_FIELDS
        or value.get("schemaVersion") != REMOTE_TRANSACTION_SCHEMA_VERSION
        or not isinstance(value.get("transactionId"), str)
        or DIGEST.fullmatch(value["transactionId"]) is None
        or value.get("role") != role
        or value.get("skill") != skill
        or value.get("phase") not in REMOTE_TRANSACTION_PHASES
        or value.get("releaseManifestSha256") != release_manifest_digest
        or not isinstance(value.get("manifestSha256"), str)
        or DIGEST.fullmatch(value["manifestSha256"]) is None
        or _canonical_digest(
            {key: item for key, item in value.items() if key != "manifestSha256"}
        )
        != value["manifestSha256"]
    ):
        raise RoleSkillError("remote transaction manifest attestation failed")
    new_tree = _transaction_tree(value.get("newTree"), "new tree")
    expected_tree = {
        "present": True,
        "files": {
            relative: {
                "size": expected[relative]["size"],
                "sha256": expected[relative]["sha256"],
            }
            for relative in sorted(expected)
        },
    }
    if new_tree != expected_tree:
        raise RoleSkillError("remote transaction release tree attestation failed")
    old_value = value.get("oldTree")
    if value["phase"] == "staging":
        if old_value is not None:
            raise RoleSkillError("remote transaction staging manifest is malformed")
        old_tree = None
    else:
        old_tree = _transaction_tree(old_value, "old tree")
    return {**value, "newTree": new_tree, "oldTree": old_tree}


def _write_remote_object(destination: str, data: bytes, label: str) -> None:
    if not destination or destination.startswith("-") or len(data) > MAX_SOURCE_FILE_BYTES:
        raise RoleSkillError(f"{label} target is outside policy")
    with tempfile.TemporaryDirectory(prefix="devflow-role-skill-object-") as temporary:
        temp, _metadata = _canonical_directory(Path(temporary), "remote object staging root")
        staged = temp / "payload"
        with staged.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _run_quiet(_mc_command("cp", str(staged), destination), label)
    if _read_remote_object(destination, len(data)) != data:
        raise RoleSkillError(f"{label} readback mismatch")


def _copy_remote_object(source: str, destination: str, label: str) -> None:
    if not source or not destination or source.startswith("-") or destination.startswith("-"):
        raise RoleSkillError(f"{label} target is outside policy")
    _run_quiet(_mc_command("cp", source, destination), label)


def _remote_target_root(prefix: str, role: str, skill: str) -> str:
    prefix = _validate_storage_prefix(prefix)
    if role not in ROLE_SKILLS or skill not in ROLE_SKILLS[role]:
        raise RoleSkillError("allowed Skill target is outside role policy")
    return f"{prefix}/agents/{role}/skills/{skill}"


def _remove_allowed_remote_target(prefix: str, role: str, skill: str) -> None:
    root = _remote_target_root(prefix, role, skill)
    _run_quiet(
        _mc_command("rm", "--recursive", "--force", "--", f"{root}/"),
        "allowed Skill transaction target removal",
    )


def _transaction_object_path(
    prefix: str,
    role: str,
    skill: str,
    tree: str,
    relative: str,
) -> str:
    if tree not in {"staging", "backup"} or not _validate_remote_key(relative):
        raise RoleSkillError("remote transaction object path is outside policy")
    return f"{_remote_transaction_root(prefix, role, skill)}/{tree}/{relative}"


def _put_transaction_manifest(
    prefix: str,
    role: str,
    skill: str,
    data: bytes,
) -> None:
    destination = f"{_remote_transaction_root(prefix, role, skill)}/manifest.json"
    _write_remote_object(destination, data, "remote transaction manifest write")


def _read_transaction_manifest(
    prefix: str,
    role: str,
    skill: str,
    listing: dict[str, Any],
    release_manifest_digest: str,
    expected: dict[str, Any],
) -> dict[str, Any]:
    size = listing["sizes"].get("manifest.json")
    if (
        isinstance(size, bool)
        or not isinstance(size, int)
        or not 0 < size <= MAX_TRANSACTION_MANIFEST_BYTES
    ):
        raise RoleSkillError("remote transaction has no valid phase manifest")
    source = f"{_remote_transaction_root(prefix, role, skill)}/manifest.json"
    return _parse_transaction_manifest(
        _read_remote_object(source, size),
        role,
        skill,
        release_manifest_digest,
        expected,
    )


def _verify_transaction_tree(
    prefix: str,
    role: str,
    skill: str,
    tree: str,
    expected_tree: dict[str, Any],
) -> None:
    expected_tree = _transaction_tree(expected_tree, f"{tree} tree")
    listing = _audit_remote_transaction(prefix, role, skill)
    observed = {
        path[len(tree) + 1 :]: listing["sizes"][path]
        for path in listing["paths"]
        if path.startswith(f"{tree}/")
    }
    expected_files = expected_tree["files"]
    if set(observed) != set(expected_files) or any(
        observed[relative] != expected_files[relative]["size"] for relative in observed
    ):
        raise RoleSkillError("remote transaction tree listing verification failed")
    for relative in sorted(expected_files):
        record = expected_files[relative]
        source = _transaction_object_path(prefix, role, skill, tree, relative)
        data = _read_remote_object(source, record["size"])
        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise RoleSkillError("remote transaction tree digest verification failed")


def _remote_target_tree(
    prefix: str,
    role: str,
    skill: str,
    remote: dict[str, Any],
) -> dict[str, Any]:
    if skill not in remote["all"]:
        return {"present": False, "files": {}}
    files: dict[str, dict[str, Any]] = {}
    for relative in remote["files"].get(skill, ()):
        size = remote["fileSizes"][skill][relative]
        source = f"{_remote_target_root(prefix, role, skill)}/{relative}"
        data = _read_remote_object(source, size)
        files[relative] = {"size": size, "sha256": hashlib.sha256(data).hexdigest()}
    return _transaction_tree({"present": True, "files": files}, "old tree")


def _verify_remote_target_tree(
    prefix: str,
    role: str,
    skill: str,
    expected_tree: dict[str, Any],
) -> None:
    expected_tree = _transaction_tree(expected_tree, "target tree")
    remote = _audit_remote_skills(prefix, role)
    observed_present = skill in remote["all"]
    expected_files = expected_tree["files"]
    if (
        observed_present is not expected_tree["present"]
        or set(remote["files"].get(skill, ())) != set(expected_files)
        or any(
            remote["fileSizes"].get(skill, {}).get(relative) != record["size"]
            for relative, record in expected_files.items()
        )
    ):
        raise RoleSkillError("remote transaction target listing verification failed")
    for relative in sorted(expected_files):
        record = expected_files[relative]
        source = f"{_remote_target_root(prefix, role, skill)}/{relative}"
        data = _read_remote_object(source, record["size"])
        if hashlib.sha256(data).hexdigest() != record["sha256"]:
            raise RoleSkillError("remote transaction target digest verification failed")


def _remove_transaction_tree(prefix: str, role: str, skill: str, tree: str) -> None:
    if tree not in {"staging", "backup"}:
        raise RoleSkillError("remote transaction cleanup target is outside policy")
    listing = _audit_remote_transaction(prefix, role, skill)
    if any(path.startswith(f"{tree}/") for path in listing["paths"]):
        root = _remote_transaction_root(prefix, role, skill)
        _run_quiet(
            _mc_command("rm", "--recursive", "--force", "--", f"{root}/{tree}/"),
            "remote transaction tree cleanup",
        )


def _cleanup_remote_transaction(prefix: str, role: str, skill: str) -> None:
    _remove_transaction_tree(prefix, role, skill, "staging")
    _remove_transaction_tree(prefix, role, skill, "backup")
    listing = _audit_remote_transaction(prefix, role, skill)
    if listing["paths"] == ("manifest.json",):
        manifest = f"{_remote_transaction_root(prefix, role, skill)}/manifest.json"
        _run_quiet(
            _mc_command("rm", "--force", "--", manifest),
            "remote transaction manifest cleanup",
        )
    elif listing["paths"]:
        raise RoleSkillError("remote transaction cleanup encountered unexpected objects")
    if _audit_remote_transaction(prefix, role, skill)["paths"]:
        raise RoleSkillError("remote transaction cleanup did not converge")


def _copy_transaction_tree_to_target(
    prefix: str,
    role: str,
    skill: str,
    tree: str,
    expected_tree: dict[str, Any],
) -> None:
    expected_tree = _transaction_tree(expected_tree, f"{tree} tree")
    target = _remote_target_root(prefix, role, skill)
    for relative in sorted(expected_tree["files"]):
        source = _transaction_object_path(prefix, role, skill, tree, relative)
        _copy_remote_object(
            source,
            f"{target}/{relative}",
            "remote transaction target copy",
        )


def _restore_remote_transaction(
    prefix: str,
    role: str,
    skill: str,
    old_tree: dict[str, Any],
) -> None:
    old_tree = _transaction_tree(old_tree, "old tree")
    _verify_transaction_tree(prefix, role, skill, "backup", old_tree)
    _remove_allowed_remote_target(prefix, role, skill)
    if old_tree["present"]:
        _copy_transaction_tree_to_target(prefix, role, skill, "backup", old_tree)
    _verify_remote_target_tree(prefix, role, skill, old_tree)


def _recover_remote_transaction(
    prefix: str,
    role: str,
    skill: str,
    release_manifest_digest: str,
    expected: dict[str, Any],
) -> bool:
    listing = _audit_remote_transaction(prefix, role, skill)
    if not listing["paths"]:
        return False
    manifest = _read_transaction_manifest(
        prefix,
        role,
        skill,
        listing,
        release_manifest_digest,
        expected,
    )
    phase = manifest["phase"]
    if phase == "staging":
        # By protocol the authoritative tree is untouched until a durable,
        # read-back-verified ``replacing`` manifest exists. S3 object PUT is
        # atomic, but no claim is made that the subsequent tree update is.
        _cleanup_remote_transaction(prefix, role, skill)
        return True
    if phase == "replacing":
        _restore_remote_transaction(prefix, role, skill, manifest["oldTree"])
        _cleanup_remote_transaction(prefix, role, skill)
        return True
    try:
        _verify_remote_target_tree(prefix, role, skill, manifest["newTree"])
    except RoleSkillError:
        # A committed marker with a non-converged target is conservatively
        # rolled back; the caller may then begin a fresh transaction.
        _restore_remote_transaction(prefix, role, skill, manifest["oldTree"])
    _cleanup_remote_transaction(prefix, role, skill)
    return True


def _recover_remote_transactions(
    prefix: str,
    role: str,
    release: dict[str, Any],
) -> None:
    for skill in sorted(ROLE_SKILLS[role]):
        _recover_remote_transaction(
            prefix,
            role,
            skill,
            release["manifestSha256"],
            release["skills"][skill],
        )


def _replace_remote_skill(
    prefix: str,
    role: str,
    skill: str,
    files: dict[str, bytes],
    expected: dict[str, Any],
    release_manifest_digest: str,
) -> None:
    if (
        role not in ROLE_SKILLS
        or skill not in ROLE_SKILLS[role]
        or set(files) != set(EXPECTED_SKILL_FILES[skill])
        or set(expected) != set(files)
        or DIGEST.fullmatch(release_manifest_digest) is None
    ):
        raise RoleSkillError("remote release replacement is outside role policy")
    prefix = _validate_storage_prefix(prefix)
    for relative, data in files.items():
        if (
            len(data) != expected[relative]["size"]
            or hashlib.sha256(data).hexdigest() != expected[relative]["sha256"]
            or _secret_shaped(data)
        ):
            raise RoleSkillError("remote release replacement bytes are invalid")

    _recover_remote_transaction(
        prefix,
        role,
        skill,
        release_manifest_digest,
        expected,
    )
    current = _audit_remote_skills(prefix, role)
    if _remote_skill_matches_release(prefix, role, skill, current, expected):
        return
    before = current
    old_tree = _remote_target_tree(prefix, role, skill, before)
    if _audit_remote_skills(prefix, role) != before:
        raise RoleSkillError("allowed Skill changed during transaction preparation")
    new_tree = {
        "present": True,
        "files": {
            relative: {
                "size": expected[relative]["size"],
                "sha256": expected[relative]["sha256"],
            }
            for relative in sorted(expected)
        },
    }
    transaction_id = hashlib.sha256(
        (
            f"{role}|{skill}|{release_manifest_digest}|{before['digest']}|"
            f"{time.time_ns()}|{os.getpid()}"
        ).encode("ascii")
    ).hexdigest()
    staging_manifest = _transaction_manifest_bytes(
        transaction_id,
        role,
        skill,
        "staging",
        release_manifest_digest,
        new_tree,
        None,
    )
    try:
        _put_transaction_manifest(prefix, role, skill, staging_manifest)
        for relative in sorted(files):
            destination = _transaction_object_path(
                prefix,
                role,
                skill,
                "staging",
                relative,
            )
            _write_remote_object(destination, files[relative], "remote transaction staging write")
        _verify_transaction_tree(prefix, role, skill, "staging", new_tree)

        target = _remote_target_root(prefix, role, skill)
        for relative in sorted(old_tree["files"]):
            destination = _transaction_object_path(
                prefix,
                role,
                skill,
                "backup",
                relative,
            )
            _copy_remote_object(
                f"{target}/{relative}",
                destination,
                "remote transaction backup copy",
            )
        _verify_transaction_tree(prefix, role, skill, "backup", old_tree)
        if _audit_remote_skills(prefix, role) != before:
            raise RoleSkillError("allowed Skill changed before transaction replacement")

        replacing_manifest = _transaction_manifest_bytes(
            transaction_id,
            role,
            skill,
            "replacing",
            release_manifest_digest,
            new_tree,
            old_tree,
        )
        _put_transaction_manifest(prefix, role, skill, replacing_manifest)
        _remove_allowed_remote_target(prefix, role, skill)
        _copy_transaction_tree_to_target(prefix, role, skill, "staging", new_tree)
        _verify_remote_target_tree(prefix, role, skill, new_tree)
        committed_manifest = _transaction_manifest_bytes(
            transaction_id,
            role,
            skill,
            "committed",
            release_manifest_digest,
            new_tree,
            old_tree,
        )
        _put_transaction_manifest(prefix, role, skill, committed_manifest)
        _cleanup_remote_transaction(prefix, role, skill)
    except Exception:
        try:
            _recover_remote_transaction(
                prefix,
                role,
                skill,
                release_manifest_digest,
                expected,
            )
        except Exception as recovery_error:
            raise RoleSkillError("remote Skill transaction recovery failed") from recovery_error
        raise


def _remove_local_tree(directory: Path, *, skills_root: Path, root_device: int) -> None:
    try:
        before = directory.lstat()
        directory.relative_to(skills_root)
    except (OSError, ValueError) as exc:
        raise RoleSkillError("local deletion directory escaped the skills root") from exc
    if (
        not stat.S_ISDIR(before.st_mode)
        or directory.is_symlink()
        or directory.resolve(strict=True) != directory
        or before.st_dev != root_device
    ):
        raise RoleSkillError("local deletion encountered an unsafe directory")
    try:
        children = sorted(os.scandir(directory), key=lambda entry: entry.name)
    except OSError as exc:
        raise RoleSkillError("local deletion directory cannot be enumerated") from exc
    for child in children:
        if not _safe_component(child.name):
            raise RoleSkillError("local deletion encountered an unsafe component")
        child_path = Path(child.path)
        try:
            metadata = child_path.lstat()
        except OSError as exc:
            raise RoleSkillError("local deletion metadata cannot be read") from exc
        if child.is_symlink() or stat.S_ISLNK(metadata.st_mode):
            raise RoleSkillError("local deletion refuses symbolic links")
        if metadata.st_dev != root_device or child_path.resolve(strict=True) != child_path:
            raise RoleSkillError("local deletion refuses an escaped entry")
        if stat.S_ISDIR(metadata.st_mode):
            _remove_local_tree(
                child_path,
                skills_root=skills_root,
                root_device=root_device,
            )
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RoleSkillError("local deletion refuses a special or hard-linked file")
        current = child_path.lstat()
        if _stat_identity(current) != _stat_identity(metadata):
            raise RoleSkillError("local Skill file changed before deletion")
        try:
            child_path.unlink()
        except OSError as exc:
            raise RoleSkillError("local Skill file deletion failed") from exc
    try:
        after = directory.lstat()
    except OSError as exc:
        raise RoleSkillError("local deletion directory changed unexpectedly") from exc
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_mode != before.st_mode
        or directory.is_symlink()
        or directory.resolve(strict=True) != directory
    ):
        raise RoleSkillError("local deletion directory changed concurrently")
    try:
        directory.rmdir()
    except OSError as exc:
        raise RoleSkillError("local Skill directory deletion failed") from exc


def _remove_local_skill(
    skills_root: Path,
    role: str,
    skill: str,
    expected_digest: str,
) -> None:
    if role not in ROLE_SKILLS or skill not in ALL_DEVFLOW_SKILLS or skill in ROLE_SKILLS[role]:
        raise RoleSkillError("local deletion target is outside role policy")
    root, root_metadata = _canonical_directory(skills_root, "skills root")
    before = _snapshot_local_once(root)
    if before["stableSkillDigests"].get(skill) != expected_digest:
        raise RoleSkillError("local deletion target changed after preflight")
    workspace, workspace_metadata = _canonical_directory(root.parent, "role workspace")
    if workspace_metadata.st_dev != root_metadata.st_dev:
        raise RoleSkillError("local deletion quarantine crosses a filesystem boundary")
    target = root / skill
    if target.parent != root or target.name != skill:
        raise RoleSkillError("local deletion target is not exact")
    quarantine = Path(tempfile.mkdtemp(prefix=".devflow-role-skill-delete-", dir=workspace))
    quarantined_target = quarantine / skill
    verified = False
    try:
        _rename_noreplace(target, quarantined_target)
        _fsync_directory(root)
        quarantined = _snapshot_local_once(quarantine)
        if quarantined["stableSkillDigests"].get(skill) != expected_digest:
            if not target.exists():
                _rename_noreplace(quarantined_target, target)
                _fsync_directory(root)
                quarantine.rmdir()
            raise RoleSkillError("local deletion target identity changed during quarantine")
        verified = True
        _remove_local_tree(
            quarantined_target,
            skills_root=quarantine,
            root_device=root_metadata.st_dev,
        )
        quarantine.rmdir()
    except OSError as exc:
        raise RoleSkillError("local deletion quarantine failed") from exc
    except Exception:
        # Never erase an unverified quarantine: it may be a raced built-in or
        # allowed tree.  A verified target is safe to finish deleting.
        if verified and quarantined_target.exists():
            try:
                _remove_local_tree(
                    quarantined_target,
                    skills_root=quarantine,
                    root_device=root_metadata.st_dev,
                )
                quarantine.rmdir()
            except (OSError, RoleSkillError):
                pass
        raise


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":  # Windows has no portable directory fsync primitive.
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise RoleSkillError("release directory could not be synchronized") from exc


def _sync_file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
    )


def _validate_sync_contract(workspace_path: Path) -> tuple[Path, tuple[int, ...]]:
    entrypoint = Path(WORKER_ENTRYPOINT_PATH)
    entrypoint_root, entrypoint_root_metadata = _canonical_directory(
        entrypoint.parent,
        "worker entrypoint directory",
    )
    try:
        entrypoint_metadata = entrypoint.lstat()
    except OSError as exc:
        raise RoleSkillError("worker sync contract is missing") from exc
    if (
        entrypoint.parent != entrypoint_root
        or not stat.S_ISREG(entrypoint_metadata.st_mode)
        or entrypoint.is_symlink()
        or entrypoint.resolve(strict=True) != entrypoint
        or entrypoint_metadata.st_dev != entrypoint_root_metadata.st_dev
        or entrypoint_metadata.st_uid != 0
        or entrypoint_metadata.st_gid != 0
        or entrypoint_metadata.st_nlink != 1
        or stat.S_IMODE(entrypoint_metadata.st_mode) != 0o755
    ):
        raise RoleSkillError("worker sync contract metadata is outside policy")
    entrypoint_data = _read_regular_file(
        entrypoint,
        root=entrypoint_root,
        root_device=entrypoint_root_metadata.st_dev,
        scan_secrets=False,
    )
    if hashlib.sha256(entrypoint_data).hexdigest() != WORKER_ENTRYPOINT_SHA256:
        raise RoleSkillError("worker sync contract digest mismatch")

    workspace, workspace_metadata = _canonical_directory(workspace_path, "role workspace")
    marker = workspace / ".last-pull"
    try:
        marker_metadata = marker.lstat()
    except OSError as exc:
        raise RoleSkillError("worker sync marker is missing") from exc
    if (
        not stat.S_ISREG(marker_metadata.st_mode)
        or marker.is_symlink()
        or marker.resolve(strict=True) != marker
        or marker_metadata.st_dev != workspace_metadata.st_dev
        or marker_metadata.st_uid != 0
        or marker_metadata.st_gid != 0
        or marker_metadata.st_nlink != 1
        or marker_metadata.st_size != 0
        or stat.S_IMODE(marker_metadata.st_mode) != 0o644
    ):
        raise RoleSkillError("worker sync marker metadata is outside policy")
    if _read_regular_file(
        marker,
        root=workspace,
        root_device=workspace_metadata.st_dev,
        scan_secrets=False,
    ):
        raise RoleSkillError("worker sync marker is not empty")
    return marker, _sync_file_identity(marker_metadata)


def _flock_marker(descriptor: int, *, acquire: bool) -> None:
    try:
        module = importlib.import_module("fcntl")
        operation = module.LOCK_EX | module.LOCK_NB if acquire else module.LOCK_UN
        module.flock(descriptor, operation)
    except ModuleNotFoundError as exc:  # pragma: no cover - Linux deployment invariant
        raise RoleSkillError("worker sync marker locking is unavailable") from exc
    except OSError as exc:
        if acquire and exc.errno in {errno.EACCES, errno.EAGAIN}:
            raise RoleSkillError("worker sync marker lease is already held") from exc
        raise RoleSkillError("worker sync marker locking failed") from exc


def _acquire_sync_marker_lease(
    workspace_path: Path,
) -> tuple[int, tuple[int, ...], int]:
    marker, expected_identity = _validate_sync_contract(workspace_path)
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    locked = False
    retained = False
    lease_written = False
    lease_mtime_ns = 0
    try:
        descriptor = os.open(marker, flags)
        _flock_marker(descriptor, acquire=True)
        locked = True
        before = os.fstat(descriptor)
        if _sync_file_identity(before) != expected_identity:
            raise RoleSkillError("worker sync marker changed before coordination")
        if before.st_mtime_ns > time.time_ns():
            raise RoleSkillError("worker sync marker has an unexpired lease")
        now = time.time_ns()
        target = now + SYNC_LEASE_SECONDS * 1_000_000_000
        os.utime(descriptor, ns=(before.st_atime_ns, target))
        lease_written = True
        lease_mtime_ns = target
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if _sync_file_identity(after) != expected_identity or after.st_mtime_ns != target:
            raise RoleSkillError("worker sync marker lease did not stabilize")
        retained = True
        return descriptor, expected_identity, after.st_mtime_ns
    except (OSError, RoleSkillError) as exc:
        rollback_failed = False
        if lease_written and descriptor >= 0:
            try:
                current = os.fstat(descriptor)
                if current.st_mtime_ns != lease_mtime_ns:
                    rollback_failed = True
                else:
                    rollback_now = time.time_ns()
                    os.utime(descriptor, ns=(current.st_atime_ns, rollback_now))
                    os.fsync(descriptor)
                    restored = os.fstat(descriptor)
                    rollback_failed = (
                        _sync_file_identity(restored) != expected_identity
                        or restored.st_mtime_ns != rollback_now
                    )
            except OSError:
                rollback_failed = True
        if rollback_failed:
            raise RoleSkillError("worker sync marker coordination and rollback failed") from exc
        if isinstance(exc, RoleSkillError):
            raise
        raise RoleSkillError("worker sync marker coordination failed") from exc
    finally:
        if descriptor >= 0 and not retained:
            if locked:
                with suppress(RoleSkillError):
                    _flock_marker(descriptor, acquire=False)
            os.close(descriptor)


def _release_sync_marker_lease(
    descriptor: int,
    expected_identity: tuple[int, ...],
    expected_mtime_ns: int,
) -> None:
    error: BaseException | None = None
    try:
        current = os.fstat(descriptor)
        if (
            _sync_file_identity(current) != expected_identity
            or current.st_mtime_ns != expected_mtime_ns
            or expected_mtime_ns <= time.time_ns()
        ):
            raise RoleSkillError("worker sync marker lease ownership changed")
        released_mtime_ns = time.time_ns()
        os.utime(descriptor, ns=(current.st_atime_ns, released_mtime_ns))
        os.fsync(descriptor)
        released = os.fstat(descriptor)
        if (
            _sync_file_identity(released) != expected_identity
            or released.st_mtime_ns != released_mtime_ns
        ):
            raise RoleSkillError("worker sync marker lease release did not stabilize")
    except (OSError, RoleSkillError) as exc:
        error = exc
    finally:
        try:
            _flock_marker(descriptor, acquire=False)
        except RoleSkillError as exc:
            error = error or exc
        try:
            os.close(descriptor)
        except OSError as exc:
            error = error or exc
    if error is not None:
        if isinstance(error, RoleSkillError):
            raise error
        raise RoleSkillError("worker sync marker lease release failed") from error


@contextmanager
def _sync_marker_lease(
    workspace_path: Path,
) -> Iterator[tuple[tuple[int, ...], int]]:
    descriptor, lease_identity, lease_mtime_ns = _acquire_sync_marker_lease(workspace_path)
    try:
        yield lease_identity, lease_mtime_ns
    finally:
        _release_sync_marker_lease(descriptor, lease_identity, lease_mtime_ns)


def _verify_sync_marker_lease(
    workspace_path: Path,
    expected_identity: tuple[int, ...],
    expected_mtime_ns: int,
) -> None:
    marker, observed_identity = _validate_sync_contract(workspace_path)
    try:
        metadata = marker.lstat()
    except OSError as exc:  # pragma: no cover - validated immediately above
        raise RoleSkillError("worker sync marker cannot be read") from exc
    if (
        observed_identity != expected_identity
        or metadata.st_mtime_ns != expected_mtime_ns
        or expected_mtime_ns <= time.time_ns()
    ):
        raise RoleSkillError("worker sync marker lease was interrupted")


def _set_directory_mode(path: Path, root_device: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode) or before.st_dev != root_device:
            raise RoleSkillError("release staging directory crossed a boundary")
        fchmod: Any = getattr(os, "fchmod", None)
        if fchmod is None:  # pragma: no cover - remote helper is Linux
            os.chmod(path, 0o755)
        else:
            fchmod(descriptor, 0o755)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or not stat.S_ISDIR(after.st_mode)
            or stat.S_IMODE(after.st_mode) != 0o755
        ):
            raise RoleSkillError("release staging directory mode did not stabilize")
    except OSError as exc:
        raise RoleSkillError("release staging directory could not be prepared") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _rename_exchange(left: Path, right: Path) -> None:
    """Atomically exchange two Linux directory entries; never emulate it."""

    try:
        library: Any = ctypes.CDLL(None, use_errno=True)
        operation: Any = library.renameat2
    except (AttributeError, OSError) as exc:
        raise RoleSkillError("atomic directory exchange is unavailable") from exc
    operation.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    operation.restype = ctypes.c_int
    at_fdcwd = -100
    rename_exchange = 2
    result = operation(
        at_fdcwd,
        os.fsencode(left),
        at_fdcwd,
        os.fsencode(right),
        rename_exchange,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise RoleSkillError("atomic directory exchange failed") from OSError(
            error, os.strerror(error)
        )


def _rename_noreplace(left: Path, right: Path) -> None:
    """Atomically install an expected-missing directory without overwriting."""

    try:
        library: Any = ctypes.CDLL(None, use_errno=True)
        operation: Any = library.renameat2
    except (AttributeError, OSError) as exc:
        raise RoleSkillError("atomic no-replace rename is unavailable") from exc
    operation.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    operation.restype = ctypes.c_int
    result = operation(-100, os.fsencode(left), -100, os.fsencode(right), 1)
    if result != 0:
        error = ctypes.get_errno()
        raise RoleSkillError("atomic no-replace rename failed") from OSError(
            error, os.strerror(error)
        )


def _probe_local_filesystem(workspace_path: Path) -> None:
    """Exercise required atomic primitives outside ``skills`` before any write."""

    def probe_identity(directory: Path) -> tuple[int, int, int, int]:
        try:
            metadata = directory.lstat()
            children = tuple(directory.iterdir())
        except OSError as exc:
            raise RoleSkillError("filesystem probe directory is unreadable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or directory.is_symlink() or children:
            raise RoleSkillError("filesystem probe directory changed type or content")
        # renameat2 is allowed to update ctime, and some filesystems also
        # update directory mtime. Device/inode/type/mode are the stable entry
        # identity needed to prove exchange/no-replace semantics here.
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_nlink,
        )

    workspace, workspace_metadata = _canonical_directory(workspace_path, "role workspace")
    probe_parent = Path(tempfile.mkdtemp(prefix=".devflow-role-skill-probe-", dir=workspace))
    try:
        probe, probe_metadata = _canonical_directory(probe_parent, "filesystem probe root")
        if probe_metadata.st_dev != workspace_metadata.st_dev:
            raise RoleSkillError("filesystem probe crosses a filesystem boundary")
        left = probe / "left"
        right = probe / "right"
        source = probe / "source"
        destination = probe / "destination"
        collision_source = probe / "collision-source"
        collision_target = probe / "collision-target"
        for directory in (
            left,
            right,
            source,
            collision_source,
            collision_target,
        ):
            directory.mkdir(mode=0o700)
            _set_directory_mode(directory, probe_metadata.st_dev)
        left_identity = probe_identity(left)
        right_identity = probe_identity(right)
        _rename_exchange(left, right)
        if probe_identity(left) != right_identity or probe_identity(right) != left_identity:
            raise RoleSkillError("atomic exchange filesystem probe failed")
        source_identity = probe_identity(source)
        _rename_noreplace(source, destination)
        if source.exists() or probe_identity(destination) != source_identity:
            raise RoleSkillError("atomic no-replace filesystem probe failed")
        collision_source_identity = probe_identity(collision_source)
        collision_target_identity = probe_identity(collision_target)
        try:
            _rename_noreplace(collision_source, collision_target)
        except RoleSkillError as exc:
            cause = exc.__cause__
            if not isinstance(cause, OSError) or cause.errno not in {
                errno.EEXIST,
                errno.ENOTEMPTY,
            }:
                raise RoleSkillError("atomic no-replace collision probe failed") from exc
        else:
            raise RoleSkillError("atomic no-replace overwrote an existing directory")
        if (
            probe_identity(collision_source) != collision_source_identity
            or probe_identity(collision_target) != collision_target_identity
        ):
            raise RoleSkillError("atomic no-replace collision changed an existing directory")
        _fsync_directory(probe)
        _fsync_directory(workspace)
        _remove_local_tree(
            probe,
            skills_root=workspace,
            root_device=workspace_metadata.st_dev,
        )
    except Exception:
        if probe_parent.exists():
            with suppress(OSError, RoleSkillError):
                _remove_local_tree(
                    probe_parent,
                    skills_root=workspace,
                    root_device=workspace_metadata.st_dev,
                )
        raise


def _replace_local_skill(
    skills_root: Path,
    role: str,
    skill: str,
    files: dict[str, bytes],
    expected: dict[str, Any],
    expected_before_digest: str | None,
) -> None:
    if (
        role not in ROLE_SKILLS
        or skill not in ROLE_SKILLS[role]
        or set(files) != set(EXPECTED_SKILL_FILES[skill])
        or set(expected) != set(files)
    ):
        raise RoleSkillError("local release replacement is outside role policy")
    root, root_metadata = _canonical_directory(skills_root, "skills root")
    before_snapshot = _snapshot_local_once(root)
    observed_before = before_snapshot["stableSkillDigests"].get(skill)
    if observed_before != expected_before_digest:
        raise RoleSkillError("local release target changed before atomic exchange")
    workspace, workspace_metadata = _canonical_directory(root.parent, "role workspace")
    if workspace_metadata.st_dev != root_metadata.st_dev:
        raise RoleSkillError("local release staging crosses a filesystem boundary")
    stage_parent_text = tempfile.mkdtemp(prefix=".devflow-role-skill-stage-", dir=workspace)
    stage_parent = Path(stage_parent_text)
    stage_safe_to_delete = True
    target = root / skill
    try:
        stage, stage_metadata = _canonical_directory(stage_parent, "release staging root")
        if stage_metadata.st_dev != root_metadata.st_dev:
            raise RoleSkillError("local release staging crosses a filesystem boundary")
        stage_skill = stage / skill
        stage_skill.mkdir(mode=0o755)
        for relative in sorted(files):
            parts = tuple(relative.split("/"))
            if not parts or any(not _safe_component(part) for part in parts):
                raise RoleSkillError("release Skill file path is outside policy")
            data = files[relative]
            if (
                len(data) != expected[relative]["size"]
                or hashlib.sha256(data).hexdigest() != expected[relative]["sha256"]
                or _secret_shaped(data)
            ):
                raise RoleSkillError("local release replacement bytes are invalid")
            parent = stage_skill.joinpath(*parts[:-1])
            parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            destination = parent / parts[-1]
            descriptor = -1
            try:
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise RoleSkillError("release Skill file write was incomplete")
                    view = view[written:]
                fchmod: Any = getattr(os, "fchmod", None)
                if fchmod is None:  # pragma: no cover - remote helper is Linux
                    os.chmod(destination, 0o644)
                else:
                    fchmod(descriptor, 0o644)
                os.fsync(descriptor)
            except OSError as exc:
                raise RoleSkillError("release Skill file could not be staged") from exc
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        staged_directories = {
            stage_skill if relative == "." else stage_skill.joinpath(*relative.split("/"))
            for relative in _expected_skill_directories(tuple(sorted(files)))
        }
        for directory in sorted(staged_directories, key=lambda path: len(path.parts)):
            _set_directory_mode(directory, stage_metadata.st_dev)
        for directory in sorted(
            staged_directories,
            key=lambda path: len(path.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        staged_snapshot = _snapshot_local_once(stage)
        if not _local_skill_matches_release(staged_snapshot, skill, expected):
            raise RoleSkillError("staged local release failed manifest verification")

        target_exists = expected_before_digest is not None
        if target_exists:
            _rename_exchange(stage_skill, target)
            stage_safe_to_delete = False
        else:
            _rename_noreplace(stage_skill, target)
        _fsync_directory(root)
        if target_exists:
            exchanged = _snapshot_local_once(stage)
            if exchanged["stableSkillDigests"].get(skill) != expected_before_digest:
                _rename_exchange(stage_skill, target)
                stage_safe_to_delete = True
                _fsync_directory(root)
                raise RoleSkillError("local release target identity changed during exchange")
            stage_safe_to_delete = True
        installed = _snapshot_local_once(root)
        if not _local_skill_matches_release(installed, skill, expected):
            if target_exists:
                _rename_exchange(stage_skill, target)
                stage_safe_to_delete = True
                _fsync_directory(root)
            raise RoleSkillError("atomic local release readback failed")

        if target_exists:
            old_metadata = stage_skill.lstat()
            _remove_local_tree(
                stage_skill,
                skills_root=stage,
                root_device=old_metadata.st_dev,
            )
        stage.rmdir()
    except Exception:
        if stage_safe_to_delete and stage_parent.exists():
            try:
                stage_metadata = stage_parent.lstat()
                _remove_local_tree(
                    stage_parent,
                    skills_root=workspace,
                    root_device=stage_metadata.st_dev,
                )
            except (OSError, RoleSkillError):
                pass
        raise


def _verify_preserved(
    before: dict[str, Any],
    current: dict[str, Any],
    *,
    removed: set[str],
    added: set[str],
    modified: set[str] | None = None,
) -> None:
    modified = set() if modified is None else modified
    if (
        removed & added
        or removed & modified
        or added & modified
        or not modified <= set(before["all"])
    ):
        raise RoleSkillError("Skill preservation plan is inconsistent")
    expected_names = (set(before["all"]) - removed) | added
    if set(current["all"]) != expected_names:
        raise RoleSkillError("Skill names changed outside the fixed plan")
    for skill in set(before["all"]) - removed - modified:
        if current["skillDigests"].get(skill) != before["skillDigests"].get(skill):
            raise RoleSkillError("an allowed or built-in Skill changed concurrently")
    if not added <= set(current["all"]):
        raise RoleSkillError("allowed Skill synchronization did not materialize")
    if not modified <= set(current["all"]):
        raise RoleSkillError("partial allowed Skill synchronization disappeared")


def _verify_outside_plan_preserved(
    before: dict[str, Any],
    current: dict[str, Any],
    mutable: set[str],
) -> None:
    if not mutable <= ALL_DEVFLOW_SKILLS:
        raise RoleSkillError("sync convergence plan exceeds the fixed DevFlow Skill set")
    before_fixed = set(before["all"]) - mutable
    current_fixed = set(current["all"]) - mutable
    if before_fixed != current_fixed:
        raise RoleSkillError("a Skill outside the convergence plan changed names")
    for skill in before_fixed:
        if current["skillDigests"].get(skill) != before["skillDigests"].get(skill):
            raise RoleSkillError("a Skill outside the convergence plan changed content")


def _apply_local_plan(
    skills_root: Path,
    role: str,
    state: dict[str, Any],
    release_files: dict[str, dict[str, bytes]],
    release: dict[str, Any],
) -> tuple[set[str], set[str], set[str]]:
    before_local = state["local"]
    local_refresh_added_plan = set(state["localRefresh"]) - set(before_local["all"])
    local_refresh_modified_plan = set(state["localRefresh"]) & set(before_local["all"])
    refreshed_local_added: set[str] = set()
    refreshed_local_modified: set[str] = set()
    removed_local: set[str] = set()
    for skill in state["localRefresh"]:
        current_local = _audit_local_skills(skills_root, role)
        _verify_preserved(
            before_local,
            current_local,
            removed=removed_local,
            added=refreshed_local_added,
            modified=refreshed_local_modified,
        )
        _replace_local_skill(
            skills_root,
            role,
            skill,
            release_files[skill],
            release["skills"][skill],
            before_local["stableSkillDigests"].get(skill),
        )
        if skill in local_refresh_added_plan:
            refreshed_local_added.add(skill)
        elif skill in local_refresh_modified_plan:
            refreshed_local_modified.add(skill)
        else:  # pragma: no cover - fixed-plan invariant
            raise RoleSkillError("local Skill refresh plan changed unexpectedly")
        refreshed_local = _audit_local_skills(skills_root, role)
        _verify_preserved(
            before_local,
            refreshed_local,
            removed=removed_local,
            added=refreshed_local_added,
            modified=refreshed_local_modified,
        )
        if not _local_skill_matches_release(
            refreshed_local,
            skill,
            release["skills"][skill],
        ):
            raise RoleSkillError("atomic local Skill refresh verification failed")

    for skill in state["localRemove"]:
        current_local = _audit_local_skills(skills_root, role)
        _verify_preserved(
            before_local,
            current_local,
            removed=removed_local,
            added=refreshed_local_added,
            modified=refreshed_local_modified,
        )
        _remove_local_skill(
            skills_root,
            role,
            skill,
            before_local["stableSkillDigests"][skill],
        )
        removed_local.add(skill)
    local_after = _audit_local_skills(skills_root, role)
    _verify_preserved(
        before_local,
        local_after,
        removed=removed_local,
        added=refreshed_local_added,
        modified=refreshed_local_modified,
    )
    if tuple(local_after["known"]) != tuple(state["allowed"]):
        raise RoleSkillError("local convergence did not produce the role allowlist")
    for skill in state["allowed"]:
        if not _local_skill_matches_release(local_after, skill, release["skills"][skill]):
            raise RoleSkillError("local convergence release readback failed")
    return removed_local, refreshed_local_added, refreshed_local_modified


def _apply_remote_plan(
    prefix: str,
    role: str,
    state: dict[str, Any],
    release_files: dict[str, dict[str, bytes]],
    release: dict[str, Any],
) -> set[str]:
    before_remote = state["remote"]
    mutable = (
        set(state["remoteRemove"])
        | set(state["remoteSync"])
        | set(state["localRemove"])
        | set(state["localRefresh"])
    )
    for skill in state["remoteRemove"]:
        current_remote = _audit_remote_skills(prefix, role)
        _verify_outside_plan_preserved(before_remote, current_remote, mutable)
        if skill in current_remote["all"]:
            _remove_remote_skill(prefix, role, skill)
    for skill in state["remoteSync"]:
        current_remote = _audit_remote_skills(prefix, role)
        _verify_outside_plan_preserved(before_remote, current_remote, mutable)
        _replace_remote_skill(
            prefix,
            role,
            skill,
            release_files[skill],
            release["skills"][skill],
            release["manifestSha256"],
        )
        refreshed = _audit_remote_skills(prefix, role)
        _verify_outside_plan_preserved(before_remote, refreshed, mutable)
        if not _remote_skill_matches_release(
            prefix,
            role,
            skill,
            refreshed,
            release["skills"][skill],
        ):
            raise RoleSkillError("allowed Skill remote refresh verification failed")
    remote_after = _audit_remote_skills(prefix, role)
    _verify_outside_plan_preserved(before_remote, remote_after, mutable)
    if tuple(remote_after["known"]) != tuple(state["allowed"]):
        raise RoleSkillError("remote convergence did not produce the role allowlist")
    for skill in state["allowed"]:
        if not _remote_skill_matches_release(
            prefix,
            role,
            skill,
            remote_after,
            release["skills"][skill],
        ):
            raise RoleSkillError("allowed Skill final remote verification failed")
    return mutable


def _summary_from_state(state: dict[str, Any], role: str, *, applied: bool) -> dict[str, Any]:
    local_known = list(state["local"]["known"])
    remote_known = list(state["remote"]["known"])
    return {
        "ok": True,
        "role": role,
        "allowedSkills": list(state["allowed"]),
        "localKnownSkills": local_known,
        "remoteKnownSkills": remote_known,
        "localRemove": list(state["localRemove"]),
        "remoteRemove": list(state["remoteRemove"]),
        "remoteSync": list(state["remoteSync"]),
        "localRefresh": list(state["localRefresh"]),
        "localCount": len(local_known),
        "remoteCount": len(remote_known),
        "localSnapshot": state["local"]["digest"],
        "remoteSnapshot": state["remoteSnapshot"],
        "needsApply": state["needsApply"],
        "applied": applied,
    }


def _remote_main_configured(config_directory: Path, arguments: list[str]) -> None:
    if len(arguments) != 6 or arguments[1] not in {"check", "prepare", "apply"}:
        raise SystemExit(2)
    release_text, action, role, workspace, expected_local, expected_remote = arguments
    release = _parse_release_spec(release_text, role)
    workspace_path = Path(workspace)
    skills_root = workspace_path / "skills"
    expected_workspace = f"/root/hiclaw-fs/agents/{role}"
    try:
        workspace_exact = workspace_path.resolve(strict=True) == workspace_path
        skills_exact = skills_root.resolve(strict=True) == skills_root
    except OSError:
        workspace_exact = False
        skills_exact = False
    if (
        role not in ROLE_SKILLS
        or workspace != expected_workspace
        or os.environ.get("AGENTTEAMS_WORKER_NAME") != role
        or os.environ.get("HOME") != workspace
        or not workspace_exact
        or workspace_path.is_symlink()
        or Path.cwd().resolve() != workspace_path
        or not skills_exact
        or not skills_root.is_dir()
        or skills_root.is_symlink()
    ):
        raise SystemExit(3)

    prefix = _validate_storage_prefix(os.environ.get("AGENTTEAMS_STORAGE_PREFIX", ""))
    access_key, secret_key = _initialize_mc_client(prefix, config_directory)
    _validate_sync_contract(workspace_path)
    state = _state(workspace, role, release)
    if action == "prepare":
        _probe_local_filesystem(workspace_path)
        prepared_state = _state(workspace, role, release)
        if (
            prepared_state["local"]["digest"] != state["local"]["digest"]
            or prepared_state["remoteSnapshot"] != state["remoteSnapshot"]
        ):
            raise RoleSkillError("role Skill state changed during filesystem preparation")
        state = prepared_state
    if action == "apply":
        if (
            DIGEST.fullmatch(expected_local) is None
            or DIGEST.fullmatch(expected_remote) is None
            or state["local"]["digest"] != expected_local
            or state["remoteSnapshot"] != expected_remote
        ):
            raise RoleSkillError("role Skill state changed after all-Pod preflight")
        archive_data = sys.stdin.buffer.read(MAX_ARCHIVE_BYTES + 1)
        release_files = _load_release_archive(archive_data, release, role)
        initial_local = state["local"]
        initial_remote = state["remote"]
        with _sync_marker_lease(workspace_path) as (
            lease_identity,
            lease_mtime_ns,
        ):
            _recover_remote_transactions(state["prefix"], role, release)
            recovered = _state(workspace, role, release)
            if recovered["local"]["digest"] != initial_local["digest"]:
                raise RoleSkillError("local Skill state changed during transaction recovery")
            _verify_outside_plan_preserved(
                initial_remote,
                recovered["remote"],
                set(state["allowed"]),
            )
            state = recovered
            before_local = state["local"]
            before_remote = state["remote"]
            time.sleep(SYNC_SETTLE_SECONDS)
            _verify_sync_marker_lease(workspace_path, lease_identity, lease_mtime_ns)
            settled = _state(workspace, role, release)
            if (
                settled["local"]["digest"] != before_local["digest"]
                or settled["remoteSnapshot"] != state["remoteSnapshot"]
            ):
                raise RoleSkillError("worker sync did not quiesce before convergence")
            state = settled
            before_local = state["local"]
            before_remote = state["remote"]

            removed_local, refreshed_local_added, refreshed_local_modified = _apply_local_plan(
                skills_root,
                role,
                state,
                release_files,
                release,
            )
            _verify_sync_marker_lease(workspace_path, lease_identity, lease_mtime_ns)
            remote_before_write = _audit_remote_skills(state["prefix"], role)
            planned_mutable = (
                set(state["remoteRemove"])
                | set(state["remoteSync"])
                | set(state["localRemove"])
                | set(state["localRefresh"])
            )
            _verify_outside_plan_preserved(
                before_remote,
                remote_before_write,
                planned_mutable,
            )
            remote_mutable = _apply_remote_plan(
                state["prefix"],
                role,
                state,
                release_files,
                release,
            )
            _verify_sync_marker_lease(workspace_path, lease_identity, lease_mtime_ns)

        state = _state(workspace, role, release)
        _verify_preserved(
            before_local,
            state["local"],
            removed=removed_local,
            added=refreshed_local_added,
            modified=refreshed_local_modified,
        )
        _verify_outside_plan_preserved(
            before_remote,
            state["remote"],
            remote_mutable,
        )
        if (
            state["needsApply"]
            or tuple(state["local"]["known"]) != tuple(state["allowed"])
            or tuple(state["remote"]["known"]) != tuple(state["allowed"])
        ):
            raise RoleSkillError("post-apply role Skill verification failed")
        time.sleep(SYNC_SETTLE_SECONDS)
        stable_state = _state(workspace, role, release)
        if (
            stable_state["local"]["digest"] != state["local"]["digest"]
            or stable_state["remoteSnapshot"] != state["remoteSnapshot"]
            or stable_state["needsApply"]
        ):
            raise RoleSkillError("post-apply role Skill state did not remain stable")
        state = stable_state
        _validate_runtime_trust(workspace, role)
    _validate_mc_binary()
    _validate_mc_alias(prefix, access_key, secret_key)
    print(
        json.dumps(
            _summary_from_state(state, role, applied=action == "apply"),
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _remote_main() -> None:
    value = globals().get("_DEVFLOW_REMOTE_PARAMETERS")
    if not isinstance(value, list) or len(value) != 6 or any(
        not isinstance(item, str) for item in value
    ):
        raise SystemExit(2)
    arguments = [item for item in value if isinstance(item, str)]
    with (
        tempfile.TemporaryDirectory(prefix="devflow-role-skill-mc-") as temporary,
        _remote_helper_deadline(),
    ):
        _remote_main_configured(Path(temporary), arguments)


REMOTE_HELPER = "\n\n".join(
    [
        "from __future__ import annotations",
        (
            "import ctypes\nimport errno\nimport hashlib\nimport importlib\nimport io\nimport json\nimport os\nimport re\n"
            "import signal\nimport stat\nimport subprocess\nimport sys\nimport tempfile\nimport threading\n"
            "import time\nimport zipfile\n"
            "from collections.abc import Iterator\n"
            "from contextlib import contextmanager, suppress\n"
            "from pathlib import Path, "
            "PurePosixPath\nfrom typing import Any"
        ),
        f"ROLE_SKILLS = {ROLE_SKILLS!r}",
        f"RELEASE_ARCHIVE_DIGESTS = {RELEASE_ARCHIVE_DIGESTS!r}",
        f"ALL_DEVFLOW_SKILLS = frozenset({sorted(ALL_DEVFLOW_SKILLS)!r})",
        f"EXPECTED_SKILL_FILES = {EXPECTED_SKILL_FILES!r}",
        f"EXPECTED_PACKAGE_FILES = {EXPECTED_PACKAGE_FILES!r}",
        f"PACKAGE_MANIFEST_FIELDS = frozenset({sorted(PACKAGE_MANIFEST_FIELDS)!r})",
        f"PACKAGE_VERSION = {PACKAGE_VERSION!r}",
        f"MAX_ARCHIVE_BYTES = {MAX_ARCHIVE_BYTES!r}",
        f"MAX_SOURCE_FILE_BYTES = {MAX_SOURCE_FILE_BYTES!r}",
        f"SAFE_COMPONENT = re.compile({SAFE_COMPONENT.pattern!r})",
        f"MC_ENTRY_FIELDS = frozenset({sorted(MC_ENTRY_FIELDS)!r})",
        f"MAX_LOCAL_ENTRIES = {MAX_LOCAL_ENTRIES!r}",
        f"MAX_LOCAL_FILE_BYTES = {MAX_LOCAL_FILE_BYTES!r}",
        f"MAX_LOCAL_TOTAL_BYTES = {MAX_LOCAL_TOTAL_BYTES!r}",
        f"MAX_MOUNTINFO_BYTES = {MAX_MOUNTINFO_BYTES!r}",
        f"MAX_REMOTE_OBJECTS = {MAX_REMOTE_OBJECTS!r}",
        f"MAX_REMOTE_TOTAL_BYTES = {MAX_REMOTE_TOTAL_BYTES!r}",
        f"MAX_MC_OUTPUT_BYTES = {MAX_MC_OUTPUT_BYTES!r}",
        f"MAX_REMOTE_FRAME_BYTES = {MAX_REMOTE_FRAME_BYTES!r}",
        f"REMOTE_READ_TIMEOUT_SECONDS = {REMOTE_READ_TIMEOUT_SECONDS!r}",
        f"REMOTE_COMMAND_TIMEOUT_SECONDS = {REMOTE_COMMAND_TIMEOUT_SECONDS!r}",
        f"APPLY_HELPER_MAX_SECONDS = {APPLY_HELPER_MAX_SECONDS!r}",
        f"MC_BINARY_PATH = {MC_BINARY_PATH!r}",
        f"MC_BINARY_SHA256 = {MC_BINARY_SHA256!r}",
        f"MC_BINARY_VERSION = {MC_BINARY_VERSION!r}",
        f"MC_ENDPOINT = {MC_ENDPOINT!r}",
        f"MC_ALIAS = {MC_ALIAS!r}",
        f"MC_STORAGE_PREFIX = {MC_STORAGE_PREFIX!r}",
        f"MC_CONFIG_VERSION = {MC_CONFIG_VERSION!r}",
        f"MC_API = {MC_API!r}",
        f"MC_PATH = {MC_PATH!r}",
        "MC_CONFIG_DIRECTORY: str | None = None",
        f"REMOTE_TRANSACTION_DIRECTORY = {REMOTE_TRANSACTION_DIRECTORY!r}",
        f"REMOTE_TRANSACTION_SCHEMA_VERSION = {REMOTE_TRANSACTION_SCHEMA_VERSION!r}",
        f"REMOTE_TRANSACTION_PHASES = frozenset({sorted(REMOTE_TRANSACTION_PHASES)!r})",
        f"REMOTE_TRANSACTION_FIELDS = frozenset({sorted(REMOTE_TRANSACTION_FIELDS)!r})",
        (
            "REMOTE_TRANSACTION_TREE_FIELDS = "
            f"frozenset({sorted(REMOTE_TRANSACTION_TREE_FIELDS)!r})"
        ),
        (
            "REMOTE_TRANSACTION_FILE_FIELDS = "
            f"frozenset({sorted(REMOTE_TRANSACTION_FILE_FIELDS)!r})"
        ),
        f"MAX_TRANSACTION_MANIFEST_BYTES = {MAX_TRANSACTION_MANIFEST_BYTES!r}",
        f"WORKER_ENTRYPOINT_PATH = {WORKER_ENTRYPOINT_PATH!r}",
        f"WORKER_ENTRYPOINT_SHA256 = {WORKER_ENTRYPOINT_SHA256!r}",
        f"SYNC_SETTLE_SECONDS = {SYNC_SETTLE_SECONDS!r}",
        f"SYNC_LEASE_SECONDS = {SYNC_LEASE_SECONDS!r}",
        f"SECRET_PATTERNS = {SECRET_PATTERNS!r}",
        f"HIGH_ENTROPY_TOKEN = {HIGH_ENTROPY_TOKEN!r}",
        f"DIGEST = re.compile({DIGEST.pattern!r})",
        f"LEADER_ROLE = {LEADER_ROLE!r}",
        f"TEAM_NAME = {TEAM_NAME!r}",
        f"TEAMHARNESS_MANIFEST_PATH = {TEAMHARNESS_MANIFEST_PATH!r}",
        f"TEAMHARNESS_CORE_ARTIFACTS = {TEAMHARNESS_CORE_ARTIFACTS!r}",
        f"TEAMHARNESS_LEADER_ARTIFACTS = {TEAMHARNESS_LEADER_ARTIFACTS!r}",
        f"TEAMHARNESS_POLICY_FIELDS = frozenset({sorted(TEAMHARNESS_POLICY_FIELDS)!r})",
        f"RUNTIME_BINDING_FIELDS = frozenset({sorted(RUNTIME_BINDING_FIELDS)!r})",
        (f"TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH = {TEAMHARNESS_APPROVAL_PUBLIC_KEY_PATH!r}"),
        f"TEAMHARNESS_APPROVAL_POLICY_PATH = {TEAMHARNESS_APPROVAL_POLICY_PATH!r}",
        f"TEAMHARNESS_APPROVAL_LEDGER_PATH = {TEAMHARNESS_APPROVAL_LEDGER_PATH!r}",
        f"TEAMHARNESS_OPENSSL_PATH = {TEAMHARNESS_OPENSSL_PATH!r}",
        f"TEAMHARNESS_SHARED_DIR = {TEAMHARNESS_SHARED_DIR!r}",
        inspect.getsource(PolicyError),
        inspect.getsource(_sha256_file),
        inspect.getsource(_trusted_fixed_file),
        inspect.getsource(_trusted_fixed_directory),
        inspect.getsource(_read_strict_json),
        inspect.getsource(_validate_runtime_attestation),
        inspect.getsource(_validate_runtime_trust),
        inspect.getsource(RoleSkillError),
        inspect.getsource(_remote_helper_deadline),
        inspect.getsource(_strict_json_object),
        inspect.getsource(_reject_json_constant),
        inspect.getsource(_canonical_digest),
        inspect.getsource(_release_spec_digest),
        inspect.getsource(_parse_release_spec),
        inspect.getsource(_safe_component),
        inspect.getsource(_change_time_ns),
        inspect.getsource(_stat_identity),
        inspect.getsource(_canonical_directory),
        inspect.getsource(_validate_mountinfo),
        inspect.getsource(_reject_nested_mounts),
        inspect.getsource(_secret_shaped),
        inspect.getsource(_read_regular_file),
        inspect.getsource(_snapshot_local_once),
        inspect.getsource(_audit_local_skills),
        inspect.getsource(_validate_remote_key),
        inspect.getsource(_parse_remote_listing),
        inspect.getsource(_validate_storage_prefix),
        inspect.getsource(_stop_process),
        inspect.getsource(_run_bounded_process),
        inspect.getsource(_mc_command),
        inspect.getsource(_validate_mc_binary),
        inspect.getsource(_validate_mc_alias),
        inspect.getsource(_write_isolated_mc_config),
        inspect.getsource(_initialize_mc_client),
        inspect.getsource(_mc_listing),
        inspect.getsource(_audit_remote_skills),
        inspect.getsource(_read_remote_object),
        inspect.getsource(_remote_transaction_root),
        inspect.getsource(_mc_transaction_listing),
        inspect.getsource(_parse_transaction_listing),
        inspect.getsource(_audit_remote_transaction),
        inspect.getsource(_audit_remote_transactions),
        inspect.getsource(_remote_skill_matches_release),
        inspect.getsource(_expected_skill_directories),
        inspect.getsource(_local_skill_matches_release),
        inspect.getsource(_state),
        inspect.getsource(_run_quiet),
        inspect.getsource(_remove_remote_skill),
        inspect.getsource(_load_release_archive),
        inspect.getsource(_transaction_file_map),
        inspect.getsource(_transaction_tree),
        inspect.getsource(_transaction_manifest_bytes),
        inspect.getsource(_parse_transaction_manifest),
        inspect.getsource(_write_remote_object),
        inspect.getsource(_copy_remote_object),
        inspect.getsource(_remote_target_root),
        inspect.getsource(_remove_allowed_remote_target),
        inspect.getsource(_transaction_object_path),
        inspect.getsource(_put_transaction_manifest),
        inspect.getsource(_read_transaction_manifest),
        inspect.getsource(_verify_transaction_tree),
        inspect.getsource(_remote_target_tree),
        inspect.getsource(_verify_remote_target_tree),
        inspect.getsource(_remove_transaction_tree),
        inspect.getsource(_cleanup_remote_transaction),
        inspect.getsource(_copy_transaction_tree_to_target),
        inspect.getsource(_restore_remote_transaction),
        inspect.getsource(_recover_remote_transaction),
        inspect.getsource(_recover_remote_transactions),
        inspect.getsource(_replace_remote_skill),
        inspect.getsource(_remove_local_tree),
        inspect.getsource(_remove_local_skill),
        inspect.getsource(_fsync_directory),
        inspect.getsource(_sync_file_identity),
        inspect.getsource(_validate_sync_contract),
        inspect.getsource(_flock_marker),
        inspect.getsource(_acquire_sync_marker_lease),
        inspect.getsource(_release_sync_marker_lease),
        inspect.getsource(_sync_marker_lease),
        inspect.getsource(_verify_sync_marker_lease),
        inspect.getsource(_set_directory_mode),
        inspect.getsource(_rename_exchange),
        inspect.getsource(_rename_noreplace),
        inspect.getsource(_probe_local_filesystem),
        inspect.getsource(_replace_local_skill),
        inspect.getsource(_verify_preserved),
        inspect.getsource(_verify_outside_plan_preserved),
        inspect.getsource(_apply_local_plan),
        inspect.getsource(_apply_remote_plan),
        inspect.getsource(_summary_from_state),
        inspect.getsource(_remote_main_configured),
        inspect.getsource(_remote_main),
        "_remote_main()",
    ]
)

REMOTE_STDIN_BOOTSTRAP = f'''import io
import json
import sys

raw = sys.stdin.buffer.read({MAX_REMOTE_FRAME_BYTES + 1})
if len(raw) < 12 or len(raw) > {MAX_REMOTE_FRAME_BYTES}:
    raise SystemExit(97)
source_size = int.from_bytes(raw[:4], "big")
parameter_size = int.from_bytes(raw[4:8], "big")
payload_size = int.from_bytes(raw[8:12], "big")
if not 1 <= source_size <= {MAX_REMOTE_HELPER_SOURCE_BYTES}:
    raise SystemExit(97)
if not 2 <= parameter_size <= {MAX_REMOTE_PARAMETERS_BYTES}:
    raise SystemExit(97)
if not 0 <= payload_size <= {MAX_ARCHIVE_BYTES}:
    raise SystemExit(97)
if len(raw) != 12 + source_size + parameter_size + payload_size:
    raise SystemExit(97)
source_end = 12 + source_size
parameter_end = source_end + parameter_size
try:
    source = raw[12:source_end].decode("utf-8")
    parameters = json.loads(raw[source_end:parameter_end].decode("utf-8"))
except (UnicodeError, json.JSONDecodeError):
    raise SystemExit(97) from None
if not isinstance(parameters, list) or len(parameters) != 6:
    raise SystemExit(97)
if any(not isinstance(item, str) or "\\x00" in item for item in parameters):
    raise SystemExit(97)
sys.stdin = io.TextIOWrapper(io.BytesIO(raw[parameter_end:]), encoding="utf-8")
namespace = {{
    "__name__": "__main__",
    "__file__": "<devflow-role-skill-helper>",
    "_DEVFLOW_REMOTE_PARAMETERS": parameters,
}}
exec(compile(source, "<devflow-role-skill-helper>", "exec"), namespace)
'''.strip()


def _remote_frame(
    helper: str,
    parameters: list[str],
    payload: bytes | None,
) -> bytes:
    try:
        source = helper.encode("utf-8")
        parameter_data = json.dumps(
            parameters,
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, UnicodeError) as exc:
        raise RoleSkillError("remote helper frame is malformed") from exc
    payload_data = payload or b""
    if (
        not 1 <= len(source) <= MAX_REMOTE_HELPER_SOURCE_BYTES
        or len(parameters) != 6
        or any(not isinstance(item, str) or "\x00" in item for item in parameters)
        or not 2 <= len(parameter_data) <= MAX_REMOTE_PARAMETERS_BYTES
        or len(payload_data) > MAX_ARCHIVE_BYTES
    ):
        raise RoleSkillError("remote helper frame is outside policy")
    frame = (
        len(source).to_bytes(4, "big")
        + len(parameter_data).to_bytes(4, "big")
        + len(payload_data).to_bytes(4, "big")
        + source
        + parameter_data
        + payload_data
    )
    if len(frame) > MAX_REMOTE_FRAME_BYTES:
        raise RoleSkillError("remote helper frame exceeds its byte limit")
    return frame


class Runner(Protocol):
    def run(self, args: list[str], input_data: bytes | None = None) -> str: ...


class SubprocessRunner:
    """Run without a shell and suppress potentially sensitive failure output."""

    def run(self, args: list[str], input_data: bytes | None = None) -> str:
        output = _run_bounded_process(
            args,
            max_output_bytes=MAX_HOST_OUTPUT_BYTES,
            timeout_seconds=HOST_COMMAND_TIMEOUT_SECONDS,
            label="role Skill command",
            input_data=input_data,
        )
        try:
            return output.decode("utf-8")
        except UnicodeError as exc:
            raise RoleSkillError("role Skill command returned invalid text") from exc


@dataclass(frozen=True)
class Report:
    target: Target
    allowed: tuple[str, ...]
    local_known: tuple[str, ...]
    remote_known: tuple[str, ...]
    local_remove: tuple[str, ...]
    remote_remove: tuple[str, ...]
    local_refresh: tuple[str, ...]
    remote_sync: tuple[str, ...]
    local_snapshot: str
    remote_snapshot: str
    needs_apply: bool
    applied: bool

    @property
    def snapshot(self) -> tuple[Any, ...]:
        return (
            self.allowed,
            self.local_known,
            self.remote_known,
            self.local_remove,
            self.remote_remove,
            self.local_refresh,
            self.remote_sync,
            self.local_snapshot,
            self.remote_snapshot,
            self.needs_apply,
        )


@dataclass(frozen=True)
class ReconcileResult:
    reports: tuple[Report, ...]
    changed_roles: tuple[str, ...]


def _kubectl(kubectl: str, *args: str) -> list[str]:
    return [kubectl, "--namespace", NAMESPACE, *args]


def _exec_helper(
    kubectl: str,
    target: Target,
) -> list[str]:
    command = _kubectl(
        kubectl,
        "exec",
        "--stdin",
        target.pod_name,
        "--container",
        CONTAINER_NAME,
        "--",
        "python3",
        "-c",
        REMOTE_STDIN_BOOTSTRAP,
    )
    encoded = [item.encode("utf-8") for item in command]
    if (
        any(len(item) > MAX_KUBECTL_ARGUMENT_BYTES for item in encoded)
        or sum(len(item) + 1 for item in encoded) > MAX_KUBECTL_ARGV_BYTES
    ):
        raise RoleSkillError("role Skill kubectl argv exceeds its byte limit")
    return command


def _helper_parameters(
    target: Target,
    release: RoleRelease,
    action: str,
    expected_local: str = "-",
    expected_remote: str = "-",
) -> list[str]:
    if action not in {"check", "prepare", "apply"}:
        raise RoleSkillError("remote helper action is outside policy")
    return [
        release.spec_json,
        action,
        target.role_name,
        target.workspace,
        expected_local,
        expected_remote,
    ]


def _name_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(name, str) or name not in ALL_DEVFLOW_SKILLS for name in value
    ):
        raise RoleSkillError(f"remote helper returned invalid {label}")
    if value != sorted(set(value)):
        raise RoleSkillError(f"remote helper returned invalid {label}")
    return tuple(value)


def _parse_report(text: str, target: Target, *, applied: bool) -> Report:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RoleSkillError("remote helper returned malformed JSON") from exc
    if not isinstance(value, dict) or set(value) != SUMMARY_FIELDS:
        raise RoleSkillError("remote helper returned an unexpected summary")
    if value.get("ok") is not True or value.get("role") != target.role_name:
        raise RoleSkillError("remote helper summary identity mismatch")
    if value.get("applied") is not applied or not isinstance(value.get("needsApply"), bool):
        raise RoleSkillError("remote helper summary state mismatch")
    allowed = _name_list(value.get("allowedSkills"), "allowed Skill names")
    local_known = _name_list(value.get("localKnownSkills"), "local Skill names")
    remote_known = _name_list(value.get("remoteKnownSkills"), "remote Skill names")
    local_remove = _name_list(value.get("localRemove"), "local removals")
    remote_remove = _name_list(value.get("remoteRemove"), "remote removals")
    local_refresh = _name_list(value.get("localRefresh"), "local refresh names")
    remote_sync = _name_list(value.get("remoteSync"), "remote sync names")
    expected_allowed = tuple(sorted(ROLE_SKILLS[target.role_name]))
    if (
        allowed != expected_allowed
        or local_remove != tuple(sorted(set(local_known) - set(allowed)))
        or remote_remove != tuple(sorted(set(remote_known) - set(allowed)))
        or not set(local_refresh) <= set(allowed)
        or not set(remote_sync) <= set(allowed)
        or not (set(allowed) - set(local_known)) <= set(local_refresh)
        or not (set(allowed) - set(remote_known)) <= set(remote_sync)
        or value.get("needsApply")
        is not bool(local_remove or remote_remove or local_refresh or remote_sync)
        or isinstance(value.get("localCount"), bool)
        or value.get("localCount") != len(local_known)
        or isinstance(value.get("remoteCount"), bool)
        or value.get("remoteCount") != len(remote_known)
    ):
        raise RoleSkillError("remote helper summary violates role policy")
    local_snapshot = value.get("localSnapshot")
    remote_snapshot = value.get("remoteSnapshot")
    if (
        not isinstance(local_snapshot, str)
        or DIGEST.fullmatch(local_snapshot) is None
        or not isinstance(remote_snapshot, str)
        or DIGEST.fullmatch(remote_snapshot) is None
    ):
        raise RoleSkillError("remote helper returned an invalid snapshot digest")
    return Report(
        target=target,
        allowed=allowed,
        local_known=local_known,
        remote_known=remote_known,
        local_remove=local_remove,
        remote_remove=remote_remove,
        local_refresh=local_refresh,
        remote_sync=remote_sync,
        local_snapshot=local_snapshot,
        remote_snapshot=remote_snapshot,
        needs_apply=value["needsApply"],
        applied=value["applied"],
    )


def _discover(runner: Runner, kubectl: str) -> list[Target]:
    runner.run([kubectl, "version", "--request-timeout=10s"])
    team_text = runner.run(_kubectl(kubectl, "get", "team", TEAM_NAME, "--output", "json"))
    pods_text = runner.run(
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
    try:
        team = json.loads(
            team_text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        pods = json.loads(
            pods_text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise RoleSkillError("Kubernetes discovery returned malformed JSON") from exc
    if not isinstance(team, dict) or not isinstance(pods, dict):
        raise RoleSkillError("Kubernetes discovery documents must be objects")
    return discover_targets(team, pods)


def _check_all(
    runner: Runner,
    kubectl: str,
    targets: list[Target],
    releases: dict[str, RoleRelease],
) -> list[Report]:
    return [
        _parse_report(
            runner.run(
                _exec_helper(kubectl, target),
                _remote_frame(
                    REMOTE_HELPER,
                    _helper_parameters(target, releases[target.role_name], "check"),
                    None,
                ),
            ),
            target,
            applied=False,
        )
        for target in targets
    ]


def _prepare_all(
    runner: Runner,
    kubectl: str,
    targets: list[Target],
    releases: dict[str, RoleRelease],
) -> list[Report]:
    return [
        _parse_report(
            runner.run(
                _exec_helper(kubectl, target),
                _remote_frame(
                    REMOTE_HELPER,
                    _helper_parameters(target, releases[target.role_name], "prepare"),
                    None,
                ),
            ),
            target,
            applied=False,
        )
        for target in targets
    ]


def reconcile(
    runner: Runner,
    *,
    releases: dict[str, RoleRelease],
    kubectl: str = "kubectl",
    apply: bool = False,
) -> ReconcileResult:
    """Preflight every Pod, then optionally execute the digest-gated fixed plan."""

    _validate_role_releases(releases)
    targets = _discover(runner, kubectl)
    preflight = _check_all(runner, kubectl, targets, releases)
    changed_roles = tuple(report.target.role_name for report in preflight if report.needs_apply)
    if not apply or not changed_roles:
        return ReconcileResult(tuple(preflight), ())

    barrier = _check_all(runner, kubectl, targets, releases)
    if any(
        first.snapshot != second.snapshot for first, second in zip(preflight, barrier, strict=True)
    ):
        raise RoleSkillError("role Skill state changed during the all-Pod apply barrier")
    prepared = _prepare_all(runner, kubectl, targets, releases)
    if any(
        before.snapshot != after.snapshot for before, after in zip(barrier, prepared, strict=True)
    ):
        raise RoleSkillError("role Skill state changed during all-Pod filesystem preparation")

    applied_reports: dict[str, Report] = {}
    for report in prepared:
        if not report.needs_apply:
            continue
        applied_report = _parse_report(
            runner.run(
                _exec_helper(kubectl, report.target),
                _remote_frame(
                    REMOTE_HELPER,
                    _helper_parameters(
                        report.target,
                        releases[report.target.role_name],
                        "apply",
                        report.local_snapshot,
                        report.remote_snapshot,
                    ),
                    releases[report.target.role_name].archive,
                ),
            ),
            report.target,
            applied=True,
        )
        if (
            applied_report.needs_apply
            or applied_report.local_known != applied_report.allowed
            or applied_report.remote_known != applied_report.allowed
        ):
            raise RoleSkillError("post-apply role Skill verification failed")
        applied_reports[report.target.role_name] = applied_report

    final = _check_all(runner, kubectl, targets, releases)
    prepared_by_role = {report.target.role_name: report for report in prepared}
    for report in final:
        if (
            report.needs_apply
            or report.local_known != report.allowed
            or report.remote_known != report.allowed
        ):
            raise RoleSkillError("final all-Pod role Skill readback failed")
        prior = applied_reports.get(
            report.target.role_name,
            prepared_by_role[report.target.role_name],
        )
        if report.snapshot != prior.snapshot:
            raise RoleSkillError("role Skill state changed before final all-Pod readback")
    return ReconcileResult(tuple(final), tuple(sorted(applied_reports)))


@dataclass(frozen=True)
class AuthorityReconcileResult:
    worker: ReconcileResult
    controller: ControllerReconcileResult
    changed_roles: tuple[str, ...]
    controller_changed_roles: tuple[str, ...]
    worker_changed_roles: tuple[str, ...]


def _worker_drift_roles(result: ReconcileResult) -> tuple[str, ...]:
    return tuple(sorted(report.target.role_name for report in result.reports if report.needs_apply))


def _require_worker_converged(result: ReconcileResult) -> None:
    if any(
        report.needs_apply
        or report.local_known != report.allowed
        or report.remote_known != report.allowed
        for report in result.reports
    ):
        raise RoleSkillError("three-surface worker readback did not converge")


def reconcile_all_authorities(
    runner: Runner,
    *,
    releases: dict[str, RoleRelease],
    kubectl: str = "kubectl",
    apply: bool = False,
) -> AuthorityReconcileResult:
    """Converge controller archive/cache, Worker local, and MinIO authority."""

    controller_target = discover_controller(runner, kubectl)
    controller = reconcile_controller_authority(
        runner,
        controller_target,
        releases,
        kubectl=kubectl,
        apply=apply,
    )
    worker = reconcile(
        runner,
        releases=releases,
        kubectl=kubectl,
        apply=apply,
    )
    worker_drift = worker.changed_roles if apply else _worker_drift_roles(worker)
    changed_roles = tuple(sorted(set(controller.changed_roles) | set(worker_drift)))
    if not apply or not changed_roles:
        return AuthorityReconcileResult(
            worker,
            controller,
            changed_roles,
            controller.changed_roles if apply else (),
            worker.changed_roles if apply else (),
        )

    if discover_controller(runner, kubectl) != controller_target:
        raise RoleSkillError("controller identity changed after worker convergence")

    time.sleep(CONTROLLER_RECONCILE_STABILITY_SECONDS)
    delayed_target = discover_controller(runner, kubectl)
    if delayed_target != controller_target:
        raise RoleSkillError("controller identity changed across the stability window")
    delayed_controller = reconcile_controller_authority(
        runner,
        delayed_target,
        releases,
        kubectl=kubectl,
        apply=False,
    )
    delayed_worker = reconcile(
        runner,
        releases=releases,
        kubectl=kubectl,
        apply=False,
    )
    if delayed_controller.changed_roles:
        raise RoleSkillError("controller authority drifted after its reconcile cycle")
    _require_worker_converged(delayed_worker)

    time.sleep(SYNC_SETTLE_SECONDS)
    stable_target = discover_controller(runner, kubectl)
    if stable_target != controller_target:
        raise RoleSkillError("controller identity changed during final double read")
    stable_controller = reconcile_controller_authority(
        runner,
        stable_target,
        releases,
        kubectl=kubectl,
        apply=False,
    )
    stable_worker = reconcile(
        runner,
        releases=releases,
        kubectl=kubectl,
        apply=False,
    )
    if stable_controller.changed_roles:
        raise RoleSkillError("controller authority failed the final double read")
    _require_worker_converged(stable_worker)
    if stable_controller.reports != delayed_controller.reports or tuple(
        report.snapshot for report in stable_worker.reports
    ) != tuple(report.snapshot for report in delayed_worker.reports):
        raise RoleSkillError("three-surface state changed during final double read")

    final_controller = ControllerReconcileResult(
        target=controller.target,
        reports=stable_controller.reports,
        changed_roles=stable_controller.changed_roles,
        transaction_id=controller.transaction_id,
    )
    final_worker = ReconcileResult(stable_worker.reports, worker.changed_roles)
    return AuthorityReconcileResult(
        final_worker,
        final_controller,
        changed_roles,
        controller.changed_roles,
        worker.changed_roles,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check or reconcile fixed role-scoped DevFlow Skills."
    )
    parser.add_argument("--apply", action="store_true", help="apply after two all-Pod checks")
    parser.add_argument("--kubectl", default="kubectl", help="kubectl executable")
    parser.add_argument(
        "--dist",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "dist",
        help=f"directory containing the immutable v{PACKAGE_VERSION} role archives",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        releases = load_role_releases(args.dist)
        result = reconcile_all_authorities(
            SubprocessRunner(),
            releases=releases,
            kubectl=args.kubectl,
            apply=args.apply,
        )
    except (
        ControllerCacheError,
        PolicyError,
        RoleSkillError,
        RuntimeError,
        OSError,
        UnicodeError,
        ValueError,
    ):
        print("error: role Skill reconciliation failed safely", file=sys.stderr)
        return 1
    controller_by_role = {report.role: report for report in result.controller.reports}
    summary = {
        "applied": args.apply,
        "changedRoles": list(result.changed_roles),
        "controller": {
            "imagePinned": True,
            "podPinned": True,
            "transactionRetained": result.controller.transaction_id is not None,
        },
        "namespace": NAMESPACE,
        "roles": [
            {
                "name": report.target.role_name,
                "allowedSkills": list(report.allowed),
                "controllerArchiveValid": controller_by_role[report.target.role_name].archive_valid,
                "controllerCacheKnownSkills": list(
                    controller_by_role[report.target.role_name].known_skills
                ),
                "controllerCacheChanged": (
                    report.target.role_name in result.controller_changed_roles
                ),
                "controllerCacheNeedsApply": (
                    report.target.role_name in result.controller.changed_roles
                ),
                "localKnownSkills": list(report.local_known),
                "remoteKnownSkills": list(report.remote_known),
                "localCount": len(report.local_known),
                "remoteCount": len(report.remote_known),
                "needsApply": report.needs_apply,
            }
            for report in result.worker.reports
        ],
        "team": TEAM_NAME,
        "devflowPolicyVerified": (
            not result.controller.changed_roles
            and all(not report.needs_apply for report in result.worker.reports)
        ),
        "completeRoleSkillBoundaryVerified": False,
        "verificationScope": "fixed-seven-devflow-skills",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

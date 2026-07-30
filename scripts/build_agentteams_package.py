"""Build deterministic, role-scoped AgentTeams Worker packages."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PACKAGE_VERSION = "2.1.0"
WORKER_BASE_IMAGE = (
    "higress-registry.cn-hangzhou.cr.aliyuncs.com/agentteams/"
    "agentteams-worker@sha256:"
    "0e91141495af352660b956de49e0581886ac11b38de7381e46e43424b030fdff"
)
ROLE_SKILLS: dict[str, tuple[str, ...]] = {
    "devflow-lead": (),
    "devflow-triage": ("issue-classifier",),
    "devflow-locator": ("code-root-cause", "github-evidence"),
    "devflow-coder": ("patch-generator",),
    "devflow-tester": ("test-runner",),
    "devflow-reviewer": ("pr-reviewer", "experience-distiller"),
}
ROLE_OWNERS = {
    "devflow-lead": "TeamLeader",
    "devflow-triage": "TriageAgent",
    "devflow-locator": "LocatorAgent",
    "devflow-coder": "CoderAgent",
    "devflow-tester": "TesterAgent",
    "devflow-reviewer": "ReviewerAgent",
}
TEMPLATE_FILES = frozenset(
    {
        "manifest.json",
        "config/AGENTS.md",
        "config/SOUL.md",
    }
)
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
EXCLUDED_PARTS = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"})
EXCLUDED_SUFFIXES = frozenset({".pyc", ".pyo"})
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
SECRET_PATTERNS = (
    re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(rb"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(rb"AKIA[0-9A-Z]{16}"),
    re.compile(rb"(?i)Bearer[ \t]+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(
        rb"(?i)(?:api[_-]?key|access[_-]?key|client[_-]?secret|password|token)"
        rb"[ \t]*[:=][ \t]*(?:['\"][A-Za-z0-9._~+/=-]{12,}['\"]|"
        rb"[A-Za-z0-9_+/=-]{24,})"
    ),
    re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
)
HIGH_ENTROPY_TOKEN = re.compile(rb"(?<![A-Za-z0-9])[A-Za-z0-9._-]{40,}(?![A-Za-z0-9])")
MANIFEST_FIELDS = frozenset(
    {"version", "role", "skills", "source", "worker", "files", "manifest_sha256"}
)
SOURCE_FIELDS = frozenset({"hostname", "os", "created_at"})
WORKER_FIELDS = frozenset(
    {
        "suggested_name",
        "model",
        "runtime",
        "base_image",
        "apt_packages",
        "pip_packages",
        "npm_packages",
    }
)


class PackageBuildError(ValueError):
    """The package source violates the deterministic release policy."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _expected_skill_files(skill: str) -> frozenset[str]:
    return COMMON_SKILL_FILES | SKILL_EXTRA_FILES.get(skill, frozenset())


def expected_payload_files(role: str) -> frozenset[str]:
    if role not in ROLE_SKILLS:
        raise PackageBuildError("unknown AgentTeams role")
    names = set(TEMPLATE_FILES - {"manifest.json"})
    for skill in ROLE_SKILLS[role]:
        names.update(f"skills/{skill}/{relative}" for relative in _expected_skill_files(skill))
    return frozenset(names)


def _is_reparse(metadata: os.stat_result) -> bool:
    return bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _change_time_ns(metadata: os.stat_result) -> int:
    # Python 3.14 exposes Windows creation time separately and changes
    # ``st_ctime_ns`` semantics between path-stat and an opened descriptor.
    # Birth time is the stable identity field there; POSIX keeps ctime.
    return int(getattr(metadata, "st_birthtime_ns", metadata.st_ctime_ns))


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        _change_time_ns(metadata),
    )


def trusted_directory(path: Path, label: str) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    try:
        metadata = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PackageBuildError(f"{label} is missing or unreadable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or candidate.is_symlink()
        or _is_reparse(metadata)
        or resolved != candidate
    ):
        raise PackageBuildError(f"{label} is a symlink, reparse point, or path alias")
    return candidate


def has_secret_shaped_content(data: bytes) -> bool:
    if any(pattern.search(data) for pattern in SECRET_PATTERNS):
        return True
    for match in HIGH_ENTROPY_TOKEN.finditer(data):
        token = match.group(0)
        if (
            any(65 <= byte <= 90 for byte in token)
            and any(97 <= byte <= 122 for byte in token)
            and any(48 <= byte <= 57 for byte in token)
            and len(set(token)) >= 10
        ):
            return True
    return False


def read_regular_file(
    path: Path,
    *,
    root: Path,
    label: str,
    max_bytes: int,
    scan_secrets: bool,
) -> bytes:
    trusted_root = trusted_directory(root, "trusted file root")
    candidate = path if path.is_absolute() else trusted_root / path
    try:
        candidate.relative_to(trusted_root)
    except ValueError as exc:
        raise PackageBuildError(f"{label} escapes its trusted root") from exc
    try:
        before = candidate.lstat()
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise PackageBuildError(f"{label} is missing or unreadable") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or candidate.is_symlink()
        or _is_reparse(before)
        or resolved != candidate
        or before.st_nlink > 1
        or before.st_size > max_bytes
    ):
        raise PackageBuildError(f"{label} is not one bounded canonical regular file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise PackageBuildError(f"{label} changed before it could be read")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            data = stream.read(max_bytes + 1)
        after = candidate.lstat()
        if (
            len(data) > max_bytes
            or len(data) != before.st_size
            or _identity(after) != _identity(before)
            or candidate.resolve(strict=True) != candidate
            or candidate.is_symlink()
            or _is_reparse(after)
        ):
            raise PackageBuildError(f"{label} changed while it was read")
    except OSError as exc:
        raise PackageBuildError(f"{label} cannot be read safely") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if scan_secrets and has_secret_shaped_content(data):
        raise PackageBuildError(f"secret-shaped content is forbidden: {label}")
    return data


def _walk_files(root: Path) -> set[str]:
    """Return regular files without ever following a link or junction."""
    root = trusted_directory(root, "package source")
    files: set[str] = set()
    pending = [root]
    while pending:
        directory = trusted_directory(pending.pop(), "package source directory")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as exc:
            raise PackageBuildError("package source cannot be enumerated") from exc
        for entry in entries:
            relative = Path(entry.path).relative_to(root).as_posix()
            try:
                metadata = entry.stat(follow_symlinks=False)
                mode = metadata.st_mode
            except OSError as exc:
                raise PackageBuildError("package source metadata cannot be read") from exc
            if entry.is_symlink() or stat.S_ISLNK(mode) or _is_reparse(metadata):
                raise PackageBuildError(f"links and reparse points are forbidden: {relative}")
            if stat.S_ISDIR(mode):
                if entry.name not in EXCLUDED_PARTS:
                    pending.append(Path(entry.path))
                continue
            if not stat.S_ISREG(mode):
                raise PackageBuildError(f"non-regular package entry is forbidden: {relative}")
            path = Path(entry.path)
            if (
                EXCLUDED_PARTS.intersection(Path(relative).parts)
                or path.suffix in EXCLUDED_SUFFIXES
            ):
                continue
            try:
                path_metadata = path.lstat()
            except OSError as exc:
                raise PackageBuildError("package source metadata cannot be read") from exc
            if path_metadata.st_nlink > 1:
                raise PackageBuildError(f"hard-linked package file is forbidden: {relative}")
            if path_metadata.st_size > MAX_SOURCE_FILE_BYTES:
                raise PackageBuildError(f"package source file is too large: {relative}")
            files.add(relative)
    return files


def _read_checked(path: Path, label: str, root: Path) -> bytes:
    return read_regular_file(
        path,
        root=root,
        label=label,
        max_bytes=MAX_SOURCE_FILE_BYTES,
        scan_secrets=True,
    )


def _top_level_scalar(data: bytes, key: str, label: str) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeError as exc:
        raise PackageBuildError(f"{label} is not UTF-8") from exc
    matches = re.findall(
        rf"^{re.escape(key)}:[ \t]*([^\r\n]+?)[ \t]*\r?$",
        text,
        re.MULTILINE,
    )
    if len(matches) != 1:
        raise PackageBuildError(f"{label} must declare exactly one top-level {key}")
    return str(matches[0]).strip().strip("'\"")


def _validate_skill_identity(skill: str, checked: dict[str, bytes], owner: str) -> None:
    contract_label = f"skills/{skill}/references/contract.yaml"
    contract = checked[contract_label]
    if (
        _top_level_scalar(contract, "name", contract_label) != skill
        or _top_level_scalar(contract, "owner", contract_label) != owner
    ):
        raise PackageBuildError(f"Skill {skill} contract owner or name is outside role policy")

    skill_label = f"skills/{skill}/SKILL.md"
    try:
        text = checked[skill_label].decode("utf-8")
    except UnicodeError as exc:
        raise PackageBuildError(f"Skill {skill} frontmatter is not UTF-8") from exc
    if not text.startswith("---\n"):
        raise PackageBuildError(f"Skill {skill} frontmatter is missing")
    parts = text.split("---\n", 2)
    if len(parts) != 3:
        raise PackageBuildError(f"Skill {skill} frontmatter is malformed")
    fields: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" not in line:
            raise PackageBuildError(f"Skill {skill} frontmatter is malformed")
        name, value = line.split(":", 1)
        if name in fields:
            raise PackageBuildError(f"Skill {skill} frontmatter contains a duplicate field")
        fields[name] = value.strip()
    if (
        set(fields) != {"name", "description"}
        or fields.get("name") != skill
        or "Use when" not in fields.get("description", "")
    ):
        raise PackageBuildError(f"Skill {skill} frontmatter is outside policy")


def _validate_sources(root: Path) -> tuple[Path, Path, dict[str, bytes]]:
    template = root / "agentteams" / "worker-package"
    skills_root = root / "skills"
    template_files = _walk_files(template)
    if template_files != TEMPLATE_FILES:
        raise PackageBuildError("worker package template has missing or unknown files")

    if set(ROLE_OWNERS) != set(ROLE_SKILLS):
        raise PackageBuildError("role owner policy is incomplete")
    assigned_skills = [skill for skills in ROLE_SKILLS.values() for skill in skills]
    expected_skills = set(assigned_skills)
    if len(assigned_skills) != len(expected_skills):
        raise PackageBuildError("a Skill is assigned to more than one role")
    skills_root = trusted_directory(skills_root, "skills source")
    try:
        entries = list(os.scandir(skills_root))
    except OSError as exc:
        raise PackageBuildError("skills source cannot be enumerated") from exc
    actual_skills: set[str] = set()
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise PackageBuildError("Skill source metadata cannot be read") from exc
        if entry.is_symlink() or _is_reparse(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise PackageBuildError("skills source contains a link, reparse point, or file")
        if entry.name not in EXCLUDED_PARTS:
            actual_skills.add(entry.name)
    if actual_skills != expected_skills:
        raise PackageBuildError("skills tree has missing or unknown Skill directories")

    checked: dict[str, bytes] = {}
    for relative in sorted(TEMPLATE_FILES):
        checked[f"template/{relative}"] = _read_checked(template / relative, relative, template)
    for skill in sorted(expected_skills):
        skill_root = skills_root / skill
        actual_files = _walk_files(skill_root)
        expected_files = _expected_skill_files(skill)
        if actual_files != expected_files:
            raise PackageBuildError(f"Skill {skill} has missing or unknown files")
        for relative in sorted(expected_files):
            label = f"skills/{skill}/{relative}"
            checked[label] = _read_checked(skill_root / relative, label, skill_root)
        role = next(role for role, skills in ROLE_SKILLS.items() if skill in skills)
        _validate_skill_identity(skill, checked, ROLE_OWNERS[role])

    if _walk_files(template) != template_files:
        raise PackageBuildError("worker package template changed during validation")
    for skill in sorted(expected_skills):
        if _walk_files(skills_root / skill) != _expected_skill_files(skill):
            raise PackageBuildError(f"Skill {skill} changed during validation")
    return template, skills_root, checked


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise PackageBuildError("JSON contains a duplicate field")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> object:
    raise PackageBuildError("JSON contains a non-standard scalar")


def decode_json_object(data: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(
            data,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PackageBuildError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise PackageBuildError(f"{label} must contain an object")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def manifest_digest(value: dict[str, object]) -> str:
    material = {key: item for key, item in value.items() if key != "manifest_sha256"}
    return _sha256(_canonical_json(material))


def _source_epoch(value: object) -> int:
    if not isinstance(value, str):
        raise PackageBuildError("worker package created_at is invalid")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        epoch = int(parsed.timestamp())
    except (OverflowError, ValueError) as exc:
        raise PackageBuildError("worker package created_at is invalid") from exc
    rendered = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if rendered != value or not 0 <= epoch <= 4_354_819_199:
        raise PackageBuildError("worker package created_at is outside policy")
    return epoch


def validate_role_manifest(
    value: dict[str, object],
    *,
    role: str,
    payload: dict[str, bytes],
) -> int:
    if role not in ROLE_SKILLS or set(value) != MANIFEST_FIELDS:
        raise PackageBuildError("worker package manifest schema is invalid")
    source = value.get("source")
    worker = value.get("worker")
    files = value.get("files")
    if (
        not isinstance(source, dict)
        or set(source) != SOURCE_FIELDS
        or not isinstance(worker, dict)
        or set(worker) != WORKER_FIELDS
        or not isinstance(files, dict)
    ):
        raise PackageBuildError("worker package manifest schema is invalid")
    expected_files = expected_payload_files(role)
    if (
        value.get("version") != PACKAGE_VERSION
        or value.get("role") != role
        or value.get("skills") != list(ROLE_SKILLS[role])
        or source.get("hostname") != "devflow-template"
        or source.get("os") != "portable"
        or worker.get("suggested_name") != role
        or worker.get("model") != "glm-5.2"
        or worker.get("runtime") != "openclaw"
        or worker.get("base_image") != WORKER_BASE_IMAGE
        or worker.get("apt_packages") != []
        or worker.get("pip_packages") != []
        or worker.get("npm_packages") != []
        or set(files) != expected_files
        or set(payload) != expected_files
    ):
        raise PackageBuildError("worker package role or payload is outside policy")
    for name, data in payload.items():
        digest = files.get(name)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PackageBuildError("worker package file digest is malformed")
        if _sha256(data) != digest:
            raise PackageBuildError("worker package file digest mismatch")
    declared_manifest_digest = value.get("manifest_sha256")
    if (
        not isinstance(declared_manifest_digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", declared_manifest_digest)
        or manifest_digest(value) != declared_manifest_digest
    ):
        raise PackageBuildError("worker package manifest digest mismatch")
    return _source_epoch(source.get("created_at"))


def _manifest(
    template_bytes: bytes,
    *,
    role: str,
    skills: tuple[str, ...],
    source_date_epoch: int,
    payload: dict[str, bytes],
) -> bytes:
    value = decode_json_object(template_bytes, "worker package manifest template")
    source = value.get("source")
    worker = value.get("worker")
    if (
        set(value) != MANIFEST_FIELDS
        or not isinstance(source, dict)
        or set(source) != SOURCE_FIELDS
        or not isinstance(worker, dict)
        or set(worker) != WORKER_FIELDS
        or value.get("version") != PACKAGE_VERSION
        or value.get("role") != "build-time-required"
        or value.get("skills") != []
        or value.get("files") != {}
        or value.get("manifest_sha256") != "build-time-required"
        or source.get("hostname") != "devflow-template"
        or source.get("os") != "portable"
        or worker.get("suggested_name") != "build-time-required"
        or worker.get("model") != "glm-5.2"
        or worker.get("runtime") != "openclaw"
        or worker.get("base_image") != WORKER_BASE_IMAGE
        or worker.get("apt_packages") != []
        or worker.get("pip_packages") != []
        or worker.get("npm_packages") != []
    ):
        raise PackageBuildError("worker package manifest schema is invalid")
    value["version"] = PACKAGE_VERSION
    value["role"] = role
    value["skills"] = list(skills)
    source["created_at"] = datetime.fromtimestamp(source_date_epoch, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    worker["suggested_name"] = role
    value["files"] = {name: _sha256(data) for name, data in sorted(payload.items())}
    value["manifest_sha256"] = manifest_digest(value)
    validate_role_manifest(value, role=role, payload=payload)
    return (json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def canonical_zip_bytes(files: dict[str, bytes], source_date_epoch: int) -> bytes:
    zip_time = time.gmtime(max(source_date_epoch, 315_532_800))[:6]
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        "w",
        # Stored entries make the archive independent of Python/zlib versions;
        # the complete six-role release is small enough for one ConfigMap.
        compression=zipfile.ZIP_STORED,
        strict_timestamps=True,
    ) as archive:
        archive.comment = b""
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=zip_time)
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.compress_type = zipfile.ZIP_STORED
            info.comment = b""
            info.extra = b""
            info.internal_attr = 0
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(
                info,
                data,
                compress_type=zipfile.ZIP_STORED,
            )
    return output.getvalue()


def _safe_output(path: Path, root: Path) -> Path:
    candidate = path if path.is_absolute() else Path.cwd() / path
    candidate.parent.mkdir(parents=True, exist_ok=True)
    parent = trusted_directory(candidate.parent, "package output directory")
    candidate = parent / candidate.name
    for protected in (root / "agentteams" / "worker-package", root / "skills"):
        try:
            candidate.relative_to(protected)
        except ValueError:
            continue
        raise PackageBuildError("package output cannot overwrite package sources")
    if candidate.exists() or candidate.is_symlink():
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise PackageBuildError("package output metadata cannot be read") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or candidate.is_symlink()
            or _is_reparse(metadata)
            or metadata.st_nlink > 1
            or candidate.resolve(strict=True) != candidate
        ):
            raise PackageBuildError("package output is not a canonical regular file")
    return candidate


def _atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        trusted_directory(path.parent, "package output directory")
        os.replace(temporary, path)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if directory_flag:
            directory_descriptor = os.open(path.parent, os.O_RDONLY | directory_flag)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except OSError as exc:
        raise PackageBuildError("package output cannot be committed atomically") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _package_bytes_from_checked(
    source_date_epoch: int,
    *,
    role: str,
    checked: dict[str, bytes],
) -> bytes:
    selected_skills = ROLE_SKILLS[role]
    payload: dict[str, bytes] = {
        relative: checked[f"template/{relative}"]
        for relative in sorted(TEMPLATE_FILES - {"manifest.json"})
    }
    for skill in selected_skills:
        for relative in sorted(_expected_skill_files(skill)):
            archive_name = f"skills/{skill}/{relative}"
            payload[archive_name] = checked[archive_name]
    archive_files = {
        **payload,
        "manifest.json": _manifest(
            checked["template/manifest.json"],
            role=role,
            skills=selected_skills,
            source_date_epoch=source_date_epoch,
            payload=payload,
        )
    }
    archive_data = canonical_zip_bytes(archive_files, source_date_epoch)
    if len(archive_data) > MAX_ARCHIVE_BYTES:
        raise PackageBuildError("role archive exceeds the release size limit")
    return archive_data


def _build_package_from_checked(
    root: Path,
    output: Path,
    source_date_epoch: int,
    *,
    role: str,
    checked: dict[str, bytes],
) -> str:
    output = _safe_output(output, root)
    archive_data = _package_bytes_from_checked(
        source_date_epoch,
        role=role,
        checked=checked,
    )
    digest = _sha256(archive_data)
    sidecar = _safe_output(output.with_suffix(output.suffix + ".sha256"), root)
    sidecar_data = f"{digest}  {output.name}\n".encode("ascii")
    _atomic_write(output, archive_data)
    _atomic_write(sidecar, sidecar_data)
    if (
        read_regular_file(
            output,
            root=output.parent,
            label="written role archive",
            max_bytes=MAX_ARCHIVE_BYTES,
            scan_secrets=False,
        )
        != archive_data
        or read_regular_file(
            sidecar,
            root=sidecar.parent,
            label="written archive digest",
            max_bytes=256,
            scan_secrets=False,
        )
        != sidecar_data
    ):
        raise PackageBuildError("role archive failed read-back verification")
    return digest


def build_role_package_bytes(
    root: Path,
    source_date_epoch: int,
) -> dict[str, bytes]:
    """Build one coherent in-memory release from a single trusted source snapshot."""
    if isinstance(source_date_epoch, bool) or not 0 <= source_date_epoch <= 4_354_819_199:
        raise PackageBuildError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    root = trusted_directory(root, "repository root")
    _template, _skills_root, checked = _validate_sources(root)
    return {
        role: _package_bytes_from_checked(
            source_date_epoch,
            role=role,
            checked=checked,
        )
        for role in ROLE_SKILLS
    }


def build_package(
    root: Path,
    output: Path,
    source_date_epoch: int,
    *,
    role: str,
) -> str:
    """Build one role package and return its archive SHA-256."""
    if role not in ROLE_SKILLS:
        raise PackageBuildError("unknown AgentTeams role")
    if isinstance(source_date_epoch, bool) or not 0 <= source_date_epoch <= 4_354_819_199:
        raise PackageBuildError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    root = trusted_directory(root, "repository root")
    _template, _skills_root, checked = _validate_sources(root)
    return _build_package_from_checked(
        root,
        output,
        source_date_epoch,
        role=role,
        checked=checked,
    )


def build_role_packages(root: Path, output_dir: Path, source_date_epoch: int) -> dict[str, str]:
    """Build the complete fixed Team release without a shared all-Skill archive."""
    if isinstance(source_date_epoch, bool) or not 0 <= source_date_epoch <= 4_354_819_199:
        raise PackageBuildError("SOURCE_DATE_EPOCH is outside the ZIP timestamp range")
    root = trusted_directory(root, "repository root")
    _template, _skills_root, checked = _validate_sources(root)
    results: dict[str, str] = {}
    for role in ROLE_SKILLS:
        name = f"{role}-v{PACKAGE_VERSION}.zip"
        results[role] = _build_package_from_checked(
            root,
            output_dir / name,
            source_date_epoch,
            role=role,
            checked=checked,
        )
    return results


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    source_date_epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    results = build_role_packages(root, root / "dist", source_date_epoch)
    print(json.dumps(results, sort_keys=True))


if __name__ == "__main__":
    main()

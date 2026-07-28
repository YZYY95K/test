#!/usr/bin/env python3
"""Build and verify the deterministic GOAI preliminary submission archive.

The production CLI has no dirty-tree, tag, content-scan, or path-policy bypass.
Tests may inject a Git client and a PDF text extractor through private keyword
arguments so the security policy can be exercised without weakening the CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

try:
    from scripts.build_agentteams_package import (
        canonical_zip_bytes,
        read_regular_file,
        trusted_directory,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from build_agentteams_package import (  # type: ignore[no-redef]
        canonical_zip_bytes,
        read_regular_file,
        trusted_directory,
    )

PROJECT = "DevFlow"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXED_SOURCE_DATE_EPOCH = 315_532_800  # 1980-01-01T00:00:00Z, the ZIP minimum.
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
CANONICAL_FILE_MODE = stat.S_IFREG | 0o644

SOURCE_ARCHIVE_NAME = "05_工程代码_DevFlow.zip"
SOURCE_MANIFEST_NAME = "SOURCE_MANIFEST.json"
SOURCE_SUMS_NAME = "SOURCE_SHA256SUMS.txt"
OUTER_MANIFEST_NAME = "MANIFEST.json"
OUTER_SUMS_NAME = "SHA256SUMS.txt"

MAX_SOURCE_ENTRIES = 2_000
MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 32 * 1024 * 1024
MAX_OUTER_ENTRIES = 32
MAX_OUTER_FILE_BYTES = 32 * 1024 * 1024
MAX_OUTER_TOTAL_BYTES = 96 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_OFFICE_ENTRIES = 2_000
MAX_OFFICE_MEMBER_BYTES = 32 * 1024 * 1024
MAX_OFFICE_TOTAL_BYTES = 128 * 1024 * 1024
MAX_OFFICE_COMPRESSION_RATIO = 500

SOURCE_ROOT_FILES = frozenset(
    {
        ".env.example",
        ".gitattributes",
        ".gitignore",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "NOTICE",
        "README.md",
        "SECURITY.md",
        "pyproject.toml",
    }
)

SOURCE_DOCUMENTS = frozenset(
    {
        "docs/AGENTTEAMS.md",
        "docs/BENCHMARK.md",
        "docs/BOUNDARIES_AND_MCP.md",
        "docs/HIGRESS_GITHUB_READONLY.md",
        "docs/INFRASTRUCTURE.md",
        "docs/RESEARCH.md",
        "docs/SCORECARD.md",
        "docs/SKILL_BEHAVIOR_EVAL.md",
        "docs/SKILL_ENGINEERING.md",
        "docs/evidence/AGENTTEAMS_BETA_COMPATIBILITY.md",
        "docs/evidence/AGENTTEAMS_LIVE_20260727.md",
        "docs/evidence/LOCAL_RELEASE_CANDIDATE_20260728.md",
        "docs/evidence/REPOSITORY_BOUNDARY_GLM52.md",
        "docs/evidence/SKILL_BEHAVIOR_GLM52.md",
        "docs/evidence/repository-boundary-glm52-v2.json",
        "docs/submission/PRELIM_PACKAGE_BUILD.md",
    }
)

SOURCE_RUNTIME_REQUIRED = frozenset(
    {
        "agentteams/package-server.yaml",
        "agentteams/team.yaml",
        "agentteams/worker-package/manifest.json",
        "config/agents.yaml",
        "scripts/build_agentteams_package.py",
        "scripts/build_prelim_submission.py",
        "scripts/reconcile_agentteams_controller_cache.py",
        "scripts/run_agentteams_github_success_path.py",
        "src/devflow/cli.py",
    }
)

SOURCE_REQUIRED_EXACT = SOURCE_ROOT_FILES | SOURCE_DOCUMENTS | SOURCE_RUNTIME_REQUIRED | frozenset(
    {
        ".github/workflows/ci.yml",
        "examples/prelim_sample/README.md",
        "examples/prelim_sample/actual_output.json",
        "examples/prelim_sample/expected_output.json",
        "examples/prelim_sample/sample_input.json",
    }
)

SOURCE_REQUIRED_PREFIXES = (
    "src/",
    "skills/",
    "config/",
    "agentteams/",
    "scripts/",
    "tests/",
    "evals/",
    "benchmarks/",
)

OUTER_INPUTS: tuple[tuple[str, str, str], ...] = (
    ("docs/submission/INTRO_500_CN.md", "01_作品简介_500字内.md", "text"),
    ("outputs/DevFlow_GOAI_2026_初赛方案_20260728.pdf", "02_方案_DevFlow.pdf", "pdf"),
    ("outputs/DevFlow_GOAI_2026_初赛方案_20260728.pptx", "02_方案_DevFlow.pptx", "pptx"),
    (
        "docs/submission/AGENT_IDENTITY_APPENDIX.md",
        "03_Agent_Identity附录.md",
        "text",
    ),
    (
        "docs/submission/PRELIM_PACKAGE_BUILD.md",
        "04_打包与复验说明.md",
        "text",
    ),
    (
        "docs/submission/LIVE_DEMO_SCRIPT_CN.md",
        "附录/现场演示脚本.md",
        "text",
    ),
    (
        "docs/submission/DEFENSE_QA_CN.md",
        "附录/答辩问题库.md",
        "text",
    ),
)

EXPECTED_OUTER_PAYLOAD = frozenset(target for _, target, _ in OUTER_INPUTS) | frozenset(
    {SOURCE_ARCHIVE_NAME}
)

MANIFEST_KEYS = frozenset({"project", "version", "commit", "tag", "path", "size", "sha256"})
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SAFE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$")

KNOWN_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.IGNORECASE)),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", re.IGNORECASE)),
    (
        "bearer-token",
        re.compile(r"\bBearer[ \t]+[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", re.IGNORECASE),
    ),
    (
        "url-userinfo",
        re.compile(r"\bhttps?://[^\s/:@]+:[^\s/@]+@", re.IGNORECASE),
    ),
    ("ssh-login", re.compile(r"\bssh[ \t]+[^\r\n@]{1,100}@[^\r\n ]+", re.IGNORECASE)),
)

SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"github[_-]?token|token|secret|password|passwd|private[_-]?key|密钥|密码|令牌)"
    r"[\"']?"
    r"[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9._~+/=-]{24,})"
)
SENSITIVE_HEX_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?"
    r"(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"github[_-]?token|token|secret|password|passwd|private[_-]?key)"
    r"[\"']?[ \t]*[:=][ \t]*[\"']?([0-9a-f]{32})(?![0-9a-f])"
)
CAPABILITY_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])[\"']?capability[\"']?[ \t]*[:=][ \t]*[\"']?"
    r"([A-Za-z0-9_-]{16,4096}\.[A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])"
)
MATRIX_ROOM_ID = re.compile(
    r"(?<![A-Za-z0-9])![A-Za-z0-9._=+/~-]{6,255}:[A-Za-z0-9.-]{1,255}"
    r"(?![A-Za-z0-9.-])"
)
IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![0-9A-Fa-f:])"
)
LOCAL_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)(?<![A-Za-z0-9_])[A-Z]:[\\/](?:Users|Documents and Settings)[\\/]"),
    re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home)/[^/\s]+/"),
    re.compile("(?i)file:" + "///"),
)

FORBIDDEN_PDF_MARKERS = (
    b"/JavaScript",
    b"/EmbeddedFile",
    b"/Launch",
    b"/OpenAction",
    b"/AcroForm",
)
FORBIDDEN_OFFICE_PREFIXES = (
    "ppt/embeddings/",
    "ppt/activeX/",
    "ppt/externalLinks/",
)


class SubmissionBuildError(RuntimeError):
    """Submission inputs or archive bytes violate release policy."""


@dataclass(frozen=True)
class RepositoryState:
    commit: str
    tag: str
    tracked_files: frozenset[str]


@dataclass(frozen=True)
class ManifestContext:
    project: str
    version: str
    commit: str
    tag: str


@dataclass(frozen=True)
class BuildResult:
    output: Path
    size: int
    sha256: str
    commit: str
    tag: str


class GitClient(Protocol):
    def status_porcelain(self, root: Path) -> bytes: ...

    def head_commit(self, root: Path) -> str: ...

    def tag_commit(self, root: Path, tag: str) -> str: ...

    def tracked_files(self, root: Path) -> frozenset[str]: ...


class PdfTextExtractor(Protocol):
    def extract(self, data: bytes) -> str: ...


class SubprocessGitClient:
    """Git metadata reader used by the production CLI."""

    @staticmethod
    def _run(root: Path, arguments: list[str]) -> bytes:
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=root,
                check=False,
                capture_output=True,
            )
        except OSError as exc:
            raise SubmissionBuildError("git could not be started") from exc
        if completed.returncode != 0:
            raise SubmissionBuildError("git metadata lookup failed")
        return completed.stdout

    def status_porcelain(self, root: Path) -> bytes:
        return self._run(root, ["status", "--porcelain=v1", "--untracked-files=all", "-z"])

    def head_commit(self, root: Path) -> str:
        return self._run(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()

    def tag_commit(self, root: Path, tag: str) -> str:
        reference = f"refs/tags/{tag}^{{commit}}"
        return self._run(root, ["rev-parse", "--verify", reference]).decode("ascii").strip()

    def tracked_files(self, root: Path) -> frozenset[str]:
        raw = self._run(root, ["ls-files", "-z"])
        try:
            names = [item.decode("utf-8") for item in raw.split(b"\0") if item]
        except UnicodeDecodeError as exc:
            raise SubmissionBuildError("tracked paths are not valid UTF-8") from exc
        return frozenset(names)


class PopplerPdfTextExtractor:
    """Fail-closed PDF text extraction without retaining a local copy."""

    def extract(self, data: bytes) -> str:
        with tempfile.TemporaryDirectory(prefix="devflow-prelim-pdf-") as directory:
            source = Path(directory) / "document.pdf"
            source.write_bytes(data)
            try:
                completed = subprocess.run(
                    ["pdftotext", str(source), "-"],
                    check=False,
                    capture_output=True,
                    timeout=60,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SubmissionBuildError("PDF text extraction is unavailable") from exc
        if completed.returncode != 0:
            raise SubmissionBuildError("PDF text extraction failed")
        try:
            return completed.stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SubmissionBuildError("PDF text extraction is not UTF-8") from exc


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _name_sort_key(value: str) -> bytes:
    return value.encode("utf-8")


def _validate_tag(tag: str) -> None:
    if (
        not SAFE_TAG.fullmatch(tag)
        or ".." in tag
        or "@{" in tag
        or "//" in tag
        or tag.endswith(("/", "."))
    ):
        raise SubmissionBuildError("release tag violates the safe tag policy")


def _validate_archive_names(names: Iterable[str]) -> tuple[str, ...]:
    values = tuple(names)
    exact: set[str] = set()
    normalized: set[str] = set()
    casefolded: set[str] = set()
    windows_reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
    for value in values:
        nfc = unicodedata.normalize("NFC", value)
        path = PurePosixPath(value)
        if (
            not value
            or value != nfc
            or value != path.as_posix()
            or value.startswith(("/", "\\"))
            or "\\" in value
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or any(":" in part or part.endswith((" ", ".")) for part in path.parts)
            or any(part.split(".", 1)[0].upper() in windows_reserved for part in path.parts)
        ):
            raise SubmissionBuildError("archive path violates the canonical relative-path policy")
        folded = nfc.casefold()
        if value in exact or nfc in normalized or folded in casefolded:
            raise SubmissionBuildError("duplicate, NFC-conflicting, or case-conflicting archive path")
        exact.add(value)
        normalized.add(nfc)
        casefolded.add(folded)
    return tuple(sorted(values, key=_name_sort_key))


def _source_allowed(name: str) -> bool:
    if name in SOURCE_ROOT_FILES or name in SOURCE_DOCUMENTS:
        return True
    parts = PurePosixPath(name).parts
    if parts == (".github", "workflows", "ci.yml"):
        return True
    if not parts:
        return False
    top = parts[0]
    suffix = PurePosixPath(name).suffix.lower()
    if top == "src":
        return len(parts) >= 3 and suffix in {".py", ".typed"}
    if top == "skills":
        return len(parts) >= 3 and suffix in {".md", ".py", ".yaml", ".yml", ".json"}
    if top == "config":
        return len(parts) >= 2 and suffix in {".yaml", ".yml", ".json", ".toml"}
    if top == "scripts":
        return len(parts) == 2 and suffix in {".py", ".sh"}
    if top == "examples":
        return len(parts) >= 2 and suffix in {".py", ".md", ".json", ".yaml", ".yml"}
    if top == "tests":
        return len(parts) == 2 and suffix in {".py", ".json", ".yaml", ".yml"}
    if top in {"evals", "benchmarks"}:
        return len(parts) >= 3 and suffix in {".yaml", ".yml", ".json"}
    if top != "agentteams" or len(parts) < 2 or "systemd" in parts:
        return False
    if len(parts) == 2:
        return suffix in {".yaml", ".yml"} or parts[-1].endswith(".Containerfile")
    if parts[1] == "teamharness":
        return suffix == ".py"
    if parts[1] == "worker-package":
        return suffix in {".json", ".md"}
    return False


def _validate_source_names(names: Iterable[str]) -> tuple[str, ...]:
    ordered = _validate_archive_names(names)
    actual = frozenset(ordered)
    if not SOURCE_REQUIRED_EXACT.issubset(actual):
        raise SubmissionBuildError("required source allowlist entries are missing")
    if any(not any(name.startswith(prefix) for name in actual) for prefix in SOURCE_REQUIRED_PREFIXES):
        raise SubmissionBuildError("a required source allowlist section is empty")
    if any(not _source_allowed(name) for name in actual):
        raise SubmissionBuildError("source payload contains a path outside the allowlist")
    return ordered


def _token_entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum(
        (count / len(value)) * math.log2(count / len(value))
        for count in (value.count(character) for character in set(value))
    )


def _scan_text(text: str, label: str) -> None:
    for rule, pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(text):
            raise SubmissionBuildError(f"{label}: prohibited secret-shaped content ({rule})")
    if CAPABILITY_ASSIGNMENT.search(text):
        raise SubmissionBuildError(
            f"{label}: prohibited secret-shaped content (capability-assignment)"
        )
    if MATRIX_ROOM_ID.search(text):
        raise SubmissionBuildError(f"{label}: prohibited secret-shaped content (matrix-room-id)")
    if SENSITIVE_HEX_ASSIGNMENT.search(text):
        raise SubmissionBuildError(
            f"{label}: prohibited secret-shaped content (credential-assignment)"
        )
    for match in SECRET_ASSIGNMENT.finditer(text):
        value = match.group(1)
        classes = sum(
            (
                any(character.islower() for character in value),
                any(character.isupper() for character in value),
                any(character.isdigit() for character in value),
                any(not character.isalnum() for character in value),
            )
        )
        if classes >= 3 and len(set(value)) >= 10 and _token_entropy(value) >= 3.5:
            raise SubmissionBuildError(
                f"{label}: prohibited secret-shaped content (credential-assignment)"
            )
    for candidate in IPV4_CANDIDATE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_global:
            raise SubmissionBuildError(f"{label}: public IP literals are forbidden")
    for candidate in IPV6_CANDIDATE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_global:
            raise SubmissionBuildError(f"{label}: public IP literals are forbidden")
    if any(pattern.search(text) for pattern in LOCAL_PATH_PATTERNS):
        raise SubmissionBuildError(f"{label}: local absolute paths are forbidden")


def _scan_utf8(data: bytes, label: str) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SubmissionBuildError(f"{label}: allowlisted text is not UTF-8") from exc
    _scan_text(text, label)


def _check_payload_limits(
    payload: Mapping[str, bytes],
    *,
    label: str,
    max_entries: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> None:
    if len(payload) > max_entries:
        raise SubmissionBuildError(f"{label}: entry limit exceeded")
    if any(len(data) > max_file_bytes for data in payload.values()):
        raise SubmissionBuildError(f"{label}: file size limit exceeded")
    if sum(len(data) for data in payload.values()) > max_total_bytes:
        raise SubmissionBuildError(f"{label}: total size limit exceeded")


def _scan_pptx(data: bytes, label: str) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_OFFICE_ENTRIES:
                raise SubmissionBuildError(f"{label}: Office entry limit exceeded")
            names = _validate_archive_names(info.filename for info in infos)
            if not {"[Content_Types].xml", "ppt/presentation.xml"}.issubset(names):
                raise SubmissionBuildError(f"{label}: PPTX structure is incomplete")
            total = 0
            for info in infos:
                mode = info.external_attr >> 16
                ratio = info.file_size / max(info.compress_size, 1)
                if (
                    info.is_dir()
                    or info.flag_bits & 0x1
                    or stat.S_ISLNK(mode)
                    or info.file_size > MAX_OFFICE_MEMBER_BYTES
                    or ratio > MAX_OFFICE_COMPRESSION_RATIO
                ):
                    raise SubmissionBuildError(f"{label}: unsafe Office package member")
                total += info.file_size
                if total > MAX_OFFICE_TOTAL_BYTES:
                    raise SubmissionBuildError(f"{label}: Office package size limit exceeded")
                name = info.filename
                if (
                    name.lower().endswith(("vbaproject.bin", ".bin"))
                    or any(name.startswith(prefix) for prefix in FORBIDDEN_OFFICE_PREFIXES)
                ):
                    raise SubmissionBuildError(f"{label}: active or embedded Office content")
                if name.endswith((".xml", ".rels", ".txt", ".json")):
                    member = archive.read(info)
                    _scan_utf8(member, f"{label} Office text")
                    if name.endswith(".rels") and b'TargetMode="External"' in member:
                        raise SubmissionBuildError(f"{label}: external Office relationship")
    except zipfile.BadZipFile as exc:
        raise SubmissionBuildError(f"{label}: PPTX is not a valid ZIP package") from exc


def _scan_pdf(data: bytes, label: str, extractor: PdfTextExtractor) -> None:
    if not data.startswith(b"%PDF-"):
        raise SubmissionBuildError(f"{label}: invalid PDF header")
    if any(marker in data for marker in FORBIDDEN_PDF_MARKERS):
        raise SubmissionBuildError(f"{label}: active or embedded PDF content")
    _scan_text(data.decode("latin-1"), f"{label} raw PDF")
    _scan_text(extractor.extract(data), f"{label} extracted PDF")


def _manifest_bytes(payload: Mapping[str, bytes], context: ManifestContext) -> bytes:
    records = [
        {
            "project": context.project,
            "version": context.version,
            "commit": context.commit,
            "tag": context.tag,
            "path": name,
            "size": len(payload[name]),
            "sha256": _sha256(payload[name]),
        }
        for name in sorted(payload, key=_name_sort_key)
    ]
    return (json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sums_bytes(payload: Mapping[str, bytes]) -> bytes:
    return "".join(
        f"{_sha256(payload[name])}  {name}\n" for name in sorted(payload, key=_name_sort_key)
    ).encode("utf-8")


def _parse_manifest(data: bytes, expected_payload: Mapping[str, bytes]) -> ManifestContext:
    try:
        value: Any = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SubmissionBuildError("manifest is not canonical UTF-8 JSON") from exc
    if not isinstance(value, list) or not value:
        raise SubmissionBuildError("manifest must be one non-empty record list")
    expected_names = sorted(expected_payload, key=_name_sort_key)
    records: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict) or frozenset(item) != MANIFEST_KEYS:
            raise SubmissionBuildError("manifest contains fields outside the release schema")
        records.append(item)
    paths = [record.get("path") for record in records]
    if paths != expected_names:
        raise SubmissionBuildError("manifest path set or ordering is invalid")
    first = records[0]
    metadata = (first.get("project"), first.get("version"), first.get("commit"), first.get("tag"))
    project, version, commit, tag = metadata
    if (
        project != PROJECT
        or not isinstance(version, str)
        or not SAFE_VERSION.fullmatch(version)
        or not isinstance(commit, str)
        or not COMMIT_ID.fullmatch(commit)
        or not isinstance(tag, str)
    ):
        raise SubmissionBuildError("manifest release metadata is invalid")
    _validate_tag(tag)
    for record, name in zip(records, expected_names, strict=True):
        if (
            (record.get("project"), record.get("version"), record.get("commit"), record.get("tag"))
            != metadata
            or record.get("path") != name
            or type(record.get("size")) is not int
            or record.get("size") != len(expected_payload[name])
            or not isinstance(record.get("sha256"), str)
            or not HEX_DIGEST.fullmatch(record["sha256"])
            or record["sha256"] != _sha256(expected_payload[name])
        ):
            raise SubmissionBuildError("manifest record does not match its payload")
    canonical = _manifest_bytes(
        expected_payload,
        ManifestContext(project=project, version=version, commit=commit, tag=tag),
    )
    if data != canonical:
        raise SubmissionBuildError("manifest JSON encoding is not canonical")
    return ManifestContext(project=project, version=version, commit=commit, tag=tag)


def _verify_sums(data: bytes, expected_payload: Mapping[str, bytes]) -> None:
    if data != _sums_bytes(expected_payload):
        raise SubmissionBuildError("SHA256SUMS does not match the canonical payload")


def _read_canonical_zip(
    data: bytes,
    *,
    label: str,
    max_entries: int,
    max_total_bytes: int,
) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise SubmissionBuildError(f"{label}: archive size limit exceeded")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            if archive.comment:
                raise SubmissionBuildError(f"{label}: ZIP comment is forbidden")
            infos = archive.infolist()
            if len(infos) > max_entries:
                raise SubmissionBuildError(f"{label}: archive entry limit exceeded")
            ordered = _validate_archive_names(info.filename for info in infos)
            if [info.filename for info in infos] != list(ordered):
                raise SubmissionBuildError(f"{label}: ZIP entry order is not canonical")
            total = 0
            payload: dict[str, bytes] = {}
            for info in infos:
                total += info.file_size
                if (
                    total > max_total_bytes
                    or info.is_dir()
                    or info.flag_bits & 0x1
                    or info.flag_bits & ~0x800
                    or info.date_time != FIXED_ZIP_TIME
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.comment
                    or info.extra
                    or info.internal_attr != 0
                    or info.external_attr != CANONICAL_FILE_MODE << 16
                ):
                    raise SubmissionBuildError(f"{label}: ZIP member metadata is not canonical")
                payload[info.filename] = archive.read(info)
            return payload
    except zipfile.BadZipFile as exc:
        raise SubmissionBuildError(f"{label}: invalid ZIP archive") from exc


def _verify_source_archive(data: bytes) -> ManifestContext:
    entries = _read_canonical_zip(
        data,
        label="source archive",
        max_entries=MAX_SOURCE_ENTRIES + 2,
        max_total_bytes=MAX_SOURCE_TOTAL_BYTES + 2 * MAX_SOURCE_FILE_BYTES,
    )
    if SOURCE_MANIFEST_NAME not in entries or SOURCE_SUMS_NAME not in entries:
        raise SubmissionBuildError("source archive checksums are missing")
    payload = {
        name: content
        for name, content in entries.items()
        if name not in {SOURCE_MANIFEST_NAME, SOURCE_SUMS_NAME}
    }
    _validate_source_names(payload)
    _check_payload_limits(
        payload,
        label="source payload",
        max_entries=MAX_SOURCE_ENTRIES,
        max_file_bytes=MAX_SOURCE_FILE_BYTES,
        max_total_bytes=MAX_SOURCE_TOTAL_BYTES,
    )
    context = _parse_manifest(entries[SOURCE_MANIFEST_NAME], payload)
    sums_payload = {**payload, SOURCE_MANIFEST_NAME: entries[SOURCE_MANIFEST_NAME]}
    _verify_sums(entries[SOURCE_SUMS_NAME], sums_payload)
    for name, content in payload.items():
        _scan_utf8(content, f"source file {name}")
    return context


def verify_submission_bytes(
    data: bytes,
    *,
    _pdf_extractor: PdfTextExtractor | None = None,
) -> ManifestContext:
    """Verify both archive levels and return their authenticated release context."""

    extractor = _pdf_extractor or PopplerPdfTextExtractor()
    entries = _read_canonical_zip(
        data,
        label="submission archive",
        max_entries=MAX_OUTER_ENTRIES,
        max_total_bytes=MAX_OUTER_TOTAL_BYTES,
    )
    expected_names = EXPECTED_OUTER_PAYLOAD | {OUTER_MANIFEST_NAME, OUTER_SUMS_NAME}
    if frozenset(entries) != expected_names:
        raise SubmissionBuildError("submission archive file set is not exact")
    payload = {
        name: content
        for name, content in entries.items()
        if name not in {OUTER_MANIFEST_NAME, OUTER_SUMS_NAME}
    }
    _check_payload_limits(
        payload,
        label="outer payload",
        max_entries=MAX_OUTER_ENTRIES - 2,
        max_file_bytes=MAX_OUTER_FILE_BYTES,
        max_total_bytes=MAX_OUTER_TOTAL_BYTES,
    )
    context = _parse_manifest(entries[OUTER_MANIFEST_NAME], payload)
    sums_payload = {**payload, OUTER_MANIFEST_NAME: entries[OUTER_MANIFEST_NAME]}
    _verify_sums(entries[OUTER_SUMS_NAME], sums_payload)
    source_context = _verify_source_archive(entries[SOURCE_ARCHIVE_NAME])
    if source_context != context:
        raise SubmissionBuildError("source and outer release metadata differ")
    for name, content in payload.items():
        if name == SOURCE_ARCHIVE_NAME:
            continue
        if name.endswith(".pptx"):
            _scan_pptx(content, name)
        elif name.endswith(".pdf"):
            _scan_pdf(content, name, extractor)
        else:
            _scan_utf8(content, name)
    return context


def verify_submission_archive(
    archive: Path,
    *,
    _pdf_extractor: PdfTextExtractor | None = None,
) -> ManifestContext:
    """Safely read and verify an existing submission archive."""

    candidate = archive if archive.is_absolute() else Path.cwd() / archive
    root = trusted_directory(candidate.parent, "submission archive directory")
    data = read_regular_file(
        candidate,
        root=root,
        label="submission archive",
        max_bytes=MAX_ARCHIVE_BYTES,
        scan_secrets=False,
    )
    return verify_submission_bytes(data, _pdf_extractor=_pdf_extractor)


def _project_version(data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SubmissionBuildError("pyproject.toml is not UTF-8") from exc
    block = re.search(r"(?ms)^\[project\][ \t]*\r?\n(.*?)(?=^\[|\Z)", text)
    match = re.search(r'(?m)^version[ \t]*=[ \t]*["\']([^"\']+)["\'][ \t]*$', block.group(1)) if block else None
    if not match or not SAFE_VERSION.fullmatch(match.group(1)):
        raise SubmissionBuildError("pyproject.toml project version is missing or unsafe")
    return match.group(1)


def _repository_state(root: Path, tag: str, git: GitClient) -> RepositoryState:
    _validate_tag(tag)
    if git.status_porcelain(root):
        raise SubmissionBuildError("working tree must be clean before a release build")
    commit = git.head_commit(root).lower()
    tag_commit = git.tag_commit(root, tag).lower()
    if not COMMIT_ID.fullmatch(commit) or tag_commit != commit:
        raise SubmissionBuildError("release tag does not resolve to the clean HEAD commit")
    tracked = git.tracked_files(root)
    _validate_archive_names(tracked)
    return RepositoryState(commit=commit, tag=tag, tracked_files=tracked)


def _read_source_payload(root: Path, state: RepositoryState) -> dict[str, bytes]:
    names = _validate_source_names(name for name in state.tracked_files if _source_allowed(name))
    payload: dict[str, bytes] = {}
    for name in names:
        content = read_regular_file(
            root / Path(*PurePosixPath(name).parts),
            root=root,
            label=f"source file {name}",
            max_bytes=MAX_SOURCE_FILE_BYTES,
            scan_secrets=False,
        )
        _scan_utf8(content, f"source file {name}")
        payload[name] = content
    _check_payload_limits(
        payload,
        label="source payload",
        max_entries=MAX_SOURCE_ENTRIES,
        max_file_bytes=MAX_SOURCE_FILE_BYTES,
        max_total_bytes=MAX_SOURCE_TOTAL_BYTES,
    )
    return payload


def _read_outer_payload(
    root: Path,
    state: RepositoryState,
    extractor: PdfTextExtractor,
) -> dict[str, bytes]:
    payload: dict[str, bytes] = {}
    targets = _validate_archive_names(target for _, target, _ in OUTER_INPUTS)
    if frozenset(targets) != EXPECTED_OUTER_PAYLOAD - {SOURCE_ARCHIVE_NAME}:
        raise SubmissionBuildError("outer input mapping is not exact")
    for source, target, kind in OUTER_INPUTS:
        if source not in state.tracked_files:
            raise SubmissionBuildError("an outer submission input is not tracked by Git")
        content = read_regular_file(
            root / Path(*PurePosixPath(source).parts),
            root=root,
            label=f"outer input {source}",
            max_bytes=MAX_OUTER_FILE_BYTES,
            scan_secrets=False,
        )
        if kind == "pptx":
            _scan_pptx(content, target)
        elif kind == "pdf":
            _scan_pdf(content, target, extractor)
        else:
            _scan_utf8(content, target)
        payload[target] = content
    return payload


def _assemble_submission(
    root: Path,
    state: RepositoryState,
    extractor: PdfTextExtractor,
) -> bytes:
    source_payload = _read_source_payload(root, state)
    version = _project_version(source_payload["pyproject.toml"])
    context = ManifestContext(project=PROJECT, version=version, commit=state.commit, tag=state.tag)
    source_manifest = _manifest_bytes(source_payload, context)
    source_entries = {
        **source_payload,
        SOURCE_MANIFEST_NAME: source_manifest,
        SOURCE_SUMS_NAME: _sums_bytes({**source_payload, SOURCE_MANIFEST_NAME: source_manifest}),
    }
    source_archive = canonical_zip_bytes(source_entries, FIXED_SOURCE_DATE_EPOCH)
    outer_payload = _read_outer_payload(root, state, extractor)
    outer_payload[SOURCE_ARCHIVE_NAME] = source_archive
    _check_payload_limits(
        outer_payload,
        label="outer payload",
        max_entries=MAX_OUTER_ENTRIES - 2,
        max_file_bytes=MAX_OUTER_FILE_BYTES,
        max_total_bytes=MAX_OUTER_TOTAL_BYTES,
    )
    outer_manifest = _manifest_bytes(outer_payload, context)
    outer_entries = {
        **outer_payload,
        OUTER_MANIFEST_NAME: outer_manifest,
        OUTER_SUMS_NAME: _sums_bytes({**outer_payload, OUTER_MANIFEST_NAME: outer_manifest}),
    }
    archive = canonical_zip_bytes(outer_entries, FIXED_SOURCE_DATE_EPOCH)
    verify_submission_bytes(archive, _pdf_extractor=extractor)
    return archive


def _safe_output(root: Path, output: Path) -> Path:
    output_root = trusted_directory(root / "outputs", "submission output directory")
    candidate = output if output.is_absolute() else root / output
    if candidate.suffix.lower() != ".zip":
        raise SubmissionBuildError("submission output must use the .zip suffix")
    if candidate.parent != root / "outputs":
        raise SubmissionBuildError("submission output must be one direct child of outputs/")
    try:
        parent = candidate.parent.resolve(strict=True)
    except OSError as exc:
        raise SubmissionBuildError("submission output directory is missing") from exc
    if parent != output_root or candidate.name in {"", ".", ".."}:
        raise SubmissionBuildError("submission output must be one direct child of outputs/")
    if candidate.exists() or candidate.is_symlink():
        raise SubmissionBuildError("submission output already exists; overwrite is forbidden")
    _validate_archive_names((candidate.name,))
    return candidate


def _exclusive_atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.link(temporary, path)
        temporary.unlink()
    except OSError as exc:
        raise SubmissionBuildError("submission output cannot be committed without overwrite") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def build_submission(
    *,
    repo_root: Path,
    output: Path,
    tag: str,
    _git: GitClient | None = None,
    _pdf_extractor: PdfTextExtractor | None = None,
) -> BuildResult:
    """Build one archive; underscored dependencies are test-only injection points."""

    root = trusted_directory(repo_root, "repository root")
    destination = _safe_output(root, output)
    git = _git or SubprocessGitClient()
    extractor = _pdf_extractor or PopplerPdfTextExtractor()
    before = _repository_state(root, tag, git)
    archive = _assemble_submission(root, before, extractor)
    after = _repository_state(root, tag, git)
    if after != before:
        raise SubmissionBuildError("repository state changed during the release build")
    _exclusive_atomic_write(destination, archive)
    return BuildResult(
        output=destination,
        size=len(archive),
        sha256=_sha256(archive),
        commit=before.commit,
        tag=before.tag,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build from one clean, tagged commit")
    build.add_argument("--tag", required=True, help="Git tag that must resolve to clean HEAD")
    build.add_argument("--output", required=True, type=Path, help="new ZIP directly under outputs/")
    verify = subparsers.add_parser("verify", help="verify both manifest and checksum layers")
    verify.add_argument("archive", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "build":
            result = build_submission(
                repo_root=REPOSITORY_ROOT,
                output=arguments.output,
                tag=arguments.tag,
            )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "path": result.output.name,
                        "size": result.size,
                        "sha256": result.sha256,
                        "commit": result.commit,
                        "tag": result.tag,
                    },
                    sort_keys=True,
                )
            )
        else:
            context = verify_submission_archive(arguments.archive)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "project": context.project,
                        "version": context.version,
                        "commit": context.commit,
                        "tag": context.tag,
                    },
                    sort_keys=True,
                )
            )
    except SubmissionBuildError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

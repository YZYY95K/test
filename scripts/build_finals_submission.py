#!/usr/bin/env python3
"""Build and verify a deterministic DevFlow GOAI finals release archive.

Release bytes are read exclusively from one Git commit object.  The worktree is
used only to prove that the selected commit is the clean HEAD; it is never used
as package input.  Generated supply-chain records are derived from the committed
``pyproject.toml`` and fixed-repository benchmark manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import tempfile
import unicodedata
import uuid
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

try:
    from scripts.build_agentteams_package import canonical_zip_bytes
    from scripts.build_prelim_submission import (
        _scan_pdf,
        _scan_pptx,
        _scan_utf8,
    )
    from scripts.verify_agentteams_upstream import parse_lock_bytes, verify_manifest_payload
    from scripts.verify_finals_materials import FinalsMaterialError, verify_material_bytes
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from build_agentteams_package import canonical_zip_bytes  # type: ignore[no-redef]
    from build_prelim_submission import (  # type: ignore[no-redef]
        _scan_pdf,
        _scan_pptx,
        _scan_utf8,
    )
    from verify_agentteams_upstream import (  # type: ignore[no-redef]
        parse_lock_bytes,
        verify_manifest_payload,
    )
    from verify_finals_materials import (  # type: ignore[no-redef]
        FinalsMaterialError,
        verify_material_bytes,
    )

PROJECT = "DevFlow"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXED_SOURCE_DATE_EPOCH = 315_532_800
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
CANONICAL_FILE_MODE = stat.S_IFREG | 0o644
FINAL_PDF_PATH = "outputs/DevFlow_GOAI_2026_决赛路演_20260728.pdf"
FINAL_PPTX_PATH = "outputs/DevFlow_GOAI_2026_决赛路演_20260728.pptx"

MANIFEST_NAME = "MANIFEST.json"
SUMS_NAME = "SHA256SUMS"
PROVENANCE_NAME = "PROVENANCE.json"
SBOM_NAME = "SBOM.cdx.json"
LICENSES_NAME = "THIRD_PARTY_LICENSES.json"
VIDEO_INDEX_NAME = "DEMO_VIDEO_INDEX.json"
GENERATED_NAMES = frozenset(
    {MANIFEST_NAME, SUMS_NAME, PROVENANCE_NAME, SBOM_NAME, LICENSES_NAME, VIDEO_INDEX_NAME}
)

MAX_ENTRIES = 2_500
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 192 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_VIDEO_BYTES = 16 * 1024 * 1024 * 1024

REQUIRED_ROOT_FILES = frozenset({"README.md", "LICENSE", "NOTICE", "pyproject.toml"})
REQUIRED_EXACT = REQUIRED_ROOT_FILES | frozenset(
    {
        ".github/workflows/ci.yml",
        "agentteams/team.yaml",
        "agentteams/upstream.lock.yaml",
        "benchmarks/repository_repair/tasks.yaml",
        "config/agents.yaml",
        "config/mcp_servers.yaml",
        "config/observability.yaml",
        "config/security.yaml",
        "config/skills.yaml",
        "docs/AGENTTEAMS.md",
        "docs/BENCHMARK.md",
        "docs/BOUNDARIES_AND_MCP.md",
        "docs/INFRASTRUCTURE.md",
        "docs/SCORECARD.md",
        "docs/finals/ACCEPTANCE_MATRIX_CN.md",
        "docs/finals/AGENT_IDENTITY_APPENDIX_CN.md",
        "docs/finals/DEFENSE_QA_CN.md",
        "docs/finals/DEMO_SCRIPT_CN.md",
        "docs/finals/PROJECT_INTRO_500_CN.md",
        "docs/finals/assets/DevFlow_GOAI_2026_finals_template_source.pptx",
        "docs/finals/assets/finals_template_frame_map.json",
        FINAL_PDF_PATH,
        FINAL_PPTX_PATH,
        "requirements/dev.lock.txt",
        "requirements/licenses.yaml",
        "requirements/production.lock.txt",
        "requirements/rag.lock.txt",
        "scripts/author_finals_deck.mjs",
        "scripts/generate_dependency_licenses.py",
        "scripts/verify_finals_materials.py",
        "scripts/verify_agentteams_upstream.py",
    }
)
REQUIRED_PREFIXES = (
    "src/devflow/",
    "skills/",
    "config/",
    "agentteams/",
    "benchmarks/",
    "docs/finals/",
    "requirements/",
    "scripts/",
    "tests/",
)

ROOT_ALLOWLIST = frozenset(
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
ALLOWED_SUFFIXES: Mapping[str, frozenset[str]] = {
    ".github": frozenset({".yaml", ".yml"}),
    "agentteams": frozenset({".containerfile", ".json", ".md", ".py", ".yaml", ".yml"}),
    "benchmarks": frozenset({".json", ".md", ".py", ".txt", ".yaml", ".yml"}),
    "config": frozenset({".json", ".toml", ".yaml", ".yml"}),
    "docs": frozenset({".json", ".md"}),
    "evals": frozenset({".json", ".py", ".yaml", ".yml"}),
    "examples": frozenset({".json", ".md", ".py", ".yaml", ".yml"}),
    "requirements": frozenset({".txt", ".yaml", ".yml"}),
    "scripts": frozenset({".py", ".sh"}),
    "skills": frozenset({".json", ".md", ".py", ".yaml", ".yml"}),
    "src": frozenset({".py", ".typed"}),
    "tests": frozenset({".json", ".py", ".yaml", ".yml"}),
}
EXCLUDED_PARTS = frozenset(
    {
        ".benchmarks",
        ".devflow",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tmp",
        ".venv",
        "__pycache__",
        "dist",
        "systemd",
        "tmp",
    }
)
SAFE_REF = re.compile(r"^(?:[0-9a-fA-F]{40,64}|[A-Za-z0-9][A-Za-z0-9._/-]{0,127})$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
DEPENDENCY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
LOCK_REQUIREMENT = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)"
    r"(?:\s*;\s*([^\\]+?))?\s*\\?$"
)
LOCK_HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})(?:\s*\\)?$")
LOCK_PATHS = {
    "dev": "requirements/dev.lock.txt",
    "production": "requirements/production.lock.txt",
    "rag": "requirements/rag.lock.txt",
}
BENCHMARK_REPOSITORY_LOCK = {
    "flask": "7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1",
    "pydantic": "5f033e46c54fea1b59b6894d6527daf49475e690",
    "requests": "0e322af87745eff34caffe4df68456ebc20d9068",
}


class FinalsBuildError(RuntimeError):
    """The release input or archive violates the finals packaging policy."""


class PypdfPdfTextExtractor:
    """Extract bounded text with the hash-locked pure-Python PDF parser."""

    def extract(self, data: bytes) -> str:
        try:
            from pypdf import PdfReader
        except ImportError as exc:  # pragma: no cover - packaging environment failure
            raise FinalsBuildError("hash-locked PDF parser is unavailable") from exc
        try:
            reader = PdfReader(io.BytesIO(data), strict=True)
            if reader.is_encrypted:
                raise FinalsBuildError("PDF text extraction rejects encrypted input")
            if not 1 <= len(reader.pages) <= 100:
                raise FinalsBuildError("PDF text extraction page count is out of bounds")
            pages: list[str] = []
            total = 0
            for page in reader.pages:
                value = page.extract_text() or ""
                total += len(value.encode("utf-8"))
                if total > 4 * 1024 * 1024:
                    raise FinalsBuildError("PDF extracted text exceeds its byte limit")
                pages.append(value)
        except FinalsBuildError:
            raise
        except Exception as exc:
            raise FinalsBuildError("PDF text extraction failed") from exc
        return "\n\f\n".join(pages)


@dataclass(frozen=True)
class GitObject:
    path: str
    mode: str
    object_type: str
    oid: str


@dataclass(frozen=True)
class LockPackage:
    name: str
    version: str
    marker: str
    hashes: tuple[str, ...]

    @property
    def identity(self) -> tuple[str, str]:
        return (self.name, self.version)


@dataclass(frozen=True)
class ReleaseState:
    commit: str
    ref: str
    objects: tuple[GitObject, ...]


@dataclass(frozen=True)
class ReleaseContext:
    project: str
    version: str
    commit: str
    ref: str


@dataclass(frozen=True)
class BuildResult:
    output: Path
    size: int
    sha256: str
    commit: str
    ref: str


class GitClient(Protocol):
    def status_porcelain(self, root: Path) -> bytes: ...

    def head_commit(self, root: Path) -> str: ...

    def resolve_commit(self, root: Path, ref: str) -> str: ...

    def tree_objects(self, root: Path, commit: str) -> tuple[GitObject, ...]: ...

    def read_blob(self, root: Path, oid: str) -> bytes: ...


class PdfTextExtractor(Protocol):
    def extract(self, data: bytes) -> str: ...


class SubprocessGitClient:
    """Read release metadata and content through plumbing-level Git commands."""

    @staticmethod
    def _run(root: Path, arguments: Sequence[str], *, stdin: bytes | None = None) -> bytes:
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=root,
                input=stdin,
                check=False,
                capture_output=True,
            )
        except OSError as exc:
            raise FinalsBuildError("git could not be started") from exc
        if completed.returncode != 0:
            raise FinalsBuildError("git object lookup failed")
        return completed.stdout

    def status_porcelain(self, root: Path) -> bytes:
        return self._run(root, ["status", "--porcelain=v1", "--untracked-files=all", "-z"])

    def head_commit(self, root: Path) -> str:
        return self._run(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode("ascii").strip()

    def resolve_commit(self, root: Path, ref: str) -> str:
        revision = ref if re.fullmatch(r"[0-9a-fA-F]{40,64}", ref) else f"refs/tags/{ref}"
        return (
            self._run(root, ["rev-parse", "--verify", f"{revision}^{{commit}}"])
            .decode("ascii")
            .strip()
        )

    def tree_objects(self, root: Path, commit: str) -> tuple[GitObject, ...]:
        raw = self._run(root, ["ls-tree", "-r", "-z", "--full-tree", commit])
        objects: list[GitObject] = []
        for record in (part for part in raw.split(b"\0") if part):
            try:
                metadata, encoded_path = record.split(b"\t", 1)
                mode, object_type, oid = metadata.decode("ascii").split(" ", 2)
                path = encoded_path.decode("utf-8")
            except (UnicodeDecodeError, ValueError) as exc:
                raise FinalsBuildError("git tree output is malformed or not UTF-8") from exc
            objects.append(GitObject(path=path, mode=mode, object_type=object_type, oid=oid))
        return tuple(objects)

    def read_blob(self, root: Path, oid: str) -> bytes:
        if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", oid):
            raise FinalsBuildError("git blob id is invalid")
        return self._run(root, ["cat-file", "blob", oid])


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _sort_key(value: str) -> bytes:
    return value.encode("utf-8")


def _validate_ref(ref: str) -> None:
    if (
        not SAFE_REF.fullmatch(ref)
        or ".." in ref
        or "@{" in ref
        or "//" in ref
        or ref.endswith(("/", "."))
        or ref.startswith("-")
    ):
        raise FinalsBuildError("release ref violates the safe ref policy")


def _validate_names(names: Iterable[str]) -> tuple[str, ...]:
    values = tuple(names)
    seen: set[str] = set()
    folded: set[str] = set()
    windows_reserved = {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
    }
    for value in values:
        normalized = unicodedata.normalize("NFC", value)
        path = PurePosixPath(value)
        if (
            not value
            or value != normalized
            or value != path.as_posix()
            or value.startswith(("/", "\\"))
            or "\\" in value
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or any(":" in part or part.endswith((" ", ".")) for part in path.parts)
            or any(part.split(".", 1)[0].upper() in windows_reserved for part in path.parts)
        ):
            raise FinalsBuildError("package path violates the canonical relative-path policy")
        lower = normalized.casefold()
        if value in seen or lower in folded:
            raise FinalsBuildError("duplicate or case-conflicting package path")
        seen.add(value)
        folded.add(lower)
    return tuple(sorted(values, key=_sort_key))


def _source_allowed(path: str) -> bool:
    if path in ROOT_ALLOWLIST:
        return True
    parts = PurePosixPath(path).parts
    if len(parts) < 2 or any(part in EXCLUDED_PARTS for part in parts):
        return False
    top = parts[0]
    allowed = ALLOWED_SUFFIXES.get(top)
    if allowed is None:
        return False
    if top == "outputs":
        return False
    return PurePosixPath(path).suffix.lower() in allowed


def _selected_names(objects: Sequence[GitObject]) -> tuple[str, ...]:
    all_names = _validate_names(item.path for item in objects)
    if len(all_names) > MAX_ENTRIES * 4:
        raise FinalsBuildError("git tree entry limit exceeded")
    for item in objects:
        if item.mode == "120000" or item.object_type == "symlink":
            raise FinalsBuildError("symlinks are forbidden anywhere in the release tree")
        if item.mode == "160000" or item.object_type == "commit":
            raise FinalsBuildError("Git submodules are forbidden anywhere in the release tree")
        if item.object_type != "blob" or item.mode not in {"100644", "100755"}:
            raise FinalsBuildError("release tree contains an unsupported Git object")
    selected = set(path for path in all_names if _source_allowed(path))
    # Exact-required binary/rebuild assets and the one .mjs authoring source do
    # not broaden any prefix policy.
    selected.update(path for path in REQUIRED_EXACT if path in set(all_names))
    missing = REQUIRED_EXACT - selected
    if missing:
        raise FinalsBuildError(
            f"required finals allowlist entries are missing: {sorted(missing)!r}"
        )
    if any(not any(path.startswith(prefix) for path in selected) for prefix in REQUIRED_PREFIXES):
        raise FinalsBuildError("a required finals allowlist section is empty")
    if selected & GENERATED_NAMES:
        raise FinalsBuildError("Git tree collides with generated package metadata")
    return _validate_names(selected)


def _read_release_state(root: Path, ref: str, git: GitClient) -> ReleaseState:
    _validate_ref(ref)
    if git.status_porcelain(root):
        raise FinalsBuildError("working tree must be clean before a finals release build")
    head = git.head_commit(root).lower()
    commit = git.resolve_commit(root, ref).lower()
    if not COMMIT_ID.fullmatch(head) or commit != head:
        raise FinalsBuildError("release ref does not resolve to the clean HEAD commit")
    objects = git.tree_objects(root, commit)
    _selected_names(objects)
    return ReleaseState(commit=commit, ref=ref, objects=objects)


def _scan_source(path: str, content: bytes, extractor: PdfTextExtractor) -> None:
    try:
        if path.endswith(".pptx"):
            _scan_pptx(content, path)
        elif path.endswith(".pdf"):
            _scan_pdf(content, path, extractor)
        else:
            _scan_utf8(content, path)
    except Exception as exc:
        raise FinalsBuildError(f"release content scan failed for {path}: {exc}") from exc


def _read_source_payload(
    root: Path,
    state: ReleaseState,
    git: GitClient,
    extractor: PdfTextExtractor,
) -> dict[str, bytes]:
    selected = _selected_names(state.objects)
    by_path = {item.path: item for item in state.objects}
    payload: dict[str, bytes] = {}
    total = 0
    for path in selected:
        content = git.read_blob(root, by_path[path].oid)
        if len(content) > MAX_FILE_BYTES:
            raise FinalsBuildError(f"release source file exceeds size limit: {path}")
        total += len(content)
        if total > MAX_TOTAL_BYTES:
            raise FinalsBuildError("release source payload exceeds total size limit")
        _scan_source(path, content, extractor)
        payload[path] = content
    return payload


def _project_metadata(pyproject: bytes) -> tuple[str, str, list[str]]:
    try:
        value = tomllib.loads(pyproject.decode("utf-8"))
        project = value["project"]
        name = project["name"]
        version = project["version"]
        dependencies = project.get("dependencies", [])
        optional_dependencies = project.get("optional-dependencies", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise FinalsBuildError("committed pyproject.toml metadata is invalid") from exc
    if (
        name != "devflow"
        or not isinstance(version, str)
        or not PACKAGE_NAME.fullmatch(version)
        or not isinstance(dependencies, list)
        or any(not isinstance(item, str) for item in dependencies)
        or not isinstance(optional_dependencies, dict)
        or any(
            not isinstance(group, str)
            or not isinstance(items, list)
            or any(not isinstance(item, str) for item in items)
            for group, items in optional_dependencies.items()
        )
    ):
        raise FinalsBuildError("committed project metadata violates the release schema")
    all_dependencies = list(dependencies)
    for group in sorted(optional_dependencies):
        all_dependencies.extend(optional_dependencies[group])
    return name, version, list(dict.fromkeys(all_dependencies))


def _canonical_package_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _declared_dependency_groups(pyproject: bytes) -> dict[str, set[str]]:
    try:
        project = tomllib.loads(pyproject.decode("utf-8"))["project"]
        core = project.get("dependencies", [])
        optional = project.get("optional-dependencies", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise FinalsBuildError("committed dependency declarations are invalid") from exc
    if (
        not isinstance(core, list)
        or not isinstance(optional, dict)
        or any(not isinstance(item, str) for item in core)
        or any(
            not isinstance(group, str)
            or not isinstance(items, list)
            or any(not isinstance(item, str) for item in items)
            for group, items in optional.items()
        )
    ):
        raise FinalsBuildError("committed dependency declarations have an invalid schema")

    def names(requirements: Sequence[str]) -> set[str]:
        result: set[str] = set()
        for requirement in requirements:
            match = DEPENDENCY_NAME.match(requirement)
            if not match:
                raise FinalsBuildError("committed dependency requirement is invalid")
            result.add(_canonical_package_name(match.group(0)))
        return result

    groups = {"core": names(core)}
    groups.update({group: names(items) for group, items in optional.items()})
    return groups


def _parse_lock(data: bytes, *, profile: str) -> tuple[LockPackage, ...]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FinalsBuildError(f"{profile} dependency lock is not UTF-8") from exc
    header = "\n".join(text.splitlines()[:5])
    required_header = {
        "--universal",
        "--python-version 3.10",
        "--generate-hashes",
        "--extra mcp",
    }
    if profile in {"dev", "rag"}:
        required_header.add("--extra rag")
    if profile == "dev":
        required_header.add("--extra dev")
    if any(token not in header for token in required_header):
        raise FinalsBuildError(f"{profile} dependency lock generation header is incomplete")
    if re.search(r"(?m)^--(?:extra-)?index-url\b|@\s*https?://|^[^#\r\n]*git\+", text):
        raise FinalsBuildError(f"{profile} dependency lock contains a non-hermetic source")

    packages: list[LockPackage] = []
    current: tuple[str, str, str] | None = None
    hashes: list[str] = []

    def finish() -> None:
        nonlocal current, hashes
        if current is None:
            return
        if not hashes or len(hashes) != len(set(hashes)):
            raise FinalsBuildError(
                f"{profile} dependency lock has missing or duplicate distribution hashes"
            )
        packages.append(
            LockPackage(
                name=current[0],
                version=current[1],
                marker=current[2],
                hashes=tuple(sorted(hashes)),
            )
        )
        current = None
        hashes = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = LOCK_REQUIREMENT.fullmatch(line)
        if requirement:
            finish()
            raw_name = requirement.group(1)
            name = _canonical_package_name(raw_name)
            if raw_name != name:
                raise FinalsBuildError(f"{profile} dependency name is not PEP 503 canonical")
            current = (name, requirement.group(2), (requirement.group(3) or "").strip())
            continue
        digest = LOCK_HASH.fullmatch(line)
        if digest and current is not None:
            hashes.append(digest.group(1))
            continue
        raise FinalsBuildError(f"{profile} dependency lock contains an unsupported line")
    finish()
    if not packages:
        raise FinalsBuildError(f"{profile} dependency lock is empty")
    identities = [item.identity for item in packages]
    if len(identities) != len(set(identities)):
        raise FinalsBuildError(f"{profile} dependency lock repeats a package/version")
    return tuple(sorted(packages, key=lambda item: (item.name, item.version)))


def _dependency_locks(
    source: Mapping[str, bytes],
) -> dict[str, tuple[LockPackage, ...]]:
    locks = {
        profile: _parse_lock(source[path], profile=profile) for profile, path in LOCK_PATHS.items()
    }
    hashes_by_identity: dict[tuple[str, str], tuple[str, ...]] = {}
    for packages in locks.values():
        for package in packages:
            previous = hashes_by_identity.setdefault(package.identity, package.hashes)
            if previous != package.hashes:
                raise FinalsBuildError("dependency locks disagree on release hashes")
    declared = _declared_dependency_groups(source["pyproject.toml"])
    if "mcp" not in declared or "rag" not in declared:
        raise FinalsBuildError("pyproject must declare both mcp and rag dependency groups")
    production_names = {package.name for package in locks["production"]}
    rag_names = {package.name for package in locks["rag"]}
    if not (declared["core"] | declared["mcp"]).issubset(production_names):
        raise FinalsBuildError("production lock does not cover declared core+mcp dependencies")
    if not (declared["core"] | declared["mcp"] | declared["rag"]).issubset(rag_names):
        raise FinalsBuildError("rag lock does not cover declared core+mcp+rag dependencies")
    dev_names = {package.name for package in locks["dev"]}
    declared_dev = set().union(*declared.values())
    if not declared_dev.issubset(dev_names):
        raise FinalsBuildError("dev lock does not cover every declared dependency group")
    return locks


def _license_evidence(
    data: bytes,
    source: Mapping[str, bytes],
    locks: Mapping[str, tuple[LockPackage, ...]],
) -> dict[tuple[str, str], dict[str, str]]:
    try:
        value = yaml.safe_load(data.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise FinalsBuildError("dependency license evidence is invalid YAML") from exc
    if not isinstance(value, dict) or set(value) != {"locks", "packages", "schema_version"}:
        raise FinalsBuildError("dependency license evidence has an unexpected schema")
    if value["schema_version"] != "1.0" or not isinstance(value["locks"], dict):
        raise FinalsBuildError("dependency license evidence schema version is unsupported")
    if set(value["locks"]) != set(LOCK_PATHS):
        raise FinalsBuildError("dependency license evidence lock set is not exact")
    for profile, path in LOCK_PATHS.items():
        record = value["locks"][profile]
        if (
            not isinstance(record, dict)
            or set(record) != {"packages", "path", "sha256"}
            or record["path"] != path
            or type(record["packages"]) is not int
            or record["packages"] != len(locks[profile])
            or record["sha256"] != _sha256(source[path])
        ):
            raise FinalsBuildError("dependency license evidence lock binding is invalid")
    package_records = value["packages"]
    if not isinstance(package_records, list):
        raise FinalsBuildError("dependency license package records must be a list")
    records: dict[tuple[str, str], dict[str, str]] = {}
    expected_fields = {
        "license_expression",
        "metadata_source",
        "package",
        "source_url",
        "verify_status",
        "version",
    }
    for item in package_records:
        if (
            not isinstance(item, dict)
            or set(item) != expected_fields
            or any(not isinstance(item[field], str) or not item[field] for field in expected_fields)
        ):
            raise FinalsBuildError("dependency license package record is invalid")
        package = item["package"]
        version = item["version"]
        if (
            package != _canonical_package_name(package)
            or not PACKAGE_NAME.fullmatch(version)
            or item["metadata_source"] != f"https://pypi.org/pypi/{package}/{version}/json"
            or item["source_url"] != f"https://pypi.org/project/{package}/{version}/"
            or (
                item["license_expression"] == "NOASSERTION"
                and not item["verify_status"].startswith("noassertion-")
            )
            or (
                item["license_expression"] != "NOASSERTION"
                and not item["verify_status"].startswith("verified-")
            )
        ):
            raise FinalsBuildError("dependency license package identity or status is invalid")
        identity = (package, version)
        if identity in records:
            raise FinalsBuildError("dependency license evidence repeats a package/version")
        records[identity] = {field: item[field] for field in expected_fields}
    expected = {
        package.identity for profile_packages in locks.values() for package in profile_packages
    }
    if set(records) != expected:
        raise FinalsBuildError("dependency license evidence does not exactly cover both locks")
    return records


def _benchmark_records(data: bytes) -> list[dict[str, str]]:
    try:
        value = yaml.safe_load(data.decode("utf-8"))
        repositories = value["repositories"]
    except (UnicodeDecodeError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise FinalsBuildError("fixed benchmark repository manifest is invalid") from exc
    if not isinstance(repositories, dict) or set(repositories) != set(BENCHMARK_REPOSITORY_LOCK):
        raise FinalsBuildError("fixed benchmark repository set does not match the release lock")
    records: list[dict[str, str]] = []
    for key in sorted(repositories):
        item = repositories[key]
        try:
            license_record = item["license"]
            record = {
                "commit": item["commit"],
                "name": item["display_name"],
                "source_url": license_record["source_url"],
                "spdx": license_record["spdx"],
                "url": item["url"],
                "version": str(item["version"]),
            }
        except (KeyError, TypeError) as exc:
            raise FinalsBuildError("fixed benchmark repository record is incomplete") from exc
        if (
            not all(isinstance(field, str) and field for field in record.values())
            or record["commit"] != BENCHMARK_REPOSITORY_LOCK[key]
        ):
            raise FinalsBuildError("fixed benchmark repository record is invalid")
        records.append(record)
    return records


def _agentteams_record(data: bytes, source: Mapping[str, bytes]) -> dict[str, Any]:
    try:
        value = parse_lock_bytes(data)
        manifest_meta = value["devflow_manifest"]
        manifest_path = str(manifest_meta["path"])
        patch_path = str(manifest_meta["compatibility_patch"])
        evidence_path = str(manifest_meta["live_evidence"])
        verify_manifest_payload(value, source[manifest_path])
        if patch_path not in source or evidence_path not in source:
            raise ValueError("AgentTeams compatibility evidence is missing")
        record = {
            "commit": value["commit"],
            "crd_sha256": value["team_crd"]["sha256"],
            "release_tag": value["release_tag"],
            "release_url": value["release_url"],
            "repository": value["repository"],
            "license_spdx": value["license"]["spdx"],
            "license_source_url": value["license"]["source_url"],
            "license_sha256": value["license"]["sha256"],
            "license_utf8_bytes": value["license"]["utf8_bytes"],
        }
    except (KeyError, TypeError, ValueError) as exc:
        raise FinalsBuildError("AgentTeams upstream lock is invalid") from exc
    if (
        record["repository"] != "https://github.com/agentscope-ai/AgentTeams.git"
        or not re.fullmatch(r"[0-9a-f]{40}", record["commit"])
        or not HEX_DIGEST.fullmatch(record["crd_sha256"])
        or not record["release_tag"].startswith("v")
        or record["release_url"]
        != f"https://github.com/agentscope-ai/AgentTeams/releases/tag/{record['release_tag']}"
        or record["license_spdx"] != "Apache-2.0"
        or record["license_source_url"]
        != (
            "https://raw.githubusercontent.com/agentscope-ai/AgentTeams/"
            f"{record['release_tag']}/LICENSE"
        )
        or not isinstance(record["license_utf8_bytes"], int)
        or record["license_utf8_bytes"] <= 0
        or not isinstance(record["license_sha256"], str)
        or not HEX_DIGEST.fullmatch(record["license_sha256"])
    ):
        raise FinalsBuildError("AgentTeams upstream lock violates the release schema")
    return record


def _supply_chain_records(
    source: Mapping[str, bytes],
    context: ReleaseContext,
) -> tuple[bytes, bytes]:
    _project_metadata(source["pyproject.toml"])
    locks = _dependency_locks(source)
    license_evidence = _license_evidence(source["requirements/licenses.yaml"], source, locks)
    benchmark_repositories = _benchmark_records(source["benchmarks/repository_repair/tasks.yaml"])
    agentteams = _agentteams_record(source["agentteams/upstream.lock.yaml"], source)
    packages: dict[tuple[str, str], LockPackage] = {}
    profiles: dict[tuple[str, str], list[dict[str, str]]] = {}
    for profile, profile_packages in locks.items():
        for package in profile_packages:
            packages.setdefault(package.identity, package)
            profiles.setdefault(package.identity, []).append(
                {"marker": package.marker, "profile": profile}
            )
    components: list[dict[str, Any]] = []
    for identity in sorted(packages):
        package = packages[identity]
        evidence = license_evidence[identity]
        properties = [
            {
                "name": "devflow:lock-profiles",
                "value": ",".join(item["profile"] for item in profiles[identity]),
            },
            {
                "name": "devflow:license-verify-status",
                "value": evidence["verify_status"],
            },
        ]
        properties.extend(
            {
                "name": f"devflow:environment-marker:{item['profile']}",
                "value": item["marker"] or "<all>",
            }
            for item in profiles[identity]
        )
        components.append(
            {
                "bom-ref": f"pkg:pypi/{package.name}@{package.version}",
                "hashes": [{"alg": "SHA-256", "content": digest} for digest in package.hashes],
                "licenses": [{"expression": evidence["license_expression"]}],
                "name": package.name,
                "properties": properties,
                "purl": f"pkg:pypi/{package.name}@{package.version}",
                "type": "library",
                "version": package.version,
            }
        )
    components.extend(
        {
            "bom-ref": f"pkg:github/{item['name']}@{item['commit']}",
            "hashes": [{"alg": "SHA-1", "content": item["commit"]}],
            "name": item["name"],
            "properties": [
                {"name": "devflow:benchmark", "value": "fixed-repository"},
                {"name": "devflow:source-url", "value": item["url"]},
            ],
            "purl": f"pkg:github/{item['name']}@{item['commit']}",
            "type": "application",
            "version": item["version"],
        }
        for item in benchmark_repositories
    )
    components.append(
        {
            "bom-ref": f"pkg:github/agentscope-ai/AgentTeams@{agentteams['commit']}",
            "hashes": [{"alg": "SHA-1", "content": agentteams["commit"]}],
            "name": "agentscope-ai/AgentTeams",
            "licenses": [{"expression": agentteams["license_spdx"]}],
            "properties": [
                {"name": "devflow:agentteams-release", "value": agentteams["release_tag"]},
                {"name": "devflow:team-crd-sha256", "value": agentteams["crd_sha256"]},
                {
                    "name": "devflow:license-sha256",
                    "value": agentteams["license_sha256"],
                },
            ],
            "purl": f"pkg:github/agentscope-ai/AgentTeams@{agentteams['commit']}",
            "type": "framework",
            "version": agentteams["release_tag"],
        }
    )
    components.sort(key=lambda item: str(item["bom-ref"]).encode("utf-8"))
    sbom = {
        "bomFormat": "CycloneDX",
        "components": components,
        "metadata": {
            "component": {
                "bom-ref": f"pkg:pypi/devflow@{context.version}",
                "name": "devflow",
                "type": "application",
                "version": context.version,
            },
            "properties": [
                {"name": "devflow:git-commit", "value": context.commit},
                {"name": "devflow:git-ref", "value": context.ref},
                *(
                    {
                        "name": f"devflow:dependency-lock:{profile}",
                        "value": _sha256(source[path]),
                    }
                    for profile, path in LOCK_PATHS.items()
                ),
            ],
        },
        "serialNumber": (
            f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'{context.commit}:{context.ref}')}"
        ),
        "specVersion": "1.5",
        "version": 1,
    }
    license_entries: list[dict[str, Any]] = []
    for identity in sorted(packages):
        package = packages[identity]
        evidence = license_evidence[identity]
        license_entries.append(
            {
                "component": package.name,
                "hashes": list(package.hashes),
                "license": evidence["license_expression"],
                "lock_profiles": [item["profile"] for item in profiles[identity]],
                "metadata_source": evidence["metadata_source"],
                "source": evidence["source_url"],
                "verify_status": evidence["verify_status"],
                "version": package.version,
            }
        )
    license_entries.extend(
        {
            "commit": item["commit"],
            "component": item["name"],
            "license": item["spdx"],
            "source": item["source_url"],
            "version": item["version"],
        }
        for item in benchmark_repositories
    )
    license_entries.append(
        {
            "commit": agentteams["commit"],
            "component": "agentscope-ai/AgentTeams",
            "license": agentteams["license_spdx"],
            "license_sha256": agentteams["license_sha256"],
            "license_utf8_bytes": agentteams["license_utf8_bytes"],
            "source": agentteams["license_source_url"],
            "verify_status": "verified-upstream-license-bytes",
            "version": agentteams["release_tag"],
        }
    )
    license_entries.sort(
        key=lambda item: (str(item["component"]).casefold(), str(item.get("version", "")))
    )
    licenses = {
        "dependency_locks": {
            profile: {
                "packages": len(locks[profile]),
                "path": path,
                "sha256": _sha256(source[path]),
            }
            for profile, path in LOCK_PATHS.items()
        },
        "project_license": "Apache-2.0",
        "schema_version": "1.0",
        "third_party": license_entries,
    }
    return _canonical_json(sbom), _canonical_json(licenses)


def _video_index(video: Path | None) -> bytes | None:
    if video is None:
        return None
    candidate = video if video.is_absolute() else Path.cwd() / video
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise FinalsBuildError("demo video is missing or unreadable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_VIDEO_BYTES
    ):
        raise FinalsBuildError("demo video must be one bounded regular file")
    digest = hashlib.sha256()
    size = 0
    try:
        with candidate.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_VIDEO_BYTES:
                    raise FinalsBuildError("demo video exceeds the size limit")
                digest.update(chunk)
    except OSError as exc:
        raise FinalsBuildError("demo video could not be hashed") from exc
    if size != metadata.st_size or candidate.stat().st_mtime_ns != metadata.st_mtime_ns:
        raise FinalsBuildError("demo video changed while it was being indexed")
    return _canonical_json(
        {
            "embedded": False,
            "files": [{"bytes": size, "path": candidate.name, "sha256": digest.hexdigest()}],
            "schema_version": "1.0",
        }
    )


def _manifest(payload: Mapping[str, bytes]) -> bytes:
    return _canonical_json(
        [
            {"path": path, "sha256": _sha256(payload[path]), "size": len(payload[path])}
            for path in sorted(payload, key=_sort_key)
        ]
    )


def _sums(payload: Mapping[str, bytes]) -> bytes:
    return "".join(
        f"{_sha256(payload[path])}  {path}\n" for path in sorted(payload, key=_sort_key)
    ).encode("utf-8")


def _provenance(
    source: Mapping[str, bytes],
    context: ReleaseContext,
    sbom: bytes,
    licenses: bytes,
    video_index: bytes | None,
) -> bytes:
    locks = _dependency_locks(source)
    materials: list[dict[str, Any]] = [
        {
            "digest": {"sha256": _sha256(source[path])},
            "path": path,
            "size": len(source[path]),
            "source": "git-object",
        }
        for path in sorted(source, key=_sort_key)
    ]
    generated = {
        SBOM_NAME: _sha256(sbom),
        LICENSES_NAME: _sha256(licenses),
    }
    if video_index is not None:
        generated[VIDEO_INDEX_NAME] = _sha256(video_index)
    return _canonical_json(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://devflow.example/slsa/git-object-finals-archive/v1",
                    "externalParameters": {"ref": context.ref},
                    "resolvedDependencies": materials,
                },
                "runDetails": {
                    "builder": {"id": "devflow:scripts/build_finals_submission.py"},
                    "metadata": {
                        "reproducible": True,
                        "source_date_epoch": FIXED_SOURCE_DATE_EPOCH,
                    },
                },
                "dependencyLocks": {
                    profile: {
                        "packages": len(locks[profile]),
                        "path": path,
                        "sha256": _sha256(source[path]),
                    }
                    for profile, path in LOCK_PATHS.items()
                },
                "supplyChain": generated,
            },
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [
                {
                    "digest": {"gitCommit": context.commit},
                    "name": f"{context.project}@{context.version}",
                }
            ],
        }
    )


def _assemble(
    root: Path,
    state: ReleaseState,
    git: GitClient,
    extractor: PdfTextExtractor,
    video: Path | None,
) -> bytes:
    source = _read_source_payload(root, state, git, extractor)
    try:
        verify_material_bytes(source[FINAL_PPTX_PATH], source[FINAL_PDF_PATH])
    except FinalsMaterialError as exc:
        raise FinalsBuildError(f"finals material semantic gate failed: {exc}") from exc
    _, version, _ = _project_metadata(source["pyproject.toml"])
    context = ReleaseContext(PROJECT, version, state.commit, state.ref)
    sbom, licenses = _supply_chain_records(source, context)
    video_index = _video_index(video)
    provenance = _provenance(source, context, sbom, licenses, video_index)
    payload = {
        **source,
        SBOM_NAME: sbom,
        LICENSES_NAME: licenses,
        PROVENANCE_NAME: provenance,
    }
    if video_index is not None:
        payload[VIDEO_INDEX_NAME] = video_index
    manifest = _manifest(payload)
    entries = {**payload, MANIFEST_NAME: manifest}
    entries[SUMS_NAME] = _sums(entries)
    if len(entries) > MAX_ENTRIES or sum(map(len, entries.values())) > MAX_TOTAL_BYTES:
        raise FinalsBuildError("finals package exceeds release limits")
    archive = canonical_zip_bytes(entries, FIXED_SOURCE_DATE_EPOCH)
    verify_submission_bytes(archive, _pdf_extractor=extractor)
    return archive


def _read_zip(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise FinalsBuildError("finals archive exceeds the size limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            if archive.comment:
                raise FinalsBuildError("ZIP comments are forbidden")
            infos = archive.infolist()
            ordered = _validate_names(info.filename for info in infos)
            if [info.filename for info in infos] != list(ordered) or len(infos) > MAX_ENTRIES:
                raise FinalsBuildError("ZIP entry order or count is not canonical")
            result: dict[str, bytes] = {}
            total = 0
            for info in infos:
                total += info.file_size
                if (
                    info.is_dir()
                    or total > MAX_TOTAL_BYTES
                    or info.file_size > MAX_FILE_BYTES
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
                    raise FinalsBuildError("ZIP member metadata is not canonical")
                result[info.filename] = archive.read(info)
            return result
    except zipfile.BadZipFile as exc:
        raise FinalsBuildError("invalid finals ZIP archive") from exc


def _parse_manifest(data: bytes) -> dict[str, tuple[int, str]]:
    try:
        value: Any = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalsBuildError("MANIFEST.json is invalid") from exc
    if not isinstance(value, list) or not value:
        raise FinalsBuildError("MANIFEST.json must be a non-empty record list")
    result: dict[str, tuple[int, str]] = {}
    for item in value:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
            raise FinalsBuildError("MANIFEST.json record schema is invalid")
        path, size, digest = item["path"], item["size"], item["sha256"]
        if (
            not isinstance(path, str)
            or type(size) is not int
            or size < 0
            or not isinstance(digest, str)
            or not HEX_DIGEST.fullmatch(digest)
            or path in result
        ):
            raise FinalsBuildError("MANIFEST.json record value is invalid")
        result[path] = (size, digest)
    _validate_names(result)
    if list(result) != sorted(result, key=_sort_key):
        raise FinalsBuildError("MANIFEST.json path ordering is not canonical")
    return result


def _release_context(provenance: bytes) -> ReleaseContext:
    try:
        value = json.loads(provenance.decode("utf-8"))
        subject = value["subject"][0]
        predicate = value["predicate"]
        name = subject["name"]
        commit = subject["digest"]["gitCommit"]
        ref = predicate["buildDefinition"]["externalParameters"]["ref"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
        raise FinalsBuildError("PROVENANCE.json is invalid") from exc
    if (
        not isinstance(name, str)
        or not name.startswith(f"{PROJECT}@")
        or not isinstance(commit, str)
        or not COMMIT_ID.fullmatch(commit)
        or not isinstance(ref, str)
    ):
        raise FinalsBuildError("PROVENANCE.json release identity is invalid")
    version = name.split("@", 1)[1]
    if not PACKAGE_NAME.fullmatch(version):
        raise FinalsBuildError("PROVENANCE.json project version is invalid")
    _validate_ref(ref)
    return ReleaseContext(PROJECT, version, commit, ref)


def _verify_supply_chain(entries: Mapping[str, bytes], context: ReleaseContext) -> None:
    try:
        sbom = json.loads(entries[SBOM_NAME].decode("utf-8"))
        licenses = json.loads(entries[LICENSES_NAME].decode("utf-8"))
        provenance = json.loads(entries[PROVENANCE_NAME].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FinalsBuildError("supply-chain record is not UTF-8 JSON") from exc
    if (
        sbom.get("bomFormat") != "CycloneDX"
        or sbom.get("specVersion") != "1.5"
        or not isinstance(sbom.get("components"), list)
        or licenses.get("project_license") != "Apache-2.0"
        or not isinstance(licenses.get("third_party"), list)
    ):
        raise FinalsBuildError("SBOM or third-party license schema is invalid")
    properties = sbom.get("metadata", {}).get("properties", [])
    expected_properties = {
        ("devflow:git-commit", context.commit),
        ("devflow:git-ref", context.ref),
        *(
            (f"devflow:dependency-lock:{profile}", _sha256(entries[path]))
            for profile, path in LOCK_PATHS.items()
        ),
    }
    if {
        (item.get("name"), item.get("value")) for item in properties if isinstance(item, dict)
    } != expected_properties:
        raise FinalsBuildError("SBOM is not bound to the release identity")
    generated = provenance.get("predicate", {}).get("supplyChain", {})
    expected_generated = {
        SBOM_NAME: _sha256(entries[SBOM_NAME]),
        LICENSES_NAME: _sha256(entries[LICENSES_NAME]),
    }
    if VIDEO_INDEX_NAME in entries:
        expected_generated[VIDEO_INDEX_NAME] = _sha256(entries[VIDEO_INDEX_NAME])
    if generated != expected_generated:
        raise FinalsBuildError("provenance supply-chain digests do not match")
    if VIDEO_INDEX_NAME in entries:
        try:
            index = json.loads(entries[VIDEO_INDEX_NAME].decode("utf-8"))
            files = index["files"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise FinalsBuildError("demo video index is invalid") from exc
        if (
            index.get("embedded") is not False
            or not isinstance(files, list)
            or len(files) != 1
            or set(files[0]) != {"bytes", "path", "sha256"}
            or type(files[0]["bytes"]) is not int
            or not isinstance(files[0]["path"], str)
            or PurePosixPath(files[0]["path"]).name != files[0]["path"]
            or not isinstance(files[0]["sha256"], str)
            or not HEX_DIGEST.fullmatch(files[0]["sha256"])
        ):
            raise FinalsBuildError("demo video index schema is invalid")


def verify_submission_bytes(
    data: bytes,
    *,
    _pdf_extractor: PdfTextExtractor | None = None,
) -> ReleaseContext:
    """Verify deterministic layout, checksums, provenance, SBOM, and content."""

    entries = _read_zip(data)
    required_generated = {MANIFEST_NAME, SUMS_NAME, PROVENANCE_NAME, SBOM_NAME, LICENSES_NAME}
    if not required_generated.issubset(entries):
        raise FinalsBuildError("required generated finals records are missing")
    payload = {
        path: content for path, content in entries.items() if path not in {MANIFEST_NAME, SUMS_NAME}
    }
    records = _parse_manifest(entries[MANIFEST_NAME])
    if set(records) != set(payload):
        raise FinalsBuildError("manifest path set does not match the package payload")
    for path, content in payload.items():
        if records[path] != (len(content), _sha256(content)):
            raise FinalsBuildError("manifest record does not match package payload")
    if entries[MANIFEST_NAME] != _manifest(payload):
        raise FinalsBuildError("manifest JSON encoding or ordering is not canonical")
    if entries[SUMS_NAME] != _sums({**payload, MANIFEST_NAME: entries[MANIFEST_NAME]}):
        raise FinalsBuildError("SHA256SUMS does not match package payload")
    source_paths = set(payload) - {PROVENANCE_NAME, SBOM_NAME, LICENSES_NAME, VIDEO_INDEX_NAME}
    if not REQUIRED_EXACT.issubset(source_paths):
        raise FinalsBuildError("required finals source entries are missing")
    if any(not (_source_allowed(path) or path in REQUIRED_EXACT) for path in source_paths):
        raise FinalsBuildError("package contains a source path outside the allowlist")
    context = _release_context(entries[PROVENANCE_NAME])
    _, committed_version, _ = _project_metadata(entries["pyproject.toml"])
    if context.version != committed_version:
        raise FinalsBuildError("provenance version does not match committed pyproject.toml")
    _verify_supply_chain(entries, context)
    source_payload = {path: entries[path] for path in source_paths}
    try:
        verify_material_bytes(source_payload[FINAL_PPTX_PATH], source_payload[FINAL_PDF_PATH])
    except FinalsMaterialError as exc:
        raise FinalsBuildError(f"finals material semantic gate failed: {exc}") from exc
    expected_sbom, expected_licenses = _supply_chain_records(source_payload, context)
    if entries[SBOM_NAME] != expected_sbom or entries[LICENSES_NAME] != expected_licenses:
        raise FinalsBuildError("SBOM or third-party licenses do not match committed inputs")
    video_index = entries.get(VIDEO_INDEX_NAME)
    if entries[PROVENANCE_NAME] != _provenance(
        source_payload,
        context,
        expected_sbom,
        expected_licenses,
        video_index,
    ):
        raise FinalsBuildError("PROVENANCE.json does not match package materials")
    extractor = _pdf_extractor or PypdfPdfTextExtractor()
    for path in sorted(source_paths, key=_sort_key):
        _scan_source(path, entries[path], extractor)
    return context


def verify_submission_archive(
    archive: Path,
    *,
    _pdf_extractor: PdfTextExtractor | None = None,
) -> ReleaseContext:
    """Read and verify one existing archive without extracting it."""

    candidate = archive if archive.is_absolute() else Path.cwd() / archive
    try:
        metadata = candidate.lstat()
    except OSError as exc:
        raise FinalsBuildError("finals archive is missing or unreadable") from exc
    if (
        candidate.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size > MAX_ARCHIVE_BYTES
    ):
        raise FinalsBuildError("finals archive must be a regular non-symlink file")
    try:
        data = candidate.read_bytes()
    except OSError as exc:
        raise FinalsBuildError("finals archive could not be read") from exc
    return verify_submission_bytes(data, _pdf_extractor=_pdf_extractor)


def _exclusive_atomic_write(path: Path, data: bytes) -> None:
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise FinalsBuildError("output directory is missing") from exc
    if path.suffix.lower() != ".zip" or path.exists() or path.is_symlink():
        raise FinalsBuildError("output must be a new .zip file; overwrite is forbidden")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
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
        raise FinalsBuildError("finals output cannot be committed without overwrite") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def build_submission(
    *,
    repo_root: Path,
    output: Path,
    ref: str,
    demo_video: Path | None = None,
    _git: GitClient | None = None,
    _pdf_extractor: PdfTextExtractor | None = None,
) -> BuildResult:
    """Build one finals archive from a clean Git commit object."""

    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise FinalsBuildError("repository root is missing") from exc
    if not root.is_dir() or repo_root.is_symlink():
        raise FinalsBuildError("repository root must be a regular directory")
    destination = output if output.is_absolute() else root / output
    git = _git or SubprocessGitClient()
    extractor = _pdf_extractor or PypdfPdfTextExtractor()
    before = _read_release_state(root, ref, git)
    archive = _assemble(root, before, git, extractor, demo_video)
    after = _read_release_state(root, ref, git)
    if before != after:
        raise FinalsBuildError("repository state changed during the finals build")
    _exclusive_atomic_write(destination, archive)
    return BuildResult(destination, len(archive), _sha256(archive), before.commit, before.ref)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build from one clean Git tag or commit")
    build.add_argument(
        "--ref",
        "--tag",
        "--commit",
        dest="ref",
        required=True,
        help="tag or commit that must resolve to clean HEAD",
    )
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--demo-video", type=Path)
    verify = commands.add_parser("verify", help="verify a finals release archive")
    verify.add_argument("archive", type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "build":
            result = build_submission(
                repo_root=REPOSITORY_ROOT,
                output=arguments.output,
                ref=arguments.ref,
                demo_video=arguments.demo_video,
            )
            output = {
                "commit": result.commit,
                "ok": True,
                "path": str(result.output),
                "ref": result.ref,
                "sha256": result.sha256,
                "size": result.size,
            }
        else:
            context = verify_submission_archive(arguments.archive)
            output = {
                "commit": context.commit,
                "ok": True,
                "project": context.project,
                "ref": context.ref,
                "version": context.version,
            }
    except FinalsBuildError as exc:
        print(json.dumps({"error": str(exc), "ok": False}, ensure_ascii=False, sort_keys=True))
        return 1
    print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

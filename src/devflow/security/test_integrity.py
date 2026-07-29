"""Deterministic policy helpers for immutable baseline tests."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from devflow.exceptions import MCPError
from devflow.models.patch import ChangeType, Patch, canonical_repository_path, is_test_path
from devflow.models.test_integrity import (
    TEST_INTEGRITY_CONTROL_NAMES,
    TEST_INTEGRITY_IGNORED_PARTS,
    TEST_INTEGRITY_NON_PYTHON_OUTCOME_MARKERS,
    TEST_INTEGRITY_PYTHON_COLLECTION_ASSIGNMENTS,
    TEST_INTEGRITY_PYTHON_COLLECTION_HOOKS,
    TEST_INTEGRITY_PYTHON_OUTCOME_CALLS,
    TEST_INTEGRITY_PYTHON_OUTCOME_DECORATORS,
    canonical_integrity_digest,
)

_IGNORED_PARTS = frozenset(TEST_INTEGRITY_IGNORED_PARTS)
_TEST_CONTROL_NAMES = frozenset(TEST_INTEGRITY_CONTROL_NAMES)
_PYTHON_OUTCOME_CALLS = frozenset(TEST_INTEGRITY_PYTHON_OUTCOME_CALLS)
_PYTHON_OUTCOME_DECORATORS = frozenset(TEST_INTEGRITY_PYTHON_OUTCOME_DECORATORS)
_PYTHON_COLLECTION_HOOKS = frozenset(TEST_INTEGRITY_PYTHON_COLLECTION_HOOKS)
_PYTHON_COLLECTION_ASSIGNMENTS = frozenset(
    TEST_INTEGRITY_PYTHON_COLLECTION_ASSIGNMENTS
)
_NON_PYTHON_OUTCOME_MARKERS = TEST_INTEGRITY_NON_PYTHON_OUTCOME_MARKERS


@dataclass(frozen=True)
class ProtectedManifest:
    """Canonical digest map for repository-owned test inputs."""

    entries: tuple[tuple[str, str], ...]
    digest: str

    @classmethod
    def create(cls, entries: Iterable[tuple[str, str]]) -> ProtectedManifest:
        ordered = tuple(sorted(entries))
        return cls(entries=ordered, digest=canonical_integrity_digest(ordered))

    @property
    def paths(self) -> frozenset[str]:
        return frozenset(path for path, _digest in self.entries)

    def project(self, paths: Iterable[str]) -> ProtectedManifest:
        selected = frozenset(paths)
        return self.create(entry for entry in self.entries if entry[0] in selected)

    def added_since(self, baseline: ProtectedManifest) -> ProtectedManifest:
        return self.create(entry for entry in self.entries if entry[0] not in baseline.paths)


def is_test_control_path(value: str) -> bool:
    """Return whether a path can change test discovery or execution policy."""

    path = canonical_repository_path(value)
    name = path.rsplit("/", 1)[-1].lower()
    return name == "conftest.py" or name in _TEST_CONTROL_NAMES


def is_protected_test_path(value: str) -> bool:
    """Return whether a repository file belongs to the immutable baseline."""

    path = PurePosixPath(canonical_repository_path(value))
    directory_parts = {part.casefold() for part in path.parts[:-1]}
    if directory_parts.intersection({"test", "tests", "__tests__", "spec", "specs"}):
        return True
    name = path.name.casefold()
    stem = name.rsplit(".", 1)[0]
    conventionally_named = bool(
        (len(path.parts) == 1 and stem.startswith(("test_", "test-")))
        or stem.endswith(("_test", "-test", ".test", "_spec", "-spec", ".spec"))
        or ".test." in name
        or ".spec." in name
    )
    return conventionally_named or is_test_control_path(value)


def patch_integrity_violations(
    patch: Patch,
    *,
    baseline_protected_paths: Iterable[str] = (),
) -> tuple[str, ...]:
    """Return bounded policy codes for one untrusted candidate patch."""

    baseline = frozenset(canonical_repository_path(path) for path in baseline_protected_paths)
    violations: set[str] = set()
    for change in patch.changes:
        try:
            path = canonical_repository_path(change.file_path)
        except ValueError:
            violations.add("repository_path_invalid")
            continue
        if path in baseline or (
            is_protected_test_path(path)
            and not is_test_control_path(path)
            and change.change_type is not ChangeType.CREATE
        ):
            violations.add("existing_protected_test_changed")
        if is_test_control_path(path):
            violations.add("test_control_file_changed")
        if change.new_content is not None and _contains_outcome_control(
            path, change.new_content
        ):
            violations.add("test_outcome_control_directive")
    return tuple(sorted(violations))


def require_patch_integrity(
    patch: Patch,
    *,
    baseline_protected_paths: Iterable[str] = (),
) -> None:
    """Fail closed when a patch could manufacture a green test result."""

    violations = patch_integrity_violations(
        patch,
        baseline_protected_paths=baseline_protected_paths,
    )
    if violations:
        raise MCPError(f"test_integrity_violation:{','.join(violations)}")


def collect_protected_manifest(repository: Path) -> ProtectedManifest:
    """Hash every conventional test and test-control file below a checkout."""

    root = repository.resolve()
    if not root.is_dir():
        raise MCPError("test_integrity_violation:repository_missing")
    entries: list[tuple[str, str]] = []
    for candidate in root.rglob("*"):
        relative = candidate.relative_to(root)
        if any(part in _IGNORED_PARTS for part in relative.parts):
            continue
        relative_path = relative.as_posix()
        if not is_protected_test_path(relative_path):
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise MCPError("test_integrity_violation:protected_path_not_regular_file")
        try:
            digest = canonical_integrity_digest(
                {"bytes_sha256": _sha256_file(candidate)}
            )
        except OSError as exc:
            raise MCPError("test_integrity_violation:protected_file_unreadable") from exc
        entries.append((relative_path, digest))
    return ProtectedManifest.create(entries)


def require_same_manifest(
    expected: ProtectedManifest,
    actual: ProtectedManifest,
    *,
    violation: str,
) -> None:
    """Fail without leaking paths when two protected manifests differ."""

    if expected.entries != actual.entries:
        raise MCPError(f"test_integrity_violation:{violation}")


def _contains_outcome_control(path: str, content: str) -> bool:
    if path.lower().endswith(".py"):
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # The normal patch validator or test command owns syntax errors.
            # A textual fallback still catches obvious test-control attempts.
            lowered = content.casefold()
            return any(marker.casefold() in lowered for marker in _PYTHON_OUTCOME_CALLS)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in _PYTHON_COLLECTION_HOOKS:
                    return True
                if any(
                    _qualified_name(decorator) in _PYTHON_OUTCOME_DECORATORS
                    for decorator in node.decorator_list
                ):
                    return True
            if (
                isinstance(node, ast.Call)
                and _qualified_name(node.func) in _PYTHON_OUTCOME_DECORATORS
            ):
                return True
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(
                    isinstance(target, ast.Name)
                    and target.id in _PYTHON_COLLECTION_ASSIGNMENTS
                    for target in targets
                ):
                    return True
        return False

    if is_test_path(path) or is_test_control_path(path):
        lowered = content.casefold().replace(" ", "")
        return any(marker in lowered for marker in _NON_PYTHON_OUTCOME_MARKERS)
    return False


def _qualified_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    if isinstance(current, ast.Call):
        current = current.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "ProtectedManifest",
    "collect_protected_manifest",
    "is_protected_test_path",
    "is_test_control_path",
    "patch_integrity_violations",
    "require_patch_integrity",
    "require_same_manifest",
]

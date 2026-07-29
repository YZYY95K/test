"""Server-owned isolated test execution used by the CI/CD MCP tool."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from devflow.exceptions import MCPError
from devflow.models.patch import ChangeType, Patch
from devflow.models.test_integrity import (
    TEST_INTEGRITY_IGNORED_PARTS,
    TEST_INTEGRITY_POLICY,
    TEST_INTEGRITY_POLICY_DIGEST,
    TEST_ISOLATION_BOUNDARY,
    TestIntegrityAttestation,
    canonical_integrity_digest,
)
from devflow.models.test_result import (
    BaselineComparison,
    TestCaseResult,
    TestRunResult,
    TestStatus,
)
from devflow.security.secrets import redact_text
from devflow.security.test_integrity import (
    collect_protected_manifest,
    require_patch_integrity,
    require_same_manifest,
)

_COPY_IGNORE = shutil.ignore_patterns(*TEST_INTEGRITY_IGNORED_PARTS)

# Test commands receive only process bootstrap values.  In particular, tokens,
# cloud credentials, SSH agents, and user-provided environment values do not
# cross into repository-owned test code by default.
_SAFE_COMMAND_ENVIRONMENT = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PATHEXT",
        "PYTHONHASHSEED",
        "PYTHONPATH",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)


def isolated_command_environment(
    source: Mapping[str, str] | None = None,
    *,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build the explicit, secret-free environment for an untrusted command.

    ``extra`` is reserved for trusted server-owned adapters.  Callers must
    provide exact values and cannot inherit arbitrary process environment.
    """

    selected = source if source is not None else os.environ
    environment = {
        key: value for key, value in selected.items() if key.upper() in _SAFE_COMMAND_ENVIRONMENT
    }
    if extra:
        for key, value in extra.items():
            if not key or "=" in key or "\x00" in key or "\x00" in value:
                raise MCPError("provider environment contains an invalid entry")
            environment[key] = value
    return environment


@dataclass(frozen=True)
class CommandOutcome:
    """Bounded result from the server-owned test adapter."""

    returncode: int
    output: str
    duration_ms: int


class IsolatedTestService:
    """Apply a validated candidate only to disposable repository copies.

    The boundary prevents patch and test-process writes from touching the
    canonical checkout and attests protected test inputs before and after
    execution.  It uses stdlib temporary directories and subprocesses; it is
    deliberately *not* described as a container or operating-system sandbox.
    """

    def __init__(
        self,
        repository_root: Path,
        command: tuple[str, ...],
        *,
        timeout_seconds: int = 600,
    ) -> None:
        resolved = repository_root.resolve()
        if not resolved.is_dir():
            raise MCPError(f"repository root is not a directory: {resolved}")
        if not command or not all(command):
            raise MCPError("test command must be a non-empty server-owned argv")
        if timeout_seconds < 1 or timeout_seconds > 3600:
            raise MCPError("test timeout must be between 1 and 3600 seconds")
        self.repository_root = resolved
        self.command = command
        self.timeout_seconds = timeout_seconds

    async def run_tests(self, patch: Patch, *, full_suite: bool) -> TestRunResult:
        """Execute baseline and candidate without mutating the canonical checkout."""

        return await asyncio.to_thread(self._run_tests_sync, patch, full_suite)

    def _run_tests_sync(self, patch: Patch, full_suite: bool) -> TestRunResult:
        canonical_baseline = collect_protected_manifest(self.repository_root)
        require_patch_integrity(
            patch,
            baseline_protected_paths=canonical_baseline.paths,
        )
        with tempfile.TemporaryDirectory(prefix="devflow-cicd-") as temp_dir:
            baseline_repository = Path(temp_dir) / "baseline"
            candidate_repository = Path(temp_dir) / "candidate"
            shutil.copytree(
                self.repository_root,
                baseline_repository,
                ignore=_COPY_IGNORE,
            )
            shutil.copytree(
                self.repository_root,
                candidate_repository,
                ignore=_COPY_IGNORE,
            )

            baseline_pre_run = collect_protected_manifest(baseline_repository)
            require_same_manifest(
                canonical_baseline,
                baseline_pre_run,
                violation="baseline_copy_mismatch",
            )
            baseline = self.execute(baseline_repository)
            baseline_post_run = collect_protected_manifest(baseline_repository)
            require_same_manifest(
                baseline_pre_run,
                baseline_post_run,
                violation="baseline_tests_mutated_during_execution",
            )

            self._apply_patch(candidate_repository, patch)
            candidate_pre_run = collect_protected_manifest(candidate_repository)
            candidate_baseline = candidate_pre_run.project(canonical_baseline.paths)
            require_same_manifest(
                canonical_baseline,
                candidate_baseline,
                violation="candidate_changed_immutable_baseline",
            )
            added_tests = candidate_pre_run.added_since(canonical_baseline)
            current = self.execute(candidate_repository)
            candidate_post_run = collect_protected_manifest(candidate_repository)
            require_same_manifest(
                candidate_pre_run,
                candidate_post_run,
                violation="candidate_tests_mutated_during_execution",
            )

        attestation = TestIntegrityAttestation(
            schema_version="1.0",
            policy=TEST_INTEGRITY_POLICY,
            policy_digest=TEST_INTEGRITY_POLICY_DIGEST,
            command_digest=canonical_integrity_digest(
                {"argv": list(self.command), "full_suite": full_suite}
            ),
            baseline_manifest_digest=canonical_baseline.digest,
            candidate_baseline_manifest_digest=candidate_baseline.digest,
            candidate_pre_run_manifest_digest=candidate_pre_run.digest,
            candidate_post_run_manifest_digest=candidate_post_run.digest,
            added_tests_manifest_digest=added_tests.digest,
            baseline_protected_file_count=len(canonical_baseline.entries),
            added_test_file_count=len(added_tests.entries),
            full_suite=full_suite,
            verified=True,
            isolation_boundary=TEST_ISOLATION_BOUNDARY,
        )

        baseline_passed = int(baseline.returncode == 0)
        current_passed = int(current.returncode == 0)
        case_name = "server-owned-full-suite" if full_suite else "server-owned-focused-suite"
        passed = current_passed
        failed = int(current.returncode != 0)
        return TestRunResult(
            total=1,
            passed=passed,
            failed=failed,
            errors=0,
            skipped=0,
            duration_ms=current.duration_ms,
            results=[
                TestCaseResult(
                    name=case_name,
                    status=TestStatus.PASSED if current.returncode == 0 else TestStatus.FAILED,
                    duration_ms=current.duration_ms,
                    error_message=(
                        None if current.returncode == 0 else "Server-owned test adapter failed."
                    ),
                    traceback=None if current.returncode == 0 else current.output[-4000:],
                )
            ],
            baseline_comparison=BaselineComparison(
                baseline_passed=baseline_passed,
                current_passed=current_passed,
                new_failures=[case_name]
                if baseline.returncode == 0 and current.returncode != 0
                else [],
                fixed_tests=[case_name]
                if baseline.returncode != 0 and current.returncode == 0
                else [],
                regression=baseline.returncode == 0 and current.returncode != 0,
            ),
            integrity_attestation=attestation,
        )

    def execute(
        self,
        repository: Path,
        *,
        command: tuple[str, ...] | None = None,
    ) -> CommandOutcome:
        """Run the server-owned command in the supplied checkout."""

        resolved = repository.resolve()
        if not resolved.is_dir():
            raise MCPError("test execution root must be a directory")
        argv = command or self.command
        if not argv or not all(argv):
            raise MCPError("test command must be a non-empty server-owned argv")
        started = time.perf_counter()
        try:
            process = subprocess.run(
                list(argv),
                cwd=repository,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
                env=isolated_command_environment(),
            )
        except subprocess.TimeoutExpired as exc:
            stdout = (
                exc.stdout.decode(errors="replace")
                if isinstance(exc.stdout, bytes)
                else exc.stdout or ""
            )
            stderr = (
                exc.stderr.decode(errors="replace")
                if isinstance(exc.stderr, bytes)
                else exc.stderr or ""
            )
            output, _redacted = redact_text(stdout + stderr)
            return CommandOutcome(
                returncode=124,
                output=f"test adapter timed out\n{output}"[-4000:],
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        output, _redacted = redact_text(process.stdout + process.stderr)
        return CommandOutcome(
            returncode=process.returncode,
            output=output[-4000:],
            duration_ms=int((time.perf_counter() - started) * 1000),
        )

    @staticmethod
    def _apply_patch(repository: Path, patch: Patch) -> None:
        for change in patch.changes:
            relative = PurePosixPath(change.file_path.replace("\\", "/"))
            if relative.is_absolute() or ".." in relative.parts:
                raise MCPError(f"patch path escapes repository: {change.file_path}")
            target = repository.joinpath(*relative.parts)
            if repository not in target.resolve().parents:
                raise MCPError(f"patch path escapes repository: {change.file_path}")
            existing = target.read_text(encoding="utf-8") if target.exists() else None
            if change.change_type is ChangeType.CREATE:
                if existing is not None:
                    raise MCPError(f"create target already exists: {change.file_path}")
                if change.new_content is None:
                    raise MCPError(f"create requires new content: {change.file_path}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(change.new_content, encoding="utf-8")
            elif change.change_type is ChangeType.MODIFY:
                if existing is None:
                    raise MCPError(f"modify target is missing: {change.file_path}")
                if change.original_content is not None and existing != change.original_content:
                    raise MCPError(f"stale original content: {change.file_path}")
                if change.new_content is None:
                    raise MCPError(f"modify requires new content: {change.file_path}")
                target.write_text(change.new_content, encoding="utf-8")
            else:
                if existing is None:
                    raise MCPError(f"delete target is missing: {change.file_path}")
                if change.original_content is not None and existing != change.original_content:
                    raise MCPError(f"stale original content: {change.file_path}")
                target.unlink()


__all__ = ["CommandOutcome", "IsolatedTestService", "isolated_command_environment"]

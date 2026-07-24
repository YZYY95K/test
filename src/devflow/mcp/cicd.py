"""Server-owned isolated test execution used by the CI/CD MCP tool."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from devflow.exceptions import MCPError
from devflow.models.patch import ChangeType, Patch
from devflow.models.test_result import (
    BaselineComparison,
    TestCaseResult,
    TestRunResult,
    TestStatus,
)


@dataclass(frozen=True)
class CommandOutcome:
    """Bounded result from the server-owned test adapter."""

    returncode: int
    output: str
    duration_ms: int


class IsolatedTestService:
    """Apply a validated candidate only to a disposable repository copy."""

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
        baseline = self.execute(self.repository_root)
        with tempfile.TemporaryDirectory(prefix="devflow-cicd-") as temp_dir:
            candidate = Path(temp_dir) / "repo"
            shutil.copytree(
                self.repository_root,
                candidate,
                ignore=shutil.ignore_patterns(".git", ".devflow", "__pycache__"),
            )
            self._apply_patch(candidate, patch)
            current = self.execute(candidate)

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
        )

    def execute(self, repository: Path) -> CommandOutcome:
        """Run the server-owned command in the supplied checkout."""

        resolved = repository.resolve()
        if not resolved.is_dir():
            raise MCPError("test execution root must be a directory")
        started = time.perf_counter()
        try:
            process = subprocess.run(
                list(self.command),
                cwd=repository,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or ""
            stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or ""
            output = stdout + stderr
            return CommandOutcome(
                returncode=124,
                output=f"test adapter timed out\n{output}"[-4000:],
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        return CommandOutcome(
            returncode=process.returncode,
            output=(process.stdout + process.stderr)[-4000:],
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


__all__ = ["CommandOutcome", "IsolatedTestService"]

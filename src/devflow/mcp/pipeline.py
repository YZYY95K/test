"""Stateful CI pipeline, coverage, and bounded rollback provider adapters."""

from __future__ import annotations

import asyncio
import io
import json
import re
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from collections.abc import Mapping
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.request import urlopen

from pydantic import BaseModel, Field

from devflow.exceptions import MCPError
from devflow.mcp.cicd import (
    CommandOutcome,
    IsolatedTestService,
    isolated_command_environment,
)
from devflow.observability import metrics

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_GIT_OBJECT_ID = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")


class CoverageResult(BaseModel):
    """Coverage evidence captured from a disposable checkout."""

    line_percent: float | None = Field(default=None, ge=0, le=100)
    branch_percent: float | None = Field(default=None, ge=0, le=100)
    source: str


class PipelineRecord(BaseModel):
    """Client view of one server-owned test pipeline."""

    pipeline_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    branch: str
    commit_sha: str = Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    tree_sha: str = Field(pattern=r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
    suite: str
    status: str = Field(pattern=r"^(queued|running|passed|failed)$")
    created_at: datetime
    completed_at: datetime | None = None
    returncode: int | None = None
    duration_ms: int | None = None
    output_tail: str | None = None
    coverage: CoverageResult | None = None


class PipelineService:
    """Execute suite-specific CI commands from an exact committed Git tree.

    A requested ref is resolved once to a commit and tree object before any
    test command starts.  The command runs from a validated ``git archive``
    extraction, so dirty working-tree content and later ref movement cannot
    affect the recorded pipeline evidence.
    """

    def __init__(
        self,
        test_service: IsolatedTestService,
        *,
        suite_commands: Mapping[str, tuple[str, ...]] | None = None,
    ) -> None:
        self._test_service = test_service
        commands = suite_commands or {"full": test_service.command}
        self._suite_commands = dict(commands)
        if not self._suite_commands:
            raise MCPError("at least one CI suite command must be configured")
        for suite, command in self._suite_commands.items():
            if suite not in {"full", "affected", "smoke"}:
                raise MCPError(f"unsupported configured CI suite: {suite}")
            if not command or not all(command):
                raise MCPError(f"CI suite {suite} has an invalid server-owned argv")
        self._records: dict[str, PipelineRecord] = {}
        self._tasks: dict[str, asyncio.Task[PipelineRecord]] = {}
        self._lock = asyncio.Lock()

    async def trigger(self, *, branch: str, suite: str) -> PipelineRecord:
        if not _SAFE_REF.fullmatch(branch) or ".." in branch:
            raise MCPError("pipeline branch is unsafe")
        command = self._suite_commands.get(suite)
        if command is None:
            raise MCPError("pipeline suite has no server-owned command")
        commit_sha, tree_sha = await asyncio.to_thread(self._resolve_revision, branch)
        pipeline_id = uuid.uuid4().hex
        record = PipelineRecord(
            pipeline_id=pipeline_id,
            branch=branch,
            commit_sha=commit_sha,
            tree_sha=tree_sha,
            suite=suite,
            status="queued",
            created_at=datetime.now(timezone.utc),
        )
        async with self._lock:
            self._records[pipeline_id] = record
            self._tasks[pipeline_id] = asyncio.create_task(self._run_pipeline(record, command))
        return record

    async def _run_pipeline(
        self,
        record: PipelineRecord,
        command: tuple[str, ...],
    ) -> PipelineRecord:
        pipeline_id = record.pipeline_id
        suite = record.suite
        metrics.gauge("devflow_pipeline_active").inc()
        started = time.perf_counter()
        try:
            running = record.model_copy(update={"status": "running"})
            async with self._lock:
                self._records[pipeline_id] = running
            outcome, coverage = await asyncio.to_thread(
                self._execute_disposable,
                record.commit_sha,
                command,
            )
            outcome_label = "passed" if outcome.returncode == 0 else "failed"
            completed = running.model_copy(
                update={
                    "status": outcome_label,
                    "completed_at": datetime.now(timezone.utc),
                    "returncode": outcome.returncode,
                    "duration_ms": outcome.duration_ms,
                    "output_tail": outcome.output,
                    "coverage": coverage,
                }
            )
            async with self._lock:
                self._records[pipeline_id] = completed
            metrics.counter("devflow_pipeline_total").inc(
                labels={"suite": suite, "outcome": outcome_label}
            )
            metrics.histogram("devflow_pipeline_duration_seconds").observe(
                outcome.duration_ms / 1000,
                labels={"suite": suite, "outcome": outcome_label},
            )
            return completed
        except asyncio.CancelledError:
            cancelled = record.model_copy(
                update={
                    "status": "failed",
                    "completed_at": datetime.now(timezone.utc),
                    "output_tail": "pipeline execution was cancelled",
                }
            )
            async with self._lock:
                self._records[pipeline_id] = cancelled
            metrics.counter("devflow_pipeline_total").inc(
                labels={"suite": suite, "outcome": "cancelled"}
            )
            raise
        except Exception as exc:
            failed = record.model_copy(
                update={
                    "status": "failed",
                    "completed_at": datetime.now(timezone.utc),
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                    "output_tail": f"pipeline adapter failed: {type(exc).__name__}",
                }
            )
            async with self._lock:
                self._records[pipeline_id] = failed
            metrics.counter("devflow_pipeline_total").inc(
                labels={"suite": suite, "outcome": "infrastructure_failed"}
            )
            return failed
        finally:
            metrics.gauge("devflow_pipeline_active").dec()
            async with self._lock:
                self._tasks.pop(pipeline_id, None)

    async def get(self, pipeline_id: str, *, wait_seconds: int = 0) -> PipelineRecord:
        if not 0 <= wait_seconds <= 120:
            raise MCPError("wait_seconds must be between 0 and 120")
        async with self._lock:
            record = self._records.get(pipeline_id)
            task = self._tasks.get(pipeline_id)
        if record is None:
            raise MCPError("pipeline id is unknown")
        if task is not None and not task.done() and wait_seconds:
            with suppress(TimeoutError):
                await asyncio.wait_for(asyncio.shield(task), timeout=wait_seconds)
            async with self._lock:
                record = self._records[pipeline_id]
        return record

    async def coverage(self, pipeline_id: str) -> CoverageResult:
        record = await self.get(pipeline_id)
        if record.status not in {"passed", "failed"}:
            raise MCPError("pipeline coverage is not ready")
        return record.coverage or CoverageResult(source="not-produced")

    def _resolve_revision(self, requested_ref: str) -> tuple[str, str]:
        commit = self._git_output(
            ("rev-parse", "--verify", "--end-of-options", f"{requested_ref}^{{commit}}")
        )
        if _GIT_OBJECT_ID.fullmatch(commit) is None:
            raise MCPError("pipeline ref did not resolve to a Git commit")
        tree = self._git_output(("rev-parse", "--verify", "--end-of-options", f"{commit}^{{tree}}"))
        if _GIT_OBJECT_ID.fullmatch(tree) is None:
            raise MCPError("pipeline commit did not resolve to a Git tree")
        return commit, tree

    def _git_output(self, arguments: tuple[str, ...]) -> str:
        try:
            process = subprocess.run(
                ["git", "-C", str(self._test_service.repository_root), *arguments],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                shell=False,
                env=isolated_command_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MCPError("Git repository adapter is unavailable") from exc
        if process.returncode != 0:
            raise MCPError("pipeline ref is unavailable in the configured repository")
        return process.stdout.strip().casefold()

    def _execute_disposable(
        self,
        commit_sha: str,
        command: tuple[str, ...],
    ) -> tuple[CommandOutcome, CoverageResult | None]:
        with tempfile.TemporaryDirectory(prefix="devflow-pipeline-") as temp_dir:
            candidate = Path(temp_dir) / "repo"
            candidate.mkdir()
            archive = self._git_archive(commit_sha)
            _extract_git_archive(archive, candidate)
            outcome = self._test_service.execute(candidate, command=command)
            return outcome, _read_coverage(candidate / "coverage.json")

    def _git_archive(self, commit_sha: str) -> bytes:
        try:
            process = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self._test_service.repository_root),
                    "archive",
                    "--format=tar",
                    commit_sha,
                ],
                capture_output=True,
                timeout=60,
                check=False,
                shell=False,
                env=isolated_command_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MCPError("Git archive adapter is unavailable") from exc
        if process.returncode != 0 or not process.stdout:
            raise MCPError("resolved pipeline commit could not be archived")
        return process.stdout


def _extract_git_archive(payload: bytes, destination: Path) -> None:
    """Extract regular Git tree files while rejecting link and path escapes."""

    root = destination.resolve()
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            for member in archive.getmembers():
                if "\\" in member.name or "\x00" in member.name:
                    raise MCPError("Git archive contains an ambiguous path")
                relative = PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise MCPError("Git archive path escapes the disposable checkout")
                normalized = relative.as_posix().rstrip("/")
                if not normalized or normalized in seen:
                    raise MCPError("Git archive contains an invalid duplicate path")
                seen.add(normalized)
                target = destination.joinpath(*relative.parts)
                resolved = target.resolve(strict=False)
                if resolved != root and root not in resolved.parents:
                    raise MCPError("Git archive path escapes the disposable checkout")
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise MCPError("Git archive contains an unsupported link or device")
                source = archive.extractfile(member)
                if source is None:
                    raise MCPError("Git archive file payload is unavailable")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("xb") as handle:
                    while chunk := source.read(1024 * 1024):
                        handle.write(chunk)
                if member.mode & stat.S_IXUSR:
                    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    except (OSError, tarfile.TarError) as exc:
        raise MCPError("Git archive is invalid or cannot be extracted") from exc


class RollbackResult(BaseModel):
    environment: str
    previous_release: str
    restored_release: str
    health_verified: bool
    rolled_back_at: datetime


class RollbackService:
    """Rollback through a server-owned provider command and atomic state file."""

    def __init__(
        self,
        state_path: Path,
        *,
        command: tuple[str, ...] | None = None,
        health_check_url: str | None = None,
        timeout_seconds: int = 120,
    ) -> None:
        if command is not None and (not command or not all(command)):
            raise MCPError("rollback command must be a non-empty server-owned argv")
        if timeout_seconds < 1 or timeout_seconds > 600:
            raise MCPError("rollback timeout must be between 1 and 600 seconds")
        self.state_path = state_path
        self.command = command
        self.health_check_url = health_check_url
        self.timeout_seconds = timeout_seconds
        self._lock = threading.RLock()

    async def rollback(
        self,
        *,
        environment: str,
        target_release: str | None,
        provider_environment: Mapping[str, str] | None = None,
    ) -> RollbackResult:
        started = time.perf_counter()
        try:
            result = await asyncio.to_thread(
                self._rollback_sync,
                environment,
                target_release,
                dict(provider_environment or {}),
            )
        except Exception:
            metrics.counter("devflow_rollback_total").inc(
                labels={"environment": environment, "outcome": "failed"}
            )
            raise
        metrics.counter("devflow_rollback_total").inc(
            labels={"environment": environment, "outcome": "succeeded"}
        )
        metrics.histogram("devflow_rollback_duration_seconds").observe(
            time.perf_counter() - started,
            labels={"environment": environment, "outcome": "succeeded"},
        )
        return result

    def _rollback_sync(
        self,
        environment: str,
        target_release: str | None,
        provider_environment: Mapping[str, str],
    ) -> RollbackResult:
        with self._lock:
            return self._rollback_locked(
                environment,
                target_release,
                provider_environment,
            )

    def _rollback_locked(
        self,
        environment: str,
        target_release: str | None,
        provider_environment: Mapping[str, str],
    ) -> RollbackResult:
        if environment not in {"staging", "production"}:
            raise MCPError("rollback environment is unsupported")
        if self.command is None:
            raise MCPError("rollback provider command is not configured")
        if not self.health_check_url:
            raise MCPError("rollback health check is not configured")
        state = self._load_state()
        entry = state.get(environment)
        if not isinstance(entry, dict):
            raise MCPError("release registry has no environment state")
        current = entry.get("current")
        previous = entry.get("previous")
        target = target_release or previous
        if not isinstance(current, str) or not isinstance(target, str):
            raise MCPError("release registry has no rollback target")
        if not _SAFE_REF.fullmatch(current) or not _SAFE_REF.fullmatch(target):
            raise MCPError("release registry contains an unsafe release")
        known_good = entry.get("known_good", [])
        if not isinstance(known_good, list) or not all(
            isinstance(release, str) and _SAFE_REF.fullmatch(release) for release in known_good
        ):
            raise MCPError("release registry known-good set is invalid")
        allowed_targets = {release for release in known_good if isinstance(release, str)}
        if isinstance(previous, str):
            allowed_targets.add(previous)
        if target not in allowed_targets:
            raise MCPError("rollback target is not registered as known-good")
        if target == current:
            raise MCPError("rollback target is already the active release")
        environment_values = isolated_command_environment(
            extra={
                **provider_environment,
                "DEVFLOW_DEPLOYMENT_ENVIRONMENT": environment,
                "DEVFLOW_TARGET_RELEASE": target,
            }
        )
        try:
            process = subprocess.run(
                list(self.command),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
                env=environment_values,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MCPError("server-owned rollback provider command is unavailable") from exc
        if process.returncode != 0:
            raise MCPError("server-owned rollback provider command failed")
        health_verified = self._health_check()
        if not health_verified:
            raise MCPError("rollback health verification failed")
        entry["current"] = target
        entry["previous"] = current
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        self._write_state(state)
        return RollbackResult(
            environment=environment,
            previous_release=current,
            restored_release=target,
            health_verified=health_verified,
            rolled_back_at=datetime.now(timezone.utc),
        )

    def _load_state(self) -> dict[str, Any]:
        try:
            parsed = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MCPError(f"release registry is unavailable: {exc}") from exc
        if not isinstance(parsed, dict):
            raise MCPError("release registry root must be an object")
        return parsed

    def _write_state(self, state: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
        temporary.replace(self.state_path)

    def _health_check(self) -> bool:
        if not self.health_check_url:
            return False
        try:
            with urlopen(self.health_check_url, timeout=10) as response:  # noqa: S310
                return 200 <= int(response.status) < 300
        except OSError:
            return False


def _read_coverage(path: Path) -> CoverageResult | None:
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        totals = raw.get("totals", {})
        line = totals.get("percent_covered")
        branch = totals.get("percent_covered_branches")
        return CoverageResult(
            line_percent=float(line) if line is not None else None,
            branch_percent=float(branch) if branch is not None else None,
            source="coverage.json",
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise MCPError(f"coverage evidence is invalid: {exc}") from exc


__all__ = [
    "CoverageResult",
    "PipelineRecord",
    "PipelineService",
    "RollbackResult",
    "RollbackService",
]

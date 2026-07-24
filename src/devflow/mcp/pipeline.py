"""Stateful CI pipeline, coverage, and bounded rollback provider adapters."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import urlopen

from pydantic import BaseModel, Field

from devflow.exceptions import MCPError
from devflow.mcp.cicd import CommandOutcome, IsolatedTestService
from devflow.observability import metrics

_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")


class CoverageResult(BaseModel):
    """Coverage evidence captured from a disposable checkout."""

    line_percent: float | None = Field(default=None, ge=0, le=100)
    branch_percent: float | None = Field(default=None, ge=0, le=100)
    source: str


class PipelineRecord(BaseModel):
    """Client view of one server-owned test pipeline."""

    pipeline_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    branch: str
    suite: str
    status: str = Field(pattern=r"^(queued|running|passed|failed)$")
    created_at: datetime
    completed_at: datetime | None = None
    returncode: int | None = None
    duration_ms: int | None = None
    output_tail: str | None = None
    coverage: CoverageResult | None = None


class PipelineService:
    """Execute registered CI commands in disposable repository copies."""

    def __init__(self, test_service: IsolatedTestService) -> None:
        self._test_service = test_service
        self._records: dict[str, PipelineRecord] = {}
        self._lock = asyncio.Lock()

    async def trigger(self, *, branch: str, suite: str) -> PipelineRecord:
        if not _SAFE_REF.fullmatch(branch) or ".." in branch:
            raise MCPError("pipeline branch is unsafe")
        if suite not in {"full", "affected", "smoke"}:
            raise MCPError("pipeline suite is unsupported")
        pipeline_id = uuid.uuid4().hex
        record = PipelineRecord(
            pipeline_id=pipeline_id,
            branch=branch,
            suite=suite,
            status="queued",
            created_at=datetime.now(timezone.utc),
        )
        async with self._lock:
            self._records[pipeline_id] = record
        metrics.gauge("devflow_pipeline_active").inc()
        try:
            running = record.model_copy(update={"status": "running"})
            async with self._lock:
                self._records[pipeline_id] = running
            outcome, coverage = await asyncio.to_thread(self._execute_disposable)
            completed = running.model_copy(
                update={
                    "status": "passed" if outcome.returncode == 0 else "failed",
                    "completed_at": datetime.now(timezone.utc),
                    "returncode": outcome.returncode,
                    "duration_ms": outcome.duration_ms,
                    "output_tail": outcome.output,
                    "coverage": coverage,
                }
            )
            async with self._lock:
                self._records[pipeline_id] = completed
            return completed
        finally:
            metrics.gauge("devflow_pipeline_active").dec()

    async def get(self, pipeline_id: str) -> PipelineRecord:
        async with self._lock:
            record = self._records.get(pipeline_id)
        if record is None:
            raise MCPError("pipeline id is unknown")
        return record

    async def coverage(self, pipeline_id: str) -> CoverageResult:
        record = await self.get(pipeline_id)
        if record.status not in {"passed", "failed"}:
            raise MCPError("pipeline coverage is not ready")
        return record.coverage or CoverageResult(source="not-produced")

    def _execute_disposable(self) -> tuple[CommandOutcome, CoverageResult | None]:
        with tempfile.TemporaryDirectory(prefix="devflow-pipeline-") as temp_dir:
            candidate = Path(temp_dir) / "repo"
            shutil.copytree(
                self._test_service.repository_root,
                candidate,
                ignore=shutil.ignore_patterns(".git", ".devflow", "__pycache__"),
            )
            outcome = self._test_service.execute(candidate)
            return outcome, _read_coverage(candidate / "coverage.json")


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
        self.state_path = state_path
        self.command = command
        self.health_check_url = health_check_url
        self.timeout_seconds = timeout_seconds

    async def rollback(
        self, *, environment: str, target_release: str | None
    ) -> RollbackResult:
        return await asyncio.to_thread(self._rollback_sync, environment, target_release)

    def _rollback_sync(
        self, environment: str, target_release: str | None
    ) -> RollbackResult:
        if environment not in {"staging", "production"}:
            raise MCPError("rollback environment is unsupported")
        state = self._load_state()
        entry = state.get(environment)
        if not isinstance(entry, dict):
            raise MCPError("release registry has no environment state")
        current = entry.get("current")
        previous = entry.get("previous")
        target = target_release or previous
        if not isinstance(current, str) or not isinstance(target, str):
            raise MCPError("release registry has no rollback target")
        if not _SAFE_REF.fullmatch(target):
            raise MCPError("rollback target release is unsafe")
        if self.command:
            environment_values = dict(os.environ)
            environment_values.update(
                {
                    "DEVFLOW_DEPLOYMENT_ENVIRONMENT": environment,
                    "DEVFLOW_TARGET_RELEASE": target,
                }
            )
            process = subprocess.run(
                list(self.command),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
                env=environment_values,
            )
            if process.returncode != 0:
                raise MCPError("server-owned rollback provider command failed")
        health_verified = self._health_check()
        if self.health_check_url and not health_verified:
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
            return True
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

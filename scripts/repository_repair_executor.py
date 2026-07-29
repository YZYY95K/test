"""Safe execution kernel for the fixed repository-repair benchmark.

The kernel deliberately does not know how to call an LLM.  A caller supplies a
``PatchProvider`` which receives only the public issue, allowed target paths,
mutated source bytes decoded as UTF-8, and a bounded/redacted failing-test
summary.  In particular, neither ``SourceMutation.before`` nor the manifest is
passed across the provider boundary.

Every selected task runs in a disposable local clone of the exact pinned Git
commit.  Provider output is a structured full-file replacement rather than a
shell command or free-form diff, which keeps path and stale-write checks small
and fail-closed.

This module enforces benchmark provenance, data minimization, path boundaries,
and evidence integrity.  A temporary directory is not an operating-system
sandbox: production runs must still place this process (and any provider
adapter) in the project's low-privilege, network-restricted runner boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol, TypeAlias

from pydantic import Field, ValidationError, field_validator, model_validator

ROOT = Path(__file__).resolve().parents[1]
for import_path in (ROOT, ROOT / "src"):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from devflow.security.secrets import redact_text  # noqa: E402
from scripts.run_repository_benchmark import (  # noqa: E402
    AcceptanceCommand,
    CommandEvidence,
    ExecutionEvidence,
    RepairBenchmarkManifest,
    RepairBenchmarkReport,
    RepairCostProvenance,
    RepairRepositorySpec,
    RepairTask,
    RepairTaskResult,
    StrictBenchmarkModel,
    _canonical_json,
    _command_sha256,
    _repair_summary,
    _self_digest,
    build_unexecuted_repair_report,
    repair_manifest_sha256,
)

RUNNER: Literal["devflow-repository-repair/v1"] = "devflow-repository-repair/v1"
_ORACLE_REDACTION = "[ORACLE_REDACTED]"
_URL_USERINFO = re.compile(r"(?i)\b(https?://)[^\s/:@]+:[^\s/@]+@")
_IGNORED_RUNTIME_PARTS = frozenset(
    {".git", ".hypothesis", ".mypy_cache", ".pytest_cache", "__pycache__"}
)
_SAFE_ENVIRONMENT_NAMES = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TZ",
    "WINDIR",
)


class PatchSource(StrictBenchmarkModel):
    """One exact mutated source exposed to a patch provider."""

    content: str = Field(max_length=5_000_000)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def _content_digest_matches(self) -> PatchSource:
        if _sha256(self.content.encode("utf-8")) != self.sha256:
            raise ValueError("mutated source digest does not match its UTF-8 content")
        return self


class PatchRequest(StrictBenchmarkModel):
    """The complete and intentionally narrow provider-visible request."""

    issue: str = Field(min_length=1, max_length=2_000)
    target_paths: list[str] = Field(min_length=1, max_length=8)
    mutated_sources: dict[str, PatchSource] = Field(min_length=1, max_length=8)
    failure_summary: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def _sources_exactly_cover_targets(self) -> PatchRequest:
        if len(self.target_paths) != len(set(self.target_paths)):
            raise ValueError("target paths must be unique")
        if set(self.mutated_sources) != set(self.target_paths):
            raise ValueError("mutated sources must exactly cover target paths")
        return self


class FileReplacement(StrictBenchmarkModel):
    """A stale-write-protected, whole-file patch operation."""

    path: str = Field(min_length=1, max_length=512)
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content: str = Field(max_length=5_000_000)

    @field_validator("path")
    @classmethod
    def _canonical_relative_path(cls, value: str) -> str:
        normalized = Path(value.replace("\\", "/"))
        if (
            value != normalized.as_posix()
            or normalized.is_absolute()
            or ".." in normalized.parts
            or not normalized.parts
        ):
            raise ValueError("replacement path must be canonical and repository-relative")
        return value

    @field_validator("content")
    @classmethod
    def _valid_utf8_content(cls, value: str) -> str:
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError("replacement content must encode as UTF-8") from exc
        return value


class PatchProposal(StrictBenchmarkModel):
    """Structured provider response plus measured provider usage."""

    replacements: list[FileReplacement] = Field(min_length=1, max_length=8)
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    human_intervention: bool = False

    @model_validator(mode="after")
    def _replacement_paths_are_unique(self) -> PatchProposal:
        paths = [item.path for item in self.replacements]
        if len(paths) != len(set(paths)):
            raise ValueError("replacement paths must be unique")
        return self


PatchProviderResponse: TypeAlias = PatchProposal | Mapping[str, object]


class PatchProvider(Protocol):
    """Synchronous adapter boundary for an Agent, model, or deterministic stub."""

    def __call__(self, request: PatchRequest, /) -> PatchProviderResponse: ...


class PatchProviderError(RuntimeError):
    """Provider failure carrying usage that was known before it failed."""

    def __init__(
        self,
        message: str = "patch provider failed",
        *,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        estimated_cost_usd: float | None = None,
        human_intervention: bool = False,
    ) -> None:
        super().__init__(message)
        if prompt_tokens < 0 or completion_tokens < 0:
            raise ValueError("provider token counts cannot be negative")
        if estimated_cost_usd is not None and estimated_cost_usd < 0:
            raise ValueError("provider cost cannot be negative")
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.estimated_cost_usd = estimated_cost_usd
        self.human_intervention = human_intervention


@dataclass(frozen=True)
class CommandRun:
    evidence: CommandEvidence
    summary: str


class _TaskExecutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repository: Path, *arguments: str, timeout: int = 30) -> str:
    completed: subprocess.CompletedProcess[str] = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return completed.stdout.strip()


def _assert_pinned_clean_source(
    repository: Path,
    *,
    spec: RepairRepositorySpec,
) -> None:
    if not repository.is_dir() or repository.is_symlink():
        raise _TaskExecutionError("source-unavailable")
    try:
        commit = _git(repository, "rev-parse", "HEAD")
        tree = _git(repository, "rev-parse", "HEAD^{tree}")
        status = _git(repository, "status", "--porcelain", "--untracked-files=all")
    except (OSError, subprocess.SubprocessError) as exc:
        raise _TaskExecutionError("source-binding-failed") from exc
    if commit != spec.commit or tree != spec.tree:
        raise _TaskExecutionError("source-binding-failed")
    if status:
        raise _TaskExecutionError("source-not-clean")


def _clone_pinned_source(source: Path, workspace: Path, spec: RepairRepositorySpec) -> None:
    try:
        subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                "--local",
                "--no-hardlinks",
                "--no-checkout",
                "--",
                str(source),
                str(workspace),
            ],
            capture_output=True,
            check=True,
            timeout=180,
            stdin=subprocess.DEVNULL,
        )
        _git(workspace, "checkout", "--quiet", "--detach", spec.commit, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise _TaskExecutionError("source-copy-failed") from exc
    _assert_pinned_clean_source(workspace, spec=spec)


def _safe_environment(repository: Path, extra_pythonpath: Path | None) -> dict[str, str]:
    environment = {
        name: value
        for name in _SAFE_ENVIRONMENT_NAMES
        if (value := os.environ.get(name)) is not None
    }
    source_root = repository / "src" if (repository / "src").is_dir() else repository
    python_paths = [str(source_root)]
    if extra_pythonpath is not None:
        python_paths.append(str(extra_pythonpath.resolve()))
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": os.pathsep.join(python_paths),
        }
    )
    return environment


def _as_bytes(value: bytes | str | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8", errors="replace")


def _bounded_summary(stdout: bytes, stderr: bytes, *, oracle: str) -> str:
    combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    summary = " | ".join(lines[-8:]) or "command produced no bounded output"
    summary = _URL_USERINFO.sub(r"\1[REDACTED]@", summary)
    summary = str(redact_text(summary)[0])
    summary = _redact_oracle_text(summary, oracle)
    return summary[-2_000:]


def _oracle_variants(oracle: str) -> tuple[str, ...]:
    variants = {oracle, oracle.replace("\r\n", "\n"), oracle.strip()}
    return tuple(sorted((value for value in variants if value), key=len, reverse=True))


def _source_oracle_variants(oracle: str) -> tuple[str, ...]:
    variants = {oracle, oracle.replace("\r\n", "\n"), oracle.replace("\n", "\r\n")}
    return tuple(value for value in variants if value)


def _redact_oracle_text(value: str, oracle: str) -> str:
    for variant in _oracle_variants(oracle):
        value = value.replace(variant, _ORACLE_REDACTION)
    return value


def _run_acceptance(
    repository: Path,
    command: AcceptanceCommand,
    *,
    executable: Path,
    extra_pythonpath: Path | None,
    oracle: str,
) -> CommandRun:
    argv = [str(executable), *command.argv[1:]]
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            cwd=repository,
            capture_output=True,
            check=False,
            timeout=command.timeout_seconds,
            env=_safe_environment(repository, extra_pythonpath),
            stdin=subprocess.DEVNULL,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        evidence = CommandEvidence(
            argv_sha256=_command_sha256(command),
            completed=True,
            exit_code=completed.returncode,
            duration_ms=round((time.perf_counter() - started) * 1_000),
            stdout_sha256=_sha256(stdout),
            stderr_sha256=_sha256(stderr),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = _as_bytes(exc.stdout)
        stderr = _as_bytes(exc.stderr)
        evidence = CommandEvidence(
            argv_sha256=_command_sha256(command),
            completed=False,
            exit_code=None,
            duration_ms=round((time.perf_counter() - started) * 1_000),
            stdout_sha256=_sha256(stdout),
            stderr_sha256=_sha256(stderr),
        )
    except OSError as exc:
        stdout = b""
        stderr = type(exc).__name__.encode("ascii", errors="replace")
        evidence = CommandEvidence(
            argv_sha256=_command_sha256(command),
            completed=False,
            exit_code=None,
            duration_ms=round((time.perf_counter() - started) * 1_000),
            stdout_sha256=_sha256(stdout),
            stderr_sha256=_sha256(stderr),
        )
    return CommandRun(
        evidence=evidence,
        summary=_bounded_summary(stdout, stderr, oracle=oracle),
    )


def _apply_manifest_mutation(repository: Path, task: RepairTask) -> None:
    target = _contained_file(repository, task.mutation.path)
    original = target.read_bytes()
    newline = b"\r\n" if b"\r\n" in original else b"\n"
    before = task.mutation.before.encode("utf-8").replace(b"\n", newline)
    after = task.mutation.after.encode("utf-8").replace(b"\n", newline)
    if original.count(before) != 1:
        raise _TaskExecutionError("mutation-source-mismatch")
    target.write_bytes(original.replace(before, after, 1))
    if _git_changed_paths(repository) != [task.mutation.path]:
        raise _TaskExecutionError("mutation-boundary-failed")


def _contained_file(repository: Path, relative: str) -> Path:
    candidate = repository / Path(relative)
    resolved = candidate.resolve()
    if (
        repository.resolve() not in resolved.parents
        or candidate.is_symlink()
        or not candidate.is_file()
    ):
        raise _TaskExecutionError("target-boundary-failed")
    return candidate


def _git_changed_paths(repository: Path) -> list[str]:
    try:
        tracked = _git(repository, "diff", "--name-only", "--no-renames", "HEAD", "--")
        untracked = _git(repository, "ls-files", "--others", "--exclude-standard")
    except (OSError, subprocess.SubprocessError) as exc:
        raise _TaskExecutionError("workspace-diff-failed") from exc
    return sorted({line for value in (tracked, untracked) for line in value.splitlines() if line})


def _workspace_snapshot(repository: Path) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in repository.rglob("*"):
        relative = path.relative_to(repository)
        if any(part in _IGNORED_RUNTIME_PARTS for part in relative.parts):
            continue
        if path.is_symlink():
            payload = f"SYMLINK:{path.readlink()}".encode()
        elif path.is_file():
            payload = path.read_bytes()
        else:
            continue
        snapshot[relative.as_posix()] = _sha256(payload)
    return snapshot


def _build_provider_request(
    repository: Path, task: RepairTask, failure_summary: str
) -> PatchRequest:
    sources: dict[str, PatchSource] = {}
    for relative in task.target_paths:
        payload = _contained_file(repository, relative).read_bytes()
        try:
            content = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _TaskExecutionError("target-not-utf8") from exc
        _sanitized, credential_detected = redact_text(content)
        if credential_detected:
            raise _TaskExecutionError("source-credential-detected")
        if any(variant in content for variant in _source_oracle_variants(task.mutation.before)):
            raise _TaskExecutionError("oracle-leakage-detected")
        sources[relative] = PatchSource(content=content, sha256=_sha256(payload))
    issue = _redact_oracle_text(task.issue, task.mutation.before)
    summary = _redact_oracle_text(failure_summary, task.mutation.before)
    request = PatchRequest(
        issue=issue,
        target_paths=list(task.target_paths),
        mutated_sources=sources,
        failure_summary=summary,
    )
    public_metadata = json.dumps(
        {
            "failure_summary": request.failure_summary,
            "issue": request.issue,
            "target_paths": request.target_paths,
        },
        ensure_ascii=False,
    )
    if any(variant in public_metadata for variant in _oracle_variants(task.mutation.before)):
        raise _TaskExecutionError("oracle-leakage-detected")
    return request


def _proposal_digest(value: object) -> str:
    if isinstance(value, PatchProposal):
        payload: object = {
            "replacements": [item.model_dump(mode="json") for item in value.replacements]
        }
    elif isinstance(value, Mapping):
        try:
            payload = json.loads(json.dumps(value, allow_nan=False, default=_type_name))
        except Exception:
            payload = {"type": _type_name(value)}
    else:
        payload = {"type": _type_name(value)}
    return _sha256(_canonical_json(payload))


def _request_digest(request: PatchRequest) -> str | None:
    try:
        return _sha256(_canonical_json(request.model_dump(mode="json")))
    except Exception:
        return None


def _type_name(value: object) -> str:
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


def _skipped_acceptance(task: RepairTask) -> list[CommandEvidence]:
    return [
        CommandEvidence(
            argv_sha256=_command_sha256(command),
            completed=False,
            exit_code=None,
            duration_ms=0,
            stdout_sha256=None,
            stderr_sha256=None,
        )
        for command in task.acceptance
    ]


def _seal_result(
    task: RepairTask,
    spec: RepairRepositorySpec,
    *,
    execution_status: Literal["unexecuted", "blocked", "executed"],
    success: bool,
    duration_ms: int,
    prompt_tokens: int,
    completion_tokens: int,
    estimated_cost_usd: float | None,
    human_intervention: bool,
    evidence: ExecutionEvidence | None,
    error_code: str | None,
) -> RepairTaskResult:
    result = RepairTaskResult(
        task_id=task.id,
        repository=task.repository,
        commit=spec.commit,
        execution_status=execution_status,
        success=success,
        duration_ms=duration_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        estimated_cost_usd=estimated_cost_usd,
        human_intervention=human_intervention,
        evidence=evidence,
        error_code=error_code,
        result_sha256="0" * 64,
    )
    return result.model_copy(update={"result_sha256": _self_digest(result, "result_sha256")})


def _blocked_result(
    task: RepairTask,
    spec: RepairRepositorySpec,
    *,
    started: float,
    error_code: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    estimated_cost_usd: float | None = None,
    human_intervention: bool = False,
) -> RepairTaskResult:
    return _seal_result(
        task,
        spec,
        execution_status="blocked",
        success=False,
        duration_ms=round((time.perf_counter() - started) * 1_000),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        estimated_cost_usd=estimated_cost_usd,
        human_intervention=human_intervention,
        evidence=None,
        error_code=error_code,
    )


def _safety_failure_result(
    task: RepairTask,
    spec: RepairRepositorySpec,
    *,
    started: float,
    baseline: CommandEvidence,
    patch_sha256: str,
    proposal: PatchProposal | None,
    error_code: str,
) -> RepairTaskResult:
    evidence = ExecutionEvidence(
        runner=RUNNER,
        baseline=baseline,
        patch_sha256=patch_sha256,
        # The rejected proposal is never applied.  The only actual workspace
        # difference remains the manifest mutation, which is inside the bound.
        changed_paths=[task.mutation.path],
        acceptance=_skipped_acceptance(task),
        safety_pass=False,
    )
    return _seal_result(
        task,
        spec,
        execution_status="executed",
        success=False,
        duration_ms=round((time.perf_counter() - started) * 1_000),
        prompt_tokens=proposal.prompt_tokens if proposal is not None else 0,
        completion_tokens=proposal.completion_tokens if proposal is not None else 0,
        estimated_cost_usd=(proposal.estimated_cost_usd if proposal is not None else None),
        human_intervention=proposal.human_intervention if proposal is not None else False,
        evidence=evidence,
        error_code=error_code,
    )


def _validate_proposal(
    proposal: PatchProposal,
    task: RepairTask,
    repository: Path,
) -> str | None:
    allowed = frozenset(task.target_paths)
    if any(item.path not in allowed for item in proposal.replacements):
        return "patch-boundary-violation"
    for item in proposal.replacements:
        _sanitized, credential_detected = redact_text(item.content)
        if credential_detected:
            return "patch-credential-detected"
        try:
            target = _contained_file(repository, item.path)
        except _TaskExecutionError:
            return "patch-boundary-violation"
        if _sha256(target.read_bytes()) != item.expected_sha256:
            return "patch-stale-source"
    return None


def _apply_proposal(repository: Path, proposal: PatchProposal) -> list[str]:
    originals: dict[Path, bytes] = {}
    replacements: dict[Path, bytes] = {}
    for item in proposal.replacements:
        target = _contained_file(repository, item.path)
        originals[target] = target.read_bytes()
        replacements[target] = item.content.encode("utf-8")
    changed = [
        item.path
        for item in proposal.replacements
        if originals[_contained_file(repository, item.path)]
        != replacements[_contained_file(repository, item.path)]
    ]
    if not changed:
        raise _TaskExecutionError("patch-no-change")
    staged: dict[Path, Path] = {}
    try:
        for index, (target, payload) in enumerate(replacements.items()):
            temporary = target.with_name(f".{target.name}.devflow-{index}.tmp")
            if temporary.exists() or temporary.is_symlink():
                raise _TaskExecutionError("patch-staging-conflict")
            temporary.write_bytes(payload)
            temporary.chmod(stat.S_IMODE(target.stat().st_mode))
            staged[target] = temporary
        for target, temporary in staged.items():
            os.replace(temporary, target)
    except (OSError, _TaskExecutionError) as exc:
        for target, payload in originals.items():
            with suppress(OSError):
                target.write_bytes(payload)
        code = exc.code if isinstance(exc, _TaskExecutionError) else "patch-application-failed"
        raise _TaskExecutionError(code) from exc
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    return sorted(changed)


def execute_repair_task(
    manifest: RepairBenchmarkManifest,
    task: RepairTask,
    *,
    repos_root: Path,
    provider: PatchProvider,
    executable: Path | None = None,
    extra_pythonpath: Path | None = None,
    temp_root: Path | None = None,
) -> RepairTaskResult:
    """Execute one task and return a self-digested result; never mutate the source checkout."""

    started = time.perf_counter()
    spec = manifest.repositories[task.repository]
    source = (repos_root.resolve() / task.repository).resolve()
    python = Path(sys.executable if executable is None else executable).resolve()
    try:
        if not python.is_file():
            raise _TaskExecutionError("python-unavailable")
        _assert_pinned_clean_source(source, spec=spec)
        if temp_root is not None:
            temp_root = temp_root.resolve()
            temp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=f"devflow-repair-{task.id}-",
            dir=temp_root,
        ) as temporary:
            workspace = Path(temporary) / "repository"
            _clone_pinned_source(source, workspace, spec)
            _apply_manifest_mutation(workspace, task)
            pre_baseline_snapshot = _workspace_snapshot(workspace)
            baseline = _run_acceptance(
                workspace,
                task.acceptance[0],
                executable=python,
                extra_pythonpath=extra_pythonpath,
                oracle=task.mutation.before,
            )
            if _workspace_snapshot(workspace) != pre_baseline_snapshot:
                raise _TaskExecutionError("mutation-test-side-effect")
            if not baseline.evidence.completed:
                raise _TaskExecutionError("mutation-acceptance-timeout")
            if baseline.evidence.exit_code == 0:
                raise _TaskExecutionError("mutation-did-not-fail")
            if "failed" not in baseline.summary.casefold():
                raise _TaskExecutionError("mutation-invalid-failure")
            request = _build_provider_request(workspace, task, baseline.summary)
            snapshot = _workspace_snapshot(workspace)
            request_digest = _request_digest(request)
            try:
                raw_proposal = provider(request)
            except PatchProviderError as exc:
                return _blocked_result(
                    task,
                    spec,
                    started=started,
                    error_code="provider-failed",
                    prompt_tokens=exc.prompt_tokens,
                    completion_tokens=exc.completion_tokens,
                    estimated_cost_usd=exc.estimated_cost_usd,
                    human_intervention=exc.human_intervention,
                )
            except Exception:
                return _blocked_result(
                    task,
                    spec,
                    started=started,
                    error_code="provider-failed",
                )
            if request_digest is None or _request_digest(request) != request_digest:
                return _safety_failure_result(
                    task,
                    spec,
                    started=started,
                    baseline=baseline.evidence,
                    patch_sha256=_proposal_digest(raw_proposal),
                    proposal=None,
                    error_code="provider-request-tampering",
                )
            if _workspace_snapshot(workspace) != snapshot:
                return _safety_failure_result(
                    task,
                    spec,
                    started=started,
                    baseline=baseline.evidence,
                    patch_sha256=_proposal_digest(raw_proposal),
                    proposal=None,
                    error_code="provider-workspace-tampering",
                )
            try:
                proposal_input = (
                    raw_proposal.model_dump(mode="json")
                    if isinstance(raw_proposal, PatchProposal)
                    else raw_proposal
                )
                proposal = PatchProposal.model_validate(proposal_input)
            except Exception:
                return _safety_failure_result(
                    task,
                    spec,
                    started=started,
                    baseline=baseline.evidence,
                    patch_sha256=_proposal_digest(raw_proposal),
                    proposal=None,
                    error_code="patch-schema-invalid",
                )
            patch_sha256 = _proposal_digest(proposal)
            proposal_error = _validate_proposal(proposal, task, workspace)
            if proposal_error is not None:
                return _safety_failure_result(
                    task,
                    spec,
                    started=started,
                    baseline=baseline.evidence,
                    patch_sha256=patch_sha256,
                    proposal=proposal,
                    error_code=proposal_error,
                )
            try:
                changed_paths = _apply_proposal(workspace, proposal)
                workspace_paths = _git_changed_paths(workspace)
            except _TaskExecutionError as exc:
                return _safety_failure_result(
                    task,
                    spec,
                    started=started,
                    baseline=baseline.evidence,
                    patch_sha256=patch_sha256,
                    proposal=proposal,
                    error_code=exc.code,
                )
            if not set(workspace_paths) <= set(task.target_paths):
                return _safety_failure_result(
                    task,
                    spec,
                    started=started,
                    baseline=baseline.evidence,
                    patch_sha256=patch_sha256,
                    proposal=proposal,
                    error_code="patch-boundary-violation",
                )
            pre_acceptance_snapshot = _workspace_snapshot(workspace)
            acceptance_runs = [
                _run_acceptance(
                    workspace,
                    command,
                    executable=python,
                    extra_pythonpath=extra_pythonpath,
                    oracle=task.mutation.before,
                )
                for command in task.acceptance
            ]
            acceptance_safety_pass = _workspace_snapshot(workspace) == pre_acceptance_snapshot
            acceptance_pass = all(
                item.evidence.completed and item.evidence.exit_code == command.expected_exit_code
                for item, command in zip(acceptance_runs, task.acceptance, strict=True)
            )
            error_code = None
            if not acceptance_safety_pass:
                error_code = "acceptance-workspace-side-effect"
            elif not acceptance_pass:
                error_code = (
                    "acceptance-timeout"
                    if any(not item.evidence.completed for item in acceptance_runs)
                    else "acceptance-failed"
                )
            evidence = ExecutionEvidence(
                runner=RUNNER,
                baseline=baseline.evidence,
                patch_sha256=patch_sha256,
                changed_paths=changed_paths,
                acceptance=[item.evidence for item in acceptance_runs],
                safety_pass=acceptance_safety_pass,
            )
            return _seal_result(
                task,
                spec,
                execution_status="executed",
                success=acceptance_pass and acceptance_safety_pass,
                duration_ms=round((time.perf_counter() - started) * 1_000),
                prompt_tokens=proposal.prompt_tokens,
                completion_tokens=proposal.completion_tokens,
                estimated_cost_usd=proposal.estimated_cost_usd,
                human_intervention=proposal.human_intervention,
                evidence=evidence,
                error_code=error_code,
            )
    except _TaskExecutionError as exc:
        return _blocked_result(task, spec, started=started, error_code=exc.code)
    except (OSError, subprocess.SubprocessError):
        return _blocked_result(task, spec, started=started, error_code="executor-failed")


def _new_report(
    manifest: RepairBenchmarkManifest,
    *,
    generated_at: str,
    run_id: str,
    cost_provenance: RepairCostProvenance | None,
) -> RepairBenchmarkReport:
    template = build_unexecuted_repair_report(manifest, generated_at=generated_at)
    payload = template.model_dump(mode="json")
    payload.update(
        {
            "cost_provenance": (
                cost_provenance.model_dump(mode="json") if cost_provenance is not None else None
            ),
            "run_id": run_id,
            "report_sha256": "0" * 64,
        }
    )
    report = RepairBenchmarkReport.model_validate(payload)
    return report.model_copy(update={"report_sha256": _self_digest(report, "report_sha256")})


def _reseal_report(
    report: RepairBenchmarkReport,
    results: Sequence[RepairTaskResult],
) -> RepairBenchmarkReport:
    updated = report.model_copy(
        update={
            "results": list(results),
            "summary": _repair_summary(list(results)),
            "report_sha256": "0" * 64,
        }
    )
    return updated.model_copy(update={"report_sha256": _self_digest(updated, "report_sha256")})


def validate_resumable_report(
    report: RepairBenchmarkReport,
    manifest: RepairBenchmarkManifest,
) -> list[str]:
    """Validate all report/manifest bindings needed before reusing prior results."""

    errors: list[str] = []
    try:
        RepairBenchmarkReport.model_validate(report.model_dump(mode="json"))
    except ValidationError:
        return ["resume report violates the report model"]
    if report.benchmark != manifest.benchmark:
        errors.append("resume report benchmark does not match")
    if report.manifest_sha256 != repair_manifest_sha256(manifest):
        errors.append("resume report manifest digest does not match")
    if report.report_sha256 != _self_digest(report, "report_sha256"):
        errors.append("resume report self digest does not match")
    expected_tasks = {task.id: task for task in manifest.tasks}
    if [item.task_id for item in report.results] != [task.id for task in manifest.tasks]:
        errors.append("resume report results are not in exact manifest order")
        return errors
    for result in report.results:
        task = expected_tasks[result.task_id]
        spec = manifest.repositories[task.repository]
        if result.repository != task.repository or result.commit != spec.commit:
            errors.append(f"{task.id}: resume source binding does not match")
        if result.result_sha256 != _self_digest(result, "result_sha256"):
            errors.append(f"{task.id}: resume result self digest does not match")
        if result.execution_status == "executed":
            if result.evidence is None:
                errors.append(f"{task.id}: executed resume result has no evidence")
                continue
            if not set(result.evidence.changed_paths) <= set(task.target_paths):
                errors.append(f"{task.id}: resume result exceeds its path boundary")
            expected_commands = [_command_sha256(command) for command in task.acceptance]
            if result.evidence.baseline.argv_sha256 != expected_commands[0]:
                errors.append(f"{task.id}: resume baseline binding does not match")
            if [item.argv_sha256 for item in result.evidence.acceptance] != expected_commands:
                errors.append(f"{task.id}: resume acceptance binding does not match")
    if report.summary != _repair_summary(report.results):
        errors.append("resume report summary is not derived from its results")
    return errors


def load_repair_report(path: Path) -> RepairBenchmarkReport:
    payload = path.read_bytes()
    if len(payload) > 20_000_000:
        raise ValueError("repair report exceeds its byte limit")
    return RepairBenchmarkReport.model_validate_json(payload)


def write_repair_report(path: Path, report: RepairBenchmarkReport) -> None:
    """Atomically write a canonical, newline-terminated report checkpoint."""

    path = path.absolute()
    if path.is_symlink():
        raise ValueError("report output cannot be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False, sort_keys=True)
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(f".{path.name}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("report temporary path already exists")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _default_run_id(manifest: RepairBenchmarkManifest) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%Sz").casefold()
    return f"repair-{stamp}-{repair_manifest_sha256(manifest)[:8]}"


def execute_repair_benchmark(
    manifest: RepairBenchmarkManifest,
    *,
    repos_root: Path,
    provider: PatchProvider,
    task_ids: Sequence[str] | None = None,
    executables: Mapping[str, Path] | None = None,
    extra_pythonpaths: Mapping[str, Path] | None = None,
    temp_root: Path | None = None,
    resume_report: RepairBenchmarkReport | None = None,
    checkpoint_path: Path | None = None,
    generated_at: str | None = None,
    run_id: str | None = None,
    cost_provenance: RepairCostProvenance | None = None,
) -> RepairBenchmarkReport:
    """Run selected tasks, checkpoint after each, and preserve terminal results on resume.

    A single-task run still returns all manifest rows: the selected row is
    executed while the other rows remain explicitly ``unexecuted``.  Resuming
    preserves all prior ``executed`` rows and retries only blocked/unexecuted
    selected rows.
    """

    known = {task.id for task in manifest.tasks}
    selected = known if task_ids is None else set(task_ids)
    if selected - known:
        raise ValueError("task_ids contains an unknown repair task")
    if not selected:
        raise ValueError("at least one repair task must be selected")
    if resume_report is not None:
        errors = validate_resumable_report(resume_report, manifest)
        if errors:
            raise ValueError("invalid resume report: " + "; ".join(errors))
        if run_id is not None and run_id != resume_report.run_id:
            raise ValueError("run_id cannot change while resuming a report")
        if generated_at is not None and generated_at != resume_report.generated_at:
            raise ValueError("generated_at cannot change while resuming a report")
        if cost_provenance is not None and cost_provenance != resume_report.cost_provenance:
            raise ValueError("cost provenance cannot change while resuming a report")
        report = resume_report
    else:
        report = _new_report(
            manifest,
            generated_at=generated_at or datetime.now(timezone.utc).isoformat(),
            run_id=run_id or _default_run_id(manifest),
            cost_provenance=cost_provenance,
        )
    results = {item.task_id: item for item in report.results}
    if checkpoint_path is not None:
        write_repair_report(checkpoint_path, report)
    executable_by_repository = executables or {}
    pythonpath_by_repository = extra_pythonpaths or {}
    for task in manifest.tasks:
        if task.id not in selected or results[task.id].execution_status == "executed":
            continue
        result = execute_repair_task(
            manifest,
            task,
            repos_root=repos_root,
            provider=provider,
            executable=executable_by_repository.get(task.repository),
            extra_pythonpath=pythonpath_by_repository.get(task.repository),
            temp_root=temp_root,
        )
        results[task.id] = result
        report = _reseal_report(report, [results[item.id] for item in manifest.tasks])
        if checkpoint_path is not None:
            write_repair_report(checkpoint_path, report)
    errors = validate_resumable_report(report, manifest)
    if errors:
        raise RuntimeError("executor produced an invalid report: " + "; ".join(errors))
    return report


__all__ = [
    "FileReplacement",
    "PatchProposal",
    "PatchProvider",
    "PatchProviderError",
    "PatchRequest",
    "PatchSource",
    "execute_repair_benchmark",
    "execute_repair_task",
    "load_repair_report",
    "validate_resumable_report",
    "write_repair_report",
]

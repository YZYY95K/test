"""Pre-validate deterministic mutation-repair fixtures at exact Git revisions.

This runner never invokes an Agent and never reports an Agent success.  For each
task it proves three fixture facts in a clean checkout: the fixed source passes,
the declared mutation makes the pinned pytest selector fail, and restoring the
exact original bytes makes the selector pass again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
for import_path in (ROOT, ROOT / "src"):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from scripts.run_repository_benchmark import (  # noqa: E402 - bootstrap repo imports
    AcceptanceCommand,
    RepairBenchmarkManifest,
    RepairTask,
    _canonical_json,
    _command_sha256,
    load_repair_manifest,
)

RUNNER = "devflow-mutation-fixture-preflight/v1"
URL_USERINFO = re.compile(r"(?i)\b(https?://)[^\s/:@]+:[^\s/@]+@")
BEARER_TOKEN = re.compile(
    r"(?i)\b(Bearer)[ \t]+[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
)
SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"github[_-]?token|token|secret|password|passwd|private[_-]?key)"
    r"([ \t]*[:=][ \t]*[\"']?)[A-Za-z0-9._~+/=-]{24,}"
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def _assert_exact_clean_source(repository: Path, *, commit: str, tree: str, task_id: str) -> None:
    if _git(repository, "rev-parse", "HEAD") != commit:
        raise RuntimeError(f"{task_id}: checkout is not at the declared commit")
    if _git(repository, "rev-parse", "HEAD^{tree}") != tree:
        raise RuntimeError(f"{task_id}: checkout tree does not match the manifest")
    if _git(repository, "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError(f"{task_id}: checkout must be clean before fixture validation")


def _runtime_evidence(executable: Path) -> dict[str, str]:
    completed = subprocess.run(
        [str(executable), "-c", "import platform; print(platform.python_version())"],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    return {
        "implementation": "CPython",
        "python_version": completed.stdout.strip(),
        "executable_sha256": _sha256_bytes(executable.read_bytes()),
    }


def _bounded_summary(stdout: bytes, stderr: bytes) -> str:
    combined = (stdout + b"\n" + stderr).decode("utf-8", errors="replace")
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    summary = " | ".join(lines[-8:])
    summary = URL_USERINFO.sub(r"\1[REDACTED]@", summary)
    summary = BEARER_TOKEN.sub(r"\1 [REDACTED]", summary)
    summary = SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", summary)
    return summary[-2_000:]


def _run_acceptance(
    repository: Path,
    command: AcceptanceCommand,
    *,
    executable: Path,
    extra_pythonpath: Path | None,
) -> dict[str, Any]:
    argv = [str(executable), *command.argv[1:]]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    source_root = repository / "src" if (repository / "src").is_dir() else repository
    python_paths = [str(source_root)]
    if extra_pythonpath is not None:
        python_paths.append(str(extra_pythonpath))
    existing = environment.get("PYTHONPATH")
    if existing:
        python_paths.append(existing)
    environment["PYTHONPATH"] = os.pathsep.join(python_paths)
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            cwd=repository,
            capture_output=True,
            check=False,
            timeout=command.timeout_seconds,
            env=environment,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        return {
            "argv_sha256": _command_sha256(command),
            "completed": False,
            "duration_ms": round((time.perf_counter() - started) * 1_000),
            "exit_code": None,
            "output_summary": _bounded_summary(stdout, stderr),
            "stderr_sha256": _sha256_bytes(stderr),
            "stdout_sha256": _sha256_bytes(stdout),
        }
    return {
        "argv_sha256": _command_sha256(command),
        "completed": True,
        "duration_ms": round((time.perf_counter() - started) * 1_000),
        "exit_code": completed.returncode,
        "output_summary": _bounded_summary(completed.stdout, completed.stderr),
        "stderr_sha256": _sha256_bytes(completed.stderr),
        "stdout_sha256": _sha256_bytes(completed.stdout),
    }


def _assert_passed(task_id: str, phase: str, result: dict[str, Any]) -> None:
    if not result["completed"] or result["exit_code"] != 0:
        raise RuntimeError(f"{task_id}: {phase} did not pass: {result['output_summary']}")


def _assert_failed(task_id: str, result: dict[str, Any]) -> None:
    if not result["completed"] or result["exit_code"] in {None, 0}:
        raise RuntimeError(
            f"{task_id}: mutation did not fail its pinned test: {result['output_summary']}"
        )
    if "failed" not in result["output_summary"].lower():
        raise RuntimeError(
            f"{task_id}: pytest exited nonzero without a failed-test summary: "
            f"{result['output_summary']}"
        )


def _record_digest(record: dict[str, Any]) -> str:
    without_digest = dict(record)
    without_digest.pop("record_sha256", None)
    return _sha256_bytes(_canonical_json(without_digest))


def validate_task_fixture(
    manifest: RepairBenchmarkManifest,
    task: RepairTask,
    *,
    repos_root: Path,
    executable: Path,
    extra_pythonpath: Path | None,
) -> dict[str, Any]:
    spec = manifest.repositories[task.repository]
    repository = (repos_root / task.repository).resolve()
    _assert_exact_clean_source(repository, commit=spec.commit, tree=spec.tree, task_id=task.id)
    target = (repository / task.mutation.path).resolve()
    if repository not in target.parents or not target.is_file():
        raise RuntimeError(f"{task.id}: mutation target escapes or is unavailable")
    original = target.read_bytes()
    newline = b"\r\n" if b"\r\n" in original else b"\n"
    before = task.mutation.before.encode("utf-8").replace(b"\n", newline)
    after = task.mutation.after.encode("utf-8").replace(b"\n", newline)
    if original.count(before) != 1:
        raise RuntimeError(f"{task.id}: before text must occur exactly once")

    baseline = _run_acceptance(
        repository,
        task.acceptance[0],
        executable=executable,
        extra_pythonpath=extra_pythonpath,
    )
    _assert_passed(task.id, "fixed-source baseline", baseline)
    try:
        target.write_bytes(original.replace(before, after, 1))
        changed = _git(repository, "diff", "--name-only", "--")
        if changed.splitlines() != [task.mutation.path]:
            raise RuntimeError(f"{task.id}: mutation changed an unexpected path: {changed!r}")
        mutant = _run_acceptance(
            repository,
            task.acceptance[0],
            executable=executable,
            extra_pythonpath=extra_pythonpath,
        )
        _assert_failed(task.id, mutant)
    finally:
        target.write_bytes(original)

    if target.read_bytes() != original:
        raise RuntimeError(f"{task.id}: oracle restoration did not restore exact bytes")
    restoration = _run_acceptance(
        repository,
        task.acceptance[0],
        executable=executable,
        extra_pythonpath=extra_pythonpath,
    )
    _assert_passed(task.id, "oracle restoration", restoration)
    _assert_exact_clean_source(repository, commit=spec.commit, tree=spec.tree, task_id=task.id)

    record: dict[str, Any] = {
        "acceptance_argv_sha256": [_command_sha256(command) for command in task.acceptance],
        "baseline": baseline,
        "changed_paths": [task.mutation.path],
        "commit": spec.commit,
        "execution_ready": True,
        "mutation_sha256": task.mutation.sha256,
        "mutant": mutant,
        "oracle_restoration": restoration,
        "repository": task.repository,
        "runtime": _runtime_evidence(executable),
        "task_id": task.id,
        "tree": spec.tree,
    }
    record["record_sha256"] = _record_digest(record)
    return record


def _parse_mapping(values: list[str], *, option: str) -> dict[str, Path]:
    parsed: dict[str, Path] = {}
    for value in values:
        repository, separator, path = value.partition("=")
        if not separator or repository not in {"requests", "flask", "pydantic"}:
            raise ValueError(f"{option} must use repository=path")
        parsed[repository] = Path(path).resolve()
    return parsed


def main() -> int:
    root = ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest", type=Path, default=root / "benchmarks/repository_repair/tasks.yaml"
    )
    parser.add_argument("--repos-root", type=Path, default=root / ".devflow/benchmark-repos")
    parser.add_argument(
        "--output",
        type=Path,
        default=root / ".devflow/benchmarks/repository-repair-prevalidation.json",
    )
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--python-for", action="append", default=[])
    parser.add_argument("--pythonpath-for", action="append", default=[])
    parser.add_argument("--task", action="append", default=[])
    parser.add_argument("--generated-at")
    args = parser.parse_args()

    manifest = load_repair_manifest(args.manifest.resolve())
    python_for = _parse_mapping(args.python_for, option="--python-for")
    pythonpath_for = _parse_mapping(args.pythonpath_for, option="--pythonpath-for")
    selected = [task for task in manifest.tasks if not args.task or task.id in args.task]
    if args.task and {task.id for task in selected} != set(args.task):
        raise ValueError("--task contains an unknown task id")
    records = []
    for task in selected:
        executable = python_for.get(task.repository, args.python).resolve()
        if not executable.is_file():
            raise ValueError(f"{task.repository}: Python executable is unavailable")
        record = validate_task_fixture(
            manifest,
            task,
            repos_root=args.repos_root.resolve(),
            executable=executable,
            extra_pythonpath=pythonpath_for.get(task.repository),
        )
        records.append(record)
        print(f"fixture-verified: {task.id}")

    evidence: dict[str, Any] = {
        "benchmark": manifest.benchmark,
        "generated_at": args.generated_at or datetime.now(timezone.utc).isoformat(),
        "records": records,
        "runner": RUNNER,
        "schema_version": "1.0",
    }
    evidence["evidence_sha256"] = _sha256_bytes(_canonical_json(evidence))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(evidence, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    args.output.write_bytes(encoded)
    print(f"fixture-evidence-sha256: {_sha256_bytes(encoded)}")
    print(f"fixture-records: {len(records)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

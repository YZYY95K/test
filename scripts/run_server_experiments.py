#!/usr/bin/env python3
"""Run the credential-free DevFlow finals quality suite on an offline host.

Preparation (dependency installation and repository fixture checkout) happens
before this program starts.  The program then uses only fixed local commands,
passes a fresh allowlisted environment to every child, and disables ``.env``
loading.  Linux requires the managed systemd boundary and can place the run in
a real private network namespace.  The Windows-only fallback keeps networking
available, strips credentials, and never mislabels that weaker mode as
isolation.

Each step gets bounded logs and a receipt linked to the exact plan and previous
receipt.  The final verifier establishes same-run internal consistency; it is
not an external signature or WORM guarantee.  A failed or timed-out step does
not stop later steps.  The output directory is new and private so two runs
cannot silently share evidence.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import hashlib
import importlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import sysconfig
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from importlib import metadata as importlib_metadata
from pathlib import Path, PurePosixPath
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
SAFE_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
SAFE_OUTPUT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SAFE_EVIDENCE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")
REVISION = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
LOCK_PIN = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)"
    r"(?:\s*;\s*([^\\]+?))?\s*\\?$"
)
NETWORK_MODE_ISOLATED = "network_namespace_isolated"
NETWORK_MODE_AVAILABLE = "network_available_credentials_stripped"
NETWORK_ISOLATED_CONFIRMATION = "NETWORK_NAMESPACE_ISOLATED"
NETWORK_AVAILABLE_CONFIRMATION = "NETWORK_AVAILABLE_CREDENTIALS_STRIPPED"
SYSTEMD_STATE_ROOT = Path("/var/lib/devflow-experiments")
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 128 * 1024 * 1024
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_COMMAND_SECONDS = 12 * 60 * 60
MAX_ARTIFACT_FILES = 5_000
MAX_ARTIFACT_TOTAL_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_FILES = 20_000
MAX_EVIDENCE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_INSTALLED_FILES = 100_000
MAX_INSTALLED_FILE_BYTES = 256 * 1024 * 1024
MAX_INSTALLED_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
COVERAGE_PTH_SHA256 = "f1498191b7f52180654ccdb6195233612805e26344100c093058343ea04afd36"
_SUBREAPER_ENABLED = False


class ExperimentError(RuntimeError):
    """The experiment launch or evidence boundary is invalid."""


@dataclass(frozen=True)
class Step:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: int


@dataclass(frozen=True)
class StepResult:
    name: str
    argv: list[str]
    started_at: str
    finished_at: str
    duration_ms: int
    process_exit_code: int
    exit_code: int
    timed_out: bool
    capture_limit_exceeded: bool
    descendant_cleanup_supported: bool
    descendant_cleanup_succeeded: bool
    terminated_descendant_count: int
    failure_reason: str | None
    stdout_sha256: str
    stderr_sha256: str
    stdout_log_sha256: str
    stderr_log_sha256: str
    stdout_bytes: int
    stderr_bytes: int
    stdout_truncated: bool
    stderr_truncated: bool
    passed: bool


@dataclass(frozen=True)
class StepRecord:
    result: StepResult
    receipt_sha256: str


@dataclass(frozen=True)
class CommandCapture:
    process_exit_code: int
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    capture_limit_exceeded: bool
    descendant_cleanup_supported: bool
    descendant_cleanup_succeeded: bool
    terminated_descendant_count: int


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_regular(path: Path, *, maximum: int, label: str) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
        ):
            raise ExperimentError(f"{label} is outside the evidence policy")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError(f"{label} is unavailable") from exc
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if path.is_symlink() or resolved != path or len(payload) > maximum:
        raise ExperimentError(f"{label} is outside the evidence policy")
    identity = (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
    final_identity = (
        final_metadata.st_dev,
        final_metadata.st_ino,
        final_metadata.st_size,
        final_metadata.st_mtime_ns,
    )
    if identity != final_identity or metadata.st_size != len(payload):
        raise ExperimentError(f"{label} changed during bounded read")
    return payload


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o444)
    except OSError as exc:
        raise ExperimentError(f"evidence file already exists or is unsafe: {path.name}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o444)
    except OSError as exc:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise ExperimentError(f"evidence write failed: {path.name}") from exc


def _replace_state(path: Path, value: dict[str, Any], *, final: bool = False) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    payload = _canonical(value) + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o444 if final else 0o600)
    except OSError as exc:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise ExperimentError("heartbeat update failed safely") from exc
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)


def _safe_output(output: Path, *, managed_state_directory: bool = False) -> Path:
    if not output.is_absolute() or SAFE_OUTPUT_NAME.fullmatch(output.name) is None:
        raise ExperimentError("--output must be an absolute safe directory path")
    if managed_state_directory and output.parent != SYSTEMD_STATE_ROOT:
        raise ExperimentError("isolated output is outside the systemd state directory")
    try:
        parent = output.parent.resolve(strict=True)
        repository = ROOT.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError("repository or output parent is unavailable") from exc
    candidate = parent / output.name
    if (
        (not managed_state_directory and output.parent.is_symlink())
        or (not managed_state_directory and parent != output.parent)
        or not parent.is_dir()
        or candidate == repository
        or repository in candidate.parents
        or candidate.exists()
        or candidate.is_symlink()
    ):
        raise ExperimentError("output must be a new directory outside the repository")
    return candidate


def _prepared_python_entry() -> tuple[Path, Path, Path, tuple[Path, ...]]:
    if sys.flags.isolated != 1 or sys.flags.no_site != 1:
        raise ExperimentError("the runner must start with Python -I -S")
    entry = Path(os.path.abspath(sys.executable))
    try:
        entry_metadata = entry.lstat()
        target = entry.resolve(strict=True)
        target_metadata = target.stat()
    except OSError as exc:
        raise ExperimentError("prepared Python entry is unavailable") from exc
    if (
        not (stat.S_ISREG(entry_metadata.st_mode) or stat.S_ISLNK(entry_metadata.st_mode))
        or not stat.S_ISREG(target_metadata.st_mode)
        or (os.name == "posix" and target_metadata.st_mode & 0o022)
        or not os.access(target, os.X_OK)
        or (
            os.name == "posix"
            and stat.S_ISREG(entry_metadata.st_mode)
            and entry_metadata.st_mode & 0o022
        )
    ):
        raise ExperimentError("prepared Python entry or target is outside policy")
    if entry.parent.name.lower() not in {"bin", "scripts"}:
        raise ExperimentError("prepared Python entry is outside a virtual-environment layout")
    venv_root = entry.parent.parent.absolute()
    try:
        resolved_root = venv_root.resolve(strict=True)
        root_metadata = venv_root.lstat()
    except OSError as exc:
        raise ExperimentError("prepared virtual-environment root is unavailable") from exc
    if (
        venv_root.is_symlink()
        or resolved_root != venv_root
        or not stat.S_ISDIR(root_metadata.st_mode)
        or (os.name == "posix" and (root_metadata.st_uid != 0 or root_metadata.st_mode & 0o022))
    ):
        raise ExperimentError("prepared virtual-environment root is outside policy")
    config_payload = _read_regular(
        venv_root / "pyvenv.cfg",
        maximum=64 * 1024,
        label="virtual-environment configuration",
    )
    try:
        config_lines = config_payload.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise ExperimentError("virtual-environment configuration is not UTF-8") from exc
    config: dict[str, str] = {}
    for line in config_lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        config[key.strip().lower()] = value.strip().lower()
    if config.get("include-system-site-packages") != "false":
        raise ExperimentError("virtual environment must exclude system site-packages")
    scheme = "nt" if os.name == "nt" else "posix_prefix"
    try:
        paths = sysconfig.get_paths(
            scheme=scheme,
            vars={"base": str(venv_root), "platbase": str(venv_root)},
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ExperimentError("virtual-environment site-packages layout is unavailable") from exc
    site_roots = tuple(
        sorted(
            {Path(paths[key]).absolute() for key in ("purelib", "platlib")},
            key=str,
        )
    )
    if not site_roots:
        raise ExperimentError("virtual environment has no explicit site-packages root")
    for site_root in site_roots:
        try:
            resolved_site = site_root.resolve(strict=True)
            site_metadata = site_root.lstat()
        except OSError as exc:
            raise ExperimentError("virtual-environment site-packages root is unavailable") from exc
        if (
            site_root.is_symlink()
            or resolved_site != site_root
            or venv_root not in site_root.parents
            or not stat.S_ISDIR(site_metadata.st_mode)
            or (os.name == "posix" and (site_metadata.st_uid != 0 or site_metadata.st_mode & 0o022))
        ):
            raise ExperimentError("virtual-environment site-packages root is outside policy")
    return entry, target, venv_root, site_roots


def _activate_audited_runtime_paths(site_roots: tuple[Path, ...]) -> None:
    for path in (*site_roots, ROOT):
        value = str(path)
        if value not in sys.path:
            sys.path.append(value)


def _create_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError("private experiment directory could not be created") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise ExperimentError("private experiment directory metadata is unsafe")


def _environment(output: Path) -> dict[str, str]:
    runtime = output / ".runtime"
    _create_private_directory(runtime)
    home = runtime / "home"
    temporary = runtime / "tmp"
    cache = runtime / "cache"
    config = runtime / "config"
    for directory in (home, temporary, cache, config):
        _create_private_directory(directory)

    environment: dict[str, str] = {}
    for key in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(
        {
            "APPDATA": str(config),
            "AWS_EC2_METADATA_DISABLED": "true",
            "CARGO_NET_OFFLINE": "true",
            "CI": "true",
            "COVERAGE_FILE": str(output / "artifacts" / ".coverage"),
            "GCM_INTERACTIVE": "Never",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HF_HUB_OFFLINE": "1",
            "HOME": str(home),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "LOCALAPPDATA": str(cache),
            "MYPY_CACHE_DIR": str(cache / "mypy"),
            "NPM_CONFIG_OFFLINE": "true",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": str(ROOT / "src"),
            "PYTHON_DOTENV_DISABLED": "1",
            "RUFF_CACHE_DIR": str(cache / "ruff"),
            "SOURCE_DATE_EPOCH": "0",
            "TEMP": str(temporary),
            "TMP": str(temporary),
            "TMPDIR": str(temporary),
            "TRANSFORMERS_OFFLINE": "1",
            "TZ": "UTC",
            "USERPROFILE": str(home),
            "UV_OFFLINE": "1",
            "XDG_CACHE_HOME": str(cache),
            "XDG_CONFIG_HOME": str(config),
        }
    )
    return environment


def _steps(python: str, output: Path) -> tuple[Step, ...]:
    artifacts = output / "artifacts"
    return (
        Step("config", (python, "-m", "devflow.cli", "validate"), 180),
        Step(
            "upstream",
            (python, "scripts/verify_agentteams_upstream.py", "--offline"),
            180,
        ),
        Step("skills", (python, "scripts/evaluate_skills.py"), 600),
        Step(
            "behavior-schema",
            (python, "scripts/run_behavior_evals.py", "--validate-only"),
            300,
        ),
        Step(
            "repair-manifest",
            (
                python,
                "scripts/run_repository_benchmark.py",
                "--repair-manifest",
                "benchmarks/repository_repair/tasks.yaml",
                "--validate-only",
            ),
            600,
        ),
        Step("ruff", (python, "-m", "ruff", "check", "--no-cache", "."), 900),
        Step("mypy", (python, "-m", "mypy", "src", "scripts", "tests"), 2400),
        Step(
            "receipt-and-ci",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/test_agentteams_tester_cicd.py",
                "tests/test_reconcile_agentteams_tester_cicd.py",
                "tests/test_teamharness_test_execution_receipt.py",
                "tests/test_reconcile_agentteams_mcporter_policy.py",
            ),
            2400,
        ),
        Step(
            "collaboration-and-t4",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "tests/test_agentteams_finals_flow.py",
                "tests/test_agentteams_t4_approval.py",
                "tests/test_teamharness_openclaw.py",
            ),
            3600,
        ),
        Step(
            "full-quality-gate",
            (
                python,
                "-m",
                "pytest",
                "-q",
                "-p",
                "no:cacheprovider",
                "--cov=devflow",
                "--cov-report=term-missing",
                f"--cov-report=json:{artifacts / 'coverage.json'}",
                f"--cov-report=xml:{artifacts / 'coverage.xml'}",
                "--cov-fail-under=80",
            ),
            10_800,
        ),
        Step(
            "offline-demo",
            (
                python,
                "-m",
                "devflow.cli",
                "demo",
                "--output-dir",
                str(artifacts / "demo"),
            ),
            1200,
        ),
        Step(
            "role-packages-pass-1",
            (
                python,
                "scripts/build_server_experiment_packages.py",
                "--output-dir",
                str(artifacts / "packages" / "pass-1"),
            ),
            1800,
        ),
        Step(
            "role-packages-pass-2",
            (
                python,
                "scripts/build_server_experiment_packages.py",
                "--output-dir",
                str(artifacts / "packages" / "pass-2"),
            ),
            1800,
        ),
    )


def _validate_steps(steps: tuple[Step, ...], python: str) -> None:
    names: set[str] = set()
    for step in steps:
        if (
            SAFE_RUN_ID.fullmatch(step.name) is None
            or step.name in names
            or not 1 <= step.timeout_seconds <= MAX_COMMAND_SECONDS
            or not step.argv
            or step.argv[0] != python
            or any(not value or "\x00" in value for value in step.argv)
        ):
            raise ExperimentError("fixed experiment step contract is invalid")
        names.add(step.name)
        for argument in step.argv[1:]:
            if argument.startswith(("scripts/", "tests/", "benchmarks/")):
                candidate = ROOT.joinpath(*PurePosixPath(argument).parts)
                if not candidate.is_file() or candidate.is_symlink():
                    raise ExperimentError(
                        "fixed experiment step references an unavailable local file"
                    )
    expected = {
        "config",
        "upstream",
        "skills",
        "behavior-schema",
        "repair-manifest",
        "ruff",
        "mypy",
        "receipt-and-ci",
        "collaboration-and-t4",
        "full-quality-gate",
        "offline-demo",
        "role-packages-pass-1",
        "role-packages-pass-2",
    }
    if names != expected:
        raise ExperimentError("fixed experiment plan is incomplete")


def _normalize_distribution(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _validate_cli_contracts(
    python: str,
    environment: dict[str, str],
) -> str:
    contracts = (
        ((python, "-m", "devflow.cli", "--help"), ("demo", "validate")),
        (
            (python, "-m", "devflow.cli", "demo", "--help"),
            ("--output-dir",),
        ),
        (
            (python, "scripts/verify_agentteams_upstream.py", "--help"),
            ("--offline",),
        ),
        (
            (python, "scripts/evaluate_skills.py", "--help"),
            ("--root",),
        ),
        (
            (python, "scripts/run_behavior_evals.py", "--help"),
            ("--validate-only",),
        ),
        (
            (python, "scripts/run_repository_benchmark.py", "--help"),
            ("--repair-manifest", "--validate-only"),
        ),
        (
            (python, "scripts/build_server_experiment_packages.py", "--help"),
            ("--output-dir",),
        ),
        ((python, "-m", "ruff", "check", "--help"), ("--output-format",)),
        ((python, "-m", "mypy", "--help"), ("--strict",)),
        (
            (python, "-m", "pytest", "--help"),
            ("--cov", "--cov-report", "--cov-fail-under"),
        ),
    )
    evidence: list[dict[str, Any]] = []
    for argv, required in contracts:
        try:
            completed = _run_bounded_capture(
                argv,
                cwd=ROOT,
                environment=environment,
                timeout=60,
            )
        except OSError as exc:
            raise ExperimentError("fixed CLI contract probe failed") from exc
        output = completed.stdout + completed.stderr
        if (
            completed.exit_code != 0
            or completed.timed_out
            or completed.capture_limit_exceeded
            or len(output) > 1024 * 1024
            or any(token.encode("ascii") not in output for token in required)
        ):
            raise ExperimentError("fixed CLI option is unavailable")
        evidence.append(
            {
                "argv": list(argv),
                "required": list(required),
                "helpSha256": _sha256(output),
            }
        )
    return _sha256(_canonical(evidence))


def _validate_locked_environment(
    lock_payload: bytes,
    installed: dict[str, str],
) -> str:
    try:
        text = lock_payload.decode("utf-8")
    except UnicodeError as exc:
        raise ExperimentError("development dependency lock is not UTF-8") from exc
    try:
        from packaging.markers import InvalidMarker, Marker
    except ImportError as exc:
        raise ExperimentError("dependency marker evaluator is unavailable") from exc
    pins: dict[str, str] = {}
    for line in text.splitlines():
        match = LOCK_PIN.fullmatch(line)
        if match is None:
            continue
        name = _normalize_distribution(match.group(1))
        marker_text = match.group(3)
        try:
            selected = marker_text is None or Marker(marker_text).evaluate()
        except InvalidMarker as exc:
            raise ExperimentError("development dependency marker is invalid") from exc
        if not selected:
            continue
        version = match.group(2)
        if name in pins and pins[name] != version:
            raise ExperimentError("development dependency lock has conflicting pins")
        pins[name] = version
    critical = {"mypy", "pytest", "pytest-cov", "ruff", "python-dotenv"}
    if not critical <= set(pins):
        raise ExperimentError("development dependency lock lacks critical tools")
    for name, version in installed.items():
        if name not in pins or version != pins[name]:
            raise ExperimentError("installed environment differs from the development lock")
    for name, version in pins.items():
        if installed.get(name) != version:
            raise ExperimentError("installed environment is incomplete for the development lock")
    return _sha256(_canonical(installed))


def _read_installed_file(
    path: Path,
    *,
    prefix: Path,
    require_root_owned: bool,
) -> bytes:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError("installed distribution file is unavailable") from exc
    if resolved != path.absolute() or (resolved != prefix and prefix not in resolved.parents):
        raise ExperimentError("installed distribution file escapes the virtual environment")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_INSTALLED_FILE_BYTES
            or (os.name == "posix" and metadata.st_mode & 0o022)
            or (require_root_owned and metadata.st_uid != 0)
        ):
            raise ExperimentError("installed distribution file is outside policy")
        chunks: list[bytes] = []
        remaining = MAX_INSTALLED_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
    except OSError as exc:
        raise ExperimentError("installed distribution file could not be read safely") from exc
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if (
        len(payload) > MAX_INSTALLED_FILE_BYTES
        or len(payload) != metadata.st_size
        or (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
        )
    ):
        raise ExperimentError("installed distribution file changed during bounded read")
    return payload


def _audit_site_package_claims(
    site_roots: tuple[Path, ...],
    allowed_files: set[Path],
    *,
    require_root_owned: bool,
    allowed_path_configuration_files: set[Path] | None = None,
) -> None:
    allowed_pth = allowed_path_configuration_files or set()
    discovered_directories: set[Path] = set()
    scanned_entries = 0
    for site_root in site_roots:
        if not site_root.is_dir() or site_root.is_symlink():
            raise ExperimentError("virtual-environment site-packages root is unsafe")
        for path in site_root.rglob("*"):
            scanned_entries += 1
            if scanned_entries > MAX_INSTALLED_FILES:
                raise ExperimentError("site-packages exceeds the installed-file entry limit")
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise ExperimentError("site-packages changed during inventory") from exc
            if path.is_symlink():
                raise ExperimentError("site-packages contains an untrusted symbolic link")
            if os.name == "posix" and (
                metadata.st_mode & 0o022 or (require_root_owned and metadata.st_uid != 0)
            ):
                raise ExperimentError("site-packages contains an untrusted writable or owned entry")
            if stat.S_ISDIR(metadata.st_mode):
                discovered_directories.add(path.resolve(strict=True))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ExperimentError("site-packages contains a non-regular entry")
            resolved = path.resolve(strict=True)
            if path.name.lower() in {"sitecustomize.py", "usercustomize.py"}:
                raise ExperimentError("site-packages contains a startup customization hook")
            if path.suffix.lower() == ".pth" and resolved not in allowed_pth:
                raise ExperimentError("site-packages contains a forbidden path configuration file")
            if path.suffix.lower() == ".pyc":
                raise ExperimentError("site-packages contains forbidden precompiled bytecode")
            if resolved in allowed_files:
                continue
            raise ExperimentError("site-packages contains a file absent from every RECORD")

    allowed_directories: set[Path] = set()
    for file_path in allowed_files:
        for site_root in site_roots:
            if file_path == site_root or site_root not in file_path.parents:
                continue
            current = file_path.parent
            while current != site_root:
                allowed_directories.add(current)
                current = current.parent
    if not discovered_directories <= allowed_directories:
        raise ExperimentError("site-packages contains an unclaimed directory")


def _installed_inventory(site_roots: tuple[Path, ...]) -> dict[str, str]:
    installed: dict[str, str] = {}
    for distribution in importlib_metadata.distributions(path=[str(path) for path in site_roots]):
        raw_name = distribution.metadata["Name"]
        version = distribution.version
        if (
            not isinstance(raw_name, str)
            or not raw_name
            or not isinstance(version, str)
            or not version
        ):
            raise ExperimentError("installed distribution metadata lacks a name or version")
        name = _normalize_distribution(raw_name)
        if name in installed:
            raise ExperimentError("installed distribution metadata is duplicated")
        installed[name] = version
    if not installed:
        raise ExperimentError("prepared virtual environment contains no distributions")
    return dict(sorted(installed.items()))


def _verify_record_hash(
    *,
    relative_name: str,
    mode: str | None,
    value: str | None,
    recorded_size: int | None,
    payload: bytes,
) -> bool:
    if mode is None or value is None:
        if Path(relative_name).name != "RECORD":
            raise ExperimentError("installed distribution has an unhashed RECORD entry")
        return False
    if mode != "sha256":
        raise ExperimentError("installed distribution uses a non-SHA256 RECORD hash")
    encoded = (
        base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
    )
    if value != encoded or recorded_size != len(payload):
        raise ExperimentError("installed distribution RECORD verification failed")
    return True


def _is_locked_coverage_pth(
    *,
    distribution: str,
    version: str,
    path: Path,
    site_roots: tuple[Path, ...],
    payload: bytes,
) -> bool:
    return (
        distribution == "coverage"
        and version == "7.15.2"
        and path.name == "a1_coverage.pth"
        and path.parent in site_roots
        and _sha256(payload) == COVERAGE_PTH_SHA256
    )


def _installed_files_tree_sha256(
    installed: dict[str, str],
    *,
    site_roots: tuple[Path, ...],
    prefix: Path,
) -> str:
    prefix = prefix.resolve(strict=True)
    require_root_owned = platform.system() == "Linux"
    distributions: dict[str, Any] = {}
    for distribution in importlib_metadata.distributions(path=[str(path) for path in site_roots]):
        raw_name = distribution.metadata["Name"]
        if not isinstance(raw_name, str) or not raw_name:
            raise ExperimentError("installed distribution metadata lacks a name")
        name = _normalize_distribution(raw_name)
        if name in distributions:
            raise ExperimentError("installed distribution metadata is duplicated")
        distributions[name] = distribution
    if set(distributions) != set(installed):
        raise ExperimentError("audited inventory and distribution metadata differ")

    entries: list[dict[str, Any]] = []
    allowed_files: set[Path] = set()
    allowed_path_configuration_files: set[Path] = set()
    claimed_files: dict[Path, str] = {}
    total_bytes = 0
    for name, version in sorted(installed.items()):
        distribution = distributions[name]
        files = distribution.files
        if files is None:
            raise ExperimentError("installed distribution has no RECORD inventory")
        for package_path in sorted(files, key=lambda item: str(item)):
            if len(entries) >= MAX_INSTALLED_FILES:
                raise ExperimentError("installed file inventory exceeds its file limit")
            located = Path(distribution.locate_file(package_path)).absolute()
            resolved_located = located.resolve(strict=True)
            if resolved_located in claimed_files:
                raise ExperimentError("installed file is claimed more than once")
            claimed_files[resolved_located] = name
            payload = _read_installed_file(
                located,
                prefix=prefix,
                require_root_owned=require_root_owned,
            )
            allowed_files.add(resolved_located)
            if _is_locked_coverage_pth(
                distribution=name,
                version=version,
                path=resolved_located,
                site_roots=site_roots,
                payload=payload,
            ):
                allowed_path_configuration_files.add(resolved_located)
            total_bytes += len(payload)
            if total_bytes > MAX_INSTALLED_TOTAL_BYTES:
                raise ExperimentError("installed file inventory exceeds its byte limit")
            actual_digest = hashlib.sha256(payload).digest()
            record_hash = package_path.hash
            record_hash_verified = _verify_record_hash(
                relative_name=str(package_path),
                mode=record_hash.mode if record_hash is not None else None,
                value=record_hash.value if record_hash is not None else None,
                recorded_size=package_path.size,
                payload=payload,
            )
            relative = located.resolve(strict=True).relative_to(prefix).as_posix()
            entries.append(
                {
                    "distribution": name,
                    "version": version,
                    "path": relative,
                    "bytes": len(payload),
                    "sha256": actual_digest.hex(),
                    "recordHashVerified": record_hash_verified,
                }
            )
    _audit_site_package_claims(
        site_roots,
        allowed_files,
        require_root_owned=require_root_owned,
        allowed_path_configuration_files=allowed_path_configuration_files,
    )
    return _sha256(_canonical(entries))


def _trusted_command(name: str, environment: dict[str, str]) -> Path:
    selected = shutil.which(name, path=environment.get("PATH"))
    if selected is None:
        raise ExperimentError(f"{name} is unavailable for source identity verification")
    try:
        path = Path(selected).resolve(strict=True)
        metadata = path.lstat()
    except OSError as exc:
        raise ExperimentError(f"{name} executable metadata is unavailable") from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not os.access(path, os.X_OK)
        or (os.name == "posix" and (metadata.st_uid != 0 or metadata.st_mode & 0o022))
    ):
        raise ExperimentError(f"{name} executable is outside policy")
    return path


def _git_argv(git: Path, *arguments: str) -> tuple[str, ...]:
    return (
        str(git),
        "-c",
        f"safe.directory={ROOT}",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        f"core.excludesFile={os.devnull}",
        "-c",
        "credential.helper=",
        "-C",
        str(ROOT),
        *arguments,
    )


def _repository_identity(
    environment: dict[str, str],
    *,
    git: Path | None = None,
) -> dict[str, str]:
    git_path = git or _trusted_command("git", environment)
    try:
        revision_result = _run_bounded_capture(
            _git_argv(git_path, "rev-parse", "--verify", "HEAD^{commit}"),
            cwd=ROOT,
            environment=environment,
            timeout=30,
        )
        status_result = _run_bounded_capture(
            _git_argv(
                git_path,
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "-z",
            ),
            cwd=ROOT,
            environment=environment,
            timeout=30,
        )
        tree_result = _run_bounded_capture(
            _git_argv(git_path, "rev-parse", "--verify", "HEAD^{tree}"),
            cwd=ROOT,
            environment=environment,
            timeout=30,
        )
        tracked_result = _run_bounded_capture(
            _git_argv(git_path, "ls-files", "-v", "-z"),
            cwd=ROOT,
            environment=environment,
            timeout=30,
        )
        ignored_result = _run_bounded_capture(
            _git_argv(
                git_path,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
            ),
            cwd=ROOT,
            environment=environment,
            timeout=30,
        )
    except OSError as exc:
        raise ExperimentError("repository identity verification failed") from exc
    try:
        revision = revision_result.stdout.decode("ascii").strip()
        tree = tree_result.stdout.decode("ascii").strip()
    except UnicodeError as exc:
        raise ExperimentError("repository revision is malformed") from exc
    tracked_records = [record for record in tracked_result.stdout.split(b"\0") if record]
    if (
        revision_result.exit_code != 0
        or revision_result.timed_out
        or revision_result.capture_limit_exceeded
        or REVISION.fullmatch(revision) is None
        or status_result.exit_code != 0
        or status_result.timed_out
        or status_result.capture_limit_exceeded
        or status_result.stdout
        or status_result.stderr
        or tree_result.exit_code != 0
        or tree_result.timed_out
        or tree_result.capture_limit_exceeded
        or REVISION.fullmatch(tree) is None
        or tree_result.stderr
        or tracked_result.exit_code != 0
        or tracked_result.timed_out
        or tracked_result.capture_limit_exceeded
        or tracked_result.stderr
        or not tracked_records
        or any(not record.startswith(b"H ") for record in tracked_records)
        or ignored_result.exit_code != 0
        or ignored_result.timed_out
        or ignored_result.capture_limit_exceeded
        or ignored_result.stdout
        or ignored_result.stderr
    ):
        raise ExperimentError("experiments require a completely clean committed source")
    value = {
        "revision": revision,
        "tree": tree,
        "trackedInventorySha256": _sha256(tracked_result.stdout),
        "ignoredInventorySha256": _sha256(ignored_result.stdout),
    }
    return {**value, "identitySha256": _sha256(_canonical(value))}


def _repository_revision(environment: dict[str, str], *, git: Path | None = None) -> str:
    return _repository_identity(environment, git=git)["revision"]


def _source_matches(
    environment: dict[str, str],
    *,
    git: Path,
    identity_sha256: str,
) -> bool:
    try:
        return _repository_identity(environment, git=git)["identitySha256"] == identity_sha256
    except ExperimentError:
        return False


def _network_namespace_isolated() -> bool:
    if os.name != "posix":
        return False
    try:
        current = Path("/proc/self/ns/net").stat()
        host = Path("/proc/1/ns/net").stat()
    except OSError:
        return False
    return (current.st_dev, current.st_ino) != (host.st_dev, host.st_ino)


def _dangerous_network_capabilities_absent() -> bool:
    if os.name != "posix":
        return False
    try:
        status_payload = Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return False
    match = re.search(r"(?m)^CapEff:\s*([0-9A-Fa-f]+)\s*$", status_payload)
    if match is None:
        return False
    effective = int(match.group(1), 16)
    cap_net_admin = 1 << 12
    cap_sys_admin = 1 << 21
    return effective & (cap_net_admin | cap_sys_admin) == 0


def _systemd_runtime_policy_verified() -> bool:
    if platform.system() != "Linux":
        return False
    posix_module = importlib.import_module("posix")
    geteuid = cast(Callable[[], int], posix_module.geteuid)
    if geteuid() == 0:
        return False
    try:
        status_payload = Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return False
    match = re.search(r"(?m)^NoNewPrivs:\s*([01])\s*$", status_payload)
    return match is not None and match.group(1) == "1"


def _enable_child_subreaper() -> bool:
    global _SUBREAPER_ENABLED
    if platform.system() != "Linux":
        _SUBREAPER_ENABLED = False
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        prctl.restype = ctypes.c_int
        result = cast(int, prctl(36, 1, 0, 0, 0))  # PR_SET_CHILD_SUBREAPER
    except (AttributeError, OSError, TypeError, ValueError):
        _SUBREAPER_ENABLED = False
        return False
    _SUBREAPER_ENABLED = result == 0
    return _SUBREAPER_ENABLED


def _linux_descendant_pids() -> set[int]:
    if not _SUBREAPER_ENABLED or platform.system() != "Linux":
        return set()
    descendants: set[int] = set()
    pending = [os.getpid()]
    while pending:
        parent = pending.pop()
        children_path = Path(f"/proc/{parent}/task/{parent}/children")
        try:
            values = children_path.read_text(encoding="ascii").split()
        except (OSError, UnicodeError):
            continue
        for value in values:
            try:
                child = int(value)
            except ValueError:
                continue
            if child > 1 and child != os.getpid() and child not in descendants:
                descendants.add(child)
                pending.append(child)
    return descendants


def _reap_orphaned_children() -> None:
    if platform.system() != "Linux":
        return
    while True:
        try:
            pid, _status = os.waitpid(-1, 1)  # WNOHANG
        except (ChildProcessError, OSError):
            return
        if pid <= 0:
            return


def _cleanup_descendants() -> tuple[bool, bool, int]:
    if not _SUBREAPER_ENABLED or platform.system() != "Linux":
        return False, True, 0
    terminated: set[int] = set()
    for signal_number, grace_seconds in ((15, 1.0), (9, 3.0)):
        deadline = time.monotonic() + grace_seconds
        while True:
            _reap_orphaned_children()
            descendants = _linux_descendant_pids()
            if not descendants:
                return True, True, len(terminated)
            terminated.update(descendants)
            for pid in descendants:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.kill(pid, signal_number)
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)
    _reap_orphaned_children()
    return True, not _linux_descendant_pids(), len(terminated)


def _network_claim(mode: str, confirmation: str) -> dict[str, Any]:
    if mode == NETWORK_MODE_ISOLATED:
        if confirmation != NETWORK_ISOLATED_CONFIRMATION or not _network_namespace_isolated():
            raise ExperimentError("a verified private network namespace is required")
        if not _dangerous_network_capabilities_absent():
            raise ExperimentError("dangerous network namespace capabilities remain effective")
        if not _systemd_runtime_policy_verified():
            raise ExperimentError("DynamicUser and NoNewPrivileges runtime policy is not verified")
        return {
            "mode": NETWORK_MODE_ISOLATED,
            "namespaceVerifiedAgainstPid1": True,
            "dangerousNetworkCapabilitiesAbsent": True,
            "systemdRuntimePolicyVerified": True,
            "networkAvailable": None,
            "outboundConnectivityTested": False,
            "claimBoundary": "network_namespace_and_capability_policy_only",
            "credentialEnvironmentStripped": True,
            "credentialFilesystemIsolationVerified": False,
        }
    if mode == NETWORK_MODE_AVAILABLE:
        if confirmation != NETWORK_AVAILABLE_CONFIRMATION:
            raise ExperimentError("the exact credential-stripped network confirmation is required")
        return {
            "mode": NETWORK_MODE_AVAILABLE,
            "namespaceVerifiedAgainstPid1": False,
            "dangerousNetworkCapabilitiesAbsent": False,
            "systemdRuntimePolicyVerified": False,
            "networkAvailable": True,
            "outboundConnectivityTested": False,
            "claimBoundary": "network_available_environment_credentials_omitted_only",
            "credentialEnvironmentStripped": True,
            "credentialFilesystemIsolationVerified": False,
        }
    raise ExperimentError("network mode is invalid")


def _bounded(data: bytes) -> tuple[bytes, bool]:
    if len(data) <= MAX_LOG_BYTES:
        return data, False
    marker = b"\n[DEVFLOW LOG TRUNCATED; RECEIPT BINDS FULL CAPTURE]\n"
    return data[: MAX_LOG_BYTES - len(marker)] + marker, True


def _capture_limiter() -> None:
    try:
        resource_module = importlib.import_module("resource")
        resource_module.setrlimit(
            resource_module.RLIMIT_FSIZE,
            (MAX_CAPTURE_BYTES, MAX_CAPTURE_BYTES),
        )
    except (ImportError, OSError, ValueError):
        return


def _read_capture(stream: Any) -> tuple[bytes, bool]:
    stream.flush()
    stream.seek(0, os.SEEK_END)
    size = stream.tell()
    stream.seek(0)
    payload = stream.read(min(size, MAX_CAPTURE_BYTES))
    if not isinstance(payload, bytes):
        raise ExperimentError("step capture is not binary")
    return payload, size >= MAX_CAPTURE_BYTES


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            posix_module = importlib.import_module("posix")
            signal_module = importlib.import_module("signal")
            killpg = cast(Callable[[int, int], None], posix_module.killpg)
            sigkill = cast(int, signal_module.SIGKILL)
            killpg(process.pid, sigkill)
        else:  # pragma: no cover - preferred server path is Linux/systemd
            process.kill()
    except OSError:
        with contextlib.suppress(OSError):
            process.kill()
    try:
        process.communicate(timeout=10)
    except (OSError, subprocess.SubprocessError):
        with contextlib.suppress(OSError):
            process.kill()
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            process.communicate(timeout=10)


def _run_bounded_capture(
    argv: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout: int,
) -> CommandCapture:
    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_stream,
        tempfile.TemporaryFile(mode="w+b") as stderr_stream,
    ):
        process = subprocess.Popen(
            list(argv),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_stream,
            stderr=stderr_stream,
            shell=False,
            start_new_session=os.name == "posix",
            preexec_fn=_capture_limiter if os.name == "posix" else None,
        )
        timed_out = False
        try:
            process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process(process)
        process_exit_code = process.returncode if process.returncode is not None else -1
        (
            descendant_cleanup_supported,
            descendant_cleanup_succeeded,
            terminated_descendant_count,
        ) = _cleanup_descendants()
        stdout, stdout_limited = _read_capture(stdout_stream)
        stderr, stderr_limited = _read_capture(stderr_stream)
        capture_limit_exceeded = stdout_limited or stderr_limited
        exit_code = (
            126
            if descendant_cleanup_supported and not descendant_cleanup_succeeded
            else 125
            if capture_limit_exceeded
            else 124
            if timed_out
            else process_exit_code
        )
        return CommandCapture(
            process_exit_code=process_exit_code,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
            capture_limit_exceeded=capture_limit_exceeded,
            descendant_cleanup_supported=descendant_cleanup_supported,
            descendant_cleanup_succeeded=descendant_cleanup_succeeded,
            terminated_descendant_count=terminated_descendant_count,
        )


def _run_step(
    step: Step,
    *,
    output: Path,
    environment: dict[str, str],
    ordinal: int,
) -> StepResult:
    started_at = _now()
    started = time.monotonic()
    try:
        capture = _run_bounded_capture(
            step.argv,
            cwd=ROOT,
            environment=environment,
            timeout=step.timeout_seconds,
        )
        process_exit_code = capture.process_exit_code
        exit_code = capture.exit_code
        timed_out = capture.timed_out
        capture_limit_exceeded = capture.capture_limit_exceeded
        descendant_cleanup_supported = capture.descendant_cleanup_supported
        descendant_cleanup_succeeded = capture.descendant_cleanup_succeeded
        terminated_descendant_count = capture.terminated_descendant_count
        stdout = capture.stdout
        stderr = capture.stderr
        failure_reason = (
            "descendant_cleanup_failed"
            if descendant_cleanup_supported and not descendant_cleanup_succeeded
            else "capture_limit_exceeded"
            if capture_limit_exceeded
            else "timeout"
            if timed_out
            else "process_exit_nonzero"
            if exit_code != 0
            else None
        )
        if timed_out:
            stderr += b"\n[DEVFLOW STEP TIMEOUT]\n"
        if capture_limit_exceeded:
            stderr += b"\n[DEVFLOW CAPTURE LIMIT EXCEEDED]\n"
    except OSError:
        process_exit_code = 127
        exit_code = 127
        timed_out = False
        capture_limit_exceeded = False
        descendant_cleanup_supported = _SUBREAPER_ENABLED
        descendant_cleanup_succeeded = True
        terminated_descendant_count = 0
        stdout = b""
        stderr = b"[DEVFLOW STEP SPAWN FAILED]\n"
        failure_reason = "spawn_failed"
    duration_ms = int((time.monotonic() - started) * 1000)
    stored_stdout, stdout_truncated = _bounded(stdout)
    stored_stderr, stderr_truncated = _bounded(stderr)
    prefix = f"{ordinal:02d}-{step.name}"
    _write_new(output / f"{prefix}.stdout.log", stored_stdout)
    _write_new(output / f"{prefix}.stderr.log", stored_stderr)
    passed = exit_code == 0
    return StepResult(
        name=step.name,
        argv=list(step.argv),
        started_at=started_at,
        finished_at=_now(),
        duration_ms=duration_ms,
        process_exit_code=process_exit_code,
        exit_code=exit_code,
        timed_out=timed_out,
        capture_limit_exceeded=capture_limit_exceeded,
        descendant_cleanup_supported=descendant_cleanup_supported,
        descendant_cleanup_succeeded=descendant_cleanup_succeeded,
        terminated_descendant_count=terminated_descendant_count,
        failure_reason=failure_reason,
        stdout_sha256=_sha256(stdout),
        stderr_sha256=_sha256(stderr),
        stdout_log_sha256=_sha256(stored_stdout),
        stderr_log_sha256=_sha256(stored_stderr),
        stdout_bytes=len(stdout),
        stderr_bytes=len(stderr),
        stdout_truncated=stdout_truncated,
        stderr_truncated=stderr_truncated,
        passed=passed,
    )


def _blocked_step(step: Step, *, output: Path, ordinal: int) -> StepResult:
    started_at = _now()
    stdout = b""
    stderr = b"[DEVFLOW STEP BLOCKED: SOURCE IDENTITY DRIFT]\n"
    prefix = f"{ordinal:02d}-{step.name}"
    _write_new(output / f"{prefix}.stdout.log", stdout)
    _write_new(output / f"{prefix}.stderr.log", stderr)
    return StepResult(
        name=step.name,
        argv=list(step.argv),
        started_at=started_at,
        finished_at=_now(),
        duration_ms=0,
        process_exit_code=-1,
        exit_code=4,
        timed_out=False,
        capture_limit_exceeded=False,
        descendant_cleanup_supported=_SUBREAPER_ENABLED,
        descendant_cleanup_succeeded=True,
        terminated_descendant_count=0,
        failure_reason="source_identity_drift",
        stdout_sha256=_sha256(stdout),
        stderr_sha256=_sha256(stderr),
        stdout_log_sha256=_sha256(stdout),
        stderr_log_sha256=_sha256(stderr),
        stdout_bytes=0,
        stderr_bytes=len(stderr),
        stdout_truncated=False,
        stderr_truncated=False,
        passed=False,
    )


def _package_digests(package_root: Path) -> dict[str, str]:
    try:
        from scripts.build_agentteams_package import PACKAGE_VERSION, ROLE_SKILLS
    except (ImportError, RuntimeError) as exc:
        raise ExperimentError("role package contract is unavailable") from exc
    try:
        dist = package_root.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError("isolated role package directory is unavailable") from exc
    if package_root.is_symlink() or dist != package_root or not dist.is_dir():
        raise ExperimentError("isolated role package directory is unsafe")
    expected_files: set[str] = set()
    for role in ROLE_SKILLS:
        archive_name = f"{role}-v{PACKAGE_VERSION}.zip"
        expected_files.update({archive_name, f"{archive_name}.sha256"})
    try:
        entries: list[Path] = []
        for path in dist.iterdir():
            entries.append(path)
            if len(entries) > len(expected_files):
                raise ExperimentError("isolated role package set has unexpected entries")
    except OSError as exc:
        raise ExperimentError("isolated role package set is unavailable") from exc
    actual_files = {path.name for path in entries if path.is_file() and not path.is_symlink()}
    if (
        any(not path.is_file() or path.is_symlink() for path in entries)
        or actual_files != expected_files
    ):
        raise ExperimentError("isolated role package set has unexpected entries")
    results: dict[str, str] = {}
    for role in sorted(ROLE_SKILLS):
        archive = dist / f"{role}-v{PACKAGE_VERSION}.zip"
        sidecar = archive.with_suffix(archive.suffix + ".sha256")
        archive_payload = _read_regular(
            archive,
            maximum=MAX_PACKAGE_BYTES,
            label="role package",
        )
        sidecar_payload = _read_regular(
            sidecar,
            maximum=256,
            label="role package sidecar",
        )
        digest = _sha256(archive_payload)
        expected_sidecar = f"{digest}  {archive.name}\n".encode("ascii")
        if sidecar_payload != expected_sidecar:
            raise ExperimentError("role package sidecar does not bind its archive")
        results[archive.name] = digest
        results[sidecar.name] = _sha256(sidecar_payload)
    if not results:
        raise ExperimentError("role package set is empty")
    return dict(sorted(results.items()))


def _write_package_evidence(
    output: Path,
    *,
    pass_number: int,
    digests: dict[str, str] | None,
) -> str:
    payload = (
        _canonical(
            {
                "schema": "devflow.role-package-set/v1",
                "pass": pass_number,
                "available": digests is not None,
                "digests": digests,
            }
        )
        + b"\n"
    )
    name = f"role-packages-pass-{pass_number}.json"
    _write_new(output / name, payload)
    return _sha256(payload)


def _tree_sha256(root: Path) -> str:
    try:
        resolved = root.resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as exc:
        raise ExperimentError("artifact tree is unavailable") from exc
    if root.is_symlink() or resolved != root or not stat.S_ISDIR(root_metadata.st_mode):
        raise ExperimentError("artifact tree root is unsafe")
    paths: list[Path] = []
    for path in root.rglob("*"):
        paths.append(path)
        if len(paths) > MAX_ARTIFACT_FILES:
            raise ExperimentError("artifact tree exceeds the entry limit")
    entries: list[dict[str, Any]] = []
    file_count = 0
    total_bytes = 0
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if SAFE_EVIDENCE_PATH.fullmatch(relative) is None:
            raise ExperimentError("artifact path is not canonical")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ExperimentError("artifact tree changed during hashing") from exc
        if path.is_symlink():
            raise ExperimentError("artifact tree contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            entries.append({"path": relative, "type": "directory"})
            continue
        payload = _read_regular(
            path,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="artifact file",
        )
        file_count += 1
        total_bytes += len(payload)
        if file_count > MAX_ARTIFACT_FILES or total_bytes > MAX_ARTIFACT_TOTAL_BYTES:
            raise ExperimentError("artifact tree exceeds the bounded evidence budget")
        entries.append(
            {
                "path": relative,
                "type": "file",
                "bytes": len(payload),
                "sha256": _sha256(payload),
            }
        )
    return _sha256(_canonical(entries))


def _write_step_receipt(
    output: Path,
    *,
    run_id: str,
    ordinal: int,
    plan_sha256: str,
    previous_receipt_sha256: str | None,
    result: StepResult,
    evidence: dict[str, Any],
) -> str:
    if previous_receipt_sha256 is not None and DIGEST.fullmatch(previous_receipt_sha256) is None:
        raise ExperimentError("previous receipt digest is invalid")
    value = {
        "schema": "devflow.offline-experiment-step-receipt/v2",
        "runId": run_id,
        "ordinal": ordinal,
        "planSha256": plan_sha256,
        "previousReceiptSha256": previous_receipt_sha256,
        "result": asdict(result),
        "evidence": evidence,
    }
    payload = _canonical(value) + b"\n"
    _write_new(output / f"{ordinal:02d}-{result.name}.receipt.json", payload)
    return _sha256(payload)


def _verified_package_set_evidence(
    output: Path,
    *,
    pass_number: int,
    expected_sha256: Any,
) -> tuple[bool, dict[str, str] | None]:
    if not isinstance(expected_sha256, str) or DIGEST.fullmatch(expected_sha256) is None:
        return False, None
    payload = _read_regular(
        output / f"role-packages-pass-{pass_number}.json",
        maximum=MAX_EVIDENCE_FILE_BYTES,
        label="role package set evidence",
    )
    if _sha256(payload) != expected_sha256:
        return False, None
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError):
        return False, None
    if (
        not isinstance(value, dict)
        or payload != _canonical(value) + b"\n"
        or set(value) != {"schema", "pass", "available", "digests"}
        or value.get("schema") != "devflow.role-package-set/v1"
        or value.get("pass") != pass_number
        or not isinstance(value.get("available"), bool)
    ):
        return False, None
    digests = value.get("digests")
    if digests is None:
        return value["available"] is False, None
    if (
        value["available"] is not True
        or not isinstance(digests, dict)
        or not digests
        or any(
            not isinstance(name, str)
            or "/" in name
            or SAFE_EVIDENCE_PATH.fullmatch(name) is None
            or not isinstance(digest, str)
            or DIGEST.fullmatch(digest) is None
            for name, digest in digests.items()
        )
    ):
        return False, None
    return True, dict(sorted(digests.items()))


def _verified_determinism_evidence(
    output: Path,
    *,
    expected_sha256: Any,
    first: dict[str, str] | None,
    second: dict[str, str] | None,
) -> bool:
    if not isinstance(expected_sha256, str) or DIGEST.fullmatch(expected_sha256) is None:
        return False
    payload = _read_regular(
        output / "role-packages-determinism.json",
        maximum=MAX_EVIDENCE_FILE_BYTES,
        label="role package determinism evidence",
    )
    expected = {
        "schema": "devflow.role-package-determinism/v2",
        "deterministic": first is not None and second is not None and first == second,
        "first": first,
        "second": second,
        "firstSetSha256": _sha256(_canonical(first)) if first is not None else None,
        "secondSetSha256": _sha256(_canonical(second)) if second is not None else None,
    }
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError):
        return False
    return (
        _sha256(payload) == expected_sha256
        and isinstance(value, dict)
        and payload == _canonical(value) + b"\n"
        and value == expected
    )


def _verify_receipt_chain(
    output: Path,
    *,
    run_id: str,
    plan_sha256: str,
    records: list[StepRecord],
) -> bool:
    try:
        plan_payload = _read_regular(
            output / "PLAN.json",
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="experiment plan",
        )
        if _sha256(plan_payload) != plan_sha256:
            return False
        expected_root_files = {"HEARTBEAT.json", "PLAN.json"}
        expected_root_directories = {".runtime", "artifacts"}
        previous: str | None = None
        terminal_receipt: dict[str, Any] | None = None
        first_package_set: dict[str, str] | None = None
        saw_first_package_set = False
        for ordinal, record in enumerate(records, start=1):
            prefix = f"{ordinal:02d}-{record.result.name}"
            receipt_name = f"{prefix}.receipt.json"
            expected_root_files.update(
                {
                    receipt_name,
                    f"{prefix}.stdout.log",
                    f"{prefix}.stderr.log",
                }
            )
            receipt_payload = _read_regular(
                output / receipt_name,
                maximum=MAX_EVIDENCE_FILE_BYTES,
                label="step receipt",
            )
            if _sha256(receipt_payload) != record.receipt_sha256:
                return False
            try:
                receipt = json.loads(receipt_payload)
            except (json.JSONDecodeError, UnicodeError):
                return False
            if not isinstance(receipt, dict) or receipt_payload != _canonical(receipt) + b"\n":
                return False
            if (
                receipt.get("schema") != "devflow.offline-experiment-step-receipt/v2"
                or receipt.get("runId") != run_id
                or receipt.get("ordinal") != ordinal
                or receipt.get("planSha256") != plan_sha256
                or receipt.get("previousReceiptSha256") != previous
                or receipt.get("result") != asdict(record.result)
                or not isinstance(receipt.get("evidence"), dict)
            ):
                return False
            stdout = _read_regular(
                output / f"{prefix}.stdout.log",
                maximum=MAX_EVIDENCE_FILE_BYTES,
                label="step stdout log",
            )
            stderr = _read_regular(
                output / f"{prefix}.stderr.log",
                maximum=MAX_EVIDENCE_FILE_BYTES,
                label="step stderr log",
            )
            if (
                _sha256(stdout) != record.result.stdout_log_sha256
                or _sha256(stderr) != record.result.stderr_log_sha256
            ):
                return False
            previous = record.receipt_sha256
            terminal_receipt = receipt
            if record.result.name == "role-packages-pass-1":
                expected_root_files.add("role-packages-pass-1.json")
                verified, first_package_set = _verified_package_set_evidence(
                    output,
                    pass_number=1,
                    expected_sha256=receipt["evidence"].get("packageSetEvidenceSha256"),
                )
                if not verified:
                    return False
                saw_first_package_set = True
            elif record.result.name == "role-packages-pass-2":
                expected_root_files.update(
                    {
                        "role-packages-pass-2.json",
                        "role-packages-determinism.json",
                    }
                )
                second_verified, second_package_set = _verified_package_set_evidence(
                    output,
                    pass_number=2,
                    expected_sha256=receipt["evidence"].get("packageSetEvidenceSha256"),
                )
                if (
                    not saw_first_package_set
                    or not second_verified
                    or not _verified_determinism_evidence(
                        output,
                        expected_sha256=receipt["evidence"].get("determinismEvidenceSha256"),
                        first=first_package_set,
                        second=second_package_set,
                    )
                ):
                    return False
        actual_root_files: set[str] = set()
        actual_root_directories: set[str] = set()
        for path in output.iterdir():
            metadata = path.lstat()
            if path.is_symlink():
                return False
            if stat.S_ISREG(metadata.st_mode):
                actual_root_files.add(path.name)
            elif stat.S_ISDIR(metadata.st_mode):
                actual_root_directories.add(path.name)
            else:
                return False
        if (
            actual_root_files != expected_root_files
            or actual_root_directories != expected_root_directories
            or terminal_receipt is None
            or terminal_receipt["evidence"].get("artifactTreeSha256")
            != _tree_sha256(output / "artifacts")
        ):
            return False
    except (ExperimentError, OSError, TypeError, ValueError):
        return False
    return True


def _remove_runtime(output: Path) -> None:
    runtime = output / ".runtime"
    try:
        resolved_output = output.resolve(strict=True)
        resolved_runtime = runtime.resolve(strict=True)
    except OSError as exc:
        raise ExperimentError("runtime cleanup target is unavailable") from exc
    if (
        runtime.is_symlink()
        or resolved_runtime.parent != resolved_output
        or resolved_runtime.name != ".runtime"
    ):
        raise ExperimentError("runtime cleanup target is unsafe")
    try:
        shutil.rmtree(resolved_runtime)
    except OSError as exc:
        raise ExperimentError("runtime cleanup failed safely") from exc


def _evidence_files(output: Path) -> tuple[Path, ...]:
    files: list[Path] = []
    scanned_entries = 0
    total_bytes = 0
    for path in output.rglob("*"):
        scanned_entries += 1
        if scanned_entries > MAX_EVIDENCE_FILES:
            raise ExperimentError("evidence tree exceeds the entry limit")
        relative = path.relative_to(output).as_posix()
        if relative in {"COMPLETION.json", "SHA256SUMS"}:
            continue
        if SAFE_EVIDENCE_PATH.fullmatch(relative) is None:
            raise ExperimentError("evidence path is not canonical")
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ExperimentError("evidence tree changed during sealing") from exc
        if path.is_symlink():
            raise ExperimentError("evidence tree contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_EVIDENCE_FILE_BYTES
        ):
            raise ExperimentError("evidence tree contains an unsafe file")
        total_bytes += metadata.st_size
        if len(files) >= MAX_EVIDENCE_FILES or total_bytes > MAX_EVIDENCE_TOTAL_BYTES:
            raise ExperimentError("evidence tree exceeds the total byte limit")
        files.append(path)
    return tuple(sorted(files, key=lambda item: item.relative_to(output).as_posix()))


def _sha256sums(output: Path) -> bytes:
    lines = [
        f"{_sha256(_read_regular(path, maximum=MAX_EVIDENCE_FILE_BYTES, label='evidence file'))}  "
        f"{path.relative_to(output).as_posix()}"
        for path in _evidence_files(output)
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _seal_evidence(output: Path) -> None:
    try:
        for path in _evidence_files(output):
            os.chmod(path, 0o444)
    except OSError as exc:
        raise ExperimentError("evidence files could not be sealed") from exc


def _seal_directories(output: Path) -> None:
    directories = [path for path in output.rglob("*") if path.is_dir()]
    try:
        for path in sorted(directories, key=lambda item: len(item.parts), reverse=True):
            if path.is_symlink():
                raise ExperimentError("evidence directory tree contains a link")
            os.chmod(path, 0o555)
        os.chmod(output, 0o555)
    except OSError as exc:
        raise ExperimentError("evidence directories could not be sealed") from exc


def _read_canonical_object(path: Path, *, label: str) -> tuple[dict[str, Any], bytes]:
    payload = _read_regular(path, maximum=MAX_EVIDENCE_FILE_BYTES, label=label)
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ExperimentError(f"{label} is malformed") from exc
    if not isinstance(value, dict) or payload != _canonical(value) + b"\n":
        raise ExperimentError(f"{label} is not a canonical JSON object")
    return value, payload


def _verified_sha256_manifest(output: Path, payload: bytes) -> dict[str, Path]:
    try:
        text = payload.decode("ascii")
    except UnicodeError as exc:
        raise ExperimentError("SHA256SUMS is not ASCII") from exc
    if not text or not text.endswith("\n"):
        raise ExperimentError("SHA256SUMS is malformed")
    expected: dict[str, str] = {}
    for line in text.splitlines():
        if len(line) < 67 or line[64:66] != "  " or DIGEST.fullmatch(line[:64]) is None:
            raise ExperimentError("SHA256SUMS contains a malformed entry")
        relative_name = line[66:]
        relative = PurePosixPath(relative_name)
        if (
            not relative_name
            or relative.is_absolute()
            or relative.as_posix() != relative_name
            or any(part in {"", ".", ".."} for part in relative.parts)
            or SAFE_EVIDENCE_PATH.fullmatch(relative_name) is None
            or relative_name in {"COMPLETION.json", "SHA256SUMS"}
            or relative_name in expected
        ):
            raise ExperimentError("SHA256SUMS contains an unsafe or duplicate path")
        expected[relative_name] = line[:64]
    if list(expected) != sorted(expected):
        raise ExperimentError("SHA256SUMS is not canonically ordered")
    actual = {path.relative_to(output).as_posix(): path for path in _evidence_files(output)}
    if set(actual) != set(expected):
        raise ExperimentError("SHA256SUMS does not enumerate the exact evidence file set")
    for relative_name, path in actual.items():
        digest = _sha256(
            _read_regular(path, maximum=MAX_EVIDENCE_FILE_BYTES, label="manifest evidence file")
        )
        if digest != expected[relative_name]:
            raise ExperimentError("SHA256SUMS evidence digest mismatch")
    return actual


def _verify_completed_output(raw_output: Path) -> dict[str, Any]:
    output = Path(os.path.abspath(raw_output))
    try:
        resolved_output = output.resolve(strict=True)
        output_metadata = output.lstat()
    except OSError as exc:
        raise ExperimentError("completed evidence directory is unavailable") from exc
    if (
        output.is_symlink()
        or resolved_output != output
        or not stat.S_ISDIR(output_metadata.st_mode)
    ):
        raise ExperimentError("completed evidence directory is unsafe")

    completion, completion_payload = _read_canonical_object(
        output / "COMPLETION.json",
        label="completion evidence",
    )
    manifest_payload = _read_regular(
        output / "SHA256SUMS",
        maximum=MAX_EVIDENCE_FILE_BYTES,
        label="SHA256SUMS",
    )
    if completion.get("sha256sumsSha256") != _sha256(manifest_payload):
        raise ExperimentError("completion evidence does not bind SHA256SUMS")
    manifested_files = _verified_sha256_manifest(output, manifest_payload)

    root_directories: set[str] = set()
    root_files: set[str] = set()
    for path in output.iterdir():
        metadata = path.lstat()
        if path.is_symlink():
            raise ExperimentError("completed evidence root contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            root_directories.add(path.name)
        elif stat.S_ISREG(metadata.st_mode):
            root_files.add(path.name)
        else:
            raise ExperimentError("completed evidence root contains an unsafe entry")
    if root_directories != {"artifacts"}:
        raise ExperimentError("completed evidence has an unexpected root directory")

    plan, plan_payload = _read_canonical_object(output / "PLAN.json", label="experiment plan")
    summary, summary_payload = _read_canonical_object(
        output / "SUMMARY.json",
        label="experiment summary",
    )
    heartbeat, heartbeat_payload = _read_canonical_object(
        output / "HEARTBEAT.json",
        label="final heartbeat",
    )
    run_id = completion.get("runId")
    if (
        completion.get("schema") != "devflow.offline-experiment-completion/v1"
        or not isinstance(run_id, str)
        or SAFE_RUN_ID.fullmatch(run_id) is None
        or plan.get("schema") != "devflow.offline-experiment-plan/v2"
        or summary.get("schema") != "devflow.offline-experiment-summary/v2"
        or heartbeat.get("schema") != "devflow.offline-experiment-heartbeat/v1"
        or plan.get("runId") != run_id
        or summary.get("runId") != run_id
        or heartbeat.get("runId") != run_id
        or heartbeat.get("state") != "sealing"
        or completion.get("planSha256") != _sha256(plan_payload)
        or completion.get("summarySha256") != _sha256(summary_payload)
        or completion.get("heartbeatSha256") != _sha256(heartbeat_payload)
        or summary.get("planSha256") != completion.get("planSha256")
    ):
        raise ExperimentError("completion, plan, summary, and heartbeat bindings disagree")

    steps = plan.get("steps")
    summary_results = summary.get("results")
    if not isinstance(steps, list) or not isinstance(summary_results, list) or not steps:
        raise ExperimentError("completed evidence lacks a fixed step/result inventory")
    receipts: list[tuple[int, str, Path]] = []
    for path in output.glob("*.receipt.json"):
        match = re.fullmatch(
            r"([0-9]{2})-([A-Za-z0-9][A-Za-z0-9._-]{0,79})\.receipt\.json",
            path.name,
        )
        if match is None:
            raise ExperimentError("completed evidence contains a malformed receipt name")
        receipts.append((int(match.group(1)), match.group(2), path))
    receipts.sort()
    if len(receipts) != len(steps) or len(receipts) != len(summary_results):
        raise ExperimentError("completed evidence receipt count differs from the fixed plan")

    expected_root_files = {
        "PLAN.json",
        "HEARTBEAT.json",
        "SUMMARY.json",
        "SHA256SUMS",
        "COMPLETION.json",
    }
    previous: str | None = None
    reconstructed_results: list[dict[str, Any]] = []
    terminal_receipt: dict[str, Any] | None = None
    first_package_set: dict[str, str] | None = None
    saw_first_package_set = False
    package_deterministic: bool | None = None
    result_fields = set(StepResult.__dataclass_fields__)
    for expected_ordinal, ((ordinal, name, receipt_path), step) in enumerate(
        zip(receipts, steps, strict=True),
        start=1,
    ):
        if (
            ordinal != expected_ordinal
            or not isinstance(step, dict)
            or step.get("name") != name
            or not isinstance(step.get("argv"), list)
        ):
            raise ExperimentError("completed evidence receipt order differs from the plan")
        receipt, receipt_payload = _read_canonical_object(receipt_path, label="step receipt")
        result = receipt.get("result")
        evidence = receipt.get("evidence")
        if (
            set(receipt)
            != {
                "schema",
                "runId",
                "ordinal",
                "planSha256",
                "previousReceiptSha256",
                "result",
                "evidence",
            }
            or receipt.get("schema") != "devflow.offline-experiment-step-receipt/v2"
            or receipt.get("runId") != run_id
            or receipt.get("ordinal") != ordinal
            or receipt.get("planSha256") != completion.get("planSha256")
            or receipt.get("previousReceiptSha256") != previous
            or not isinstance(result, dict)
            or set(result) != result_fields
            or result.get("name") != name
            or result.get("argv") != step.get("argv")
            or not isinstance(evidence, dict)
        ):
            raise ExperimentError("completed evidence contains an invalid step receipt")
        receipt_sha256 = _sha256(receipt_payload)
        stdout_name = f"{ordinal:02d}-{name}.stdout.log"
        stderr_name = f"{ordinal:02d}-{name}.stderr.log"
        stdout = _read_regular(
            output / stdout_name,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="step stdout log",
        )
        stderr = _read_regular(
            output / stderr_name,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="step stderr log",
        )
        if result.get("stdout_log_sha256") != _sha256(stdout) or result.get(
            "stderr_log_sha256"
        ) != _sha256(stderr):
            raise ExperimentError("completed evidence step log digest mismatch")
        expected_root_files.update({receipt_path.name, stdout_name, stderr_name})
        if name == "role-packages-pass-1":
            expected_root_files.add("role-packages-pass-1.json")
            verified, first_package_set = _verified_package_set_evidence(
                output,
                pass_number=1,
                expected_sha256=evidence.get("packageSetEvidenceSha256"),
            )
            if not verified:
                raise ExperimentError("completed first role-package evidence is invalid")
            saw_first_package_set = True
        elif name == "role-packages-pass-2":
            expected_root_files.update(
                {"role-packages-pass-2.json", "role-packages-determinism.json"}
            )
            second_verified, second_package_set = _verified_package_set_evidence(
                output,
                pass_number=2,
                expected_sha256=evidence.get("packageSetEvidenceSha256"),
            )
            if (
                not saw_first_package_set
                or not second_verified
                or not _verified_determinism_evidence(
                    output,
                    expected_sha256=evidence.get("determinismEvidenceSha256"),
                    first=first_package_set,
                    second=second_package_set,
                )
            ):
                raise ExperimentError("completed role-package determinism evidence is invalid")
            package_deterministic = (
                first_package_set is not None
                and second_package_set is not None
                and first_package_set == second_package_set
            )
        reconstructed_results.append({**result, "receiptSha256": receipt_sha256})
        previous = receipt_sha256
        terminal_receipt = receipt

    manifested_root_files = {name for name in manifested_files if "/" not in name}
    if (
        root_files != expected_root_files
        or manifested_root_files != expected_root_files - {"SHA256SUMS", "COMPLETION.json"}
        or summary_results != reconstructed_results
        or summary.get("plannedSteps") != len(steps)
        or summary.get("receiptedSteps") != len(receipts)
        or summary.get("terminalReceiptSha256") != previous
        or completion.get("terminalReceiptSha256") != previous
        or summary.get("packageDeterministic") != package_deterministic
        or summary.get("evidenceIntegrityVerified") is not True
        or summary.get("sameRunInternalConsistencyVerified") is not True
        or terminal_receipt is None
        or terminal_receipt["evidence"].get("artifactTreeSha256")
        != _tree_sha256(output / "artifacts")
    ):
        raise ExperimentError("completed summary, receipt, package, or artifact binding is invalid")
    experiment_passed = summary.get("passed")
    if (
        not isinstance(experiment_passed, bool)
        or completion.get("passed") is not experiment_passed
        or completion.get("state")
        != ("completed" if experiment_passed else "completed_with_failures")
    ):
        raise ExperimentError("completion state disagrees with the experiment summary")
    return {
        "schema": "devflow.offline-experiment-verification/v1",
        "output": str(output),
        "runId": run_id,
        "integrityVerified": True,
        "experimentPassed": experiment_passed,
        "manifestedFiles": len(manifested_files),
        "verifiedReceipts": len(receipts),
        "completionCanonicalSha256": _sha256(completion_payload),
        "terminalReceiptSha256": previous,
        "claimBoundary": "same_run_internal_consistency_without_external_signature_or_worm",
    }


def run(
    output: Path,
    run_id: str,
    *,
    network_mode: str,
    network_confirmation: str,
) -> int:
    if SAFE_RUN_ID.fullmatch(run_id) is None:
        raise ExperimentError("run id is invalid")
    network = _network_claim(network_mode, network_confirmation)
    subreaper_enabled = _enable_child_subreaper()
    if platform.system() == "Linux" and not subreaper_enabled:
        raise ExperimentError("Linux child subreaper could not be enabled")
    managed_state_directory = output.parent == SYSTEMD_STATE_ROOT
    if network_mode == NETWORK_MODE_ISOLATED and not managed_state_directory:
        raise ExperimentError("isolated output is outside the systemd state directory")
    destination = _safe_output(
        output,
        managed_state_directory=managed_state_directory,
    )
    _create_private_directory(destination)
    _create_private_directory(destination / "artifacts")
    _create_private_directory(destination / "artifacts" / "packages")
    environment = _environment(destination)
    python_entry, python_target, venv_root, site_roots = _prepared_python_entry()
    python = str(python_entry)
    steps = _steps(python, destination)
    _validate_steps(steps, python)
    dependency_lock_payload = _read_regular(
        ROOT / "requirements" / "dev.lock.txt",
        maximum=MAX_EVIDENCE_FILE_BYTES,
        label="development dependency lock",
    )
    dependency_lock_sha256 = _sha256(dependency_lock_payload)
    installed = _installed_inventory(site_roots)
    installed_files_tree_sha256 = _installed_files_tree_sha256(
        installed,
        site_roots=site_roots,
        prefix=venv_root,
    )
    _activate_audited_runtime_paths(site_roots)
    cli_contract_sha256 = _validate_cli_contracts(python, environment)
    installed_environment_sha256 = _validate_locked_environment(
        dependency_lock_payload,
        installed,
    )
    git_path = _trusted_command("git", environment)
    repository_identity = _repository_identity(environment, git=git_path)
    revision = repository_identity["revision"]
    git_sha256 = _sha256(
        _read_regular(
            git_path,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="Git executable",
        )
    )
    runner_sha256 = _sha256(
        _read_regular(
            Path(__file__).resolve(strict=True),
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="experiment runner",
        )
    )
    python_sha256 = _sha256(
        _read_regular(
            python_target,
            maximum=MAX_EVIDENCE_FILE_BYTES,
            label="Python executable",
        )
    )
    plan = {
        "schema": "devflow.offline-experiment-plan/v2",
        "runId": run_id,
        "createdAt": _now(),
        "repository": str(ROOT),
        "repositoryRevision": revision,
        "repositoryTree": repository_identity["tree"],
        "repositoryIdentitySha256": repository_identity["identitySha256"],
        "trackedInventorySha256": repository_identity["trackedInventorySha256"],
        "ignoredInventorySha256": repository_identity["ignoredInventorySha256"],
        "git": str(git_path),
        "gitSha256": git_sha256,
        "runnerSha256": runner_sha256,
        "cliContractSha256": cli_contract_sha256,
        "pythonSha256": python_sha256,
        "dependencyLockSha256": dependency_lock_sha256,
        "installedEnvironmentSha256": installed_environment_sha256,
        "installedFilesTreeSha256": installed_files_tree_sha256,
        "installedSnapshotTreeSha256": installed_files_tree_sha256,
        "installedSnapshotOwnershipPolicy": (
            "root_owned_group_world_nonwritable" if platform.system() == "Linux" else "platform_acl"
        ),
        "installedSnapshotProvenanceClaim": "record_verified_snapshot_not_lock_wheel_provenance",
        "installedDistributionCount": len(installed),
        "pythonEntry": python,
        "pythonTarget": str(python_target),
        "pythonVenvRoot": str(venv_root),
        "auditedSitePackages": [str(path) for path in site_roots],
        "sitePackagesActivatedAfterSnapshotAudit": True,
        "isolatedNoSiteStartupVerified": True,
        "pathConfigurationException": {
            "distribution": "coverage",
            "version": "7.15.2",
            "path": "a1_coverage.pth",
            "sha256": COVERAGE_PTH_SHA256,
            "reason": "exact RECORD-owned coverage subprocess hook required by the locked tool",
        },
        "pythonVersion": platform.python_version(),
        "platform": platform.platform(),
        "linuxChildSubreaperEnabled": subreaper_enabled,
        "environmentKeys": sorted(environment),
        "credentialEnvironmentInherited": False,
        "dotenvLoadingDisabled": True,
        "networkRequiredAfterLaunch": False,
        "network": network,
        "claims": {
            "repositoryRepairAgentExecutions": 0,
            "reason": "No provider call is made; fixture validation is not repair success.",
        },
        "steps": [asdict(step) for step in steps],
    }
    plan_payload = _canonical(plan) + b"\n"
    plan_sha256 = _sha256(plan_payload)
    _write_new(destination / "PLAN.json", plan_payload)
    records: list[StepRecord] = []
    package_first: dict[str, str] | None = None
    package_deterministic: bool | None = None
    previous_receipt_sha256: str | None = None
    for ordinal, step in enumerate(steps, start=1):
        _replace_state(
            destination / "HEARTBEAT.json",
            {
                "schema": "devflow.offline-experiment-heartbeat/v1",
                "runId": run_id,
                "state": "running",
                "step": step.name,
                "ordinal": ordinal,
                "completedSteps": len(records),
                "lastReceiptSha256": previous_receipt_sha256,
                "updatedAt": _now(),
            },
        )
        source_clean_before = _source_matches(
            environment,
            git=git_path,
            identity_sha256=repository_identity["identitySha256"],
        )
        result = (
            _run_step(
                step,
                output=destination,
                environment=environment,
                ordinal=ordinal,
            )
            if source_clean_before
            else _blocked_step(step, output=destination, ordinal=ordinal)
        )
        source_clean_after = _source_matches(
            environment,
            git=git_path,
            identity_sha256=repository_identity["identitySha256"],
        )
        if result.passed and not source_clean_after:
            result = replace(
                result,
                exit_code=4,
                failure_reason="source_identity_drift",
                passed=False,
            )
        evidence: dict[str, Any] = {}
        evidence["sourceCleanBefore"] = source_clean_before
        evidence["sourceCleanAfter"] = source_clean_after
        if step.name == "role-packages-pass-1":
            try:
                package_first = (
                    _package_digests(destination / "artifacts" / "packages" / "pass-1")
                    if result.passed
                    else None
                )
            except ExperimentError:
                package_first = None
            package_evidence_sha256 = _write_package_evidence(
                destination,
                pass_number=1,
                digests=package_first,
            )
            evidence["packageSetEvidenceSha256"] = package_evidence_sha256
            if result.passed and package_first is None:
                result = replace(
                    result,
                    exit_code=3,
                    failure_reason="package_evidence_invalid",
                    passed=False,
                )
        elif step.name == "role-packages-pass-2":
            try:
                package_second = (
                    _package_digests(destination / "artifacts" / "packages" / "pass-2")
                    if result.passed
                    else None
                )
            except ExperimentError:
                package_second = None
            package_evidence_sha256 = _write_package_evidence(
                destination,
                pass_number=2,
                digests=package_second,
            )
            package_deterministic = (
                package_first is not None
                and package_second is not None
                and package_first == package_second
            )
            determinism_payload = (
                _canonical(
                    {
                        "schema": "devflow.role-package-determinism/v2",
                        "deterministic": package_deterministic,
                        "first": package_first,
                        "second": package_second,
                        "firstSetSha256": (
                            _sha256(_canonical(package_first))
                            if package_first is not None
                            else None
                        ),
                        "secondSetSha256": (
                            _sha256(_canonical(package_second))
                            if package_second is not None
                            else None
                        ),
                    }
                )
                + b"\n"
            )
            _write_new(
                destination / "role-packages-determinism.json",
                determinism_payload,
            )
            evidence.update(
                {
                    "packageSetEvidenceSha256": package_evidence_sha256,
                    "determinismEvidenceSha256": _sha256(determinism_payload),
                }
            )
            if not package_deterministic and result.passed:
                result = replace(
                    result,
                    exit_code=3,
                    failure_reason="package_determinism_failed",
                    passed=False,
                )
        evidence["artifactTreeSha256"] = _tree_sha256(destination / "artifacts")
        receipt_sha256 = _write_step_receipt(
            destination,
            run_id=run_id,
            ordinal=ordinal,
            plan_sha256=plan_sha256,
            previous_receipt_sha256=previous_receipt_sha256,
            result=result,
            evidence=evidence,
        )
        records.append(StepRecord(result=result, receipt_sha256=receipt_sha256))
        previous_receipt_sha256 = receipt_sha256

    source_clean_at_seal = _source_matches(
        environment,
        git=git_path,
        identity_sha256=repository_identity["identitySha256"],
    )
    try:
        installed_files_unchanged = (
            _installed_files_tree_sha256(
                installed,
                site_roots=site_roots,
                prefix=venv_root,
            )
            == installed_files_tree_sha256
        )
    except ExperimentError:
        installed_files_unchanged = False
    evidence_integrity_verified = _verify_receipt_chain(
        destination,
        run_id=run_id,
        plan_sha256=plan_sha256,
        records=records,
    )
    passed = (
        len(records) == len(steps)
        and source_clean_at_seal
        and evidence_integrity_verified
        and installed_files_unchanged
        and all(record.result.passed for record in records)
    )
    failure_ordinals = [
        ordinal for ordinal, record in enumerate(records, start=1) if not record.result.passed
    ]
    blocked_records = [
        record
        for record in records
        if record.result.process_exit_code == -1
        and record.result.failure_reason == "source_identity_drift"
    ]
    launched_records = [
        record
        for record in records
        if record not in blocked_records and record.result.failure_reason != "spawn_failed"
    ]
    continued_after_failure = bool(
        failure_ordinals
        and any(
            ordinal > min(failure_ordinals) and record in launched_records
            for ordinal, record in enumerate(records, start=1)
        )
    )
    summary = {
        "schema": "devflow.offline-experiment-summary/v2",
        "runId": run_id,
        "repositoryRevision": revision,
        "runnerSha256": runner_sha256,
        "gitSha256": git_sha256,
        "planSha256": plan_sha256,
        "terminalReceiptSha256": previous_receipt_sha256,
        "finishedAt": _now(),
        "passed": passed,
        "plannedSteps": len(steps),
        "receiptedSteps": len(records),
        "blockedSteps": len(blocked_records),
        "blockedStepNames": [record.result.name for record in blocked_records],
        "launchedSteps": len(launched_records),
        "executedSteps": len(launched_records),
        "passedSteps": sum(record.result.passed for record in records),
        "failedSteps": [record.result.name for record in records if not record.result.passed],
        "timedOutSteps": [record.result.name for record in records if record.result.timed_out],
        "continuedAfterFailure": continued_after_failure,
        "packageDeterministic": package_deterministic,
        "sourceCleanAtSeal": source_clean_at_seal,
        "installedFilesUnchangedAtSeal": installed_files_unchanged,
        "evidenceIntegrityVerified": evidence_integrity_verified,
        "sameRunInternalConsistencyVerified": evidence_integrity_verified,
        "credentialEnvironmentInherited": False,
        "network": network,
        "results": [
            {**asdict(record.result), "receiptSha256": record.receipt_sha256} for record in records
        ],
        "limitations": [
            "No LLM or embedding provider is called.",
            "Repository repair Agent attempts remain zero.",
            "Local tests do not become live AgentTeams cluster evidence.",
            (
                "The fallback mode keeps host networking available; safety then relies on "
                "the empty child environment and offline-only commands."
                if network.get("networkAvailable") is True
                else "The private network namespace is verified against PID 1 at launch."
            ),
            "A hard-killed runner is not resumable; use a new run ID and directory.",
            (
                "Checksums and receipt links establish same-run internal consistency only; "
                "they are not externally signed or stored on WORM media."
            ),
            (
                "PrivateNetwork evidence verifies namespace separation, dangerous capability "
                "removal, and requested systemd policy; it is not an arbitrary egress probe."
            ),
            (
                "File and byte limits are checked after each bounded step and at sealing; "
                "there is no portable hard filesystem quota during step execution."
            ),
        ],
    }
    summary_payload = _canonical(summary) + b"\n"
    _write_new(destination / "SUMMARY.json", summary_payload)
    heartbeat = {
        "schema": "devflow.offline-experiment-heartbeat/v1",
        "runId": run_id,
        "state": "sealing",
        "completedSteps": len(records),
        "lastReceiptSha256": previous_receipt_sha256,
        "summarySha256": _sha256(summary_payload),
        "updatedAt": _now(),
    }
    _replace_state(destination / "HEARTBEAT.json", heartbeat, final=True)
    _remove_runtime(destination)
    _seal_evidence(destination)
    sums_payload = _sha256sums(destination)
    _write_new(destination / "SHA256SUMS", sums_payload)
    completion = {
        "schema": "devflow.offline-experiment-completion/v1",
        "runId": run_id,
        "state": "completed" if passed else "completed_with_failures",
        "passed": passed,
        "planSha256": plan_sha256,
        "summarySha256": _sha256(summary_payload),
        "heartbeatSha256": _sha256(_canonical(heartbeat) + b"\n"),
        "sha256sumsSha256": _sha256(sums_payload),
        "terminalReceiptSha256": previous_receipt_sha256,
        "finishedAt": _now(),
    }
    completion_payload = _canonical(completion) + b"\n"
    completion_path = destination / "COMPLETION.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        completion_descriptor = os.open(completion_path, flags, 0o444)
    except OSError as exc:
        raise ExperimentError("completion evidence could not be reserved") from exc
    try:
        _seal_directories(destination)
        with os.fdopen(completion_descriptor, "wb") as completion_stream:
            completion_descriptor = -1
            completion_stream.write(completion_payload)
            completion_stream.flush()
            os.fsync(completion_stream.fileno())
    except OSError as exc:
        raise ExperimentError("completion evidence could not be finalized") from exc
    finally:
        if completion_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(completion_descriptor)
    return 0 if passed else 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-output", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--run-id")
    parser.add_argument(
        "--network-mode",
        choices=(NETWORK_MODE_ISOLATED, NETWORK_MODE_AVAILABLE),
    )
    parser.add_argument("--network-confirmation")
    return parser


def main() -> int:
    if sys.flags.isolated != 1 or sys.flags.no_site != 1:
        print("error: experiment runner requires Python -I -S", file=sys.stderr)
        return 2
    args = _parser().parse_args()
    if args.verify_output is not None:
        if any(
            value is not None
            for value in (args.output, args.run_id, args.network_mode, args.network_confirmation)
        ):
            print("error: --verify-output cannot be combined with run arguments", file=sys.stderr)
            return 2
        try:
            verification = _verify_completed_output(args.verify_output)
        except (ExperimentError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
            print(f"error: completed evidence verification failed: {exc}", file=sys.stderr)
            return 2
        print(json.dumps(verification, indent=2, sort_keys=True))
        return 0
    if any(
        value is None
        for value in (args.output, args.run_id, args.network_mode, args.network_confirmation)
    ):
        print(
            "error: run mode requires --output, --run-id, --network-mode, and confirmation",
            file=sys.stderr,
        )
        return 2
    try:
        return run(
            cast(Path, args.output),
            cast(str, args.run_id),
            network_mode=cast(str, args.network_mode),
            network_confirmation=cast(str, args.network_confirmation),
        )
    except (ExperimentError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"error: offline experiment launch failed safely: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

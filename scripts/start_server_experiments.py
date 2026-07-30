#!/usr/bin/env python3
"""Launch the fixed server experiment without executing repository code first.

Run this trust-root launcher with ``python -I -S``.  It imports only the Python
standard library, validates fixed paths and metadata, and asks systemd to start
the real runner inside the requested sandbox.  Dependency, Git, CLI, and venv
identity checks happen inside that sandbox.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).absolute().parent.parent
RUNNER = ROOT / "scripts" / "run_server_experiments.py"
LOCK = ROOT / "requirements" / "dev.lock.txt"
STATE_ROOT = Path("/var/lib/devflow-experiments")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
NETWORK_MODE_ISOLATED = "network_namespace_isolated"
NETWORK_MODE_AVAILABLE = "network_available_credentials_stripped"
NETWORK_ISOLATED_CONFIRMATION = "NETWORK_NAMESPACE_ISOLATED"
NETWORK_AVAILABLE_CONFIRMATION = "NETWORK_AVAILABLE_CREDENTIALS_STRIPPED"
MAX_TRUST_ROOT_BYTES = 128 * 1024 * 1024
MAX_STARTUP_JSON_BYTES = 1024 * 1024
MAX_SYSTEMCTL_OUTPUT_BYTES = 64 * 1024
STARTUP_WAIT_SECONDS = 300


class LaunchError(RuntimeError):
    """The detached launch could not be performed without ambiguity."""


def _is_linux_systemd_host() -> bool:
    return os.name == "posix" and platform.system() == "Linux"


def _is_windows_host() -> bool:
    return os.name == "nt"


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _bootstrap_environment() -> dict[str, str]:
    environment: dict[str, str] = {}
    for key in ("PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        value = os.environ.get(key)
        if value:
            environment[key] = value
    environment.update(
        {
            "CI": "true",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHON_DOTENV_DISABLED": "1",
            "SOURCE_DATE_EPOCH": "0",
            "UV_OFFLINE": "1",
        }
    )
    return environment


def _read_trust_root(path: Path, *, executable: bool = False) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_TRUST_ROOT_BYTES
        ):
            raise LaunchError(f"trust-root file is unsafe: {path.name}")
        chunks: list[bytes] = []
        remaining = MAX_TRUST_ROOT_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
        resolved = path.resolve(strict=True)
        resolved_metadata = resolved.stat()
    except OSError as exc:
        raise LaunchError(f"trust-root file is unavailable: {path.name}") from exc
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if (
        path.is_symlink()
        or resolved != path.absolute()
        or not stat.S_ISREG(resolved_metadata.st_mode)
        or (os.name == "posix" and resolved_metadata.st_mode & 0o022)
        or len(payload) > MAX_TRUST_ROOT_BYTES
        or metadata.st_size != len(payload)
        or (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
        )
        or (executable and not os.access(resolved, os.X_OK))
    ):
        raise LaunchError(f"trust-root file is unsafe: {path.name}")
    return payload


def _read_startup_json(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > MAX_STARTUP_JSON_BYTES
        ):
            raise LaunchError("runner startup evidence is unsafe")
        chunks: list[bytes] = []
        remaining = metadata.st_size + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        final_metadata = os.fstat(descriptor)
    except OSError as exc:
        raise LaunchError("runner startup evidence is unavailable") from exc
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    if (
        len(payload) > MAX_STARTUP_JSON_BYTES
        or len(payload) != metadata.st_size
        or (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)
        != (
            final_metadata.st_dev,
            final_metadata.st_ino,
            final_metadata.st_size,
            final_metadata.st_mtime_ns,
        )
    ):
        raise LaunchError("runner startup evidence changed during bounded read")
    try:
        value = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise LaunchError("runner startup evidence is malformed") from exc
    if not isinstance(value, dict):
        raise LaunchError("runner startup evidence is malformed")
    return value


def _require_python_path_ownership(
    entry: Path,
    target: Path,
    entry_metadata: os.stat_result,
    target_metadata: os.stat_result,
) -> None:
    linux = platform.system() == "Linux"
    if os.name == "posix" and (
        target_metadata.st_mode & 0o022
        or (stat.S_ISREG(entry_metadata.st_mode) and entry_metadata.st_mode & 0o022)
    ):
        raise LaunchError(
            "prepared virtual-environment entry or target is writable by another user"
        )
    if linux and (entry_metadata.st_uid != 0 or target_metadata.st_uid != 0):
        raise LaunchError("Linux virtual-environment entry and target must be root-owned")
    checked: set[Path] = set()
    for initial_parent in (entry.parent, target.parent):
        parent = initial_parent
        while parent not in checked:
            checked.add(parent)
            try:
                parent_metadata = parent.stat()
            except OSError as exc:
                raise LaunchError("virtual-environment path metadata is unavailable") from exc
            if os.name == "posix" and parent_metadata.st_mode & 0o022:
                raise LaunchError("virtual-environment path is writable by another user")
            if linux and parent_metadata.st_uid != 0:
                raise LaunchError("Linux virtual-environment paths must be root-owned")
            if parent == parent.parent:
                break
            parent = parent.parent


def _safe_python_entry(raw: str) -> tuple[Path, Path]:
    entry = Path(os.path.abspath(raw))
    try:
        entry_metadata = entry.lstat()
        target = entry.resolve(strict=True)
        target_metadata = target.stat()
    except OSError as exc:
        raise LaunchError("prepared virtual-environment entry is unavailable") from exc
    if (
        not entry.is_absolute()
        or not (stat.S_ISREG(entry_metadata.st_mode) or stat.S_ISLNK(entry_metadata.st_mode))
        or not stat.S_ISREG(target_metadata.st_mode)
        or not os.access(target, os.X_OK)
    ):
        raise LaunchError("prepared virtual-environment entry or target is unsafe")
    _require_python_path_ownership(entry, target, entry_metadata, target_metadata)
    return entry, target


def _python_entry_lstat(path: Path) -> dict[str, int]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LaunchError("prepared virtual-environment entry metadata is unavailable") from exc
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": metadata.st_mode,
        "links": metadata.st_nlink,
        "size": metadata.st_size,
        "mtimeNs": metadata.st_mtime_ns,
        "uid": getattr(metadata, "st_uid", 0),
        "gid": getattr(metadata, "st_gid", 0),
    }


def _safe_fallback_output(output: Path) -> Path:
    if not output.is_absolute() or SAFE_ID.fullmatch(output.name) is None:
        raise LaunchError("--output must be a new absolute safe path")
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as exc:
        raise LaunchError("output parent is unavailable") from exc
    candidate = parent / output.name
    if output.parent.is_symlink() or candidate.exists() or candidate.is_symlink():
        raise LaunchError("output must be a new non-symlink directory")
    return candidate


def _safe_isolated_output(output: Path) -> Path:
    if (
        not output.is_absolute()
        or SAFE_ID.fullmatch(output.name) is None
        or output.parent != STATE_ROOT
        or output.exists()
        or output.is_symlink()
    ):
        raise LaunchError(
            "isolated output must be a new /var/lib/devflow-experiments/<safe-name> path"
        )
    return output


def _trusted_system_command(name: str, environment: dict[str, str]) -> Path:
    selected = shutil.which(name, path=environment.get("PATH"))
    if selected is None:
        raise LaunchError(f"{name} is unavailable")
    try:
        path = Path(selected).resolve(strict=True)
        metadata = path.stat()
    except OSError as exc:
        raise LaunchError(f"{name} metadata is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(path, os.X_OK)
        or (os.name == "posix" and (metadata.st_uid != 0 or metadata.st_mode & 0o022))
    ):
        raise LaunchError(f"{name} executable is outside policy")
    return path


def _unit_name(run_id: str) -> str:
    normalized = "".join(
        character.lower() if character.isalnum() else "-" for character in run_id
    ).strip("-")
    if not normalized:
        raise LaunchError("run id cannot form a systemd unit identity")
    suffix = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:10]
    return f"devflow-experiment-{normalized[:36]}-{suffix}"


def _runner_argv(
    python_entry: Path,
    output: Path,
    run_id: str,
    network_mode: str,
) -> list[str]:
    confirmation = (
        NETWORK_ISOLATED_CONFIRMATION
        if network_mode == NETWORK_MODE_ISOLATED
        else NETWORK_AVAILABLE_CONFIRMATION
    )
    return [
        str(python_entry),
        "-I",
        "-S",
        str(RUNNER),
        "--output",
        str(output),
        "--run-id",
        run_id,
        "--network-mode",
        network_mode,
        "--network-confirmation",
        confirmation,
    ]


def _fixed_source_attestation() -> dict[str, str]:
    launcher_payload = _read_trust_root(Path(__file__).absolute())
    runner_payload = _read_trust_root(RUNNER)
    lock_payload = _read_trust_root(LOCK)
    return {
        "launcherSha256": _sha256(launcher_payload),
        "runnerSha256": _sha256(runner_payload),
        "dependencyLockSha256": _sha256(lock_payload),
    }


def _require_dynamic_user_readability(python_entry: Path) -> None:
    protected_roots = (Path("/root"), Path("/home"), Path("/run/user"))
    for candidate in (ROOT, python_entry):
        absolute = candidate.absolute()
        if any(
            absolute == protected or protected in absolute.parents for protected in protected_roots
        ):
            raise LaunchError("DynamicUser source and venv must be staged outside protected homes")
    for file_path in (RUNNER, LOCK, python_entry.resolve(strict=True)):
        metadata = file_path.stat()
        required = 0o001 if file_path == python_entry.resolve(strict=True) else 0o004
        if metadata.st_mode & required != required:
            raise LaunchError("DynamicUser cannot read the fixed runner, lock, or interpreter")
    checked: set[Path] = set()
    for candidate in (ROOT, python_entry.parent):
        current = candidate.absolute()
        while current not in checked:
            checked.add(current)
            if current.stat().st_mode & 0o001 != 0o001:
                raise LaunchError("DynamicUser cannot traverse the source or venv path")
            if current == current.parent:
                break
            current = current.parent


def _stop_unit(unit: str, environment: dict[str, str]) -> bool:
    try:
        systemctl = _trusted_system_command("systemctl", environment)
        subprocess.run(
            [str(systemctl), "stop", unit],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
            shell=False,
        )
    except (LaunchError, OSError, subprocess.SubprocessError):
        pass
    try:
        systemctl = _trusted_system_command("systemctl", environment)
    except LaunchError:
        return False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            completed = subprocess.run(
                [str(systemctl), "is-active", unit],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=5,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        output = completed.stdout + completed.stderr
        if len(output) > MAX_SYSTEMCTL_OUTPUT_BYTES:
            return False
        state = completed.stdout.decode("ascii", errors="replace").strip().lower()
        if state in {"inactive", "failed", "unknown"}:
            return True
        if completed.returncode not in {0, 3, 4}:
            return False
        time.sleep(0.1)
    return False


def _wait_for_runner_start(output: Path, run_id: str) -> dict[str, str]:
    deadline = time.monotonic() + STARTUP_WAIT_SECONDS
    plan_path = output / "PLAN.json"
    heartbeat_path = output / "HEARTBEAT.json"
    while time.monotonic() < deadline:
        if plan_path.is_file() and heartbeat_path.is_file():
            try:
                plan = _read_startup_json(plan_path)
                heartbeat = _read_startup_json(heartbeat_path)
            except LaunchError:
                time.sleep(0.1)
                continue
            if plan.get("runId") != run_id or heartbeat.get("runId") != run_id:
                raise LaunchError("runner startup evidence belongs to another run")
            if (
                plan.get("schema") != "devflow.offline-experiment-plan/v2"
                or heartbeat.get("schema") != "devflow.offline-experiment-heartbeat/v1"
                or heartbeat.get("state") not in {"running", "sealing"}
            ):
                time.sleep(0.1)
                continue
            return {
                "planCanonicalSha256": _sha256(_canonical(plan)),
                "heartbeatCanonicalSha256": _sha256(_canonical(heartbeat)),
                "runnerSha256": str(plan.get("runnerSha256", "")),
                "dependencyLockSha256": str(plan.get("dependencyLockSha256", "")),
                "pythonSha256": str(plan.get("pythonSha256", "")),
            }
        time.sleep(0.1)
    raise LaunchError("runner did not publish PLAN and HEARTBEAT before the startup deadline")


def _start_systemd(
    python_entry: Path,
    output: Path,
    run_id: str,
    environment: dict[str, str],
    *,
    private_network: bool,
) -> dict[str, Any]:
    if not _is_linux_systemd_host():
        raise LaunchError("managed experiment launch requires Linux systemd")
    _require_dynamic_user_readability(python_entry)
    destination = _safe_isolated_output(output)
    systemd_run = _trusted_system_command("systemd-run", environment)
    unit = _unit_name(run_id)
    argv = [
        str(systemd_run),
        "--collect",
        "--quiet",
        "--expand-environment=no",
        f"--unit={unit}",
        "--property=Type=exec",
        "--property=DynamicUser=yes",
        "--property=StateDirectory=devflow-experiments",
        "--property=StateDirectoryMode=0700",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=PrivateDevices=yes",
        "--property=PrivateTmp=yes",
        "--property=ProtectHome=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectControlGroups=yes",
        "--property=ProtectKernelModules=yes",
        "--property=ProtectKernelTunables=yes",
        "--property=ProtectKernelLogs=yes",
        "--property=RestrictSUIDSGID=yes",
        "--property=LockPersonality=yes",
        "--property=SystemCallArchitectures=native",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=15s",
        "--property=MemoryMax=8G",
        "--property=TasksMax=512",
        "--property=RuntimeMaxSec=12h",
        "--property=UMask=0077",
        f"--property=WorkingDirectory={ROOT}",
        f"--property=ReadOnlyPaths={ROOT}",
        f"--property=ReadWritePaths={STATE_ROOT}",
        (
            "--property=InaccessiblePaths=-/run/systemd/private -/run/docker.sock "
            "-/var/run/docker.sock -/run/containerd/containerd.sock -/root/.ssh "
            "-/root/.aws -/root/.config/gcloud -/home -/run/user"
        ),
        (
            "--property=Environment=PYTHON_DOTENV_DISABLED=1 "
            "PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_INDEX=1 "
            "UV_OFFLINE=1 SOURCE_DATE_EPOCH=0"
        ),
    ]
    mode = NETWORK_MODE_ISOLATED if private_network else NETWORK_MODE_AVAILABLE
    if private_network:
        argv.extend(
            (
                "--property=PrivateNetwork=yes",
                "--property=IPAddressDeny=any",
                "--property=IPAddressAllow=127.0.0.0/8 ::1/128",
                "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            )
        )
    argv.extend(("--", *_runner_argv(python_entry, destination, run_id, mode)))
    try:
        completed = subprocess.run(
            argv,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        stopped = _stop_unit(unit, environment)
        status = "rollback verified stopped" if stopped else "rollback could not be verified"
        raise LaunchError(f"systemd managed launch failed; {status}") from exc
    output_bytes = completed.stdout + completed.stderr
    if completed.returncode != 0 or len(output_bytes) > 1024 * 1024:
        stopped = _stop_unit(unit, environment)
        status = "rollback verified stopped" if stopped else "rollback could not be verified"
        raise LaunchError(f"systemd rejected the managed service; {status}")
    try:
        startup = _wait_for_runner_start(destination, run_id)
    except LaunchError as exc:
        stopped = _stop_unit(unit, environment)
        status = "rollback verified stopped" if stopped else "rollback could not be verified"
        raise LaunchError(f"{exc}; {status}") from exc
    return {
        "mode": mode,
        "unit": unit,
        "pid": None,
        "output": str(destination),
        "launcherOutputSha256": _sha256(output_bytes),
        "systemdPolicyRequested": True,
        "privateNetworkRequested": private_network,
        "startup": startup,
        "completionLog": f"journalctl --unit={unit}",
    }


def _start_isolated(
    python_entry: Path,
    output: Path,
    run_id: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    return _start_systemd(
        python_entry,
        output,
        run_id,
        environment,
        private_network=True,
    )


def _start_managed_network_available(
    python_entry: Path,
    output: Path,
    run_id: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    return _start_systemd(
        python_entry,
        output,
        run_id,
        environment,
        private_network=False,
    )


def _start_credential_stripped(
    python_entry: Path,
    output: Path,
    run_id: str,
    environment: dict[str, str],
) -> dict[str, Any]:
    destination = _safe_fallback_output(output)
    log_path = destination.parent / f".{destination.name}.{run_id}.launcher.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(log_path, flags, 0o600)
    except OSError as exc:
        raise LaunchError("fallback launcher log already exists or is unsafe") from exc
    try:
        platform_options: dict[str, Any]
        if os.name == "posix":
            platform_options = {"start_new_session": True}
        else:  # pragma: no cover - exercised by Windows desktop/CI
            detached = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            new_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            platform_options = {"creationflags": detached | new_group}
        with os.fdopen(descriptor, "wb") as log_stream:
            descriptor = -1
            process = subprocess.Popen(
                _runner_argv(python_entry, destination, run_id, NETWORK_MODE_AVAILABLE),
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                close_fds=True,
                shell=False,
                **platform_options,
            )
    except (OSError, subprocess.SubprocessError) as exc:
        with contextlib.suppress(OSError):
            log_path.unlink(missing_ok=True)
        raise LaunchError("credential-environment-stripped process could not start") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
    return {
        "mode": NETWORK_MODE_AVAILABLE,
        "unit": None,
        "pid": process.pid,
        "output": str(destination),
        "launcherOutputSha256": None,
        "systemdPolicyRequested": False,
        "persistenceGuarantee": "weaker_detached_process_only",
        "processTreeCleanupGuaranteedByLauncher": False,
        "completionLog": str(log_path),
    }


def _stop_launch(launch: dict[str, Any], environment: dict[str, str]) -> bool:
    unit = launch.get("unit")
    if isinstance(unit, str) and unit:
        return _stop_unit(unit, environment)
    pid = launch.get("pid")
    if not isinstance(pid, int) or pid <= 1:
        return False
    try:
        if os.name == "posix":
            posix_module = __import__("posix")
            killpg = posix_module.killpg
            killpg(pid, 15)
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    waited, _status = os.waitpid(pid, 1)  # WNOHANG
                except ChildProcessError:
                    return True
                if waited == pid:
                    return True
                time.sleep(0.05)
            killpg(pid, 9)
            with contextlib.suppress(ChildProcessError, OSError):
                os.waitpid(pid, 0)
        else:  # pragma: no cover - Windows fallback
            os.kill(pid, 15)
    except (OSError, ProcessLookupError):
        return False
    return True


def _write_launch_receipt(path: Path, value: dict[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o444)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(_canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o444)
    except OSError as exc:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise LaunchError("launch receipt could not be written durably") from exc
    finally:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)


def start(
    output: Path,
    run_id: str,
    *,
    network_mode: str,
    python_entry: Path | None = None,
) -> dict[str, Any]:
    if SAFE_ID.fullmatch(run_id) is None:
        raise LaunchError("run id is invalid")
    if network_mode not in {NETWORK_MODE_ISOLATED, NETWORK_MODE_AVAILABLE}:
        raise LaunchError("network mode is invalid")
    environment = _bootstrap_environment()
    prepared_entry, python_target = _safe_python_entry(str(python_entry or sys.executable))
    python_entry_lstat = _python_entry_lstat(prepared_entry)
    source = _fixed_source_attestation()
    python_target_sha256 = _sha256(_read_trust_root(python_target, executable=True))
    if network_mode == NETWORK_MODE_ISOLATED:
        launch = _start_isolated(prepared_entry, output, run_id, environment)
    elif platform.system() == "Linux":
        if shutil.which("systemd-run", path=environment.get("PATH")) is None:
            raise LaunchError("Linux experiments require systemd-run; fallback is forbidden")
        launch = _start_managed_network_available(prepared_entry, output, run_id, environment)
    elif _is_windows_host():
        launch = _start_credential_stripped(prepared_entry, output, run_id, environment)
    else:
        raise LaunchError("detached fallback is supported only on Windows")
    startup = launch.get("startup")
    try:
        entry_unchanged = _python_entry_lstat(prepared_entry) == python_entry_lstat
    except LaunchError:
        entry_unchanged = False
    if not entry_unchanged or (
        isinstance(startup, dict)
        and (
            startup.get("runnerSha256") != source["runnerSha256"]
            or startup.get("dependencyLockSha256") != source["dependencyLockSha256"]
            or startup.get("pythonSha256") != python_target_sha256
        )
    ):
        stopped = _stop_launch(launch, environment)
        status = "rollback verified stopped" if stopped else "rollback could not be verified"
        raise LaunchError(
            "sandbox startup does not match the pre-isolation trust-root identity; " + status
        )
    destination = Path(str(launch["output"]))
    receipt_path = destination.parent / f".{destination.name}.{run_id}.launch.json"
    receipt = {
        "schema": "devflow.offline-experiment-launch/v3",
        "runId": run_id,
        "background": True,
        "preIsolationTrustRootLauncherExecuted": True,
        "preIsolationCandidateOrDependencyCodeExecuted": False,
        "credentialEnvironmentInherited": False,
        "credentialFilesystemIsolationVerified": False,
        "pythonEntry": str(prepared_entry),
        "pythonEntryLstat": python_entry_lstat,
        "pythonTarget": str(python_target),
        "pythonTargetSha256": python_target_sha256,
        **source,
        "completionMustBeVerifiedFromOutput": True,
        "receiptPath": str(receipt_path),
        "launch": launch,
    }
    try:
        _write_launch_receipt(receipt_path, receipt)
    except LaunchError as exc:
        if not _stop_launch(launch, environment):
            raise LaunchError(f"{exc}; launch rollback could not be verified") from exc
        raise
    return receipt


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--python-entry", required=True, type=Path)
    parser.add_argument(
        "--network-mode",
        choices=(NETWORK_MODE_ISOLATED, NETWORK_MODE_AVAILABLE),
        default=NETWORK_MODE_ISOLATED,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.flags.isolated != 1 or sys.flags.no_site != 1:
        print("error: launcher requires Python -I -S", file=sys.stderr)
        return 2
    args = _parser().parse_args(argv)
    try:
        receipt = start(
            args.output,
            args.run_id,
            network_mode=args.network_mode,
            python_entry=args.python_entry,
        )
    except (LaunchError, OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"error: server experiment launch failed safely: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

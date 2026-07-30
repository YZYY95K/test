#!/usr/bin/env python3
"""Materialize the image-fixed Tester CI demonstration assignments.

This utility runs at every main-container start, not as an Agent-facing API. The
candidate bytes and every routing field come from immutable image templates;
the only runtime value is a fresh UTC ``created_at`` timestamp required by the
TeamHarness handoff freshness gate.  It never reads the receipt signing key.

The resulting directory is deliberately a finals demonstration fixture.  It
does not claim to mirror arbitrary live AgentTeams tasks.  A production
controller integration must replace this fixed source with an authenticated,
atomic task projection while preserving the same server-side validation.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TEMPLATE_ROOT = Path("/opt/devflow/agentteams-cicd/demo-assignment-templates")
OUTPUT_ROOT = Path("/var/lib/devflow/agentteams-cicd/assignments")
POLICY_PATH = Path("/etc/devflow/agentteams-cicd/policy.json")
SOURCE = "image-fixed-demo-fixture/v1"
TASK_IDS = ("devflow-demo-focused", "devflow-demo-full")
SERVICE_UID = 10_001
SERVICE_GID = 10_001
TEMPLATE_FIELDS = frozenset(
    {"schemaVersion", "source", "taskId", "evidenceTemplate"}
)
EVIDENCE_TEMPLATE_FIELDS = frozenset({"task", "envelope"})
NETWORK_PREFIX = (
    "/usr/bin/bwrap",
    "--die-with-parent",
    "--new-session",
    "--unshare-all",
    "--cap-drop",
    "ALL",
    "--ro-bind",
    "/",
    "/",
    "--tmpfs",
    "/etc",
    "--tmpfs",
    "/home",
    "--tmpfs",
    "/root",
    "--tmpfs",
    "/run",
    "--tmpfs",
    "/tmp",
    "--proc",
    "/proc",
    "--dev",
    "/dev",
)


class MaterializeError(RuntimeError):
    """The fixed assignment source cannot be materialized safely."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MaterializeError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise MaterializeError("non-standard JSON scalar")


def _read_canonical(path: Path) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        payload = path.read_bytes()
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaterializeError("fixed assignment template is unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
        or (os.name == "posix" and metadata.st_uid != 0)
        or not isinstance(value, dict)
        or payload != _canonical(value)
    ):
        raise MaterializeError("fixed assignment template is outside policy")
    return value


def _validate_root(path: Path, *, must_be_empty: bool) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise MaterializeError("assignment directory is unavailable") from exc
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and metadata.st_uid != 0)
        or (not must_be_empty and metadata.st_mode & 0o022)
    ):
        raise MaterializeError("assignment directory is outside policy")
    if must_be_empty:
        try:
            if any(path.iterdir()):
                raise MaterializeError("assignment directory is not empty")
        except OSError as exc:
            raise MaterializeError("assignment directory cannot be inspected") from exc
    return resolved


def _validate_output_root(
    path: Path,
    *,
    refresh: bool,
    enforce_production_metadata: bool,
) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        entries = sorted(path.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise MaterializeError("assignment directory is unavailable") from exc
    expected_names = {f"{task_id}.json" for task_id in TASK_IDS}
    if (
        path.is_symlink()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or enforce_production_metadata and metadata.st_mode & 0o002
        or (not refresh and entries)
        or any(entry.name not in expected_names for entry in entries)
        or enforce_production_metadata
        and os.name == "posix"
        and (
            metadata.st_uid not in {0, SERVICE_UID}
            or metadata.st_gid != SERVICE_GID
        )
    ):
        raise MaterializeError("assignment directory is outside policy")
    for entry in entries:
        item = entry.lstat()
        if (
            entry.is_symlink()
            or not stat.S_ISREG(item.st_mode)
            or item.st_nlink != 1
            or enforce_production_metadata and item.st_mode & 0o022
            or item.st_size > 1_048_576
            or enforce_production_metadata
            and os.name == "posix"
            and (item.st_uid != SERVICE_UID or item.st_gid != SERVICE_GID)
        ):
            raise MaterializeError("existing assignment fixture is outside policy")
    return resolved


def _load_policy() -> dict[str, Any]:
    policy = _read_canonical(POLICY_PATH)
    if (
        policy.get("schemaVersion") != "1.0"
        or policy.get("networkIsolationPrefix") != list(NETWORK_PREFIX)
        or set(policy.get("testCommands", {})) != {"focused", "full"}
        or policy.get("credentialPolicy") != "empty-environment"
        or policy.get("resourceLimitLauncher") != ["/usr/bin/prlimit"]
        or policy.get("resourceLimitsApplied") is not True
        or policy.get("dynamicCandidateSupported") is not False
        or policy.get("testPathMutationSupported") is not False
    ):
        raise MaterializeError("execution policy is outside the fixed demo contract")
    return policy


def _probe_isolation(policy: dict[str, Any]) -> None:
    command = [
        *policy["networkIsolationPrefix"],
        "--clearenv",
        "--",
        "/usr/bin/true",
    ]
    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={},
            timeout=20,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MaterializeError("runtime namespace isolation probe failed") from exc
    if completed.returncode != 0:
        raise MaterializeError("runtime namespace isolation probe failed")


def _materialized(template: dict[str, Any], created_at: str) -> tuple[str, bytes]:
    if (
        set(template) != TEMPLATE_FIELDS
        or template.get("schemaVersion") != "1.0"
        or template.get("source") != SOURCE
        or template.get("taskId") not in TASK_IDS
        or not isinstance(template.get("evidenceTemplate"), dict)
        or set(template["evidenceTemplate"]) != EVIDENCE_TEMPLATE_FIELDS
        or not isinstance(template["evidenceTemplate"].get("task"), dict)
        or not isinstance(template["evidenceTemplate"].get("envelope"), dict)
    ):
        raise MaterializeError("fixed assignment template schema is invalid")
    task_id = template["taskId"]
    task = template["evidenceTemplate"]["task"]
    envelope = dict(template["evidenceTemplate"]["envelope"])
    if (
        task.get("task_id") != task_id
        or envelope.get("task_id") != task_id
        or envelope.get("created_at") != "__MATERIALIZED_AT__"
    ):
        raise MaterializeError("fixed assignment template identity is invalid")
    envelope["created_at"] = created_at
    evidence = {
        "task": task,
        "spec": _canonical(envelope).decode("utf-8"),
    }
    return task_id, _canonical(evidence)


def _write_new(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o440)
    except OSError as exc:
        raise MaterializeError("assignment fixture could not be created") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o440)
    except OSError as exc:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
        raise MaterializeError("assignment fixture write did not complete") from exc


def materialize(
    *,
    template_root: Path = TEMPLATE_ROOT,
    output_root: Path = OUTPUT_ROOT,
    probe_isolation: bool = True,
    refresh: bool = False,
    enforce_production_metadata: bool = True,
) -> dict[str, Any]:
    """Safely replace exactly the two fixtures at each container start."""

    _validate_root(template_root, must_be_empty=False)
    expected_templates = [f"{task_id}.template.json" for task_id in TASK_IDS]
    try:
        template_names = sorted(path.name for path in template_root.iterdir())
    except OSError as exc:
        raise MaterializeError("assignment template directory cannot be inspected") from exc
    if template_names != expected_templates:
        raise MaterializeError("fixed assignment template set is invalid")
    output = _validate_output_root(
        output_root,
        refresh=refresh,
        enforce_production_metadata=enforce_production_metadata,
    )
    policy = _load_policy()
    if probe_isolation:
        _probe_isolation(policy)
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    materialized: list[tuple[str, bytes]] = []
    for task_id in TASK_IDS:
        template = _read_canonical(template_root / f"{task_id}.template.json")
        checked_id, payload = _materialized(template, created_at)
        if checked_id != task_id:
            raise MaterializeError("fixed assignment template order drifted")
        materialized.append((task_id, payload))
    if refresh:
        for task_id in TASK_IDS:
            existing = output / f"{task_id}.json"
            if existing.exists():
                try:
                    existing.chmod(0o600)
                    existing.unlink()
                except OSError as exc:
                    raise MaterializeError(
                        "existing assignment fixture cannot be replaced"
                    ) from exc
    written: list[str] = []
    for task_id, payload in materialized:
        _write_new(output / f"{task_id}.json", payload)
        written.append(task_id)
    return {
        "assignmentSource": SOURCE,
        "fixtureTaskIds": written,
        "isolationProbeVerified": probe_isolation,
        "liveAgentTeamsTaskProjection": False,
        "refreshedAt": created_at,
        "containerRestartRefresh": True,
        "verified": True,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Materialize image-fixed Tester CI demonstration assignments."
    )
    parser.add_argument("--output", type=Path, default=OUTPUT_ROOT)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.output != OUTPUT_ROOT:
            raise MaterializeError("assignment output path is fixed")
        report = materialize(output_root=args.output)
    except (MaterializeError, OSError, RuntimeError, ValueError) as exc:
        print(f"error: Tester CI demo assignment setup failed safely: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

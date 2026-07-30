#!/usr/bin/env python3
"""Refresh fixed assignments, then exec the non-root Tester CI service."""

from __future__ import annotations

import importlib
import os
import sys
from collections.abc import Callable
from typing import cast

try:
    import materialize_demo_assignments as materializer
except ModuleNotFoundError:  # source-tree import; image uses the fixed first name
    from scripts import (
        materialize_agentteams_tester_cicd_demo_assignments as materializer,
    )

SERVICE_UID = 10_001
SERVICE_GID = 10_001
PYTHON = "/usr/local/bin/python3.12"
SERVER = "/opt/devflow/agentteams-cicd/tester_server.py"
SERVER_ARGUMENTS = (
    "--transport",
    "streamable-http",
    "--host",
    "0.0.0.0",
    "--port",
    "8080",
)


def main() -> int:
    if os.name != "posix":
        raise RuntimeError("Tester CI startup identity is not the fixed non-root UID/GID")
    posix_module = importlib.import_module("posix")
    geteuid = cast(Callable[[], int], posix_module.geteuid)
    getegid = cast(Callable[[], int], posix_module.getegid)
    if geteuid() != SERVICE_UID or getegid() != SERVICE_GID:
        raise RuntimeError("Tester CI startup identity is not the fixed non-root UID/GID")
    if tuple(sys.argv[1:]) != SERVER_ARGUMENTS:
        raise RuntimeError("Tester CI startup arguments are outside policy")
    materializer.materialize(refresh=True)
    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONUNBUFFERED": "1",
    }
    os.execve(PYTHON, [PYTHON, "-S", SERVER, *SERVER_ARGUMENTS], environment)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build one isolated AgentTeams role-package set for server experiments."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.build_agentteams_package import build_role_packages  # noqa: E402

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


class IsolatedPackageError(RuntimeError):
    """The per-pass output directory is not a new private directory."""


def _output_directory(path: Path) -> Path:
    if not path.is_absolute() or SAFE_NAME.fullmatch(path.name) is None:
        raise IsolatedPackageError("--output-dir must be an absolute safe path")
    try:
        parent = path.parent.resolve(strict=True)
        repository = ROOT.resolve(strict=True)
    except OSError as exc:
        raise IsolatedPackageError("output parent or repository is unavailable") from exc
    candidate = parent / path.name
    if (
        path.parent.is_symlink()
        or parent != path.parent
        or not parent.is_dir()
        or candidate == repository
        or repository in candidate.parents
        or candidate.exists()
        or candidate.is_symlink()
    ):
        raise IsolatedPackageError("output must be a new directory outside the repository")
    try:
        candidate.mkdir(mode=0o700)
        metadata = candidate.lstat()
    except OSError as exc:
        raise IsolatedPackageError("output directory could not be created") from exc
    if (
        candidate.is_symlink()
        or candidate.resolve(strict=True) != candidate
        or not stat.S_ISDIR(metadata.st_mode)
        or (os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise IsolatedPackageError("output directory metadata is unsafe")
    return candidate


def build(output_dir: Path) -> dict[str, str]:
    destination = _output_directory(output_dir)
    return build_role_packages(ROOT, destination, source_date_epoch=0)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        results = build(args.output_dir)
    except (IsolatedPackageError, OSError, RuntimeError, ValueError) as exc:
        print(f"error: isolated package build failed safely: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "output": str(args.output_dir),
                "roles": results,
                "sourceDateEpoch": 0,
                "verified": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

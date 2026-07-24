"""Atomically point an environment at a known release directory.

This adapter is intentionally configured by the trusted server. The Agent can
select only the environment and target release accepted by MCP policy; it
cannot supply a command or filesystem path.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

_SAFE_RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ENVIRONMENTS = {"staging", "production"}


def switch_release(*, releases_root: Path, link: Path, target_release: str) -> Path:
    """Atomically replace ``link`` with a symlink to a child release."""

    if not _SAFE_RELEASE.fullmatch(target_release):
        raise ValueError("target release is unsafe")
    root = releases_root.resolve(strict=True)
    target = (root / target_release).resolve(strict=True)
    if target.parent != root or not target.is_dir():
        raise ValueError("target release is outside the release registry")
    if not link.is_absolute() or not link.parent.exists():
        raise ValueError("release link must have an existing absolute parent")
    if link.exists() and not link.is_symlink():
        raise ValueError("release link exists and is not a symbolic link")

    temporary = link.with_name(f".{link.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.symlink_to(target, target_is_directory=True)
        os.replace(temporary, link)
    finally:
        if temporary.is_symlink():
            temporary.unlink()
    return target


def main() -> None:
    environment = os.environ.get("DEVFLOW_DEPLOYMENT_ENVIRONMENT", "")
    target_release = os.environ.get("DEVFLOW_TARGET_RELEASE", "")
    if environment not in _ENVIRONMENTS:
        raise SystemExit("unsupported deployment environment")
    releases_root = Path(os.environ["CICD_RELEASES_ROOT"])
    template = os.environ["CICD_RELEASE_LINK_TEMPLATE"]
    link = Path(template.format(environment=environment))
    target = switch_release(
        releases_root=releases_root,
        link=link,
        target_release=target_release,
    )
    print(
        json.dumps(
            {
                "environment": environment,
                "release": target.name,
                "release_link": str(link),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()

"""Tests for the server-owned atomic release pointer adapter."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts.rollback_release import switch_release


def test_release_provider_rejects_path_traversal(tmp_path: Path) -> None:
    root = tmp_path / "releases"
    root.mkdir()
    with pytest.raises(ValueError, match="unsafe"):
        switch_release(
            releases_root=root,
            link=tmp_path / "current",
            target_release="../secret",
        )


@pytest.mark.skipif(os.name == "nt", reason="Windows symlinks need host privileges")
def test_release_provider_switches_symlink_atomically(tmp_path: Path) -> None:
    root = tmp_path / "releases"
    old = root / "old"
    new = root / "new"
    old.mkdir(parents=True)
    new.mkdir()
    link = tmp_path / "current"
    link.symlink_to(old, target_is_directory=True)

    target = switch_release(releases_root=root, link=link, target_release="new")

    assert target == new.resolve()
    assert link.is_symlink()
    assert link.resolve() == new.resolve()

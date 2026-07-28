"""Release-version consistency gates for the preliminary source bundle."""

from __future__ import annotations

import json
import re
from pathlib import Path

from devflow import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_application_and_worker_release_versions_are_aligned() -> None:
    project_text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([0-9]+\.[0-9]+\.[0-9]+)"$', project_text, re.MULTILINE)
    assert match is not None
    project_version = match.group(1)
    observability_text = (ROOT / "config" / "observability.yaml").read_text(
        encoding="utf-8"
    )
    observability_match = re.search(
        r'^  service_version: "([0-9]+\.[0-9]+\.[0-9]+)"$',
        observability_text,
        re.MULTILINE,
    )
    assert observability_match is not None
    worker = json.loads(
        (ROOT / "agentteams" / "worker-package" / "manifest.json").read_text(
            encoding="utf-8"
        )
    )
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert project_version == "1.3.0"
    assert __version__ == project_version
    assert observability_match.group(1) == project_version
    assert worker["version"] == project_version
    assert f"## {project_version} - " in changelog


def test_distribution_contains_the_complete_apache_license() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in license_text
    assert "END OF TERMS AND CONDITIONS" in license_text
    assert (ROOT / "NOTICE").is_file()

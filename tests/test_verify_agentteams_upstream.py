"""Tests for the exact AgentTeams upstream compatibility lock."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import pytest

from scripts.verify_agentteams_upstream import (
    load_lock,
    verify_crd_payload,
    verify_license_payload,
    verify_local_contract,
)

ROOT = Path(__file__).resolve().parents[1]


def test_agentteams_upstream_lock_and_local_contract_are_valid() -> None:
    lock = load_lock(ROOT / "agentteams" / "upstream.lock.yaml")

    verify_local_contract(ROOT, lock)
    assert lock["license"] == {
        "spdx": "Apache-2.0",
        "source_path": "LICENSE",
        "source_url": (
            "https://raw.githubusercontent.com/agentscope-ai/AgentTeams/"
            "v1.2.0-beta.1/LICENSE"
        ),
        "utf8_bytes": 10770,
        "sha256": "d27b69cf7cd0a9fc3f4a04b1ee44e43ab4ebf517d85a1ea197f9ee96826196c7",
    }


def test_agentteams_upstream_payload_is_hash_and_size_bound() -> None:
    lock = load_lock(ROOT / "agentteams" / "upstream.lock.yaml")
    changed = copy.deepcopy(lock)
    payload = b"apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\n"
    changed["team_crd"]["bytes"] = len(payload)

    with pytest.raises(ValueError, match="digest"):
        verify_crd_payload(changed, payload)


def test_agentteams_upstream_lock_rejects_unofficial_source(tmp_path: Path) -> None:
    text = (ROOT / "agentteams" / "upstream.lock.yaml").read_text(encoding="utf-8")
    path = tmp_path / "upstream.lock.yaml"
    path.write_text(
        text.replace(
            "https://github.com/agentscope-ai/AgentTeams.git",
            "https://example.invalid/AgentTeams.git",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="official upstream"):
        load_lock(path)


def test_agentteams_license_payload_is_digest_and_semantics_bound() -> None:
    lock = load_lock(ROOT / "agentteams" / "upstream.lock.yaml")
    payload = b"not the Apache license"
    changed = copy.deepcopy(lock)
    changed["license"]["utf8_bytes"] = len(payload)

    with pytest.raises(ValueError, match="digest"):
        verify_license_payload(changed, payload)

    changed["license"]["sha256"] = hashlib.sha256(payload).hexdigest()
    with pytest.raises(ValueError, match="does not identify Apache-2.0"):
        verify_license_payload(changed, payload)

"""Verify DevFlow's exact AgentTeams release and Team-CRD compatibility lock."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import yaml

COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_CRD_BYTES = 1_000_000
MAX_LOCK_BYTES = 64_000
PINNED_RELEASE_TAG = "v1.2.0-beta.1"
PINNED_COMMIT = "78d0ceda336befa6e62bf89fc1a6b08b965e128d"


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{name} must be a string-keyed mapping")
    return value


def parse_lock_bytes(payload: bytes) -> dict[str, Any]:
    """Parse the exact supported AgentTeams lock from bounded committed bytes."""

    if len(payload) > MAX_LOCK_BYTES:
        raise ValueError("AgentTeams lock exceeds its byte limit")
    try:
        lock = _mapping(yaml.safe_load(payload.decode("utf-8")), "lock")
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("AgentTeams lock is not valid UTF-8 YAML") from exc
    if set(lock) != {
        "schema_version",
        "project",
        "repository",
        "release_tag",
        "commit",
        "release_url",
        "license",
        "team_crd",
        "devflow_manifest",
        "compatibility",
        "verified_at",
    }:
        raise ValueError("AgentTeams lock has an unexpected schema")
    if lock["schema_version"] != "1.0" or lock["project"] != "AgentTeams":
        raise ValueError("AgentTeams lock header is unsupported")
    if lock["repository"] != "https://github.com/agentscope-ai/AgentTeams.git":
        raise ValueError("AgentTeams repository is not the official upstream")
    if lock["release_tag"] != PINNED_RELEASE_TAG or lock["commit"] != PINNED_COMMIT:
        raise ValueError("AgentTeams release identity is not the supported exact pin")
    if lock["release_url"] != (
        "https://github.com/agentscope-ai/AgentTeams/releases/tag/"
        f"{PINNED_RELEASE_TAG}"
    ):
        raise ValueError("AgentTeams release URL is not derived from the exact pin")

    license_record = _mapping(lock["license"], "license")
    if set(license_record) != {
        "spdx",
        "source_path",
        "source_url",
        "utf8_bytes",
        "sha256",
    }:
        raise ValueError("AgentTeams license lock has an unexpected schema")
    expected_license_url = (
        "https://raw.githubusercontent.com/agentscope-ai/AgentTeams/"
        f"{lock['release_tag']}/{license_record['source_path']}"
    )
    if (
        license_record["spdx"] != "Apache-2.0"
        or license_record["source_path"] != "LICENSE"
        or license_record["source_url"] != expected_license_url
        or not isinstance(license_record["utf8_bytes"], int)
        or not 1 <= license_record["utf8_bytes"] <= MAX_CRD_BYTES
        or not isinstance(license_record["sha256"], str)
        or not DIGEST_RE.fullmatch(license_record["sha256"])
    ):
        raise ValueError("AgentTeams license lock is invalid")

    crd = _mapping(lock["team_crd"], "team_crd")
    if set(crd) != {"api_version", "source_path", "source_url", "sha256", "bytes"}:
        raise ValueError("AgentTeams Team CRD lock has an unexpected schema")
    expected_url = (
        "https://raw.githubusercontent.com/agentscope-ai/AgentTeams/"
        f"{lock['release_tag']}/{crd['source_path']}"
    )
    if crd["api_version"] != "agentteams.io/v1beta1":
        raise ValueError("AgentTeams Team CRD apiVersion is unsupported")
    if crd["source_path"] != "hiclaw-controller/config/crd/teams.agentteams.io.yaml":
        raise ValueError("AgentTeams Team CRD source path is unsupported")
    if crd["source_url"] != expected_url:
        raise ValueError("AgentTeams Team CRD URL is not derived from the pinned release")
    if not isinstance(crd["sha256"], str) or not DIGEST_RE.fullmatch(crd["sha256"]):
        raise ValueError("AgentTeams Team CRD digest is invalid")
    if not isinstance(crd["bytes"], int) or not 1 <= crd["bytes"] <= MAX_CRD_BYTES:
        raise ValueError("AgentTeams Team CRD byte count is invalid")
    manifest = _mapping(lock["devflow_manifest"], "devflow_manifest")
    if set(manifest) != {
        "path",
        "schema_mode",
        "compatibility_patch",
        "live_evidence",
    } or manifest != {
        "path": "agentteams/team.yaml",
        "schema_mode": "deprecated-inline-leader-workers",
        "compatibility_patch": "scripts/patch_agentteams_beta.sh",
        "live_evidence": "docs/evidence/AGENTTEAMS_LIVE_20260727.md",
    }:
        raise ValueError("DevFlow AgentTeams manifest lock is invalid")
    compatibility = _mapping(lock["compatibility"], "compatibility")
    if (
        set(compatibility) != {"supported", "current_main"}
        or compatibility["supported"] != "exact-pinned-release-only"
        or not isinstance(compatibility["current_main"], str)
        or "workerMembers" not in compatibility["current_main"]
    ):
        raise ValueError("AgentTeams compatibility declaration is invalid")
    if (
        not isinstance(lock["verified_at"], str)
        or re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", lock["verified_at"]) is None
    ):
        raise ValueError("AgentTeams verification date is invalid")
    return lock


def load_lock(path: Path) -> dict[str, Any]:
    """Load the bounded lock document and reject schema drift."""

    return parse_lock_bytes(path.read_bytes())


def verify_crd_payload(lock: dict[str, Any], payload: bytes) -> None:
    """Verify exact upstream bytes before using the CRD as design evidence."""

    if len(payload) > MAX_CRD_BYTES:
        raise ValueError("downloaded AgentTeams Team CRD exceeds its byte limit")
    crd = _mapping(lock["team_crd"], "team_crd")
    if len(payload) != crd["bytes"]:
        raise ValueError("AgentTeams Team CRD byte count does not match the lock")
    if hashlib.sha256(payload).hexdigest() != crd["sha256"]:
        raise ValueError("AgentTeams Team CRD digest does not match the lock")
    document = _mapping(yaml.safe_load(payload), "Team CRD")
    if document.get("kind") != "CustomResourceDefinition":
        raise ValueError("locked AgentTeams Team CRD has the wrong kind")
    if _mapping(document.get("metadata"), "Team CRD metadata").get("name") != (
        "teams.agentteams.io"
    ):
        raise ValueError("locked AgentTeams Team CRD has the wrong resource name")


def verify_license_payload(lock: dict[str, Any], payload: bytes) -> None:
    """Verify exact UTF-8 Apache-2.0 license bytes from the pinned release."""

    license_record = _mapping(lock["license"], "license")
    if len(payload) != license_record["utf8_bytes"]:
        raise ValueError("downloaded AgentTeams license byte count does not match the lock")
    if hashlib.sha256(payload).hexdigest() != license_record["sha256"]:
        raise ValueError("downloaded AgentTeams license digest does not match the lock")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("downloaded AgentTeams license is not UTF-8") from exc
    if "Apache License" not in text or "Version 2.0, January 2004" not in text:
        raise ValueError("downloaded AgentTeams license does not identify Apache-2.0")


def verify_manifest_payload(lock: dict[str, Any], payload: bytes) -> None:
    """Verify committed Team bytes against the locked beta schema path."""

    manifest_meta = _mapping(lock["devflow_manifest"], "devflow_manifest")
    try:
        manifest = _mapping(yaml.safe_load(payload), "Team manifest")
    except yaml.YAMLError as exc:
        raise ValueError("DevFlow AgentTeams manifest is invalid YAML") from exc
    spec = _mapping(manifest.get("spec"), "Team manifest spec")
    if manifest.get("apiVersion") != lock["team_crd"]["api_version"]:
        raise ValueError("DevFlow Team apiVersion does not match the lock")
    if manifest.get("kind") != "Team":
        raise ValueError("DevFlow AgentTeams manifest is not a Team")
    if manifest_meta.get("schema_mode") != "deprecated-inline-leader-workers":
        raise ValueError("DevFlow AgentTeams schema mode is not explicit")
    if "leader" not in spec or "workers" not in spec or "workerMembers" in spec:
        raise ValueError("DevFlow Team no longer matches its locked inline beta schema mode")


def verify_local_contract(root: Path, lock: dict[str, Any]) -> None:
    """Verify that local evidence uses the exact locked beta schema path."""

    manifest_meta = _mapping(lock["devflow_manifest"], "devflow_manifest")
    manifest_path = (root / str(manifest_meta["path"])).resolve()
    if root.resolve() not in manifest_path.parents or not manifest_path.is_file():
        raise ValueError("DevFlow AgentTeams manifest is unavailable or outside the repository")
    verify_manifest_payload(lock, manifest_path.read_bytes())
    patch_path = (root / str(manifest_meta["compatibility_patch"])).resolve()
    if root.resolve() not in patch_path.parents or not patch_path.is_file():
        raise ValueError("AgentTeams beta compatibility patch is unavailable")
    evidence_path = (root / str(manifest_meta["live_evidence"])).resolve()
    if root.resolve() not in evidence_path.parents or not evidence_path.is_file():
        raise ValueError("AgentTeams live evidence is unavailable")


def verify(root: Path, *, online: bool) -> dict[str, Any]:
    lock = load_lock(root / "agentteams" / "upstream.lock.yaml")
    verify_local_contract(root, lock)
    if online:
        request = Request(
            str(lock["team_crd"]["source_url"]),
            headers={"User-Agent": "DevFlow-AgentTeams-Contract-Verifier/1"},
        )
        with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed HTTPS origin
            payload = response.read(MAX_CRD_BYTES + 1)
        verify_crd_payload(lock, payload)
        license_request = Request(
            str(lock["license"]["source_url"]),
            headers={"User-Agent": "DevFlow-AgentTeams-Contract-Verifier/1"},
        )
        with urlopen(license_request, timeout=20) as response:  # noqa: S310 - fixed HTTPS origin
            license_payload = response.read(MAX_CRD_BYTES + 1)
        verify_license_payload(lock, license_payload)
    return {
        "release_tag": lock["release_tag"],
        "commit": lock["commit"],
        "team_crd_sha256": lock["team_crd"]["sha256"],
        "schema_mode": lock["devflow_manifest"]["schema_mode"],
        "license_spdx": lock["license"]["spdx"],
        "license_sha256": lock["license"]["sha256"],
        "online_verified": online,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    result = verify(args.root.resolve(), online=not args.offline)
    print(yaml.safe_dump(result, sort_keys=True).strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

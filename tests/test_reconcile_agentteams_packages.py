from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import stat
import subprocess
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import scripts.reconcile_agentteams_packages as package_reconciler
from scripts.build_agentteams_package import (
    PACKAGE_VERSION,
    ROLE_SKILLS,
    build_role_packages,
    canonical_zip_bytes,
    manifest_digest,
)
from scripts.reconcile_agentteams_packages import (
    KubectlClient,
    PackagePublishError,
    _validate_zip,
    desired_configmap,
    load_archives,
    reconcile,
)

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class FakeClient:
    value: dict[str, Any] | None = None
    creates: int = 0

    def get(self) -> dict[str, Any] | None:
        return copy.deepcopy(self.value)

    def create(self, document: dict[str, Any]) -> None:
        self.creates += 1
        self.value = copy.deepcopy(document)


def _release(tmp_path: Path) -> Path:
    build_role_packages(ROOT, tmp_path, source_date_epoch=0)
    return tmp_path


def _rewrite_archive(
    directory: Path,
    role: str,
    mutate: Any,
    *,
    source_date_epoch: int = 0,
) -> Path:
    archive_path = directory / f"{role}-v{PACKAGE_VERSION}.zip"
    with zipfile.ZipFile(archive_path) as archive:
        content = {info.filename: archive.read(info) for info in archive.infolist()}
    mutate(content)
    data = canonical_zip_bytes(content, source_date_epoch)
    archive_path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    archive_path.with_suffix(".zip.sha256").write_bytes(
        f"{digest}  {archive_path.name}\n".encode("ascii")
    )
    return archive_path


def test_loads_exact_role_release_and_builds_immutable_configmap(tmp_path: Path) -> None:
    archives = load_archives(_release(tmp_path))
    desired = desired_configmap(archives)

    assert {archive.role for archive in archives} == set(ROLE_SKILLS)
    assert desired["immutable"] is True
    assert set(desired["binaryData"]) == {archive.name for archive in archives}
    assert set(desired["metadata"]["annotations"]) == {
        f"devflow.ai/{role}-sha256" for role in ROLE_SKILLS
    }
    for archive in archives:
        encoded = desired["binaryData"][archive.name]
        assert hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest() == (
            desired["metadata"]["annotations"][f"devflow.ai/{archive.role}-sha256"]
        )


def test_check_is_read_only_and_apply_is_create_only(tmp_path: Path) -> None:
    archives = load_archives(_release(tmp_path))
    client = FakeClient()

    assert reconcile(client, archives, apply=False) == {
        "ok": False,
        "state": "absent",
        "created": False,
    }
    assert client.creates == 0
    assert reconcile(client, archives, apply=True)["created"] is True
    assert client.creates == 1
    assert reconcile(client, archives, apply=True)["created"] is False
    assert client.creates == 1


def test_existing_version_never_mutates_on_byte_or_policy_drift(tmp_path: Path) -> None:
    archives = load_archives(_release(tmp_path))
    mutations: tuple[Callable[[dict[str, Any]], object], ...] = (
        lambda value: value["binaryData"].__setitem__(archives[0].name, "different"),
        lambda value: value.__setitem__("immutable", False),
        lambda value: value["metadata"]["annotations"].clear(),
        lambda value: value["metadata"]["labels"].__setitem__("unexpected", "label"),
    )
    for mutate in mutations:
        value = desired_configmap(archives)
        mutate(value)
        client = FakeClient(value)
        with pytest.raises(PackagePublishError, match="bump the release version"):
            reconcile(client, archives, apply=True)
        assert client.creates == 0


def test_rejects_archive_and_sidecar_digest_tampering(tmp_path: Path) -> None:
    directory = _release(tmp_path)
    archive_path = next(directory.glob("*.zip"))
    archive_path.write_bytes(archive_path.read_bytes() + b"tampered")
    with pytest.raises(PackagePublishError, match="archive digest mismatch"):
        load_archives(directory)


def test_rejects_inner_file_digest_tampering_even_with_new_sidecar(tmp_path: Path) -> None:
    directory = _release(tmp_path)
    _rewrite_archive(
        directory,
        "devflow-coder",
        lambda content: content.__setitem__("config/AGENTS.md", b"changed"),
    )

    with pytest.raises(PackagePublishError, match="worker package file digest mismatch"):
        load_archives(directory)


def test_rejects_manifest_digest_tampering_with_new_outer_digest(tmp_path: Path) -> None:
    directory = _release(tmp_path)

    def mutate(content: dict[str, bytes]) -> None:
        manifest = json.loads(content["manifest.json"])
        manifest["source"]["created_at"] = "1970-01-01T00:00:01Z"
        content["manifest.json"] = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()

    _rewrite_archive(directory, "devflow-coder", mutate)

    with pytest.raises(PackagePublishError, match="manifest digest mismatch"):
        load_archives(directory)


def test_rejects_extra_skill_even_with_consistent_manifest_and_outer_digest(
    tmp_path: Path,
) -> None:
    directory = _release(tmp_path)

    def mutate(content: dict[str, bytes]) -> None:
        content["skills/issue-classifier/SKILL.md"] = b"extra privilege"
        manifest = json.loads(content["manifest.json"])
        manifest["files"]["skills/issue-classifier/SKILL.md"] = hashlib.sha256(
            b"extra privilege"
        ).hexdigest()
        manifest["manifest_sha256"] = manifest_digest(manifest)
        content["manifest.json"] = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()

    _rewrite_archive(directory, "devflow-coder", mutate)

    with pytest.raises(PackagePublishError, match="exact minimal role package"):
        load_archives(directory)


def test_rejects_secret_after_attacker_recomputes_all_digests(tmp_path: Path) -> None:
    directory = _release(tmp_path)
    secret = b"ghp_" + b"A" * 36

    def mutate(content: dict[str, bytes]) -> None:
        content["config/AGENTS.md"] = secret
        manifest = json.loads(content["manifest.json"])
        manifest["files"]["config/AGENTS.md"] = hashlib.sha256(secret).hexdigest()
        manifest["manifest_sha256"] = manifest_digest(manifest)
        content["manifest.json"] = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()

    _rewrite_archive(directory, "devflow-coder", mutate)

    with pytest.raises(PackagePublishError, match="secret-shaped"):
        load_archives(directory)


def test_rejects_benign_content_rewrite_after_all_unkeyed_digests_are_recomputed(
    tmp_path: Path,
) -> None:
    directory = _release(tmp_path)
    changed = b"benign but not from the trusted release source"

    def mutate(content: dict[str, bytes]) -> None:
        content["config/AGENTS.md"] = changed
        manifest = json.loads(content["manifest.json"])
        manifest["files"]["config/AGENTS.md"] = hashlib.sha256(changed).hexdigest()
        manifest["manifest_sha256"] = manifest_digest(manifest)
        content["manifest.json"] = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode()

    _rewrite_archive(directory, "devflow-coder", mutate)

    with pytest.raises(PackagePublishError, match="trusted source release"):
        load_archives(directory)


@pytest.mark.parametrize("name", ["../escape", "config\\escape", "/absolute"])
def test_rejects_zip_slip_names(name: str) -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(info, b"unsafe")
        manifest = zipfile.ZipInfo("manifest.json")
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, b"{}")

    archive_data = stream.getvalue()
    if name == "config\\escape" and b"config\\escape" not in archive_data:
        # ZipInfo normalizes the platform separator on Windows. Restore the
        # same-length hostile name in both ZIP headers so the reader sees the
        # actual cross-platform attack case this test is intended to cover.
        archive_data = archive_data.replace(b"config/escape", b"config\\escape")

    with pytest.raises(PackagePublishError, match="unsafe entry"):
        _validate_zip(archive_data, role="devflow-coder", name="unsafe.zip")


def test_rejects_duplicate_and_symlink_zip_entries() -> None:
    duplicate = io.BytesIO()
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(duplicate, "w") as archive,
    ):
        archive.writestr("manifest.json", b"{}")
        archive.writestr("manifest.json", b"{}")
    with pytest.raises(PackagePublishError, match="ambiguous"):
        _validate_zip(duplicate.getvalue(), role="devflow-coder", name="duplicate.zip")

    symlink = io.BytesIO()
    with zipfile.ZipFile(symlink, "w") as archive:
        info = zipfile.ZipInfo("config/AGENTS.md")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, b"config/SOUL.md")
        manifest = zipfile.ZipInfo("manifest.json")
        manifest.create_system = 3
        manifest.external_attr = (stat.S_IFREG | 0o644) << 16
        archive.writestr(manifest, b"{}")
    with pytest.raises(PackagePublishError, match="unsafe entry"):
        _validate_zip(symlink.getvalue(), role="devflow-coder", name="symlink.zip")


def test_rejects_noncanonical_trailing_zip_bytes_with_new_sidecar(tmp_path: Path) -> None:
    directory = _release(tmp_path)
    archive_path = directory / "devflow-coder-v1.2.0.zip"
    data = archive_path.read_bytes() + b"trailing-data"
    archive_path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    archive_path.with_suffix(".zip.sha256").write_bytes(
        f"{digest}  {archive_path.name}\n".encode("ascii")
    )

    with pytest.raises(PackagePublishError, match="canonical reproducible"):
        load_archives(directory)


def test_desired_configmap_rejects_incomplete_archive_set_and_size_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archives = load_archives(_release(tmp_path))
    with pytest.raises(PackagePublishError, match="exact ordered roles"):
        desired_configmap(archives[:-1])

    monkeypatch.setattr(package_reconciler, "MAX_CONFIGMAP_SERIALIZED_BYTES", 1)
    with pytest.raises(PackagePublishError, match="ConfigMap payload"):
        desired_configmap(archives)


def test_apply_fails_closed_when_created_configmap_readback_drifts(tmp_path: Path) -> None:
    archives = load_archives(_release(tmp_path))

    class DriftClient(FakeClient):
        def create(self, document: dict[str, Any]) -> None:
            super().create(document)
            assert self.value is not None
            self.value["binaryData"].pop(next(iter(self.value["binaryData"])))

    client = DriftClient()
    with pytest.raises(PackagePublishError, match="read-back verification"):
        reconcile(client, archives, apply=True)
    assert client.creates == 1


def test_kubectl_get_treats_only_successful_empty_response_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def successful_empty(args: list[str], **_kwargs: Any) -> Any:
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", successful_empty)
    client = KubectlClient("agentteams-system", "fixed")
    assert client.get() is None
    assert "--ignore-not-found=true" in calls[0]
    client.create({"apiVersion": "v1"})
    assert "create" in calls[1]
    assert "--namespace" in calls[1]
    assert "--filename=-" in calls[1]
    assert not {"apply", "patch", "replace", "delete"} & set(calls[1])

    def failed_not_found(args: list[str], **_kwargs: Any) -> Any:
        return subprocess.CompletedProcess(
            args,
            1,
            stdout="",
            stderr="Error from server (NotFound)",
        )

    monkeypatch.setattr(subprocess, "run", failed_not_found)
    with pytest.raises(PackagePublishError, match="lookup failed"):
        client.get()


def test_cli_help_has_explicit_apply_gate() -> None:
    import sys

    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            str(ROOT / "scripts" / "reconcile_agentteams_packages.py"),
            "--help",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "--apply" in completed.stdout
    assert "--dist" in completed.stdout
    assert not completed.stderr

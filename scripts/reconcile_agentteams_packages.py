#!/usr/bin/env python3
"""Create or verify the immutable role-scoped AgentTeams package ConfigMap."""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

try:
    from scripts.build_agentteams_package import (
        MAX_ARCHIVE_BYTES,
        MAX_ARCHIVE_UNCOMPRESSED_BYTES,
        MAX_SOURCE_FILE_BYTES,
        PACKAGE_VERSION,
        ROLE_SKILLS,
        PackageBuildError,
        build_role_package_bytes,
        canonical_zip_bytes,
        decode_json_object,
        expected_payload_files,
        has_secret_shaped_content,
        read_regular_file,
        trusted_directory,
        validate_role_manifest,
    )
except ModuleNotFoundError:  # pragma: no cover - direct script execution
    from build_agentteams_package import (  # type: ignore[no-redef]
        MAX_ARCHIVE_BYTES,
        MAX_ARCHIVE_UNCOMPRESSED_BYTES,
        MAX_SOURCE_FILE_BYTES,
        PACKAGE_VERSION,
        ROLE_SKILLS,
        PackageBuildError,
        build_role_package_bytes,
        canonical_zip_bytes,
        decode_json_object,
        expected_payload_files,
        has_secret_shaped_content,
        read_regular_file,
        trusted_directory,
        validate_role_manifest,
    )

NAMESPACE = "agentteams-system"
CONFIGMAP_NAME = f"devflow-worker-packages-v{PACKAGE_VERSION.replace('.', '-')}"
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SAFE_ARCHIVE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
MAX_CONFIGMAP_SERIALIZED_BYTES = 900_000
MAX_COMPRESSION_RATIO = 200
RELEASE_SOURCE_ROOT = Path(__file__).resolve().parents[1]


class PackagePublishError(RuntimeError):
    """A local release or immutable cluster object is outside policy."""


@dataclass(frozen=True)
class Archive:
    role: str
    name: str
    data: bytes
    digest: str
    source_date_epoch: int


class ConfigMapClient(Protocol):
    def get(self) -> dict[str, Any] | None: ...

    def create(self, document: dict[str, Any]) -> None: ...


class KubectlClient:
    def __init__(self, namespace: str, name: str) -> None:
        self.namespace = namespace
        self.name = name

    def get(self) -> dict[str, Any] | None:
        try:
            completed = subprocess.run(
                [
                    "kubectl",
                    "--namespace",
                    self.namespace,
                    "get",
                    "configmap",
                    self.name,
                    "--ignore-not-found=true",
                    "-o",
                    "json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise PackagePublishError("kubectl could not be started") from exc
        if completed.returncode != 0:
            raise PackagePublishError("ConfigMap lookup failed")
        if not completed.stdout.strip():
            return None
        try:
            value = decode_json_object(
                completed.stdout.encode("utf-8"),
                "ConfigMap response",
            )
        except (PackageBuildError, UnicodeError) as exc:
            raise PackagePublishError("ConfigMap response is not JSON") from exc
        return value

    def create(self, document: dict[str, Any]) -> None:
        try:
            completed = subprocess.run(
                [
                    "kubectl",
                    "--namespace",
                    self.namespace,
                    "create",
                    "--filename=-",
                ],
                input=json.dumps(document, separators=(",", ":")),
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise PackagePublishError("kubectl could not be started") from exc
        if completed.returncode != 0:
            raise PackagePublishError("immutable ConfigMap creation failed")


def _archive_name(role: str) -> str:
    return f"{role}-v{PACKAGE_VERSION}.zip"


def _read_digest(path: Path, expected_name: str, directory: Path) -> str:
    try:
        text = read_regular_file(
            path,
            root=directory,
            label="archive digest file",
            max_bytes=256,
            scan_secrets=False,
        ).decode("ascii")
    except (PackageBuildError, UnicodeError) as exc:
        raise PackagePublishError("archive digest file cannot be read") from exc
    match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)\n", text)
    if match is None or match.group(2) != expected_name:
        raise PackagePublishError("archive digest file is malformed")
    return match.group(1)


def _validate_zip(data: bytes, *, role: str, name: str) -> int:
    if len(data) > MAX_ARCHIVE_BYTES:
        raise PackagePublishError(f"archive exceeds the release size limit: {name}")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            expected_names = sorted({"manifest.json", *expected_payload_files(role)})
            if (
                len(names) != len(set(names))
                or "manifest.json" not in names
                or archive.comment != b""
            ):
                raise PackagePublishError("archive entries are ambiguous")
            total_uncompressed = 0
            for info in infos:
                path = PurePosixPath(info.filename)
                raw_parts = info.filename.split("/")
                total_uncompressed += info.file_size
                if (
                    info.orig_filename != info.filename
                    or SAFE_ARCHIVE_NAME.fullmatch(info.filename) is None
                    or any(part in {"", ".", ".."} for part in raw_parts)
                    or "\\" in info.filename
                    or path.is_absolute()
                    or ".." in path.parts
                    or path.as_posix() != info.filename
                    or info.is_dir()
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.flag_bits != 0
                    or info.external_attr != (stat.S_IFREG | 0o644) << 16
                    or info.internal_attr != 0
                    or info.extra != b""
                    or info.comment != b""
                    or info.compress_type != zipfile.ZIP_STORED
                    or info.file_size > MAX_SOURCE_FILE_BYTES
                    or (
                        info.file_size > 0
                        and (
                            info.compress_size == 0
                            or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
                        )
                    )
                ):
                    raise PackagePublishError("archive contains an unsafe entry")
            if names != expected_names:
                raise PackagePublishError("archive is not the exact minimal role package")
            if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise PackagePublishError("archive expands beyond the release size limit")
            content = {info.filename: archive.read(info) for info in infos}
            if any(has_secret_shaped_content(item) for item in content.values()):
                raise PackagePublishError("archive contains secret-shaped content")
            manifest = decode_json_object(content["manifest.json"], "archive manifest")
            payload = {key: value for key, value in content.items() if key != "manifest.json"}
            source_date_epoch = validate_role_manifest(manifest, role=role, payload=payload)
            if canonical_zip_bytes(content, source_date_epoch) != data:
                raise PackagePublishError("archive is not in the canonical reproducible form")
            return source_date_epoch
    except PackagePublishError:
        raise
    except PackageBuildError as exc:
        raise PackagePublishError(str(exc)) from exc
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        raise PackagePublishError(f"archive is invalid: {name}") from exc


def load_archives(directory: Path) -> tuple[Archive, ...]:
    try:
        directory = trusted_directory(directory, "role archive directory")
    except PackageBuildError as exc:
        raise PackagePublishError("role archive directory is unsafe") from exc
    archives: list[Archive] = []
    for role in ROLE_SKILLS:
        name = _archive_name(role)
        path = directory / name
        try:
            data = read_regular_file(
                path,
                root=directory,
                label=f"role archive {name}",
                max_bytes=MAX_ARCHIVE_BYTES,
                scan_secrets=False,
            )
        except PackageBuildError as exc:
            raise PackagePublishError(f"missing role archive: {name}") from exc
        digest = hashlib.sha256(data).hexdigest()
        if _read_digest(path.with_suffix(path.suffix + ".sha256"), name, directory) != digest:
            raise PackagePublishError("archive digest mismatch")
        source_date_epoch = _validate_zip(data, role=role, name=name)
        archives.append(Archive(role, name, data, digest, source_date_epoch))
    result = tuple(archives)
    _validate_source_release(result)
    return result


def _validate_source_release(archives: tuple[Archive, ...]) -> None:
    epochs = {archive.source_date_epoch for archive in archives}
    if len(epochs) != 1:
        raise PackagePublishError("role archives do not share one release timestamp")
    try:
        expected = build_role_package_bytes(RELEASE_SOURCE_ROOT, epochs.pop())
    except PackageBuildError as exc:
        raise PackagePublishError("trusted release sources failed validation") from exc
    if any(archive.data != expected[archive.role] for archive in archives):
        raise PackagePublishError("archive does not match the trusted source release")


def _validate_archive_set(archives: tuple[Archive, ...]) -> None:
    if tuple(archive.role for archive in archives) != tuple(ROLE_SKILLS):
        raise PackagePublishError("archive set does not contain the exact ordered roles")
    for archive in archives:
        if (
            archive.name != _archive_name(archive.role)
            or DIGEST.fullmatch(archive.digest) is None
            or hashlib.sha256(archive.data).hexdigest() != archive.digest
        ):
            raise PackagePublishError("archive identity or outer digest mismatch")
        validated_epoch = _validate_zip(archive.data, role=archive.role, name=archive.name)
        if archive.source_date_epoch != validated_epoch:
            raise PackagePublishError("archive timestamp attestation mismatch")
    _validate_source_release(archives)


def desired_configmap(archives: tuple[Archive, ...]) -> dict[str, Any]:
    _validate_archive_set(archives)
    document = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": CONFIGMAP_NAME,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "devflow-package",
                "app.kubernetes.io/part-of": "devflow",
                "devflow.ai/package-version": PACKAGE_VERSION,
            },
            "annotations": {
                f"devflow.ai/{archive.role}-sha256": archive.digest for archive in archives
            },
        },
        "immutable": True,
        "binaryData": {
            archive.name: base64.b64encode(archive.data).decode("ascii") for archive in archives
        },
    }
    serialized = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(serialized) > MAX_CONFIGMAP_SERIALIZED_BYTES:
        raise PackagePublishError("role archives exceed the safe ConfigMap payload limit")
    return document


def _matches(actual: dict[str, Any], desired: dict[str, Any]) -> bool:
    metadata = actual.get("metadata")
    wanted_metadata = desired["metadata"]
    if not isinstance(metadata, dict):
        return False
    labels = metadata.get("labels")
    annotations = metadata.get("annotations")
    return (
        set(actual) == set(desired)
        and actual.get("apiVersion") == "v1"
        and actual.get("kind") == "ConfigMap"
        and metadata.get("name") == wanted_metadata["name"]
        and metadata.get("namespace") == wanted_metadata["namespace"]
        and labels == wanted_metadata["labels"]
        and annotations == wanted_metadata["annotations"]
        and actual.get("immutable") is True
        and actual.get("binaryData") == desired["binaryData"]
        and "data" not in actual
    )


def reconcile(
    client: ConfigMapClient,
    archives: tuple[Archive, ...],
    *,
    apply: bool,
) -> dict[str, Any]:
    desired = desired_configmap(archives)
    actual = client.get()
    if actual is None:
        if not apply:
            return {"ok": False, "state": "absent", "created": False}
        client.create(desired)
        verified = client.get()
        if verified is None or not _matches(verified, desired):
            raise PackagePublishError("created ConfigMap failed read-back verification")
        return {"ok": True, "state": "compliant", "created": True}
    if not _matches(actual, desired):
        raise PackagePublishError(
            "versioned ConfigMap exists with different bytes or policy; bump the release version"
        )
    return {"ok": True, "state": "compliant", "created": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, default=Path(__file__).resolve().parents[1] / "dist")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    try:
        archives = load_archives(args.dist)
        result = reconcile(KubectlClient(NAMESPACE, CONFIGMAP_NAME), archives, apply=args.apply)
    except PackagePublishError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                **result,
                "configMap": CONFIGMAP_NAME,
                "version": PACKAGE_VERSION,
                "archiveDigests": {archive.role: archive.digest for archive in archives},
            },
            sort_keys=True,
        )
    )
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

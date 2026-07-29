#!/usr/bin/env python3
"""Generate deterministic license evidence for DevFlow's hashed dependency locks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCKS = {
    "dev": "requirements/dev.lock.txt",
    "production": "requirements/production.lock.txt",
    "rag": "requirements/rag.lock.txt",
}
REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9][A-Za-z0-9.+!_-]*)")
MAX_METADATA_BYTES = 2 * 1024 * 1024
LICENSE_FIELD_EXPRESSIONS = {
    "3-clause bsd license": "BSD-3-Clause",
    "apache-2.0": "Apache-2.0",
    "apache-2.0 and mit": "Apache-2.0 AND MIT",
    "apache 2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "isc": "ISC",
    "mit": "MIT",
    "mit license": "MIT",
    "mpl-2.0": "MPL-2.0",
    "mpl-2.0 and mit": "MPL-2.0 AND MIT",
    "mit or apache-2.0": "MIT OR Apache-2.0",
    "psf": "PSF-2.0",
    "psf-2.0": "PSF-2.0",
    "unlicense": "Unlicense",
}
LICENSE_CLASSIFIER_EXPRESSIONS = {
    "License :: OSI Approved :: Apache Software License": "Apache-2.0",
    "License :: OSI Approved :: ISC License (ISCL)": "ISC",
    "License :: OSI Approved :: MIT License": "MIT",
    "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "License :: OSI Approved :: Python Software Foundation License": "PSF-2.0",
    "License :: OSI Approved :: The Unlicense (Unlicense)": "Unlicense",
}


def canonical_name(value: str) -> str:
    """Return the PEP 503 normalized distribution name."""

    return re.sub(r"[-_.]+", "-", value).lower()


def lock_packages(data: bytes) -> frozenset[tuple[str, str]]:
    """Return the exact normalized package/version set from one uv lock."""

    text = data.decode("utf-8")
    packages: set[tuple[str, str]] = set()
    for line in text.splitlines():
        match = REQUIREMENT.match(line)
        if not match:
            continue
        package = canonical_name(match.group(1))
        version = match.group(2)
        identity = (package, version)
        if identity in packages:
            raise ValueError(f"duplicate package/version in lock: {package}=={version}")
        packages.add(identity)
    if not packages:
        raise ValueError("lock contains no exact package versions")
    return frozenset(packages)


def pypi_metadata(client: httpx.Client, package: str, version: str) -> dict[str, Any]:
    """Fetch one bounded, version-specific PyPI JSON metadata record."""

    url = f"https://pypi.org/pypi/{package}/{version}/json"
    try:
        response = client.get(url)
        response.raise_for_status()
        payload = response.content
    except httpx.HTTPError as exc:
        raise RuntimeError(f"PyPI metadata unavailable for {package}=={version}") from exc
    if len(payload) > MAX_METADATA_BYTES:
        raise RuntimeError(f"PyPI metadata exceeds size limit for {package}=={version}")
    value = json.loads(payload)
    if (
        not isinstance(value, dict)
        or not isinstance(value.get("info"), dict)
        or value["info"].get("version") != version
    ):
        raise RuntimeError(f"PyPI metadata identity mismatch for {package}=={version}")
    return value


def license_evidence(info: dict[str, Any]) -> tuple[str, str]:
    """Resolve only authoritative or exact unambiguous PyPI license metadata."""

    expression = info.get("license_expression")
    if isinstance(expression, str) and expression.strip():
        return expression.strip(), "verified-pypi-license-expression"
    license_field = info.get("license")
    if isinstance(license_field, str):
        normalized = " ".join(license_field.strip().lower().split())
        mapped = LICENSE_FIELD_EXPRESSIONS.get(normalized)
        if mapped is not None:
            return mapped, "verified-pypi-license-field-exact"
    classifiers = info.get("classifiers")
    if isinstance(classifiers, list) and all(isinstance(item, str) for item in classifiers):
        matches = {
            LICENSE_CLASSIFIER_EXPRESSIONS[item]
            for item in classifiers
            if item in LICENSE_CLASSIFIER_EXPRESSIONS
        }
        if len(matches) == 1:
            return matches.pop(), "verified-pypi-license-classifier-exact"
    return "NOASSERTION", "noassertion-pypi-license-metadata-ambiguous-or-missing"


def build_document(root: Path) -> dict[str, Any]:
    """Build the complete lock-digest and license-evidence document."""

    lock_records: dict[str, dict[str, Any]] = {}
    versions: set[tuple[str, str]] = set()
    for profile, relative in LOCKS.items():
        payload = (root / relative).read_bytes()
        packages = lock_packages(payload)
        versions.update(packages)
        lock_records[profile] = {
            "packages": len(packages),
            "path": relative,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    records: list[dict[str, str]] = []
    transport = httpx.HTTPTransport(retries=3)
    with httpx.Client(
        headers={"User-Agent": "DevFlow-License-Lock/1"},
        timeout=30,
        transport=transport,
    ) as client:
        for package, version in sorted(versions):
            metadata_url = f"https://pypi.org/pypi/{package}/{version}/json"
            metadata = pypi_metadata(client, package, version)
            license_expression, verify_status = license_evidence(metadata["info"])
            records.append(
                {
                    "license_expression": license_expression,
                    "metadata_source": metadata_url,
                    "package": package,
                    "source_url": f"https://pypi.org/project/{package}/{version}/",
                    "verify_status": verify_status,
                    "version": version,
                }
            )
    return {
        "locks": lock_records,
        "packages": records,
        "schema_version": "1.0",
    }


def atomic_write(path: Path, document: dict[str, Any]) -> None:
    """Atomically replace one generated YAML output."""

    data = yaml.safe_dump(
        document,
        allow_unicode=True,
        sort_keys=True,
        width=100,
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("requirements/licenses.yaml"),
    )
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    output = arguments.output if arguments.output.is_absolute() else root / arguments.output
    atomic_write(output, build_document(root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

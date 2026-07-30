#!/usr/bin/env python3
"""Build a deterministic, public-only Tester CI container context.

The context is derived from one completely clean Git worktree plus one
canonical Ed25519 public key.  It contains neither ``.git`` nor a receipt
private key.  Check mode is the default and writes nothing; apply mode requires
an exact confirmation and creates a new archive without overwriting a file.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

try:
    from scripts import reconcile_agentteams_tester_cicd as reconciler
except ModuleNotFoundError:  # pragma: no cover - direct ``python -S`` execution
    import reconcile_agentteams_tester_cicd as reconciler  # type: ignore[no-redef]

CONFIRMATION = "BUILD_ISOLATED_AGENTTEAMS_TESTER_CICD_CONTEXT"
MAX_CONTEXT_BYTES = 384 * 1024 * 1024
OUTPUT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.tar$")
REQUIRED_SOURCES = {
    "agentteams/tester-cicd.Containerfile": "Containerfile",
    "agentteams/cicd/tester_server.py": "tester_server.py",
    "requirements/dev.lock.txt": "requirements-dev.lock.txt",
    "scripts/finalize_agentteams_tester_cicd_image.py": "finalize_image.py",
    "scripts/materialize_agentteams_tester_cicd_demo_assignments.py": (
        "materialize_demo_assignments.py"
    ),
    "scripts/start_agentteams_tester_cicd.py": "start_service.py",
}


class ContextBuildError(RuntimeError):
    """The release source cannot produce the fixed public build context."""


@dataclass(frozen=True)
class ContextEntry:
    path: str
    payload: bytes
    mode: int


@dataclass(frozen=True)
class ContextReport:
    applied: bool
    context_sha256: str
    context_bytes: int
    entry_count: int
    output: str
    repository_revision: str
    repository_archive_sha256: str
    repository_manifest_sha256: str
    server_sha256: str
    receipt_public_key_sha256: str
    receipt_public_key_file_sha256: str


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_tracked(item: reconciler.TrackedFile) -> bytes:
    try:
        metadata = item.path.lstat()
        resolved = item.path.resolve(strict=True)
        payload = item.path.read_bytes()
    except OSError as exc:
        raise ContextBuildError("tracked source changed while building context") from exc
    if (
        item.path.is_symlink()
        or resolved != item.path
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or len(payload) != item.size
        or _sha256(payload) != item.digest
    ):
        raise ContextBuildError("tracked source changed while building context")
    return payload


def _release_source(
    runner: reconciler.Runner,
    repository: Path,
) -> tuple[reconciler.SourceAttestation, tuple[reconciler.TrackedFile, ...]]:
    revision, files = reconciler._tracked_files(runner, repository)
    archive = reconciler._archive(files)
    tree = [{"path": item.relative, "sha256": item.digest} for item in files]
    by_path = {item.relative: item for item in files}
    missing = set(REQUIRED_SOURCES) - set(by_path)
    if missing:
        raise ContextBuildError("release repository lacks a required CI image source")
    server = by_path[reconciler.SOURCE_PATH]
    return (
        reconciler.SourceAttestation(
            revision=revision,
            archive_sha256=_sha256(archive),
            tree_sha256=_sha256(_canonical(tree)),
            server_sha256=server.digest,
            file_count=len(files),
        ),
        files,
    )


def _tar(entries: tuple[ContextEntry, ...]) -> bytes:
    seen: set[str] = set()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for entry in entries:
            path = PurePosixPath(entry.path)
            if (
                not entry.path
                or path.is_absolute()
                or ".." in path.parts
                or path.as_posix() != entry.path
                or entry.path in seen
            ):
                raise ContextBuildError("container context path is unsafe or duplicated")
            seen.add(entry.path)
            info = tarfile.TarInfo(entry.path)
            info.size = len(entry.payload)
            info.mode = entry.mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            archive.addfile(info, io.BytesIO(entry.payload))
    payload = buffer.getvalue()
    if len(payload) > MAX_CONTEXT_BYTES:
        raise ContextBuildError("container context exceeds the fixed byte bound")
    return payload


def build_context(
    runner: reconciler.Runner,
    repository: Path,
    public_key_path: Path,
) -> tuple[bytes, reconciler.SourceAttestation, dict[str, str]]:
    source, files = _release_source(runner, repository)
    public_key, public_key_sha256 = reconciler.load_public_key(public_key_path)
    public_key_file_sha256 = _sha256(public_key)
    by_path = {item.relative: item for item in files}
    release_template = {
        "schemaVersion": "1.0",
        "repositoryRevision": source.revision,
        "repositoryArchiveSha256": source.archive_sha256,
        "repositoryManifestSha256": source.tree_sha256,
        "serverSha256": source.server_sha256,
        "receiptPublicKeyFileSha256": public_key_file_sha256,
        "receiptPublicKeySha256": public_key_sha256,
    }
    entries: list[ContextEntry] = [
        ContextEntry(
            f"repository/{item.relative}",
            _read_tracked(item),
            item.mode,
        )
        for item in files
    ]
    for source_path, context_path in REQUIRED_SOURCES.items():
        entries.append(
            ContextEntry(
                context_path,
                _read_tracked(by_path[source_path]),
                0o444,
            )
        )
    entries.extend(
        (
            ContextEntry("receipt-ed25519.pub", public_key, 0o444),
            ContextEntry("release-template.json", _canonical(release_template), 0o444),
        )
    )
    entries.sort(key=lambda item: item.path)
    context = _tar(tuple(entries))
    return (
        context,
        source,
        {
            "receiptPublicKeyFileSha256": public_key_file_sha256,
            "receiptPublicKeySha256": public_key_sha256,
        },
    )


def _safe_output(output: Path, repository: Path) -> Path:
    if not output.is_absolute():
        raise ContextBuildError("output path must be absolute")
    try:
        parent = output.parent.resolve(strict=True)
        repository_root = repository.resolve(strict=True)
    except OSError as exc:
        raise ContextBuildError("output parent or repository is unavailable") from exc
    resolved = parent / output.name
    try:
        inside_repository = resolved == repository_root or repository_root in resolved.parents
    except RuntimeError as exc:  # pragma: no cover - pathological path depth
        raise ContextBuildError("output path is invalid") from exc
    if (
        OUTPUT_NAME.fullmatch(output.name) is None
        or output.parent.is_symlink()
        or parent != output.parent
        or not parent.is_dir()
        or inside_repository
        or resolved.exists()
        or resolved.is_symlink()
    ):
        raise ContextBuildError(
            "output must be a new regular file outside the release repository"
        )
    return resolved


def _write_new(output: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(output, flags, 0o444)
    except OSError as exc:
        raise ContextBuildError("output could not be created safely") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(output, 0o444)
    except OSError as exc:
        with contextlib.suppress(OSError):
            output.unlink(missing_ok=True)
        raise ContextBuildError("output write did not complete safely") from exc


def build(
    runner: reconciler.Runner,
    *,
    repository: Path,
    public_key_path: Path,
    output: Path,
    apply: bool = False,
) -> ContextReport:
    safe_output = _safe_output(output, repository)
    context, source, trust = build_context(runner, repository, public_key_path)
    if apply:
        _write_new(safe_output, context)
    with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
        entry_count = len(archive.getmembers())
    return ContextReport(
        applied=apply,
        context_sha256=_sha256(context),
        context_bytes=len(context),
        entry_count=entry_count,
        output=str(safe_output),
        repository_revision=source.revision,
        repository_archive_sha256=source.archive_sha256,
        repository_manifest_sha256=source.tree_sha256,
        server_sha256=source.server_sha256,
        receipt_public_key_sha256=trust["receiptPublicKeySha256"],
        receipt_public_key_file_sha256=trust["receiptPublicKeyFileSha256"],
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a deterministic public-only Tester CI container context."
    )
    parser.add_argument("--apply", action="store_true", help="create the context archive")
    parser.add_argument("--confirm", help="exact apply confirmation")
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--receipt-public-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.apply:
            if args.confirm != CONFIRMATION:
                raise ContextBuildError("apply requires the exact confirmation")
        elif args.confirm is not None:
            raise ContextBuildError("check mode does not accept apply confirmation")
        report = build(
            reconciler.SubprocessRunner(),
            repository=args.repository,
            public_key_path=args.receipt_public_key,
            output=args.output,
            apply=args.apply,
        )
    except (
        ContextBuildError,
        reconciler.ReconcileError,
        OSError,
        RuntimeError,
        tarfile.TarError,
        UnicodeError,
        ValueError,
    ) as exc:
        print(f"error: Tester CI context build failed safely: {exc}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "applied": report.applied,
                "contextBytes": report.context_bytes,
                "contextSha256": report.context_sha256,
                "entryCount": report.entry_count,
                "output": report.output,
                "privateKeyIncluded": False,
                "receiptPublicKeyFileSha256": report.receipt_public_key_file_sha256,
                "receiptPublicKeySha256": report.receipt_public_key_sha256,
                "repositoryArchiveSha256": report.repository_archive_sha256,
                "repositoryManifestSha256": report.repository_manifest_sha256,
                "repositoryRevision": report.repository_revision,
                "serverSha256": report.server_sha256,
                "source": "clean-git-index",
                "verified": True,
                "wroteOutput": report.applied,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import io
import json
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import pytest

import scripts.build_finals_submission as finals
from scripts.build_agentteams_package import canonical_zip_bytes
from scripts.build_finals_submission import (
    FinalsBuildError,
    GitObject,
    build_submission,
    verify_submission_bytes,
)


class SafePdfExtractor:
    def extract(self, data: bytes) -> str:
        return "DevFlow GOAI finals presentation"


def test_current_finals_allowlist_passes_the_release_content_scanner() -> None:
    """Keep high-confidence scanning enabled across the real release surface."""

    root = Path(__file__).resolve().parents[1]
    required = set(finals.REQUIRED_EXACT)
    selected: list[tuple[str, Path]] = []
    for candidate in root.rglob("*"):
        if not candidate.is_file() or candidate.is_symlink():
            continue
        relative = candidate.relative_to(root).as_posix()
        if finals._source_allowed(relative) or relative in required:
            selected.append((relative, candidate))

    assert required <= {relative for relative, _ in selected}
    extractor = finals.PypdfPdfTextExtractor()
    for relative, candidate in selected:
        finals._scan_source(relative, candidate.read_bytes(), extractor)


@dataclass
class FakeGit:
    files: dict[str, bytes]
    status: bytes = b""
    head: str = "a" * 40
    resolved: str = "a" * 40
    extra_objects: tuple[GitObject, ...] = ()

    def __post_init__(self) -> None:
        self.read_oids: list[str] = []
        self._blobs = {
            self._oid(index): content
            for index, (_, content) in enumerate(sorted(self.files.items()), start=1)
        }
        self._objects = (
            tuple(
                GitObject(path, "100644", "blob", self._oid(index))
                for index, (path, _) in enumerate(sorted(self.files.items()), start=1)
            )
            + self.extra_objects
        )

    @staticmethod
    def _oid(index: int) -> str:
        return f"{index:040x}"

    def status_porcelain(self, root: Path) -> bytes:
        return self.status

    def head_commit(self, root: Path) -> str:
        return self.head

    def resolve_commit(self, root: Path, ref: str) -> str:
        return self.resolved

    def tree_objects(self, root: Path, commit: str) -> tuple[GitObject, ...]:
        return self._objects

    def read_blob(self, root: Path, oid: str) -> bytes:
        self.read_oids.append(oid)
        return self._blobs[oid]


def _pptx() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<presentation>DevFlow finals</presentation>")
        relationships = "http://schemas.openxmlformats.org/package/2006/relationships"
        office = (
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
        )
        for number in range(1, 13):
            archive.writestr(
                f"ppt/slides/slide{number}.xml",
                f"<slide><text>Slide {number}</text></slide>",
            )
            archive.writestr(
                f"ppt/notesSlides/notesSlide{number}.xml",
                f"<notes><text>[Sources] fixture {number}</text></notes>",
            )
            archive.writestr(
                f"ppt/slides/_rels/slide{number}.xml.rels",
                f'<Relationships xmlns="{relationships}">'
                f'<Relationship Id="rId1" Type="{office}notesSlide" '
                f'Target="../notesSlides/notesSlide{number}.xml"/>'
                "</Relationships>",
            )
            archive.writestr(
                f"ppt/notesSlides/_rels/notesSlide{number}.xml.rels",
                f'<Relationships xmlns="{relationships}">'
                f'<Relationship Id="rId1" Type="{office}slide" '
                f'Target="../slides/slide{number}.xml"/>'
                "</Relationships>",
            )
        archive.writestr(
            "_rels/.rels",
            f'<Relationships xmlns="{relationships}">'
            f'<Relationship Id="rId1" Type="{office}officeDocument" '
            'Target="ppt/presentation.xml"/>'
            "</Relationships>",
        )
        slide_relationships = "".join(
            f'<Relationship Id="rId{number}" Type="{office}slide" '
            f'Target="slides/slide{number}.xml"/>'
            for number in range(1, 13)
        )
        archive.writestr(
            "ppt/_rels/presentation.xml.rels",
            f'<Relationships xmlns="{relationships}">{slide_relationships}</Relationships>',
        )
    return output.getvalue()


def _pdf() -> bytes:
    from pypdf import PdfWriter

    writer = PdfWriter()
    for _ in range(12):
        writer.add_blank_page(width=100, height=100)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _lock(profile: str, packages: list[tuple[str, str, str]]) -> bytes:
    extras = "--extra mcp"
    if profile in {"dev", "rag"}:
        extras += " --extra rag"
    if profile == "dev":
        extras = "--extra dev " + extras
    lines = [
        "# This file was autogenerated by uv via the following command:",
        f"#    uv pip compile pyproject.toml {extras} --universal --python-version 3.10 "
        "--generate-hashes",
    ]
    for name, version, marker in packages:
        marker_text = f" ; {marker}" if marker else ""
        digest = finals._sha256(f"{name}=={version}".encode())
        lines.extend(
            [
                f"{name}=={version}{marker_text} \\",
                f"    --hash=sha256:{digest}",
                "    # via fixture",
            ]
        )
    return ("\n".join(lines) + "\n").encode()


def _fixture_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in finals.REQUIRED_EXACT:
        if path.endswith(".pdf"):
            content = _pdf()
        elif path.endswith(".pptx"):
            content = _pptx()
        elif path.endswith(".json"):
            content = b"{}\n"
        elif path == "pyproject.toml":
            content = (
                b'[project]\nname = "devflow"\nversion = "2.0.0rc1"\n'
                b'dependencies = ["httpx>=0.27.0", "pyyaml>=6.0"]\n'
                b"[project.optional-dependencies]\n"
                b'dev = ["pytest>=8.0.0"]\n'
                b'mcp = ["mcp>=1.2.0"]\n'
                b'rag = ["chromadb>=0.5.0"]\n'
            )
        elif path == "benchmarks/repository_repair/tasks.yaml":
            content = b"""
repositories:
  requests:
    display_name: psf/requests
    version: 2.32.3
    url: https://github.com/psf/requests.git
    commit: 0e322af87745eff34caffe4df68456ebc20d9068
    license:
      spdx: Apache-2.0
      source_url: https://github.com/psf/requests/blob/0e322af87745eff34caffe4df68456ebc20d9068/LICENSE
  flask:
    display_name: pallets/flask
    version: 3.1.1
    url: https://github.com/pallets/flask.git
    commit: 7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1
    license:
      spdx: BSD-3-Clause
      source_url: https://github.com/pallets/flask/blob/7fff56f5172c48b6f3aedf17ee14ef5c2533dfd1/LICENSE.txt
  pydantic:
    display_name: pydantic/pydantic
    version: 2.11.7
    url: https://github.com/pydantic/pydantic.git
    commit: 5f033e46c54fea1b59b6894d6527daf49475e690
    license:
      spdx: MIT
      source_url: https://github.com/pydantic/pydantic/blob/5f033e46c54fea1b59b6894d6527daf49475e690/LICENSE
"""
        elif path == "agentteams/upstream.lock.yaml":
            content = b"""
schema_version: "1.0"
project: AgentTeams
repository: https://github.com/agentscope-ai/AgentTeams.git
release_tag: v1.2.0-beta.1
commit: 78d0ceda336befa6e62bf89fc1a6b08b965e128d
release_url: https://github.com/agentscope-ai/AgentTeams/releases/tag/v1.2.0-beta.1
license:
  spdx: Apache-2.0
  source_path: LICENSE
  source_url: https://raw.githubusercontent.com/agentscope-ai/AgentTeams/v1.2.0-beta.1/LICENSE
  utf8_bytes: 10770
  sha256: d27b69cf7cd0a9fc3f4a04b1ee44e43ab4ebf517d85a1ea197f9ee96826196c7
team_crd:
  api_version: agentteams.io/v1beta1
  source_path: hiclaw-controller/config/crd/teams.agentteams.io.yaml
  source_url: https://raw.githubusercontent.com/agentscope-ai/AgentTeams/v1.2.0-beta.1/hiclaw-controller/config/crd/teams.agentteams.io.yaml
  sha256: 153859173674e5b64987cc4e203eaf5f9e31322b33a27ee50fb2f0007f70fae6
  bytes: 27309
devflow_manifest:
  path: agentteams/team.yaml
  schema_mode: deprecated-inline-leader-workers
  compatibility_patch: scripts/patch_agentteams_beta.sh
  live_evidence: docs/evidence/AGENTTEAMS_LIVE_20260727.md
compatibility:
  supported: exact-pinned-release-only
  current_main: AgentTeams main uses Team spec.workerMembers and requires separate migration.
verified_at: "2026-07-28"
"""
        elif path == "agentteams/team.yaml":
            content = b"""
apiVersion: agentteams.io/v1beta1
kind: Team
metadata:
  name: devflow
spec:
  leader: {name: devflow-lead}
  workers: [{name: devflow-triage}]
"""
        else:
            content = f"# {path}\nDevFlow sanitized finals material.\n".encode()
        files[path] = content
    production_lock = _lock(
        "production",
        [
            ("httpx", "0.28.1", ""),
            ("mcp", "1.28.1", ""),
            ("pyyaml", "6.0.3", ""),
        ],
    )
    rag_lock = _lock(
        "rag",
        [
            ("chromadb", "1.5.9", ""),
            ("httpx", "0.28.1", ""),
            ("mcp", "2.0.0", ""),
            ("pyyaml", "6.0.3", ""),
        ],
    )
    dev_lock = _lock(
        "dev",
        [
            ("chromadb", "1.5.9", ""),
            ("httpx", "0.28.1", ""),
            ("mcp", "2.0.0", ""),
            ("pytest", "9.0.2", ""),
            ("pyyaml", "6.0.3", ""),
        ],
    )
    files["requirements/dev.lock.txt"] = dev_lock
    files["requirements/production.lock.txt"] = production_lock
    files["requirements/rag.lock.txt"] = rag_lock
    license_packages = []
    for package, version in sorted(
        {
            ("httpx", "0.28.1"),
            ("mcp", "1.28.1"),
            ("mcp", "2.0.0"),
            ("pyyaml", "6.0.3"),
            ("chromadb", "1.5.9"),
            ("pytest", "9.0.2"),
        }
    ):
        license_packages.append(
            {
                "license_expression": "NOASSERTION",
                "metadata_source": f"https://pypi.org/pypi/{package}/{version}/json",
                "package": package,
                "source_url": f"https://pypi.org/project/{package}/{version}/",
                "verify_status": "noassertion-test-fixture",
                "version": version,
            }
        )
    files["requirements/licenses.yaml"] = finals._canonical_json(
        {
            "locks": {
                "dev": {
                    "packages": 5,
                    "path": "requirements/dev.lock.txt",
                    "sha256": finals._sha256(dev_lock),
                },
                "production": {
                    "packages": 3,
                    "path": "requirements/production.lock.txt",
                    "sha256": finals._sha256(production_lock),
                },
                "rag": {
                    "packages": 4,
                    "path": "requirements/rag.lock.txt",
                    "sha256": finals._sha256(rag_lock),
                },
            },
            "packages": license_packages,
            "schema_version": "1.0",
        }
    )
    files.update(
        {
            "src/devflow/__init__.py": b'__version__ = "2.0.0rc1"\n',
            "skills/demo/SKILL.md": b"# Demo\n",
            "tests/test_demo.py": b"def test_demo():\n    assert True\n",
            "scripts/tool.py": b"VALUE = 1\n",
            "scripts/not-allowlisted.mjs": b"throw new Error('excluded');\n",
            "agentteams/worker-package/config/AGENTS.md": b"# Agent\n",
            "scripts/patch_agentteams_beta.sh": b"#!/bin/sh\nset -eu\n",
            "docs/evidence/AGENTTEAMS_LIVE_20260727.md": b"# Sanitized live evidence\n",
            "benchmarks/repository_boundary/cases.yaml": b"cases: []\n",
            "docs/finals/EXTRA.md": b"# Additional finals evidence\n",
            "docs/finals/assets/not-allowlisted.pptx": _pptx(),
        }
    )
    return files


def _repo(tmp_path: Path) -> tuple[Path, FakeGit]:
    root = tmp_path / "repo"
    root.mkdir(parents=True)
    (root / "out").mkdir()
    files = _fixture_files()
    # Worktree bytes are deliberately unrelated: builds must use FakeGit blobs.
    (root / "README.md").write_text("WORKTREE MUST NOT BE PACKAGED\n", encoding="utf-8")
    return root, FakeGit(files)


def _entries(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
        return {item.filename: archive.read(item) for item in archive.infolist()}


def _build(root: Path, git: FakeGit, name: str = "finals.zip", video: Path | None = None) -> bytes:
    result = build_submission(
        repo_root=root,
        output=Path("out") / name,
        ref="v2.0.0-rc.1",
        demo_video=video,
        _git=git,
        _pdf_extractor=SafePdfExtractor(),
    )
    assert result.commit == "a" * 40
    return result.output.read_bytes()


def test_build_is_deterministic_and_reads_only_git_objects(tmp_path: Path) -> None:
    first_root, first_git = _repo(tmp_path / "first")
    second_root, second_git = _repo(tmp_path / "second")

    first = _build(first_root, first_git)
    second = _build(second_root, second_git)

    assert first == second
    entries = _entries(first)
    assert entries["README.md"] == first_git.files["README.md"]
    assert b"WORKTREE MUST NOT BE PACKAGED" not in first
    assert first_git.read_oids
    context = verify_submission_bytes(first, _pdf_extractor=SafePdfExtractor())
    assert context == finals.ReleaseContext(
        project="DevFlow",
        version="2.0.0rc1",
        commit="a" * 40,
        ref="v2.0.0-rc.1",
    )


def test_package_contains_exact_generated_integrity_and_supply_chain_records(
    tmp_path: Path,
) -> None:
    root, git = _repo(tmp_path)
    entries = _entries(_build(root, git))

    assert {
        finals.MANIFEST_NAME,
        finals.SUMS_NAME,
        finals.PROVENANCE_NAME,
        finals.SBOM_NAME,
        finals.LICENSES_NAME,
    } <= set(entries)
    assert finals.VIDEO_INDEX_NAME not in entries
    assert not any(path.endswith(".zip") for path in entries)
    assert "scripts/author_finals_deck.mjs" in entries
    assert "scripts/not-allowlisted.mjs" not in entries
    assert "docs/finals/assets/DevFlow_GOAI_2026_finals_template_source.pptx" in entries
    assert "docs/finals/assets/not-allowlisted.pptx" not in entries
    sbom = json.loads(entries[finals.SBOM_NAME])
    refs = {component["bom-ref"] for component in sbom["components"]}
    assert "pkg:pypi/httpx@0.28.1" in refs
    assert "pkg:pypi/mcp@1.28.1" in refs
    assert "pkg:pypi/mcp@2.0.0" in refs
    assert "pkg:pypi/pytest@9.0.2" in refs
    assert "pkg:github/psf/requests@0e322af87745eff34caffe4df68456ebc20d9068" in refs
    assert "pkg:github/agentscope-ai/AgentTeams@78d0ceda336befa6e62bf89fc1a6b08b965e128d" in refs
    httpx = next(component for component in sbom["components"] if component["name"] == "httpx")
    expected_httpx_hash = finals._sha256(b"httpx==0.28.1")
    assert httpx["version"] == "0.28.1"
    assert httpx["hashes"] == [{"alg": "SHA-256", "content": expected_httpx_hash}]
    sbom_properties = {item["name"]: item["value"] for item in sbom["metadata"]["properties"]}
    assert sbom_properties["devflow:dependency-lock:production"] == finals._sha256(
        entries["requirements/production.lock.txt"]
    )
    assert sbom_properties["devflow:dependency-lock:rag"] == finals._sha256(
        entries["requirements/rag.lock.txt"]
    )
    licenses = json.loads(entries[finals.LICENSES_NAME])
    assert licenses["dependency_locks"]["production"]["sha256"] == finals._sha256(
        entries["requirements/production.lock.txt"]
    )
    request_license = next(
        item for item in licenses["third_party"] if item["component"] == "psf/requests"
    )
    assert request_license["license"] == "Apache-2.0"
    provenance = json.loads(entries[finals.PROVENANCE_NAME])
    assert provenance["predicate"]["dependencyLocks"]["rag"]["sha256"] == finals._sha256(
        entries["requirements/rag.lock.txt"]
    )


def test_optional_demo_video_is_hash_only_and_never_embedded(tmp_path: Path) -> None:
    root, git = _repo(tmp_path)
    video = tmp_path / "final-demo.mp4"
    video.write_bytes(b"video bytes that must stay external")

    entries = _entries(_build(root, git, video=video))
    index = json.loads(entries[finals.VIDEO_INDEX_NAME])

    assert index == {
        "embedded": False,
        "files": [
            {
                "bytes": video.stat().st_size,
                "path": "final-demo.mp4",
                "sha256": finals._sha256(video.read_bytes()),
            }
        ],
        "schema_version": "1.0",
    }
    assert video.read_bytes() not in entries.values()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", b" M README.md\0", "working tree must be clean"),
        ("resolved", "b" * 40, "does not resolve to the clean HEAD"),
    ],
)
def test_build_rejects_dirty_or_wrong_ref(
    tmp_path: Path, field: str, value: bytes | str, message: str
) -> None:
    root, git = _repo(tmp_path)
    setattr(git, field, value)

    with pytest.raises(FinalsBuildError, match=message):
        _build(root, git)


@pytest.mark.parametrize(
    "forbidden",
    [
        GitObject("ignored-link", "120000", "blob", "f" * 40),
        GitObject("vendor/subproject", "160000", "commit", "f" * 40),
    ],
)
def test_build_rejects_symlink_or_submodule_anywhere(tmp_path: Path, forbidden: GitObject) -> None:
    root, _ = _repo(tmp_path)
    git = FakeGit(_fixture_files(), extra_objects=(forbidden,))

    with pytest.raises(FinalsBuildError, match="symlinks|submodules"):
        _build(root, git)


def test_missing_required_agentteams_upstream_lock_is_rejected(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path)
    files = _fixture_files()
    del files["agentteams/upstream.lock.yaml"]
    git = FakeGit(files)

    with pytest.raises(FinalsBuildError, match="required finals allowlist"):
        _build(root, git)


def test_dependency_license_coverage_must_be_exact(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path)
    files = _fixture_files()
    evidence = json.loads(files["requirements/licenses.yaml"])
    evidence["packages"].pop()
    files["requirements/licenses.yaml"] = finals._canonical_json(evidence)
    git = FakeGit(files)

    with pytest.raises(FinalsBuildError, match="exactly cover both locks"):
        _build(root, git)


def test_dependency_license_duplicate_is_rejected(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path)
    files = _fixture_files()
    evidence = json.loads(files["requirements/licenses.yaml"])
    evidence["packages"].append(dict(evidence["packages"][0]))
    files["requirements/licenses.yaml"] = finals._canonical_json(evidence)
    git = FakeGit(files)

    with pytest.raises(FinalsBuildError, match="repeats a package/version"):
        _build(root, git)


def test_dependency_lock_without_hash_is_rejected(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path)
    files = _fixture_files()
    files["requirements/production.lock.txt"] = re.sub(
        rb"\n    --hash=sha256:[0-9a-f]{64}",
        b"",
        files["requirements/production.lock.txt"],
        count=1,
    )
    git = FakeGit(files)

    with pytest.raises(FinalsBuildError, match="missing or duplicate distribution hashes"):
        _build(root, git)


def test_dependency_license_lock_digest_mismatch_is_rejected(tmp_path: Path) -> None:
    root, _ = _repo(tmp_path)
    files = _fixture_files()
    evidence = json.loads(files["requirements/licenses.yaml"])
    evidence["locks"]["production"]["sha256"] = "f" * 64
    files["requirements/licenses.yaml"] = finals._canonical_json(evidence)
    git = FakeGit(files)

    with pytest.raises(FinalsBuildError, match="lock binding is invalid"):
        _build(root, git)


def test_manifest_tamper_is_detected(tmp_path: Path) -> None:
    root, git = _repo(tmp_path)
    entries = _entries(_build(root, git))
    entries["README.md"] = b"tampered\n"
    tampered = canonical_zip_bytes(entries, finals.FIXED_SOURCE_DATE_EPOCH)

    with pytest.raises(FinalsBuildError, match="manifest record"):
        verify_submission_bytes(tampered, _pdf_extractor=SafePdfExtractor())


def test_sbom_tamper_with_recomputed_outer_integrity_is_detected(tmp_path: Path) -> None:
    root, git = _repo(tmp_path)
    entries = _entries(_build(root, git))
    sbom = json.loads(entries[finals.SBOM_NAME])
    sbom["components"] = []
    entries[finals.SBOM_NAME] = finals._canonical_json(sbom)
    payload = {
        path: data
        for path, data in entries.items()
        if path not in {finals.MANIFEST_NAME, finals.SUMS_NAME}
    }
    entries[finals.MANIFEST_NAME] = finals._manifest(payload)
    entries[finals.SUMS_NAME] = finals._sums(
        {**payload, finals.MANIFEST_NAME: entries[finals.MANIFEST_NAME]}
    )
    tampered = canonical_zip_bytes(entries, finals.FIXED_SOURCE_DATE_EPOCH)

    with pytest.raises(FinalsBuildError, match="provenance supply-chain|do not match committed"):
        verify_submission_bytes(tampered, _pdf_extractor=SafePdfExtractor())


def test_existing_output_is_never_overwritten(tmp_path: Path) -> None:
    root, git = _repo(tmp_path)
    target = root / "out/finals.zip"
    target.write_bytes(b"keep")

    with pytest.raises(FinalsBuildError, match="overwrite is forbidden"):
        _build(root, git)

    assert target.read_bytes() == b"keep"


@pytest.mark.skipif(shutil.which("git") is None, reason="Git is required for plumbing test")
def test_real_git_plumbing_ignores_assume_unchanged_worktree_bytes(tmp_path: Path) -> None:
    root = tmp_path / "real-repo"
    root.mkdir()
    for path, content in _fixture_files().items():
        target = root / Path(*PurePosixPath(path).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    def git(*arguments: str) -> bytes:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
        )
        return completed.stdout

    git("init", "-q")
    git("config", "user.name", "DevFlow Test")
    git("config", "user.email", "devflow-test@example.invalid")
    git("add", ".")
    git("commit", "-qm", "fixture")
    git("tag", "v2.0.0-rc.1")
    git("update-index", "--assume-unchanged", "README.md")
    (root / "README.md").write_text("UNTRUSTED WORKTREE BYTES\n", encoding="utf-8")
    assert git("status", "--porcelain=v1") == b""

    result = build_submission(
        repo_root=root,
        output=tmp_path / "real-finals.zip",
        ref="v2.0.0-rc.1",
        _pdf_extractor=SafePdfExtractor(),
    )

    entries = _entries(result.output.read_bytes())
    assert entries["README.md"] == _fixture_files()["README.md"]
    assert b"UNTRUSTED WORKTREE BYTES" not in result.output.read_bytes()

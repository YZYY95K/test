from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path

import pytest

import scripts.build_prelim_submission as submission
from scripts.build_agentteams_package import canonical_zip_bytes
from scripts.build_prelim_submission import (
    BuildResult,
    SubmissionBuildError,
    build_submission,
    verify_submission_bytes,
)


@dataclass
class FakeGit:
    tracked: frozenset[str]
    status: bytes = b""
    head: str = "a" * 40
    target: str = "a" * 40

    def status_porcelain(self, root: Path) -> bytes:
        return self.status

    def head_commit(self, root: Path) -> str:
        return self.head

    def tag_commit(self, root: Path, tag: str) -> str:
        return self.target

    def tracked_files(self, root: Path) -> frozenset[str]:
        return self.tracked


class SafePdfExtractor:
    def extract(self, data: bytes) -> str:
        return "DevFlow preliminary submission"


def _write(path: Path, data: str | bytes = "fixture\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)


def _pptx() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<presentation>DevFlow</presentation>")
    return output.getvalue()


def _fixture_repo(tmp_path: Path) -> tuple[Path, FakeGit]:
    root = tmp_path / "repo"
    root.mkdir()
    for name in submission.SOURCE_REQUIRED_EXACT:
        content = "fixture\n"
        if name == "pyproject.toml":
            content = '[project]\nname = "devflow"\nversion = "1.3.0"\n'
        elif name.endswith(".json"):
            content = "{}\n"
        _write(root / Path(*Path(name).parts), content)

    required_sections = {
        "src/devflow/__init__.py": "__version__ = '1.3.0'\n",
        "skills/demo/SKILL.md": "# Demo Skill\n",
        "config/agents.yaml": "agents: []\n",
        "agentteams/team.yaml": "apiVersion: agentteams.io/v1beta1\n",
        "scripts/tool.py": "VALUE = 1\n",
        "tests/test_demo.py": "def test_demo():\n    assert True\n",
        "evals/demo/cases.yaml": "cases: []\n",
        "benchmarks/demo/cases.yaml": "cases: []\n",
    }
    for name, content in required_sections.items():
        _write(root / Path(*Path(name).parts), content)

    outer_text_sources = {
        source
        for source, _, kind in submission.OUTER_INPUTS
        if kind == "text"
    }
    for name in outer_text_sources:
        _write(root / Path(*Path(name).parts), "# DevFlow\n\nSanitized submission material.\n")
    _write(
        root / "outputs/DevFlow_GOAI_2026_初赛方案_20260728.pdf",
        b"%PDF-1.4\n%%EOF\n",
    )
    _write(root / "outputs/DevFlow_GOAI_2026_初赛方案_20260728.pptx", _pptx())

    # These files prove the builder selects exact 20260728 inputs rather than outputs/**.
    _write(root / "outputs/DevFlow_GOAI_2026_初赛方案_20260727.pdf", b"old")
    _write(root / "outputs/DevFlow_GOAI_2026_初赛方案_20260727.pptx", b"old")
    _write(root / "outputs/GOAI_2026_AgentInfra_DevFlow_初赛提交包_20260725.zip", b"old")
    _write(root / "outputs/old.inspect.ndjson", "{}\n")
    _write(root / "outputs/.pdf-qa-20260727/page-01.png", b"qa")
    _write(root / ".devflow/private-run.txt", "excluded\n")
    _write(root / "dist/old-source.tgz", b"excluded")
    _write(root / "agentteams/systemd/local.service", "excluded\n")

    tracked = frozenset(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
    )
    return root, FakeGit(tracked=tracked)


def _build(root: Path, git: FakeGit, name: str = "submission.zip") -> BuildResult:
    return build_submission(
        repo_root=root,
        output=Path("outputs") / name,
        tag="v1.3.0",
        _git=git,
        _pdf_extractor=SafePdfExtractor(),
    )


def _entries(data: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
        return {info.filename: archive.read(info) for info in archive.infolist()}


def test_build_is_deterministic_and_both_manifest_layers_verify(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    first = _build(root, git, "first.zip")
    second = _build(root, git, "second.zip")

    first_data = first.output.read_bytes()
    assert first_data == second.output.read_bytes()
    context = verify_submission_bytes(first_data, _pdf_extractor=SafePdfExtractor())
    assert context == submission.ManifestContext(
        project="DevFlow",
        version="1.3.0",
        commit="a" * 40,
        tag="v1.3.0",
    )

    outer = _entries(first_data)
    assert set(outer) == submission.EXPECTED_OUTER_PAYLOAD | {
        submission.OUTER_MANIFEST_NAME,
        submission.OUTER_SUMS_NAME,
    }
    records = json.loads(outer[submission.OUTER_MANIFEST_NAME])
    assert all(set(record) == submission.MANIFEST_KEYS for record in records)
    assert [record["path"] for record in records] == sorted(
        submission.EXPECTED_OUTER_PAYLOAD,
        key=lambda value: value.encode("utf-8"),
    )

    source = _entries(outer[submission.SOURCE_ARCHIVE_NAME])
    assert submission.SOURCE_MANIFEST_NAME in source
    assert submission.SOURCE_SUMS_NAME in source
    assert "NOTICE" in source
    assert "docs/evidence/LOCAL_RELEASE_CANDIDATE_20260728.md" in source
    assert "examples/prelim_sample/sample_input.json" in source
    assert "examples/prelim_sample/actual_output.json" in source


def test_only_exact_current_assets_are_selected(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    result = _build(root, git)
    outer = _entries(result.output.read_bytes())
    source = _entries(outer[submission.SOURCE_ARCHIVE_NAME])

    flattened = "\n".join((*outer, *source))
    assert "20260725" not in flattened
    assert ".inspect.ndjson" not in flattened
    assert ".pdf-qa" not in flattened
    assert ".devflow" not in flattened
    assert "dist/" not in flattened
    assert "agentteams/systemd" not in flattened


def test_20260728_assets_are_the_only_outer_presentation_inputs() -> None:
    presentation_sources = {
        source
        for source, _, kind in submission.OUTER_INPUTS
        if kind in {"pdf", "pptx"}
    }

    assert presentation_sources == {
        "outputs/DevFlow_GOAI_2026_初赛方案_20260728.pdf",
        "outputs/DevFlow_GOAI_2026_初赛方案_20260728.pptx",
    }


def test_local_release_candidate_evidence_is_required(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    evidence = "docs/evidence/LOCAL_RELEASE_CANDIDATE_20260728.md"
    (root / evidence).unlink()
    git.tracked = frozenset(path for path in git.tracked if path != evidence)

    with pytest.raises(SubmissionBuildError, match="required source allowlist"):
        _build(root, git)


@pytest.mark.parametrize("name", sorted(submission.SOURCE_RUNTIME_REQUIRED))
def test_runtime_entrypoints_are_exact_required_files(tmp_path: Path, name: str) -> None:
    root, git = _fixture_repo(tmp_path)
    (root / Path(*Path(name).parts)).unlink()
    git.tracked = frozenset(path for path in git.tracked if path != name)

    with pytest.raises(SubmissionBuildError, match="required source allowlist"):
        _build(root, git)


def test_new_agentteams_entrypoints_are_exact_required_and_release_scan_clean() -> None:
    required = {
        "scripts/reconcile_agentteams_controller_cache.py",
        "scripts/run_agentteams_github_success_path.py",
    }
    assert required <= submission.SOURCE_RUNTIME_REQUIRED

    root = Path(__file__).resolve().parents[1]
    for name in sorted(required | {"tests/test_agentteams_github_success_path.py"}):
        submission._scan_utf8((root / name).read_bytes(), f"source file {name}")


def test_dirty_tree_is_rejected_without_creating_output(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    git.status = b"dirty\0"

    with pytest.raises(SubmissionBuildError, match="clean"):
        _build(root, git)
    assert not (root / "outputs/submission.zip").exists()


def test_tag_must_resolve_to_head_and_be_safe(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    git.target = "b" * 40
    with pytest.raises(SubmissionBuildError, match="tag"):
        _build(root, git)

    with pytest.raises(SubmissionBuildError, match="tag"):
        build_submission(
            repo_root=root,
            output=Path("outputs/submission.zip"),
            tag="../unsafe",
            _git=git,
            _pdf_extractor=SafePdfExtractor(),
        )


def test_untracked_outer_input_is_rejected(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    missing = "outputs/DevFlow_GOAI_2026_初赛方案_20260728.pdf"
    git.tracked = frozenset(git.tracked - {missing})

    with pytest.raises(SubmissionBuildError, match="not tracked"):
        _build(root, git)


@pytest.mark.parametrize(
    "names",
    [
        ("../escape.txt",),
        ("/absolute.txt",),
        ("folder\\child.txt",),
        ("folder//child.txt",),
        ("C:/local.txt",),
    ],
)
def test_archive_path_escape_and_aliases_are_rejected(names: tuple[str, ...]) -> None:
    with pytest.raises(SubmissionBuildError, match="path"):
        submission._validate_archive_names(names)


@pytest.mark.parametrize(
    "names",
    [
        ("same.txt", "same.txt"),
        ("Folder/a.txt", "folder/A.txt"),
        ("caf\N{LATIN SMALL LETTER E WITH ACUTE}.txt", "cafe\N{COMBINING ACUTE ACCENT}.txt"),
    ],
)
def test_duplicate_casefold_and_nfc_conflicts_are_rejected(names: tuple[str, ...]) -> None:
    with pytest.raises(SubmissionBuildError, match="duplicate|canonical"):
        submission._validate_archive_names(names)


def test_symlinked_allowlisted_file_is_rejected(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    target = root / "outside.py"
    _write(target, "VALUE = 2\n")
    link = root / "src/devflow/link.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    git.tracked = frozenset({*git.tracked, "src/devflow/link.py"})

    with pytest.raises(SubmissionBuildError, match="canonical regular file"):
        _build(root, git)


def test_secret_shaped_content_is_rejected_without_echoing_value() -> None:
    values = [
        "".join(("gh", "p_", "Ab9" * 12)),
        "".join(("sk", "-", "Az9_" * 8)),
        "Bearer " + ".".join(("Ab9_" * 3, "Cd8_" * 3, "Ef7_" * 3)),
        "api_key=" + "".join(("Ab9_", "Zy8-", "Xq7.", "Wm6+", "Tr5/", "Ku4=", "Pn3_")),
        "-----BEGIN " + "PRIVATE KEY-----",
    ]
    for value in values:
        with pytest.raises(SubmissionBuildError, match="prohibited secret-shaped") as caught:
            submission._scan_text(value, "fixture")
        assert value not in str(caught.value)


@pytest.mark.parametrize("field", ["api_key", "token", "secret", "password"])
def test_sensitive_32_hex_assignment_is_rejected_without_echoing_value(field: str) -> None:
    value = "".join(("ab12cd34",) * 4)
    text = f'"{field}": "{value}"'

    with pytest.raises(SubmissionBuildError, match="credential-assignment") as caught:
        submission._scan_text(text, "fixture")
    assert value not in str(caught.value)


def test_capability_and_matrix_room_literals_are_rejected_without_echoing_value() -> None:
    capability = "Aa0_" * 6 + "." + "Bb1_" * 10 + "Bb1"
    room_id = "!" + "audit-room-123" + ":" + "example.invalid"

    for value, text, rule in (
        (capability, f'"capability": "{capability}"', "capability-assignment"),
        (room_id, f'"room_id": "{room_id}"', "matrix-room-id"),
    ):
        with pytest.raises(SubmissionBuildError, match=rule) as caught:
            submission._scan_text(text, "fixture")
        assert value not in str(caught.value)


def test_hashes_commits_and_noncredential_opaque_ids_are_not_misclassified() -> None:
    sha256 = "a" * 64
    commit = "b" * 40
    pipeline_id = "".join(("c0ffee12",) * 4)

    submission._scan_text(
        f'"sha256":"{sha256}","commit":"{commit}","pipeline_id":"{pipeline_id}"',
        "fixture",
    )


def test_public_hosts_and_local_user_paths_are_rejected() -> None:
    public_address = ".".join(("8", "8", "8", "8"))
    local_path = "C:" + "\\" + "Users" + "\\" + "person" + "\\" + "file.txt"
    with pytest.raises(SubmissionBuildError, match="public IP"):
        submission._scan_text(public_address, "fixture")
    with pytest.raises(SubmissionBuildError, match="local absolute"):
        submission._scan_text(local_path, "fixture")

    submission._scan_text("127.0.0.1 and 10.0.0.1 are test-local", "fixture")


def test_payload_entry_file_and_total_limits_are_enforced() -> None:
    with pytest.raises(SubmissionBuildError, match="entry"):
        submission._check_payload_limits(
            {"a": b"1", "b": b"2"},
            label="fixture",
            max_entries=1,
            max_file_bytes=10,
            max_total_bytes=10,
        )
    with pytest.raises(SubmissionBuildError, match="file size"):
        submission._check_payload_limits(
            {"a": b"12"},
            label="fixture",
            max_entries=2,
            max_file_bytes=1,
            max_total_bytes=10,
        )
    with pytest.raises(SubmissionBuildError, match="total"):
        submission._check_payload_limits(
            {"a": b"12"},
            label="fixture",
            max_entries=2,
            max_file_bytes=10,
            max_total_bytes=1,
        )


def test_active_pptx_content_is_rejected() -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("ppt/presentation.xml", "<presentation/>")
        archive.writestr("ppt/vbaProject.bin", b"macro")
    with pytest.raises(SubmissionBuildError, match="active"):
        submission._scan_pptx(output.getvalue(), "fixture")


def test_tampered_payload_and_extra_outer_file_are_rejected(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    result = _build(root, git)
    entries = _entries(result.output.read_bytes())
    entries["01_作品简介_500字内.md"] += b"tampered"
    tampered = canonical_zip_bytes(entries, submission.FIXED_SOURCE_DATE_EPOCH)
    with pytest.raises(SubmissionBuildError, match="manifest"):
        verify_submission_bytes(tampered, _pdf_extractor=SafePdfExtractor())

    entries = _entries(result.output.read_bytes())
    entries["unexpected.txt"] = b"extra"
    extra = canonical_zip_bytes(entries, submission.FIXED_SOURCE_DATE_EPOCH)
    with pytest.raises(SubmissionBuildError, match="file set"):
        verify_submission_bytes(extra, _pdf_extractor=SafePdfExtractor())


def test_output_must_be_new_zip_directly_under_outputs(tmp_path: Path) -> None:
    root, git = _fixture_repo(tmp_path)
    existing = root / "outputs/existing.zip"
    _write(existing, b"existing")
    with pytest.raises(SubmissionBuildError, match="exists"):
        _build(root, git, "existing.zip")
    with pytest.raises(SubmissionBuildError, match="direct child"):
        _build(root, git, "nested/submission.zip")
    with pytest.raises(SubmissionBuildError, match=".zip"):
        _build(root, git, "submission.tar")

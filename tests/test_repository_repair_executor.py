"""Execution-kernel tests with local Git repositories and a deterministic stub."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

PYTEST_SITE_PACKAGES = Path(pytest.__file__).resolve().parents[1]

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.repository_repair_executor import (  # noqa: E402 - repo script bootstrap
    FileReplacement,
    PatchProposal,
    PatchProviderError,
    PatchRequest,
    execute_repair_benchmark,
    execute_repair_task,
    load_repair_report,
    validate_resumable_report,
)
from scripts.run_repository_benchmark import (  # noqa: E402 - repo script bootstrap
    RepairBenchmarkManifest,
    _canonical_json,
)


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    return completed.stdout.strip()


def _mutation_digest(path: str, before: str, after: str) -> str:
    return hashlib.sha256(
        _canonical_json({"after": after, "before": before, "path": path})
    ).hexdigest()


def _create_repository(path: Path) -> tuple[str, str, str]:
    (path / "src").mkdir(parents=True)
    (path / "tests").mkdir()
    (path / "src" / "app.py").write_text(
        "def proxy_credentials(proxy):\n"
        "    username, password = get_auth_from_url(proxy)\n"
        "    return username, password\n\n"
        "def value() -> int:\n"
        "    return 1\n",
        encoding="utf-8",
    )
    # Captured output intentionally contains the oracle line.  The executor
    # must redact it before the provider sees the failure summary.
    (path / "tests" / "test_app.py").write_text(
        "from app import value\n\n"
        "def test_value() -> None:\n"
        "    print('    return 1')\n"
        "    assert value() == 1\n",
        encoding="utf-8",
    )
    license_bytes = b"Test license\n"
    (path / "LICENSE").write_bytes(license_bytes)
    subprocess.run(["git", "init", "--quiet", str(path)], check=True, timeout=30)
    _git(path, "config", "user.email", "executor-tests@example.invalid")
    _git(path, "config", "user.name", "Executor Tests")
    _git(path, "config", "core.autocrlf", "false")
    _git(path, "add", "--all")
    _git(path, "commit", "--quiet", "-m", "fixed source")
    return (
        _git(path, "rev-parse", "HEAD"),
        _git(path, "rev-parse", "HEAD^{tree}"),
        hashlib.sha256(license_bytes).hexdigest(),
    )


@pytest.fixture
def repair_fixture(tmp_path: Path) -> tuple[RepairBenchmarkManifest, Path, Path]:
    repos_root = tmp_path / "repos"
    specs: dict[str, dict[str, object]] = {}
    for name in ("alpha", "beta", "gamma"):
        commit, tree, license_sha256 = _create_repository(repos_root / name)
        specs[name] = {
            "display_name": f"fixtures/{name}",
            "version": "1.0.0",
            "url": f"https://github.com/fixtures/{name}.git",
            "commit": commit,
            "tree": tree,
            "snapshot_sha256": "0" * 64,
            "license": {
                "spdx": "MIT",
                "path": "LICENSE",
                "sha256": license_sha256,
                "source_url": f"https://github.com/fixtures/{name}/blob/{commit}/LICENSE",
            },
        }
    before = "    return 1\n"
    after = "    return 0\n"
    tasks: list[dict[str, object]] = []
    for repository, count in (("alpha", 7), ("beta", 7), ("gamma", 6)):
        for index in range(count):
            tasks.append(
                {
                    "id": f"{repository}-{index:02d}",
                    "repository": repository,
                    "title": "Repair the deterministic value regression",
                    "issue": (
                        "Restore the public value behavior after a deterministic "
                        "single-file regression in the pinned source revision."
                    ),
                    "origin": "deterministic-mutation",
                    "execution_ready": True,
                    "target_paths": ["src/app.py"],
                    "mutation": {
                        "path": "src/app.py",
                        "before": before,
                        "after": after,
                        "sha256": _mutation_digest("src/app.py", before, after),
                    },
                    "acceptance": [
                        {
                            "argv": [
                                "python",
                                "-m",
                                "pytest",
                                "-q",
                                "tests/test_app.py::test_value",
                            ],
                            "timeout_seconds": 30,
                        }
                    ],
                    "human_intervention_expected": False,
                }
            )
    manifest = RepairBenchmarkManifest.model_validate(
        {
            "schema_version": "1.1",
            "benchmark": "executor-local-fixture",
            "evaluation_kind": "repository_patch_resolution",
            "fixture_evidence": {
                "path": "benchmarks/repository_repair/evidence/prevalidation.json",
                "sha256": "0" * 64,
            },
            "repositories": specs,
            "tasks": tasks,
        }
    )
    return manifest, repos_root, tmp_path / "task-work"


class RestoringStub:
    """Deterministic, non-LLM provider used only by these execution tests."""

    def __init__(self) -> None:
        self.requests: list[PatchRequest] = []

    def __call__(self, request: PatchRequest) -> PatchProposal:
        self.requests.append(request)
        source = request.mutated_sources["src/app.py"]
        return PatchProposal(
            replacements=[
                FileReplacement(
                    path="src/app.py",
                    expected_sha256=source.sha256,
                    content=source.content.replace("return 0", "return 1"),
                )
            ],
            prompt_tokens=11,
            completion_tokens=7,
            estimated_cost_usd=0.0025,
            human_intervention=False,
        )


def test_single_task_success_has_narrow_input_metrics_hashes_and_cleanup(
    repair_fixture: tuple[RepairBenchmarkManifest, Path, Path],
) -> None:
    manifest, repos_root, temp_root = repair_fixture
    task = manifest.tasks[0]
    source_before = (repos_root / "alpha" / "src" / "app.py").read_bytes()
    provider = RestoringStub()

    report = execute_repair_benchmark(
        manifest,
        repos_root=repos_root,
        provider=provider,
        task_ids=[task.id],
        executables={"alpha": Path(sys.executable)},
        extra_pythonpaths={"alpha": PYTEST_SITE_PACKAGES},
        temp_root=temp_root,
        generated_at="2026-07-28T00:00:00+00:00",
        run_id="executor-success",
    )

    result = report.results[0]
    assert report.summary.attempted == 1
    assert report.summary.executed == 1
    assert report.summary.unexecuted == 19
    assert result.execution_status == "executed" and result.success
    assert result.prompt_tokens == 11 and result.completion_tokens == 7
    assert result.estimated_cost_usd == 0.0025
    assert result.evidence is not None and result.evidence.safety_pass
    assert result.evidence.baseline.exit_code not in {None, 0}
    assert result.evidence.acceptance[0].exit_code == 0
    assert result.result_sha256 != "0" * 64
    assert report.report_sha256 != "0" * 64
    assert validate_resumable_report(report, manifest) == []

    request = provider.requests[0]
    assert set(request.model_dump()) == {
        "issue",
        "target_paths",
        "mutated_sources",
        "failure_summary",
    }
    assert task.mutation.before not in request.model_dump_json()
    assert task.mutation.before.strip() not in request.model_dump_json()
    assert "ORACLE_REDACTED" in request.failure_summary
    assert (repos_root / "alpha" / "src" / "app.py").read_bytes() == source_before
    assert _git(repos_root / "alpha", "status", "--porcelain", "--untracked-files=all") == ""
    assert temp_root.is_dir() and list(temp_root.iterdir()) == []


def test_out_of_boundary_patch_is_rejected_without_application(
    repair_fixture: tuple[RepairBenchmarkManifest, Path, Path],
) -> None:
    manifest, repos_root, temp_root = repair_fixture
    task = manifest.tasks[0]

    def outside_provider(request: PatchRequest) -> PatchProposal:
        return PatchProposal(
            replacements=[
                FileReplacement(
                    path="src/outside.py",
                    expected_sha256="0" * 64,
                    content="unsafe = True\n",
                )
            ],
            prompt_tokens=3,
            completion_tokens=2,
        )

    result = execute_repair_task(
        manifest,
        task,
        repos_root=repos_root,
        provider=outside_provider,
        executable=Path(sys.executable),
        extra_pythonpath=PYTEST_SITE_PACKAGES,
        temp_root=temp_root,
    )

    assert result.execution_status == "executed" and not result.success
    assert result.error_code == "patch-boundary-violation"
    assert result.evidence is not None and not result.evidence.safety_pass
    assert all(not item.completed for item in result.evidence.acceptance)
    assert not (repos_root / "alpha" / "src" / "outside.py").exists()
    assert temp_root.is_dir() and list(temp_root.iterdir()) == []


def test_provider_failure_is_checkpointed_and_resumable(
    repair_fixture: tuple[RepairBenchmarkManifest, Path, Path],
    tmp_path: Path,
) -> None:
    manifest, repos_root, temp_root = repair_fixture
    task = manifest.tasks[0]
    checkpoint = tmp_path / "checkpoint.json"

    def failing_provider(_request: PatchRequest) -> PatchProposal:
        raise PatchProviderError(
            "synthetic outage",
            prompt_tokens=5,
            completion_tokens=1,
            estimated_cost_usd=0.001,
        )

    failed = execute_repair_benchmark(
        manifest,
        repos_root=repos_root,
        provider=failing_provider,
        task_ids=[task.id],
        executables={"alpha": Path(sys.executable)},
        extra_pythonpaths={"alpha": PYTEST_SITE_PACKAGES},
        temp_root=temp_root,
        checkpoint_path=checkpoint,
        generated_at="2026-07-28T00:00:00+00:00",
        run_id="executor-resume",
    )

    blocked = failed.results[0]
    assert failed.summary.attempted == 1
    assert failed.summary.success_rate == 0
    assert failed.summary.prompt_tokens == 5
    assert failed.summary.completion_tokens == 1
    assert failed.summary.estimated_cost_usd == 0.001
    assert failed.summary.safety_evaluated == 0
    assert failed.summary.safety_rate is None
    assert blocked.execution_status == "blocked"
    assert blocked.error_code == "provider-failed"
    assert (blocked.prompt_tokens, blocked.completion_tokens) == (5, 1)
    assert blocked.estimated_cost_usd == 0.001
    loaded = load_repair_report(checkpoint)
    assert loaded == failed
    assert validate_resumable_report(loaded, manifest) == []
    assert temp_root.is_dir() and list(temp_root.iterdir()) == []

    resumed = execute_repair_benchmark(
        manifest,
        repos_root=repos_root,
        provider=RestoringStub(),
        task_ids=[task.id],
        executables={"alpha": Path(sys.executable)},
        extra_pythonpaths={"alpha": PYTEST_SITE_PACKAGES},
        temp_root=temp_root,
        resume_report=loaded,
        checkpoint_path=checkpoint,
    )
    assert resumed.run_id == loaded.run_id
    assert resumed.results[0].success
    assert load_repair_report(checkpoint) == resumed

    tampered = resumed.model_copy(update={"report_sha256": "0" * 64})
    with pytest.raises(ValueError, match="self digest"):
        execute_repair_benchmark(
            manifest,
            repos_root=repos_root,
            provider=RestoringStub(),
            task_ids=[task.id],
            resume_report=tampered,
        )


def test_blocked_attempt_remains_in_success_usage_cost_and_human_denominators(
    repair_fixture: tuple[RepairBenchmarkManifest, Path, Path],
) -> None:
    manifest, repos_root, temp_root = repair_fixture
    selected = [manifest.tasks[0].id, manifest.tasks[1].id]
    restoring = RestoringStub()
    calls = 0

    def mixed_provider(request: PatchRequest) -> PatchProposal:
        nonlocal calls
        calls += 1
        if calls == 1:
            return restoring(request)
        raise PatchProviderError(
            "synthetic outage",
            prompt_tokens=5,
            completion_tokens=1,
            estimated_cost_usd=0.001,
            human_intervention=True,
        )

    report = execute_repair_benchmark(
        manifest,
        repos_root=repos_root,
        provider=mixed_provider,
        task_ids=selected,
        executables={"alpha": Path(sys.executable)},
        extra_pythonpaths={"alpha": PYTEST_SITE_PACKAGES},
        temp_root=temp_root,
        generated_at="2026-07-28T00:00:00+00:00",
        run_id="executor-denominators",
    )

    assert report.summary.attempted == 2
    assert report.summary.executed == 1
    assert report.summary.blocked == 1
    assert report.summary.successes == 1
    assert report.summary.success_rate == 0.5
    assert report.summary.safety_evaluated == 1
    assert report.summary.safety_rate == 1
    assert report.summary.human_intervention_rate == 0.5
    assert report.summary.prompt_tokens == 16
    assert report.summary.completion_tokens == 8
    assert report.summary.estimated_cost_usd == pytest.approx(0.0035)


def test_provider_callback_type_is_reusable(
    repair_fixture: tuple[RepairBenchmarkManifest, Path, Path],
) -> None:
    """A plain callback can provide a mapping; no provider subclass is required."""

    manifest, repos_root, temp_root = repair_fixture
    task = manifest.tasks[0]

    def mapping_provider(request: PatchRequest) -> dict[str, object]:
        source = request.mutated_sources["src/app.py"]
        return {
            "replacements": [
                {
                    "path": "src/app.py",
                    "expected_sha256": source.sha256,
                    "content": source.content.replace("return 0", "return 1"),
                }
            ],
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "human_intervention": False,
        }

    result = execute_repair_task(
        manifest,
        task,
        repos_root=repos_root,
        provider=mapping_provider,
        executable=Path(sys.executable),
        extra_pythonpath=PYTEST_SITE_PACKAGES,
        temp_root=temp_root,
    )

    assert result.success


def test_source_credential_shape_fails_closed_before_provider(
    repair_fixture: tuple[RepairBenchmarkManifest, Path, Path],
) -> None:
    manifest, repos_root, temp_root = repair_fixture
    repository = repos_root / "alpha"
    target = repository / "src" / "app.py"
    credential = "".join(("Ab9_", "Zy8-", "Xq7.", "Wm6+", "Tr5/", "Ku4="))
    target.write_text(
        target.read_text(encoding="utf-8") + f'\npassword = "{credential}"\n',
        encoding="utf-8",
    )
    _git(repository, "add", "src/app.py")
    _git(repository, "commit", "--quiet", "--amend", "--no-edit")
    value = manifest.model_dump(mode="json")
    value["repositories"]["alpha"]["commit"] = _git(repository, "rev-parse", "HEAD")
    value["repositories"]["alpha"]["tree"] = _git(repository, "rev-parse", "HEAD^{tree}")
    updated = RepairBenchmarkManifest.model_validate(value)
    calls = 0

    def provider(_request: PatchRequest) -> PatchProposal:
        nonlocal calls
        calls += 1
        raise AssertionError("provider must not receive credential-shaped source")

    result = execute_repair_task(
        updated,
        updated.tasks[0],
        repos_root=repos_root,
        provider=provider,
        executable=Path(sys.executable),
        extra_pythonpath=PYTEST_SITE_PACKAGES,
        temp_root=temp_root,
    )

    assert result.execution_status == "blocked"
    assert result.error_code == "source-credential-detected"
    assert calls == 0
    assert temp_root.is_dir() and list(temp_root.iterdir()) == []

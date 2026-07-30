"""Fail-closed tests for the offline server experiment runner."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from importlib import metadata as importlib_metadata
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import pytest
from dotenv import load_dotenv

from scripts import run_server_experiments as experiments
from scripts import start_server_experiments as launcher


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _make_writable(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts)):
        with contextlib.suppress(OSError):
            os.chmod(path, 0o700 if path.is_dir() else 0o600)
    with contextlib.suppress(OSError):
        os.chmod(root, 0o700)


def test_safe_output_requires_new_absolute_private_location(tmp_path: Path) -> None:
    safe = tmp_path / "experiment-001"
    assert experiments._safe_output(safe) == safe

    with pytest.raises(experiments.ExperimentError, match="absolute safe"):
        experiments._safe_output(Path("relative-output"))
    with pytest.raises(experiments.ExperimentError, match="absolute safe"):
        experiments._safe_output(tmp_path / "unsafe name")
    with pytest.raises(experiments.ExperimentError, match="outside"):
        experiments._safe_output(experiments.ROOT / "experiment-output")

    safe.mkdir()
    with pytest.raises(experiments.ExperimentError, match="new directory"):
        experiments._safe_output(safe)


def test_launcher_requires_isolated_no_site_mode_and_uses_only_stdlib() -> None:
    launcher_path = Path(launcher.__file__).resolve(strict=True)
    runner_path = Path(experiments.__file__).resolve(strict=True)
    without_flags = subprocess.run(
        [sys.executable, str(launcher_path), "--help"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    isolated = subprocess.run(
        [sys.executable, "-I", "-S", str(launcher_path), "--help"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    runner_without_flags = subprocess.run(
        [sys.executable, str(runner_path), "--help"],
        capture_output=True,
        check=False,
        timeout=30,
    )
    runner_isolated = subprocess.run(
        [sys.executable, "-I", "-S", str(runner_path), "--help"],
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert without_flags.returncode == 2
    assert b"requires Python -I -S" in without_flags.stderr
    assert isolated.returncode == 0
    assert runner_without_flags.returncode == 2
    assert b"requires Python -I -S" in runner_without_flags.stderr
    assert runner_isolated.returncode == 0
    source = launcher_path.read_text(encoding="utf-8")
    assert "from scripts" not in source
    assert "import run_server_experiments" not in source


def test_runner_argv_preserves_venv_entry_and_unit_names_do_not_truncate_identity() -> None:
    entry = Path("/opt/devflow-venv/bin/python")
    argv = launcher._runner_argv(
        entry,
        Path("/var/lib/devflow-experiments/run-1"),
        "run-1",
        launcher.NETWORK_MODE_ISOLATED,
    )

    assert argv[:3] == [str(entry), "-I", "-S"]
    prefix = "a" * 70
    assert launcher._unit_name(prefix + "x") != launcher._unit_name(prefix + "y")


def test_environment_does_not_inherit_credentials_or_load_dotenv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "evidence"
    experiments._create_private_directory(output)
    experiments._create_private_directory(output / "artifacts")
    monkeypatch.setenv("LLM_API_KEY", "provider-secret-sentinel")
    monkeypatch.setenv("GITHUB_PERSONAL_ACCESS_TOKEN", "github-secret-sentinel")
    monkeypatch.setenv("UNRELATED_PASSWORD", "password-secret-sentinel")

    environment = experiments._environment(output)

    assert "LLM_API_KEY" not in environment
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in environment
    assert "UNRELATED_PASSWORD" not in environment
    assert all("secret-sentinel" not in value for value in environment.values())
    assert environment["PYTHON_DOTENV_DISABLED"] == "1"
    assert environment["PYTHONNOUSERSITE"] == "1"
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["UV_OFFLINE"] == "1"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert Path(environment["HOME"]).is_relative_to(output)
    assert Path(environment["TMPDIR"]).is_relative_to(output)

    dotenv_path = tmp_path / "credential.env"
    dotenv_path.write_text("SHOULD_NOT_LOAD=forbidden\n", encoding="utf-8")
    with patch.dict(os.environ, environment, clear=True):
        assert load_dotenv(dotenv_path) is False
        assert "SHOULD_NOT_LOAD" not in os.environ


def test_launcher_accepts_safe_venv_symlink_without_resolving_the_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "python-target"
    target.write_bytes(b"interpreter")
    os.chmod(target, 0o755)
    entry = tmp_path / "python-entry"
    try:
        entry.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable to this test user")
    monkeypatch.setattr(launcher, "_require_python_path_ownership", lambda *_args: None)

    selected, resolved = launcher._safe_python_entry(str(entry))

    assert selected == entry.absolute()
    assert selected.is_symlink()
    assert resolved == target.resolve(strict=True)


@pytest.mark.skipif(platform.system() != "Linux", reason="Linux ownership policy is specific")
def test_linux_python_entry_rejects_untrusted_parent_path(tmp_path: Path) -> None:
    target = tmp_path / "python-target"
    target.write_bytes(b"interpreter")
    os.chmod(target, 0o777)
    entry = tmp_path / "python-entry"
    entry.symlink_to(target)

    with pytest.raises(launcher.LaunchError, match="writable"):
        launcher._safe_python_entry(str(entry))


def test_startup_reader_retries_transient_partial_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "run"
    output.mkdir()
    (output / "PLAN.json").write_text("{", encoding="utf-8")
    (output / "HEARTBEAT.json").write_text("{}", encoding="utf-8")
    calls = 0

    def transient(path: Path) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise launcher.LaunchError("temporarily partial")
        if path.name == "PLAN.json":
            return {
                "schema": "devflow.offline-experiment-plan/v2",
                "runId": "run-1",
                "runnerSha256": _digest("runner"),
                "dependencyLockSha256": _digest("lock"),
                "pythonSha256": _digest("python"),
            }
        return {
            "schema": "devflow.offline-experiment-heartbeat/v1",
            "runId": "run-1",
            "state": "running",
        }

    monkeypatch.setattr(launcher, "_read_startup_json", transient)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    result = launcher._wait_for_runner_start(output, "run-1")

    assert calls == 3
    assert {"planCanonicalSha256", "heartbeatCanonicalSha256"} <= set(result)
    assert result["pythonSha256"] == _digest("python")


def test_fixed_steps_use_real_offline_cli_contracts(tmp_path: Path) -> None:
    python = str(Path(sys.executable).resolve(strict=True))
    output = tmp_path / "evidence"
    steps = experiments._steps(python, output)

    experiments._validate_steps(steps, python)

    by_name = {step.name: step for step in steps}
    assert by_name["upstream"].argv[-1] == "--offline"
    assert by_name["behavior-schema"].argv[-1] == "--validate-only"
    assert by_name["repair-manifest"].argv[-3:] == (
        "--repair-manifest",
        "benchmarks/repository_repair/tasks.yaml",
        "--validate-only",
    )
    assert by_name["offline-demo"].argv[1:5] == (
        "-m",
        "devflow.cli",
        "demo",
        "--output-dir",
    )
    assert str(output / "artifacts" / "demo") == by_name["offline-demo"].argv[-1]
    assert "--cov=devflow" in by_name["full-quality-gate"].argv


def test_cli_help_probe_checks_every_option_without_inheriting_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    help_text = " ".join(
        (
            "demo",
            "validate",
            "--output-dir",
            "--offline",
            "--root",
            "--validate-only",
            "--repair-manifest",
            "--output-format",
            "--strict",
            "--cov",
            "--cov-report",
            "--cov-fail-under",
        )
    ).encode("utf-8")
    environment = {"PATH": "fixed-path", "PYTHON_DOTENV_DISABLED": "1"}

    def fake_capture(argv: tuple[str, ...], **kwargs: Any) -> experiments.CommandCapture:
        calls.append((argv, kwargs))
        return experiments.CommandCapture(0, 0, help_text, b"", False, False, False, True, 0)

    monkeypatch.setattr(experiments, "_run_bounded_capture", fake_capture)

    digest = experiments._validate_cli_contracts("/fixed/python", environment)

    assert len(calls) == 10
    assert len(digest) == 64
    assert all("pip" not in argv for argv, _kwargs in calls)
    assert all(kwargs["cwd"] == experiments.ROOT for _, kwargs in calls)
    assert all(kwargs["environment"] is environment for _, kwargs in calls)
    assert all(kwargs["timeout"] == 60 for _, kwargs in calls)


def test_real_locked_environment_exposes_every_fixed_cli_option(tmp_path: Path) -> None:
    output = tmp_path / "cli-contracts"
    experiments._create_private_directory(output)
    experiments._create_private_directory(output / "artifacts")
    environment = experiments._environment(output)
    python = str(Path(sys.executable).resolve(strict=True))

    digest = experiments._validate_cli_contracts(python, environment)

    assert len(digest) == 64
    assert experiments.DIGEST.fullmatch(digest) is not None


def test_locked_environment_rejects_missing_wrong_or_extra_distributions() -> None:
    lock = (
        b"mypy==2.3.0\n"
        b"pytest==9.1.1\n"
        b"pytest-cov==7.1.0\n"
        b"python-dotenv==1.2.2\n"
        b"ruff==0.16.0\n"
        b"selected-dependency==4.0 ; python_version >= '3.0'\n"
        b"other-platform==1.0 ; python_version < '2.0'\n"
    )
    installed = {
        "mypy": "2.3.0",
        "pytest": "9.1.1",
        "pytest-cov": "7.1.0",
        "python-dotenv": "1.2.2",
        "ruff": "0.16.0",
        "selected-dependency": "4.0",
    }

    assert experiments.DIGEST.fullmatch(experiments._validate_locked_environment(lock, installed))
    with pytest.raises(experiments.ExperimentError, match="differs"):
        experiments._validate_locked_environment(lock, {**installed, "pip": "26.0"})
    with pytest.raises(experiments.ExperimentError, match="differs"):
        experiments._validate_locked_environment(lock, {**installed, "rogue-plugin": "1"})
    missing = dict(installed)
    del missing["selected-dependency"]
    with pytest.raises(experiments.ExperimentError, match="incomplete"):
        experiments._validate_locked_environment(lock, missing)


@pytest.mark.skipif(platform.system() != "Linux", reason="FIFO policy is Linux-specific")
def test_bounded_regular_reader_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "not-a-file"
    cast(Any, os).mkfifo(fifo)

    with pytest.raises(experiments.ExperimentError, match="outside the evidence policy"):
        experiments._read_regular(fifo, maximum=128, label="fifo")


def test_artifact_tree_enforces_file_count_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "one.txt").write_text("one", encoding="utf-8")
    (tmp_path / "two.txt").write_text("two", encoding="utf-8")
    monkeypatch.setattr(experiments, "MAX_ARTIFACT_FILES", 1)

    with pytest.raises(experiments.ExperimentError, match="entry limit"):
        experiments._tree_sha256(tmp_path)


def test_site_packages_audit_rejects_unclaimed_startup_hook(tmp_path: Path) -> None:
    site_root = tmp_path / "site-packages"
    package = site_root / "safe_package"
    package.mkdir(parents=True)
    claimed = package / "__init__.py"
    claimed.write_text("VALUE = 1\n", encoding="utf-8")
    hook = site_root / "sitecustomize.py"
    hook.write_text("raise RuntimeError('must never execute')\n", encoding="utf-8")

    with pytest.raises(experiments.ExperimentError, match="customization hook"):
        experiments._audit_site_package_claims(
            (site_root.resolve(strict=True),),
            {claimed.resolve(strict=True)},
            require_root_owned=False,
        )


@pytest.mark.parametrize(
    ("name", "message"),
    (("injected.pth", "path configuration"), ("module.pyc", "precompiled bytecode")),
)
def test_site_packages_audit_rejects_pth_and_all_pyc(
    tmp_path: Path,
    name: str,
    message: str,
) -> None:
    site_root = tmp_path / "site-packages"
    site_root.mkdir()
    forbidden = site_root / name
    forbidden.write_bytes(b"forbidden")

    with pytest.raises(experiments.ExperimentError, match=message):
        experiments._audit_site_package_claims(
            (site_root.resolve(strict=True),),
            {forbidden.resolve(strict=True)},
            require_root_owned=False,
        )


def test_exact_locked_coverage_pth_is_the_only_path_configuration_exception(
    tmp_path: Path,
) -> None:
    distribution = importlib_metadata.distribution("coverage")
    assert distribution.version == "7.15.2"
    package_path = next(path for path in distribution.files or () if str(path) == "a1_coverage.pth")
    installed_path = Path(str(distribution.locate_file(package_path))).resolve(strict=True)
    payload = installed_path.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == experiments.COVERAGE_PTH_SHA256
    assert experiments._verify_record_hash(
        relative_name=str(package_path),
        mode=package_path.hash.mode if package_path.hash is not None else None,
        value=package_path.hash.value if package_path.hash is not None else None,
        recorded_size=package_path.size,
        payload=payload,
    )

    site_root = tmp_path / "site-packages"
    site_root.mkdir()
    copied = site_root / "a1_coverage.pth"
    copied.write_bytes(payload)
    resolved = copied.resolve(strict=True)
    assert experiments._is_locked_coverage_pth(
        distribution="coverage",
        version="7.15.2",
        path=resolved,
        site_roots=(site_root.resolve(strict=True),),
        payload=payload,
    )
    experiments._audit_site_package_claims(
        (site_root.resolve(strict=True),),
        {resolved},
        require_root_owned=False,
        allowed_path_configuration_files={resolved},
    )
    assert not experiments._is_locked_coverage_pth(
        distribution="coverage",
        version="7.15.2",
        path=resolved,
        site_roots=(site_root.resolve(strict=True),),
        payload=payload + b"tampered",
    )


def test_record_hash_verification_rejects_tampered_bytes() -> None:
    payload = b"locked wheel file"
    value = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")

    assert experiments._verify_record_hash(
        relative_name="package/module.py",
        mode="sha256",
        value=value,
        recorded_size=len(payload),
        payload=payload,
    )
    with pytest.raises(experiments.ExperimentError, match="RECORD verification failed"):
        experiments._verify_record_hash(
            relative_name="package/module.py",
            mode="sha256",
            value=value,
            recorded_size=len(payload),
            payload=b"tampered wheel file",
        )


def test_repository_identity_rejects_index_flags_and_ignored_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, ...]] = []

    def capture_for(tracked: bytes, ignored: bytes) -> Any:
        def fake(argv: tuple[str, ...], **_kwargs: Any) -> experiments.CommandCapture:
            observed.append(argv)
            if "HEAD^{commit}" in argv:
                stdout = b"a" * 40 + b"\n"
            elif "HEAD^{tree}" in argv:
                stdout = b"b" * 40 + b"\n"
            elif "--ignored" in argv:
                stdout = ignored
            elif "ls-files" in argv:
                stdout = tracked
            else:
                stdout = b""
            return experiments.CommandCapture(0, 0, stdout, b"", False, False, False, True, 0)

        return fake

    monkeypatch.setattr(experiments, "_run_bounded_capture", capture_for(b"h file.py\0", b""))
    with pytest.raises(experiments.ExperimentError, match="clean committed source"):
        experiments._repository_identity({}, git=Path(sys.executable))
    assert observed
    for argv in observed:
        assert argv[1:3] == ("-c", f"safe.directory={experiments.ROOT}")
        assert "core.fsmonitor=false" in argv
        assert "core.untrackedCache=false" in argv
        assert f"core.hooksPath={os.devnull}" in argv
        assert "credential.helper=" in argv

    observed.clear()
    monkeypatch.setattr(
        experiments,
        "_run_bounded_capture",
        capture_for(b"H file.py\0", b"sitecustomize.py\0"),
    )
    with pytest.raises(experiments.ExperimentError, match="clean committed source"):
        experiments._repository_identity({}, git=Path(sys.executable))


def test_timeout_receipt_fields_bind_full_and_stored_output(tmp_path: Path) -> None:
    result = experiments._run_step(
        experiments.Step(
            "timeout",
            (
                str(Path(sys.executable).resolve(strict=True)),
                "-c",
                (
                    "import sys,time; print('partial stdout', flush=True); "
                    "print('partial stderr', file=sys.stderr, flush=True); time.sleep(5)"
                ),
            ),
            1,
        ),
        output=tmp_path,
        environment=dict(os.environ),
        ordinal=1,
    )
    stdout_log = (tmp_path / "01-timeout.stdout.log").read_bytes()
    stderr_log = (tmp_path / "01-timeout.stderr.log").read_bytes()

    assert result.timed_out is True
    assert result.process_exit_code != 0
    assert result.exit_code == 124
    assert result.failure_reason == "timeout"
    assert result.passed is False
    assert b"partial stdout" in stdout_log
    assert result.stdout_sha256 == hashlib.sha256(stdout_log).hexdigest()
    assert result.stdout_log_sha256 == hashlib.sha256(stdout_log).hexdigest()
    assert result.stderr_log_sha256 == hashlib.sha256(stderr_log).hexdigest()
    assert b"DEVFLOW STEP TIMEOUT" in stderr_log


def test_descendant_cleanup_failure_fails_the_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        experiments,
        "_run_bounded_capture",
        lambda *_args, **_kwargs: experiments.CommandCapture(
            0,
            126,
            b"",
            b"",
            False,
            False,
            True,
            False,
            2,
        ),
    )

    result = experiments._run_step(
        experiments.Step("daemon-cleanup", (sys.executable, "-c", "pass"), 10),
        output=tmp_path,
        environment={},
        ordinal=1,
    )

    assert result.passed is False
    assert result.exit_code == 126
    assert result.failure_reason == "descendant_cleanup_failed"
    assert result.descendant_cleanup_supported is True
    assert result.descendant_cleanup_succeeded is False
    assert result.terminated_descendant_count == 2


@pytest.mark.skipif(platform.system() != "Linux", reason="subreaper requires Linux /proc")
def test_linux_subreaper_terminates_daemon_left_by_successful_step(tmp_path: Path) -> None:
    assert experiments._enable_child_subreaper()
    code = (
        "import subprocess,sys; "
        "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
        "start_new_session=True); print(p.pid, flush=True)"
    )
    result = experiments._run_step(
        experiments.Step("daemon", (sys.executable, "-c", code), 10),
        output=tmp_path,
        environment=dict(os.environ),
        ordinal=1,
    )

    assert result.passed is True
    assert result.descendant_cleanup_supported is True
    assert result.descendant_cleanup_succeeded is True
    assert result.terminated_descendant_count >= 1


def test_package_digest_rejects_unexpected_entries(tmp_path: Path) -> None:
    from scripts.build_agentteams_package import PACKAGE_VERSION, ROLE_SKILLS

    package_root = tmp_path / "packages"
    package_root.mkdir()
    for role in ROLE_SKILLS:
        archive = package_root / f"{role}-v{PACKAGE_VERSION}.zip"
        archive.write_bytes(f"archive:{role}".encode())
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_suffix(".zip.sha256").write_bytes(
            f"{digest}  {archive.name}\n".encode("ascii"),
        )

    assert experiments._package_digests(package_root)
    (package_root / "unexpected.txt").write_text("not part of the package set", encoding="utf-8")
    with pytest.raises(experiments.ExperimentError, match="unexpected entries"):
        experiments._package_digests(package_root)


def test_receipt_chain_verifier_rejects_log_tampering(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    artifacts = output / "artifacts"
    runtime = output / ".runtime"
    output.mkdir()
    artifacts.mkdir()
    runtime.mkdir()
    plan_payload = b'{"plan":"fixed"}\n'
    plan_sha256 = hashlib.sha256(plan_payload).hexdigest()
    experiments._write_new(output / "PLAN.json", plan_payload)
    experiments._write_new(output / "HEARTBEAT.json", b"{}\n")
    stdout = b"verified output\n"
    stderr = b""
    experiments._write_new(output / "01-one.stdout.log", stdout)
    experiments._write_new(output / "01-one.stderr.log", stderr)
    result = experiments.StepResult(
        name="one",
        argv=[sys.executable, "-c", "pass"],
        started_at="2026-07-30T00:00:00Z",
        finished_at="2026-07-30T00:00:01Z",
        duration_ms=1,
        process_exit_code=0,
        exit_code=0,
        timed_out=False,
        capture_limit_exceeded=False,
        descendant_cleanup_supported=True,
        descendant_cleanup_succeeded=True,
        terminated_descendant_count=0,
        failure_reason=None,
        stdout_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_log_sha256=hashlib.sha256(stdout).hexdigest(),
        stderr_log_sha256=hashlib.sha256(stderr).hexdigest(),
        stdout_bytes=len(stdout),
        stderr_bytes=0,
        stdout_truncated=False,
        stderr_truncated=False,
        passed=True,
    )
    receipt_sha256 = experiments._write_step_receipt(
        output,
        run_id="run-1",
        ordinal=1,
        plan_sha256=plan_sha256,
        previous_receipt_sha256=None,
        result=result,
        evidence={"artifactTreeSha256": experiments._tree_sha256(artifacts)},
    )
    records = [experiments.StepRecord(result=result, receipt_sha256=receipt_sha256)]

    assert experiments._verify_receipt_chain(
        output,
        run_id="run-1",
        plan_sha256=plan_sha256,
        records=records,
    )
    stdout_path = output / "01-one.stdout.log"
    os.chmod(stdout_path, 0o600)
    stdout_path.write_bytes(b"tampered\n")
    assert not experiments._verify_receipt_chain(
        output,
        run_id="run-1",
        plan_sha256=plan_sha256,
        records=records,
    )


def test_receipt_chain_revalidates_package_and_determinism_payloads(tmp_path: Path) -> None:
    output = tmp_path / "evidence"
    artifacts = output / "artifacts"
    runtime = output / ".runtime"
    output.mkdir()
    artifacts.mkdir()
    runtime.mkdir()
    plan_payload = b'{"plan":"fixed"}\n'
    plan_sha256 = hashlib.sha256(plan_payload).hexdigest()
    experiments._write_new(output / "PLAN.json", plan_payload)
    experiments._write_new(output / "HEARTBEAT.json", b"{}\n")
    package_set = {"tester-v1.zip": _digest("archive")}
    pass_one_sha256 = experiments._write_package_evidence(
        output,
        pass_number=1,
        digests=package_set,
    )
    pass_two_sha256 = experiments._write_package_evidence(
        output,
        pass_number=2,
        digests=package_set,
    )
    determinism = {
        "schema": "devflow.role-package-determinism/v2",
        "deterministic": True,
        "first": package_set,
        "second": package_set,
        "firstSetSha256": hashlib.sha256(experiments._canonical(package_set)).hexdigest(),
        "secondSetSha256": hashlib.sha256(experiments._canonical(package_set)).hexdigest(),
    }
    determinism_payload = experiments._canonical(determinism) + b"\n"
    experiments._write_new(output / "role-packages-determinism.json", determinism_payload)
    artifact_tree_sha256 = experiments._tree_sha256(artifacts)

    def result(name: str) -> experiments.StepResult:
        prefix = "01" if name.endswith("1") else "02"
        experiments._write_new(output / f"{prefix}-{name}.stdout.log", b"")
        experiments._write_new(output / f"{prefix}-{name}.stderr.log", b"")
        return experiments.StepResult(
            name=name,
            argv=[sys.executable, "-c", "pass"],
            started_at="2026-07-30T00:00:00Z",
            finished_at="2026-07-30T00:00:01Z",
            duration_ms=1,
            process_exit_code=0,
            exit_code=0,
            timed_out=False,
            capture_limit_exceeded=False,
            descendant_cleanup_supported=True,
            descendant_cleanup_succeeded=True,
            terminated_descendant_count=0,
            failure_reason=None,
            stdout_sha256=_digest(""),
            stderr_sha256=_digest(""),
            stdout_log_sha256=_digest(""),
            stderr_log_sha256=_digest(""),
            stdout_bytes=0,
            stderr_bytes=0,
            stdout_truncated=False,
            stderr_truncated=False,
            passed=True,
        )

    first_result = result("role-packages-pass-1")
    first_receipt = experiments._write_step_receipt(
        output,
        run_id="run-package-chain",
        ordinal=1,
        plan_sha256=plan_sha256,
        previous_receipt_sha256=None,
        result=first_result,
        evidence={
            "artifactTreeSha256": artifact_tree_sha256,
            "packageSetEvidenceSha256": pass_one_sha256,
        },
    )
    second_result = result("role-packages-pass-2")
    second_receipt = experiments._write_step_receipt(
        output,
        run_id="run-package-chain",
        ordinal=2,
        plan_sha256=plan_sha256,
        previous_receipt_sha256=first_receipt,
        result=second_result,
        evidence={
            "artifactTreeSha256": artifact_tree_sha256,
            "packageSetEvidenceSha256": pass_two_sha256,
            "determinismEvidenceSha256": hashlib.sha256(determinism_payload).hexdigest(),
        },
    )
    records = [
        experiments.StepRecord(first_result, first_receipt),
        experiments.StepRecord(second_result, second_receipt),
    ]

    assert experiments._verify_receipt_chain(
        output,
        run_id="run-package-chain",
        plan_sha256=plan_sha256,
        records=records,
    )
    determinism_path = output / "role-packages-determinism.json"
    os.chmod(determinism_path, 0o600)
    determinism_path.write_bytes(b'{"deterministic":false}\n')
    assert not experiments._verify_receipt_chain(
        output,
        run_id="run-package-chain",
        plan_sha256=plan_sha256,
        records=records,
    )


def test_run_continues_and_determinism_failure_receipt_matches_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "server-evidence"

    def small_steps(python: str, _output: Path) -> tuple[experiments.Step, ...]:
        return (
            experiments.Step("first-failure", (python, "-c", "raise SystemExit(7)"), 10),
            experiments.Step("later-success", (python, "-c", "print('continued')"), 10),
            experiments.Step("role-packages-pass-1", (python, "-c", "print('p1')"), 10),
            experiments.Step("role-packages-pass-2", (python, "-c", "print('p2')"), 10),
        )

    package_sets = iter(
        (
            {"devflow.zip": _digest("first")},
            {"devflow.zip": _digest("second")},
        )
    )
    monkeypatch.setattr(experiments, "_steps", small_steps)
    audited_installed = {
        "mypy": "2.3.0",
        "pytest": "9.1.1",
        "pytest-cov": "7.1.0",
        "python-dotenv": "1.2.2",
        "ruff": "0.16.0",
    }
    fake_site_root = tmp_path / "site-packages"
    fake_site_root.mkdir()
    monkeypatch.setattr(
        experiments,
        "_prepared_python_entry",
        lambda: (
            Path(sys.executable).resolve(strict=True),
            Path(sys.executable).resolve(strict=True),
            tmp_path,
            (fake_site_root,),
        ),
    )
    monkeypatch.setattr(experiments, "_installed_inventory", lambda _roots: audited_installed)
    monkeypatch.setattr(experiments, "_activate_audited_runtime_paths", lambda _roots: None)
    monkeypatch.setattr(experiments, "_validate_steps", lambda *_args: None)
    monkeypatch.setattr(
        experiments,
        "_validate_cli_contracts",
        lambda *_args: _digest("cli-contracts"),
    )
    monkeypatch.setattr(
        experiments,
        "_trusted_command",
        lambda _name, _env: Path(sys.executable).resolve(strict=True),
    )
    monkeypatch.setattr(
        experiments,
        "_validate_locked_environment",
        lambda _lock, _installed: _digest("installed-environment"),
    )
    monkeypatch.setattr(
        experiments,
        "_installed_files_tree_sha256",
        lambda _installed, **_kwargs: _digest("installed-files"),
    )
    monkeypatch.setattr(
        experiments,
        "_repository_identity",
        lambda _env, *, git=None: {
            "revision": "a" * 40,
            "tree": "b" * 40,
            "trackedInventorySha256": _digest("tracked"),
            "ignoredInventorySha256": _digest("ignored"),
            "identitySha256": _digest("identity"),
        },
    )
    monkeypatch.setattr(experiments, "_enable_child_subreaper", lambda: True)
    monkeypatch.setattr(experiments, "_source_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(experiments, "_package_digests", lambda _path: next(package_sets))

    try:
        exit_code = experiments.run(
            output,
            "offline-run-001",
            network_mode=experiments.NETWORK_MODE_AVAILABLE,
            network_confirmation=experiments.NETWORK_AVAILABLE_CONFIRMATION,
        )
        summary_payload = (output / "SUMMARY.json").read_bytes()
        summary = json.loads(summary_payload)
        plan_payload = (output / "PLAN.json").read_bytes()
        plan_sha256 = hashlib.sha256(plan_payload).hexdigest()

        assert exit_code == 1
        assert summary["passed"] is False
        assert summary["plannedSteps"] == 4
        assert summary["executedSteps"] == 4
        assert summary["continuedAfterFailure"] is True
        assert summary["packageDeterministic"] is False
        assert summary["evidenceIntegrityVerified"] is True
        assert summary["network"] == {
            "mode": experiments.NETWORK_MODE_AVAILABLE,
            "namespaceVerifiedAgainstPid1": False,
            "dangerousNetworkCapabilitiesAbsent": False,
            "systemdRuntimePolicyVerified": False,
            "networkAvailable": True,
            "outboundConnectivityTested": False,
            "claimBoundary": "network_available_environment_credentials_omitted_only",
            "credentialEnvironmentStripped": True,
            "credentialFilesystemIsolationVerified": False,
        }
        assert summary["failedSteps"] == ["first-failure", "role-packages-pass-2"]
        assert (output / "02-later-success.receipt.json").is_file()
        assert b"continued" in (output / "02-later-success.stdout.log").read_bytes()

        previous: str | None = None
        receipts = sorted(output.glob("[0-9][0-9]-*.receipt.json"))
        assert len(receipts) == 4
        for ordinal, receipt_path in enumerate(receipts, start=1):
            receipt_payload = receipt_path.read_bytes()
            receipt = json.loads(receipt_payload)
            assert receipt["runId"] == "offline-run-001"
            assert receipt["ordinal"] == ordinal
            assert receipt["planSha256"] == plan_sha256
            assert receipt["previousReceiptSha256"] == previous
            previous = hashlib.sha256(receipt_payload).hexdigest()
        assert summary["terminalReceiptSha256"] == previous

        pass_two = json.loads((output / "04-role-packages-pass-2.receipt.json").read_bytes())
        result = pass_two["result"]
        assert result["process_exit_code"] == 0
        assert result["exit_code"] == 3
        assert result["passed"] is False
        assert result["failure_reason"] == "package_determinism_failed"
        determinism_payload = (output / "role-packages-determinism.json").read_bytes()
        assert json.loads(determinism_payload)["deterministic"] is False
        assert (
            pass_two["evidence"]["determinismEvidenceSha256"]
            == hashlib.sha256(determinism_payload).hexdigest()
        )

        sums: dict[str, str] = {}
        for line in (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, relative = line.split("  ", 1)
            sums[relative] = digest
            assert hashlib.sha256((output / relative).read_bytes()).hexdigest() == digest
        assert "HEARTBEAT.json" in sums
        assert "SUMMARY.json" in sums
        assert "04-role-packages-pass-2.receipt.json" in sums
        heartbeat = json.loads((output / "HEARTBEAT.json").read_bytes())
        completion_payload = (output / "COMPLETION.json").read_bytes()
        completion = json.loads(completion_payload)
        assert heartbeat["summarySha256"] == hashlib.sha256(summary_payload).hexdigest()
        assert heartbeat["lastReceiptSha256"] == previous
        assert heartbeat["state"] == "sealing"
        assert completion["state"] == "completed_with_failures"
        assert completion["passed"] is False
        assert (
            completion["sha256sumsSha256"]
            == hashlib.sha256((output / "SHA256SUMS").read_bytes()).hexdigest()
        )
        assert not (output / ".runtime").exists()
        verification = experiments._verify_completed_output(output)
        assert verification["integrityVerified"] is True
        assert verification["experimentPassed"] is False
        assert verification["verifiedReceipts"] == 4
        verify_cli = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                str(Path(experiments.__file__).resolve(strict=True)),
                "--verify-output",
                str(output),
            ],
            capture_output=True,
            check=False,
            timeout=30,
        )
        assert verify_cli.returncode == 0, verify_cli.stderr.decode(errors="replace")
        assert json.loads(verify_cli.stdout)["integrityVerified"] is True

        tampered_log = tmp_path / "tampered-log-evidence"
        shutil.copytree(output, tampered_log)
        _make_writable(tampered_log)
        (tampered_log / "02-later-success.stdout.log").write_bytes(b"tampered\n")
        with pytest.raises(experiments.ExperimentError, match="digest mismatch"):
            experiments._verify_completed_output(tampered_log)

        tampered_completion = tmp_path / "tampered-completion-evidence"
        shutil.copytree(output, tampered_completion)
        _make_writable(tampered_completion)
        completion_path = tampered_completion / "COMPLETION.json"
        changed_completion = json.loads(completion_path.read_bytes())
        changed_completion["planSha256"] = _digest("tampered-plan")
        completion_path.write_bytes(experiments._canonical(changed_completion) + b"\n")
        with pytest.raises(experiments.ExperimentError, match="bindings disagree"):
            experiments._verify_completed_output(tampered_completion)
    finally:
        if output.exists():
            _make_writable(output)


def test_run_rejects_missing_network_confirmation_before_output_access(
    tmp_path: Path,
) -> None:
    output = tmp_path / "should-not-exist"

    with pytest.raises(experiments.ExperimentError, match="exact credential-stripped"):
        experiments.run(
            output,
            "run-1",
            network_mode=experiments.NETWORK_MODE_AVAILABLE,
            network_confirmation="",
        )

    assert not output.exists()


def test_isolated_network_mode_requires_a_real_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(experiments, "_network_namespace_isolated", lambda: False)
    with pytest.raises(experiments.ExperimentError, match="verified private"):
        experiments._network_claim(
            experiments.NETWORK_MODE_ISOLATED,
            experiments.NETWORK_ISOLATED_CONFIRMATION,
        )

    monkeypatch.setattr(experiments, "_network_namespace_isolated", lambda: True)
    monkeypatch.setattr(experiments, "_dangerous_network_capabilities_absent", lambda: True)
    monkeypatch.setattr(experiments, "_systemd_runtime_policy_verified", lambda: True)
    claim = experiments._network_claim(
        experiments.NETWORK_MODE_ISOLATED,
        experiments.NETWORK_ISOLATED_CONFIRMATION,
    )
    assert claim["networkAvailable"] is None
    assert claim["namespaceVerifiedAgainstPid1"] is True
    assert claim["dangerousNetworkCapabilitiesAbsent"] is True


def test_systemd_launcher_requests_real_private_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    environment = {"PATH": "/fixed", "PYTHON_DOTENV_DISABLED": "1"}

    def fake_run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, b"Running as unit\n", b"")

    monkeypatch.setattr(launcher, "_is_linux_systemd_host", lambda: True)
    monkeypatch.setattr(launcher, "_safe_isolated_output", lambda output: output)
    monkeypatch.setattr(launcher, "_require_dynamic_user_readability", lambda _python: None)
    monkeypatch.setattr(
        launcher,
        "_trusted_system_command",
        lambda name, _environment: Path(f"/usr/bin/{name}"),
    )
    monkeypatch.setattr(
        launcher,
        "_wait_for_runner_start",
        lambda _output, _run_id: {"planCanonicalSha256": _digest("plan")},
    )
    monkeypatch.setattr(subprocess, "run", fake_run)

    result = launcher._start_isolated(
        Path("/prepared/venv/bin/python"),
        tmp_path / "evidence",
        "run-001",
        environment,
    )

    assert result["mode"] == experiments.NETWORK_MODE_ISOLATED
    assert result["privateNetworkRequested"] is True
    args, kwargs = calls[0]
    assert "--property=PrivateNetwork=yes" in args
    assert "--property=NoNewPrivileges=yes" in args
    assert "--property=CapabilityBoundingSet=" in args
    assert "--property=AmbientCapabilities=" in args
    assert "--property=IPAddressDeny=any" in args
    assert "--property=IPAddressAllow=127.0.0.0/8 ::1/128" in args
    assert "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6" in args
    assert "--property=PrivateTmp=yes" in args
    assert "--property=DynamicUser=yes" in args
    assert "--property=ProtectHome=yes" in args
    assert "--property=ProtectSystem=strict" in args
    assert "--property=ProtectControlGroups=yes" in args
    assert "--property=KillMode=control-group" in args
    assert "--property=MemoryMax=8G" in args
    assert "--property=TasksMax=512" in args
    assert "--property=RuntimeMaxSec=12h" in args
    assert "--expand-environment=no" in args
    assert launcher.NETWORK_MODE_ISOLATED in args
    assert launcher.NETWORK_ISOLATED_CONFIRMATION in args
    command_index = args.index("--")
    assert args[command_index + 1 : command_index + 4] == [
        str(Path("/prepared/venv/bin/python")),
        "-I",
        "-S",
    ]
    assert kwargs["capture_output"] is True
    assert kwargs["env"] is environment
    assert kwargs["shell"] is False


def test_systemd_startup_handshake_failure_stops_unit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped: list[str] = []

    def record_stop(unit: str, _environment: dict[str, str]) -> bool:
        stopped.append(unit)
        return True

    monkeypatch.setattr(launcher, "_is_linux_systemd_host", lambda: True)
    monkeypatch.setattr(launcher, "_safe_isolated_output", lambda output: output)
    monkeypatch.setattr(launcher, "_require_dynamic_user_readability", lambda _python: None)
    monkeypatch.setattr(
        launcher,
        "_trusted_system_command",
        lambda name, _environment: Path(f"/usr/bin/{name}"),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, b"", b""),
    )
    monkeypatch.setattr(
        launcher,
        "_wait_for_runner_start",
        lambda *_args: (_ for _ in ()).throw(launcher.LaunchError("startup failed")),
    )
    monkeypatch.setattr(
        launcher,
        "_stop_unit",
        record_stop,
    )

    with pytest.raises(launcher.LaunchError, match="startup failed"):
        launcher._start_isolated(
            Path("/opt/devflow-venv/bin/python"),
            tmp_path / "evidence",
            "run-rollback",
            {"PATH": "/fixed"},
        )

    assert stopped == [launcher._unit_name("run-rollback")]


@pytest.mark.parametrize("failure", ("os-error", "timeout", "nonzero", "oversized"))
def test_every_systemd_launch_failure_attempts_verified_stop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    stopped: list[str] = []

    def record_stop(unit: str, _environment: dict[str, str]) -> bool:
        stopped.append(unit)
        return True

    def fail_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if failure == "os-error":
            raise OSError("injected")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 60)
        if failure == "nonzero":
            return subprocess.CompletedProcess(args, 1, b"rejected", b"")
        return subprocess.CompletedProcess(args, 0, b"x" * (1024 * 1024 + 1), b"")

    monkeypatch.setattr(launcher, "_is_linux_systemd_host", lambda: True)
    monkeypatch.setattr(launcher, "_safe_isolated_output", lambda output: output)
    monkeypatch.setattr(launcher, "_require_dynamic_user_readability", lambda _python: None)
    monkeypatch.setattr(
        launcher,
        "_trusted_system_command",
        lambda name, _environment: Path(f"/usr/bin/{name}"),
    )
    monkeypatch.setattr(subprocess, "run", fail_run)
    monkeypatch.setattr(
        launcher,
        "_stop_unit",
        record_stop,
    )

    with pytest.raises(launcher.LaunchError, match="rollback verified stopped"):
        launcher._start_isolated(
            Path("/opt/devflow-venv/bin/python"),
            tmp_path / "evidence",
            f"run-{failure}",
            {"PATH": "/fixed"},
        )

    assert stopped == [launcher._unit_name(f"run-{failure}")]


def test_systemd_stop_requires_bounded_inactive_readback(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append(args)
        if "is-active" in args:
            return subprocess.CompletedProcess(args, 3, b"inactive\n", b"")
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(
        launcher,
        "_trusted_system_command",
        lambda _name, _environment: Path("/usr/bin/systemctl"),
    )
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert launcher._stop_unit("devflow-experiment-fixed", {"PATH": "/fixed"}) is True
    assert any("stop" in args for args in calls)
    assert any("is-active" in args for args in calls)


def test_systemd_failure_reports_unverified_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(launcher, "_is_linux_systemd_host", lambda: True)
    monkeypatch.setattr(launcher, "_safe_isolated_output", lambda output: output)
    monkeypatch.setattr(launcher, "_require_dynamic_user_readability", lambda _python: None)
    monkeypatch.setattr(
        launcher,
        "_trusted_system_command",
        lambda name, _environment: Path(f"/usr/bin/{name}"),
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **_kwargs: subprocess.CompletedProcess(args, 1, b"", b"rejected"),
    )
    monkeypatch.setattr(launcher, "_stop_unit", lambda _unit, _environment: False)

    with pytest.raises(launcher.LaunchError, match="rollback could not be verified"):
        launcher._start_isolated(
            Path("/opt/devflow-venv/bin/python"),
            tmp_path / "evidence",
            "run-unverified",
            {"PATH": "/fixed"},
        )


def test_linux_without_systemd_never_uses_detached_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        launcher,
        "_safe_python_entry",
        lambda _raw: (Path("/opt/devflow-venv/bin/python"), Path("/usr/bin/python")),
    )
    monkeypatch.setattr(launcher, "_python_entry_lstat", lambda _path: {"inode": 1})
    monkeypatch.setattr(
        launcher,
        "_fixed_source_attestation",
        lambda: {
            "launcherSha256": _digest("launcher"),
            "runnerSha256": _digest("runner"),
            "dependencyLockSha256": _digest("lock"),
        },
    )
    monkeypatch.setattr(launcher, "_read_trust_root", lambda *_args, **_kwargs: b"python")
    monkeypatch.setattr(shutil, "which", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        launcher,
        "_start_credential_stripped",
        lambda *_args: pytest.fail("Linux detached fallback must not execute"),
    )

    with pytest.raises(launcher.LaunchError, match="fallback is forbidden"):
        launcher.start(
            tmp_path / "evidence",
            "run-no-systemd",
            network_mode=launcher.NETWORK_MODE_AVAILABLE,
            python_entry=Path("/opt/devflow-venv/bin/python"),
        )


def test_launch_receipt_failure_rolls_back_and_claims_only_trust_root_launcher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch = {
        "mode": launcher.NETWORK_MODE_AVAILABLE,
        "unit": None,
        "pid": 4242,
        "output": str(tmp_path / "evidence"),
    }
    stopped: list[dict[str, Any]] = []

    def record_stop(value: dict[str, Any], _environment: dict[str, str]) -> bool:
        stopped.append(value)
        return True

    monkeypatch.setattr(launcher, "_is_linux_systemd_host", lambda: False)
    monkeypatch.setattr(launcher, "_is_windows_host", lambda: True)
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        launcher,
        "_safe_python_entry",
        lambda _raw: (Path("/venv/bin/python"), Path("/usr/bin/python")),
    )
    monkeypatch.setattr(launcher, "_python_entry_lstat", lambda _path: {"inode": 1})
    monkeypatch.setattr(
        launcher,
        "_fixed_source_attestation",
        lambda: {
            "launcherSha256": _digest("launcher"),
            "runnerSha256": _digest("runner"),
            "dependencyLockSha256": _digest("lock"),
        },
    )
    monkeypatch.setattr(launcher, "_read_trust_root", lambda *_args, **_kwargs: b"python")
    monkeypatch.setattr(launcher, "_start_credential_stripped", lambda *_args: launch)
    monkeypatch.setattr(
        launcher,
        "_write_launch_receipt",
        lambda *_args: (_ for _ in ()).throw(launcher.LaunchError("receipt failed")),
    )
    monkeypatch.setattr(
        launcher,
        "_stop_launch",
        record_stop,
    )

    with pytest.raises(launcher.LaunchError, match="receipt failed"):
        launcher.start(
            tmp_path / "evidence",
            "run-1",
            network_mode=launcher.NETWORK_MODE_AVAILABLE,
            python_entry=Path("/venv/bin/python"),
        )

    assert stopped == [launch]


def test_launch_receipt_uses_honest_pre_isolation_claims(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch = {
        "mode": launcher.NETWORK_MODE_AVAILABLE,
        "unit": None,
        "pid": 4242,
        "output": str(tmp_path / "evidence"),
    }
    written: list[dict[str, Any]] = []
    monkeypatch.setattr(launcher, "_is_linux_systemd_host", lambda: False)
    monkeypatch.setattr(launcher, "_is_windows_host", lambda: True)
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        launcher,
        "_safe_python_entry",
        lambda _raw: (Path("/venv/bin/python"), Path("/usr/bin/python")),
    )
    monkeypatch.setattr(launcher, "_python_entry_lstat", lambda _path: {"inode": 1})
    monkeypatch.setattr(
        launcher,
        "_fixed_source_attestation",
        lambda: {
            "launcherSha256": _digest("launcher"),
            "runnerSha256": _digest("runner"),
            "dependencyLockSha256": _digest("lock"),
        },
    )
    monkeypatch.setattr(launcher, "_read_trust_root", lambda *_args, **_kwargs: b"python")
    monkeypatch.setattr(launcher, "_start_credential_stripped", lambda *_args: launch)
    monkeypatch.setattr(
        launcher,
        "_write_launch_receipt",
        lambda _path, value: written.append(value),
    )

    receipt = launcher.start(
        tmp_path / "evidence",
        "run-1",
        network_mode=launcher.NETWORK_MODE_AVAILABLE,
        python_entry=Path("/venv/bin/python"),
    )

    assert receipt["preIsolationTrustRootLauncherExecuted"] is True
    assert receipt["preIsolationCandidateOrDependencyCodeExecuted"] is False
    assert receipt["pythonEntryLstat"] == {"inode": 1}
    assert "preIsolationRepositoryCodeExecuted" not in receipt
    assert written == [receipt]


def test_explicit_network_available_launcher_is_background_and_credential_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    environment = launcher._bootstrap_environment()

    class FakeProcess:
        pid = 4242

    def fake_popen(args: list[str], **kwargs: Any) -> FakeProcess:
        calls.append((args, kwargs))
        return FakeProcess()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    result = launcher._start_credential_stripped(
        Path(sys.executable).resolve(strict=True),
        tmp_path / "evidence",
        "run-002",
        environment,
    )

    assert result["mode"] == launcher.NETWORK_MODE_AVAILABLE
    assert result["unit"] is None
    assert result["pid"] == 4242
    assert result["systemdPolicyRequested"] is False
    assert result["persistenceGuarantee"] == "weaker_detached_process_only"
    assert result["processTreeCleanupGuaranteedByLauncher"] is False
    args, kwargs = calls[0]
    assert launcher.NETWORK_MODE_AVAILABLE in args
    assert launcher.NETWORK_AVAILABLE_CONFIRMATION in args
    assert kwargs["env"] is environment
    assert kwargs["shell"] is False
    assert "LLM_API_KEY" not in environment
    assert "GITHUB_PERSONAL_ACCESS_TOKEN" not in environment
    assert Path(result["completionLog"]).is_file()

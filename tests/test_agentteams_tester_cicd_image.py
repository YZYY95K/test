"""Supply-chain tests for the isolated AgentTeams Tester CI image."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from agentteams.cicd import tester_server
from scripts import build_agentteams_tester_cicd_context as context_builder
from scripts import finalize_agentteams_tester_cicd_image as finalizer
from scripts import materialize_agentteams_tester_cicd_demo_assignments as materializer
from scripts import reconcile_agentteams_tester_cicd as reconciler

ROOT = Path(__file__).resolve().parents[1]
CONTAINERFILE = ROOT / "agentteams" / "tester-cicd.Containerfile"
CONTEXT_SCRIPT = ROOT / "scripts" / "build_agentteams_tester_cicd_context.py"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _public_key() -> bytes:
    der = reconciler.ED25519_SPKI_PREFIX + b"P" * 32
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + base64.b64encode(der).decode("ascii")
        + "\n-----END PUBLIC KEY-----\n"
    ).encode("ascii")


def _release() -> dict[str, str]:
    return {
        "schemaVersion": "1.0",
        "repositoryRevision": "a" * 40,
        "repositoryArchiveSha256": _hash("archive"),
        "repositoryManifestSha256": _hash("manifest"),
        "serverSha256": _hash("server"),
        "receiptPublicKeyFileSha256": _hash("public-file"),
        "receiptPublicKeySha256": _hash("public-der"),
    }


def test_policy_generators_share_the_server_schema_without_a_hash_cycle() -> None:
    release = _release()
    execution = finalizer.execution_policy(
        release,
        python_sha256=_hash("python"),
        bwrap_sha256=_hash("bwrap"),
        prlimit_sha256=_hash("prlimit"),
    )
    receipt = finalizer.receipt_policy(release, execution)

    assert set(execution) == reconciler.EXECUTION_POLICY_FIELDS
    assert set(execution) == tester_server.POLICY_FIELDS
    assert set(receipt) == reconciler.RECEIPT_POLICY_FIELDS
    assert "receiptPolicySha256" not in execution
    assert execution["workspaceBinding"] == reconciler._execution_policy_binding(
        execution
    )
    assert receipt["ciPolicySha256"] == execution["workspaceBinding"]
    assert receipt["ciServerSha256"] == release["serverSha256"]
    assert receipt["repositoryArchiveSha256"] == release["repositoryArchiveSha256"]
    assert receipt["repositoryManifestSha256"] == release["repositoryManifestSha256"]
    assert receipt["repositoryRevision"] == release["repositoryRevision"]


def test_finalizer_writes_exact_canonical_bytes_without_a_trailing_newline(
    tmp_path: Path,
) -> None:
    path = tmp_path / "policy.json"
    value = {"z": 1, "a": {"value": True}}

    payload = finalizer._write(path, value)

    assert payload == b'{"a":{"value":true},"z":1}'
    assert path.read_bytes() == payload
    assert not payload.endswith(b"\n")
    assert finalizer._read_canonical(
        path,
        frozenset(value),
        "test policy",
    ) == value


def test_containerfile_builds_and_finalizes_fixed_runtime_without_a_secret() -> None:
    text = CONTAINERFILE.read_text(encoding="utf-8")

    assert text.startswith(
        "FROM python:3.12.11-slim-bookworm@sha256:"
        "519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
    )
    assert "COPY . " not in text
    assert text.count("COPY repository/ ") == 2
    assert "COPY finalize_image.py /opt/devflow/build/finalize_image.py" in text
    assert (
        "COPY materialize_demo_assignments.py "
        "/opt/devflow/agentteams-cicd/materialize_demo_assignments.py"
    ) in text
    assert "COPY receipt-ed25519.pub /opt/devflow/build/receipt-ed25519.pub" in text
    assert "COPY release-template.json /opt/devflow/build/release-template.json" in text
    assert "COPY execution-policy.json" not in text
    assert "COPY release.json" not in text
    assert "bubblewrap openssl util-linux" in text
    assert "USER 10001:10001" in text
    assert "python3 -S /opt/devflow/build/finalize_image.py" in text
    assert "FROM scratch AS policy-export" in text
    assert "FROM runtime AS production" in text
    assert (
        "COPY --from=runtime /etc/devflow/agentteams-cicd/policy.json "
        "/policy.json"
    ) in text
    assert text.index("finalize_image.py") < text.index("rm -rf /opt/devflow/build")
    assert "DEVFLOW_CI_POLICY_PATH" not in text
    assert "/var/run/secrets/devflow-test-receipt" not in text
    assert (
        'ENTRYPOINT ["/usr/local/bin/python3.12", "-S", '
        '"/opt/devflow/agentteams-cicd/start_service.py"]'
    ) in text


class _GitRunner:
    def __init__(
        self,
        paths: tuple[str, ...],
        *,
        dirty: bool = False,
    ) -> None:
        self.paths = paths
        self.dirty = dirty

    def run(self, args: list[str], *, input_data: bytes | None = None) -> str:
        assert input_data is None
        if "rev-parse" in args:
            return "a" * 40 + "\n"
        if "status" in args:
            return "?? untracked\0" if self.dirty else ""
        if "ls-files" in args:
            return "".join(
                f"100644 {index:040x} 0\t{path}\0"
                for index, path in enumerate(self.paths, start=1)
            )
        raise AssertionError(args)


def _fake_repository(tmp_path: Path) -> tuple[Path, tuple[str, ...]]:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".git").mkdir()
    payloads = {
        "README.md": b"release\n",
        "agentteams/tester-cicd.Containerfile": b"FROM fixed@sha256:" + b"a" * 64,
        "agentteams/cicd/tester_server.py": b"POLICY_FIELDS = frozenset()\n",
        "requirements/dev.lock.txt": b"pytest==1 --hash=sha256:" + b"b" * 64,
        "scripts/finalize_agentteams_tester_cicd_image.py": b"print('finalize')\n",
        "scripts/materialize_agentteams_tester_cicd_demo_assignments.py": (
            b"print('materialize')\n"
        ),
        "scripts/start_agentteams_tester_cicd.py": b"print('start')\n",
    }
    for relative, payload in payloads.items():
        path = repository.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    return repository, tuple(sorted(payloads))


def _context_members(payload: bytes) -> dict[str, bytes]:
    values: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive.getmembers():
            stream = archive.extractfile(member)
            assert stream is not None
            values[member.name] = stream.read()
    return values


def test_context_is_deterministic_public_only_and_release_bound(
    tmp_path: Path,
) -> None:
    repository, paths = _fake_repository(tmp_path)
    public_key_path = tmp_path / "receipt-ed25519.pub"
    public_key_path.write_bytes(_public_key())
    runner = _GitRunner(paths)

    first, source, trust = context_builder.build_context(
        runner,
        repository,
        public_key_path,
    )
    second, repeated_source, repeated_trust = context_builder.build_context(
        runner,
        repository,
        public_key_path,
    )
    members = _context_members(first)
    release = json.loads(members["release-template.json"])

    assert first == second
    assert source == repeated_source
    assert trust == repeated_trust
    assert members["receipt-ed25519.pub"] == _public_key()
    assert members["tester_server.py"] == members[
        "repository/agentteams/cicd/tester_server.py"
    ]
    assert members["requirements-dev.lock.txt"] == members[
        "repository/requirements/dev.lock.txt"
    ]
    assert release == {
        "schemaVersion": "1.0",
        "repositoryRevision": source.revision,
        "repositoryArchiveSha256": source.archive_sha256,
        "repositoryManifestSha256": source.tree_sha256,
        "serverSha256": source.server_sha256,
        **trust,
    }
    assert not members["release-template.json"].endswith(b"\n")
    assert all(".git" not in name for name in members)
    assert all("private" not in name.lower() for name in members)


def test_fixed_demo_assignment_templates_materialize_and_validate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _release()
    policy = finalizer.execution_policy(
        release,
        python_sha256=_hash("python"),
        bwrap_sha256=_hash("bwrap"),
        prlimit_sha256=_hash("prlimit"),
    )
    templates = finalizer.demo_assignment_templates(policy)
    template_root = tmp_path / "templates"
    output_root = tmp_path / "assignments"
    template_root.mkdir()
    output_root.mkdir()
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(finalizer._canonical(policy))
    os.chmod(policy_path, 0o444)
    for template in templates:
        path = template_root / f"{template['taskId']}.template.json"
        path.write_bytes(finalizer._canonical(template))
        os.chmod(path, 0o444)
    os.chmod(template_root, 0o555)
    monkeypatch.setattr(materializer, "POLICY_PATH", policy_path)

    report = materializer.materialize(
        template_root=template_root,
        output_root=output_root,
        probe_isolation=False,
        enforce_production_metadata=False,
    )

    assert report["assignmentSource"] == materializer.SOURCE
    assert report["fixtureTaskIds"] == list(materializer.TASK_IDS)
    assert report["isolationProbeVerified"] is False
    assert report["liveAgentTeamsTaskProjection"] is False
    assert report["containerRestartRefresh"] is True
    assert report["verified"] is True
    by_id = {template["taskId"]: template for template in templates}
    for task_id in materializer.TASK_IDS:
        output = output_root / f"{task_id}.json"
        assert stat.S_IMODE(output.stat().st_mode) & 0o022 == 0
        evidence = json.loads(output.read_text(encoding="utf-8"))
        candidate = by_id[task_id]["evidenceTemplate"]["envelope"]["artifact"][
            "inline"
        ]
        assignment, checked = tester_server.validate_teamharness_task(
            evidence,
            task_id=task_id,
            revision=policy["repositoryRevision"],
            workspace_binding=policy["workspaceBinding"],
            policy=policy,
        )
        assert checked == candidate
        assert assignment["fullSuite"] is (candidate["tier"] == "T3")
    stale = "2000-01-01T00:00:00+00:00"
    for output in output_root.iterdir():
        os.chmod(output, 0o666)
        evidence = json.loads(output.read_text(encoding="utf-8"))
        envelope = json.loads(evidence["spec"])
        envelope["created_at"] = stale
        evidence["spec"] = finalizer._canonical(envelope).decode("utf-8")
        output.write_bytes(finalizer._canonical(evidence))
        os.chmod(output, 0o440)
    refreshed = materializer.materialize(
        template_root=template_root,
        output_root=output_root,
        probe_isolation=False,
        refresh=True,
        enforce_production_metadata=False,
    )
    assert refreshed["containerRestartRefresh"] is True
    assert refreshed["refreshedAt"] != stale
    for output in output_root.iterdir():
        evidence = json.loads(output.read_text(encoding="utf-8"))
        assert json.loads(evidence["spec"])["created_at"] == refreshed[
            "refreshedAt"
        ]
    for output in output_root.iterdir():
        os.chmod(output, 0o666)
    os.chmod(output_root, 0o777)
    os.chmod(template_root, 0o777)
    os.chmod(policy_path, 0o666)


def test_context_check_writes_nothing_and_apply_never_overwrites(
    tmp_path: Path,
) -> None:
    repository, paths = _fake_repository(tmp_path)
    public_key_path = tmp_path / "receipt-ed25519.pub"
    public_key_path.write_bytes(_public_key())
    output = tmp_path / "tester-cicd-context.tar"
    runner = _GitRunner(paths)

    checked = context_builder.build(
        runner,
        repository=repository,
        public_key_path=public_key_path,
        output=output,
    )
    assert checked.applied is False
    assert not output.exists()

    applied = context_builder.build(
        runner,
        repository=repository,
        public_key_path=public_key_path,
        output=output,
        apply=True,
    )
    assert applied.applied is True
    assert hashlib.sha256(output.read_bytes()).hexdigest() == applied.context_sha256
    with pytest.raises(context_builder.ContextBuildError, match="new regular file"):
        context_builder.build(
            runner,
            repository=repository,
            public_key_path=public_key_path,
            output=output,
            apply=True,
        )


def test_context_rejects_dirty_source_and_output_inside_repository(
    tmp_path: Path,
) -> None:
    repository, paths = _fake_repository(tmp_path)
    public_key_path = tmp_path / "receipt-ed25519.pub"
    public_key_path.write_bytes(_public_key())

    with pytest.raises(reconciler.ReconcileError, match="clean"):
        context_builder.build_context(
            _GitRunner(paths, dirty=True),
            repository,
            public_key_path,
        )
    with pytest.raises(context_builder.ContextBuildError, match="outside"):
        context_builder.build(
            _GitRunner(paths),
            repository=repository,
            public_key_path=public_key_path,
            output=repository / "context.tar",
        )


def test_context_cli_refuses_apply_before_source_access_without_confirmation(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            str(CONTEXT_SCRIPT),
            "--apply",
            "--repository",
            str(tmp_path / "missing"),
            "--receipt-public-key",
            str(tmp_path / "missing.pub"),
            "--output",
            str(tmp_path / "context.tar"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "exact confirmation" in completed.stderr
    assert context_builder.CONFIRMATION not in completed.stderr
    assert "Traceback" not in completed.stderr

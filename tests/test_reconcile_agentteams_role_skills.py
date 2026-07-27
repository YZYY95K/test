"""Fail-closed tests for role-scoped AgentTeams Skill reconciliation."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import stat
import subprocess
import sys
import time
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any

import pytest

from scripts.build_agentteams_package import (
    MAX_ARCHIVE_BYTES,
    PACKAGE_VERSION,
    build_role_package_bytes,
)
from scripts.build_agentteams_package import (
    ROLE_SKILLS as PACKAGE_ROLE_SKILLS,
)
from scripts.reconcile_agentteams_packages import Archive
from scripts.reconcile_agentteams_role_skills import (
    ALL_DEVFLOW_SKILLS,
    APPLY_HELPER_MAX_SECONDS,
    HOST_COMMAND_TIMEOUT_SECONDS,
    HOST_HELPER_MARGIN_SECONDS,
    LEASE_RECOVERY_MARGIN_SECONDS,
    MAX_KUBECTL_ARGUMENT_BYTES,
    MAX_KUBECTL_ARGV_BYTES,
    MAX_REMOTE_FRAME_BYTES,
    MAX_REMOTE_HELPER_SOURCE_BYTES,
    MAX_REMOTE_PARAMETERS_BYTES,
    MC_ENTRY_FIELDS,
    MC_STORAGE_PREFIX,
    RELEASE_ARCHIVE_DIGESTS,
    REMOTE_HELPER,
    REMOTE_STDIN_BOOTSTRAP,
    ROLE_SKILLS,
    SYNC_LEASE_SECONDS,
    WORKER_ENTRYPOINT_SHA256,
    RoleRelease,
    RoleSkillError,
    SubprocessRunner,
    _acquire_sync_marker_lease,
    _audit_local_skills,
    _exec_helper,
    _expected_skill_directories,
    _helper_parameters,
    _initialize_mc_client,
    _load_release_archive,
    _local_skill_matches_release,
    _name_list,
    _parse_release_spec,
    _parse_remote_listing,
    _probe_local_filesystem,
    _read_remote_object,
    _release_sync_marker_lease,
    _remote_frame,
    _remote_helper_deadline,
    _remote_main_configured,
    _remote_skill_matches_release,
    _remove_local_skill,
    _remove_remote_skill,
    _remove_transaction_tree,
    _replace_local_skill,
    _replace_remote_skill,
    _role_release_from_archive,
    _secret_shaped,
    _state,
    _sync_marker_lease,
    _validate_mountinfo,
    _validate_storage_prefix,
    _validate_sync_contract,
    _verify_outside_plan_preserved,
    _verify_preserved,
    _verify_sync_marker_lease,
    _write_isolated_mc_config,
    reconcile,
)
from scripts.reconcile_teamharness_openclaw import (
    EXPECTED_ROLES,
    NAMESPACE,
    RUNTIME_LABEL,
    TEAM_LABEL,
    TEAM_NAME,
    WORKER_LABEL,
    Target,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile_agentteams_role_skills.py"
SECRET_SENTINEL = "credential-value-must-not-leak"


@lru_cache(maxsize=1)
def _releases() -> dict[str, RoleRelease]:
    archives = build_role_package_bytes(ROOT, 0)
    return {
        role: _role_release_from_archive(
            Archive(
                role=role,
                name=f"{role}-v{PACKAGE_VERSION}.zip",
                data=data,
                digest=hashlib.sha256(data).hexdigest(),
                source_date_epoch=0,
            )
        )
        for role, data in archives.items()
    }


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _write_skill(root: Path, name: str, *, body: str = "safe") -> Path:
    skill = root / name
    (skill / "references").mkdir(parents=True)
    (skill / "SKILL.md").write_text(body, encoding="utf-8")
    (skill / "references" / "contract.yaml").write_text(
        f"name: {name}\n",
        encoding="utf-8",
    )
    return skill


def _local_root(tmp_path: Path, role: str, *, extras: tuple[str, ...] = ()) -> Path:
    root = tmp_path / "skills"
    root.mkdir(parents=True)
    for skill in ROLE_SKILLS[role]:
        _write_skill(root, skill)
    for skill in extras:
        _write_skill(root, skill)
    _write_skill(root, "teamharness-task-execution")
    return root


def _mc_entry(key: str, *, size: int = 4, **updates: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "etag": _hash(key)[:32],
        "key": key,
        "lastModified": "2026-07-27T00:00:00Z",
        "size": size,
        "status": "success",
        "storageClass": "STANDARD",
        "type": "file",
        "url": "http://object-store.invalid/redacted",
        "versionOrdinal": 1,
    }
    value.update(updates)
    assert set(value) == MC_ENTRY_FIELDS
    return value


def _listing(*entries: dict[str, Any]) -> str:
    return "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries)


def _team() -> dict[str, Any]:
    roles = sorted(EXPECTED_ROLES)
    return {
        "apiVersion": "agentteams.io/v1beta1",
        "kind": "Team",
        "metadata": {"name": TEAM_NAME, "namespace": NAMESPACE},
        "spec": {
            "leader": {"name": "devflow-lead"},
            "workers": [{"name": role} for role in roles if role != "devflow-lead"],
        },
        "status": {
            "members": [
                {
                    "name": f"member-{index}",
                    "runtimeName": role,
                    "matrixUserID": f"@{role}:matrix.invalid",
                }
                for index, role in enumerate(roles)
            ]
        },
    }


def _pod(member: str, role: str, *, ready: bool = True) -> dict[str, Any]:
    spec: dict[str, Any] = {"containers": [{"name": "worker"}]}
    if role == "devflow-lead":
        spec = {
            "serviceAccountName": "agentteams-worker-devflow-lead",
            "automountServiceAccountToken": False,
            "volumes": [
                {
                    "name": "agentteams-token",
                    "projected": {
                        "sources": [
                            {
                                "serviceAccountToken": {
                                    "audience": "agentteams-controller",
                                    "expirationSeconds": 3600,
                                    "path": "token",
                                }
                            }
                        ]
                    },
                }
            ],
            "containers": [
                {
                    "name": "worker",
                    "volumeMounts": [
                        {
                            "name": "agentteams-token",
                            "mountPath": "/var/run/secrets/agentteams",
                            "readOnly": True,
                        }
                    ],
                }
            ],
        }
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"pod-{role}",
            "namespace": NAMESPACE,
            "labels": {
                TEAM_LABEL: TEAM_NAME,
                RUNTIME_LABEL: "openclaw",
                WORKER_LABEL: member,
            },
        },
        "spec": spec,
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True" if ready else "False"}],
            "containerStatuses": [{"name": "worker", "ready": ready}],
        },
    }


def _pods(team: dict[str, Any] | None = None) -> dict[str, Any]:
    team = team or _team()
    return {
        "apiVersion": "v1",
        "kind": "PodList",
        "items": [
            _pod(member["name"], member["runtimeName"]) for member in team["status"]["members"]
        ],
    }


class _FakeRunner:
    def __init__(
        self,
        team: dict[str, Any] | None = None,
        pods: dict[str, Any] | None = None,
        *,
        drift_roles: set[str] | None = None,
        refresh_roles: set[str] | None = None,
        barrier_drift_role: str | None = None,
        final_drift_role: str | None = None,
        malformed_role: str | None = None,
    ) -> None:
        self.team = team or _team()
        self.pods = pods or _pods(self.team)
        self.drift_roles = set(drift_roles or set())
        self.refresh_roles = set(refresh_roles or set())
        self.barrier_drift_role = barrier_drift_role
        self.final_drift_role = final_drift_role
        self.malformed_role = malformed_role
        self.calls: list[list[str]] = []
        self.inputs: list[bytes | None] = []
        self.check_counts = {role: 0 for role in EXPECTED_ROLES}
        self.applied_roles: set[str] = set()

    def run(self, args: list[str], input_data: bytes | None = None) -> str:
        self.calls.append(list(args))
        self.inputs.append(input_data)
        if "get" in args and "team" in args:
            return json.dumps(self.team)
        if "get" in args and "pods" in args:
            return json.dumps(self.pods)
        if "exec" not in args:
            return ""
        _source, parameters, _payload = _decode_remote_frame(input_data)
        _release_text, action, role, _workspace, _expected_local, _expected_remote = parameters
        if role == self.malformed_role:
            return SECRET_SENTINEL
        allowed = sorted(ROLE_SKILLS[role])
        drift = role in self.drift_roles and role not in self.applied_roles
        refresh = role in self.refresh_roles and role not in self.applied_roles
        local = sorted({*allowed, "issue-classifier"}) if drift else allowed
        remote = sorted({*allowed, "test-runner"}) if drift else allowed
        if action == "check":
            self.check_counts[role] += 1
        if action == "apply":
            self.applied_roles.add(role)
            drift = False
            refresh = False
            local = allowed
            remote = allowed
        local_snapshot = _hash(f"local:{role}:{','.join(local)}")
        remote_snapshot = _hash(f"remote:{role}:{','.join(remote)}")
        if action == "check" and role == self.barrier_drift_role and self.check_counts[role] == 2:
            local_snapshot = _hash(f"barrier-drift:{role}")
        if action == "check" and role == self.final_drift_role and self.check_counts[role] == 3:
            local_snapshot = _hash(f"final-drift:{role}")
        local_remove = sorted(set(local) - set(allowed))
        remote_remove = sorted(set(remote) - set(allowed))
        remote_sync = allowed if refresh else sorted(set(allowed) - set(remote))
        local_refresh = allowed if refresh else []
        return json.dumps(
            {
                "ok": True,
                "role": role,
                "allowedSkills": allowed,
                "localKnownSkills": local,
                "remoteKnownSkills": remote,
                "localRemove": local_remove,
                "remoteRemove": remote_remove,
                "remoteSync": remote_sync,
                "localRefresh": local_refresh,
                "localCount": len(local),
                "remoteCount": len(remote),
                "localSnapshot": local_snapshot,
                "remoteSnapshot": remote_snapshot,
                "needsApply": bool(local_remove or remote_remove or local_refresh or remote_sync),
                "applied": action == "apply",
            }
        )


def _decode_remote_frame(data: bytes | None) -> tuple[str, list[str], bytes]:
    assert data is not None and len(data) >= 12
    source_size = int.from_bytes(data[:4], "big")
    parameter_size = int.from_bytes(data[4:8], "big")
    payload_size = int.from_bytes(data[8:12], "big")
    source_end = 12 + source_size
    parameter_end = source_end + parameter_size
    assert len(data) == parameter_end + payload_size
    source = data[12:source_end].decode("utf-8")
    parameters = json.loads(data[source_end:parameter_end])
    assert isinstance(parameters, list)
    assert all(isinstance(item, str) for item in parameters)
    return source, parameters, data[parameter_end:]


def _helper_invocations(
    runner: _FakeRunner,
    action: str,
) -> list[tuple[list[str], list[str], bytes]]:
    result: list[tuple[list[str], list[str], bytes]] = []
    for index, call in enumerate(runner.calls):
        if "exec" not in call:
            continue
        source, parameters, payload = _decode_remote_frame(runner.inputs[index])
        assert source == REMOTE_HELPER
        if parameters[1] == action:
            result.append((call, parameters, payload))
    return result


def _helper_calls(runner: _FakeRunner, action: str) -> list[list[str]]:
    return [call for call, _parameters, _payload in _helper_invocations(runner, action)]


def _helper_call_indices(runner: _FakeRunner, action: str) -> list[int]:
    result: list[int] = []
    for index, call in enumerate(runner.calls):
        if "exec" not in call:
            continue
        _source, parameters, _payload = _decode_remote_frame(runner.inputs[index])
        if parameters[1] == action:
            result.append(index)
    return result


def test_fixed_policy_matches_role_packages_and_owns_exactly_seven() -> None:
    assert ROLE_SKILLS == PACKAGE_ROLE_SKILLS
    assert set(ROLE_SKILLS) == EXPECTED_ROLES
    assert len(ALL_DEVFLOW_SKILLS) == 7
    assert ROLE_SKILLS["devflow-lead"] == ()
    assert ROLE_SKILLS["devflow-reviewer"] == (
        "pr-reviewer",
        "experience-distiller",
    )
    assert set(RELEASE_ARCHIVE_DIGESTS) == set(ROLE_SKILLS)


def test_release_policy_rejects_a_self_consistent_same_version_rebuild() -> None:
    release = _releases()["devflow-coder"]
    changed = release.archive[:-1] + bytes([release.archive[-1] ^ 1])
    changed_digest = hashlib.sha256(changed).hexdigest()
    with pytest.raises(RoleSkillError, match="identity"):
        _role_release_from_archive(
            Archive(
                role="devflow-coder",
                name=f"devflow-coder-v{PACKAGE_VERSION}.zip",
                data=changed,
                digest=changed_digest,
                source_date_epoch=0,
            )
        )

    spec = json.loads(release.spec_json)
    spec["archiveSha256"] = _hash("different-release")
    with pytest.raises(RoleSkillError, match="identity"):
        _parse_release_spec(json.dumps(spec), "devflow-coder")


def test_release_archive_and_manifest_are_verified_before_payload_use() -> None:
    release = _releases()["devflow-locator"]
    spec = _parse_release_spec(release.spec_json, "devflow-locator")
    payload = _load_release_archive(release.archive, spec, "devflow-locator")

    assert set(payload) == set(ROLE_SKILLS["devflow-locator"])
    assert (
        hashlib.sha256(payload["github-evidence"]["scripts/authorize_tool.py"]).hexdigest()
        == spec["skills"]["github-evidence"]["scripts/authorize_tool.py"]["sha256"]
    )
    tampered = release.archive[:-1] + bytes([release.archive[-1] ^ 1])
    with pytest.raises(RoleSkillError, match="digest mismatch"):
        _load_release_archive(tampered, spec, "devflow-locator")


def test_local_release_match_includes_exact_file_and_directory_modes() -> None:
    spec = _parse_release_spec(
        _releases()["devflow-coder"].spec_json,
        "devflow-coder",
    )
    expected = spec["skills"]["patch-generator"]
    files = tuple(sorted(expected))
    directories = _expected_skill_directories(files)
    local: dict[str, Any] = {
        "all": ("patch-generator",),
        "files": {"patch-generator": files},
        "directories": {"patch-generator": directories},
        "fileDigests": {"patch-generator": {name: expected[name]["sha256"] for name in files}},
        "fileModes": {"patch-generator": {name: 0o644 for name in files}},
        "directoryModes": {"patch-generator": {name: 0o755 for name in directories}},
    }
    assert _local_skill_matches_release(local, "patch-generator", expected)
    file_modes: dict[str, int] = local["fileModes"]["patch-generator"]
    file_modes["SKILL.md"] = 0o777
    assert not _local_skill_matches_release(local, "patch-generator", expected)


def test_local_audit_reports_only_known_set_and_preserves_builtins(tmp_path: Path) -> None:
    root = _local_root(
        tmp_path,
        "devflow-coder",
        extras=("issue-classifier",),
    )

    state = _audit_local_skills(root, "devflow-coder")

    assert state["known"] == ("issue-classifier", "patch-generator")
    assert "teamharness-task-execution" in state["all"]
    assert re.fullmatch(r"[0-9a-f]{64}", state["digest"])


def test_local_audit_classifies_missing_or_stale_allowed_as_release_drift(
    tmp_path: Path,
) -> None:
    release = _parse_release_spec(
        _releases()["devflow-coder"].spec_json,
        "devflow-coder",
    )
    missing = tmp_path / "missing"
    missing.mkdir()
    missing_state = _audit_local_skills(missing, "devflow-coder")
    assert not _local_skill_matches_release(
        missing_state,
        "patch-generator",
        release["skills"]["patch-generator"],
    )

    unsafe = _local_root(tmp_path / "unsafe", "devflow-lead")
    (unsafe / "loose.txt").write_text("not a Skill tree", encoding="utf-8")
    with pytest.raises(RoleSkillError, match="local directory"):
        _audit_local_skills(unsafe, "devflow-lead")

    missing_entrypoint = _local_root(tmp_path / "entrypoint", "devflow-coder")
    (missing_entrypoint / "patch-generator" / "SKILL.md").unlink()
    stale_state = _audit_local_skills(missing_entrypoint, "devflow-coder")
    assert not _local_skill_matches_release(
        stale_state,
        "patch-generator",
        release["skills"]["patch-generator"],
    )


def test_local_audit_rejects_hardlinks_and_symlinks_when_supported(tmp_path: Path) -> None:
    hard_root = _local_root(tmp_path / "hard", "devflow-coder")
    source = hard_root / "patch-generator" / "SKILL.md"
    os.link(source, hard_root / "patch-generator" / "copy.md")
    with pytest.raises(RoleSkillError, match="regular file"):
        _audit_local_skills(hard_root, "devflow-coder")

    link_root = _local_root(tmp_path / "link", "devflow-coder")
    link = link_root / "patch-generator" / "outside.md"
    try:
        link.symlink_to(tmp_path / "outside.md")
    except OSError:
        return
    with pytest.raises(RoleSkillError, match="symbolic link"):
        _audit_local_skills(link_root, "devflow-coder")


@pytest.mark.parametrize("suffix", ["", "/patch-generator", "/nested/path"])
def test_mountinfo_rejects_mounts_at_or_below_skills_root(suffix: str) -> None:
    root = Path("/root/hiclaw-fs/agents/devflow-coder/skills")
    root_text = root.as_posix()
    line = f"36 25 0:32 / {root_text}{suffix} rw - ext4 /dev/sda rw\n"
    with pytest.raises(RoleSkillError, match="mount boundary"):
        _validate_mountinfo(line, root)
    sibling = f"36 25 0:32 / {root_text}-backup rw - ext4 /dev/sda rw\n"
    _validate_mountinfo(sibling, root)


def test_local_delete_is_exact_and_never_removes_allowed_or_builtin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if sys.platform != "linux":
        monkeypatch.setattr(
            "scripts.reconcile_agentteams_role_skills._rename_noreplace",
            os.replace,
        )
    root = _local_root(
        tmp_path,
        "devflow-coder",
        extras=("issue-classifier",),
    )

    before = _audit_local_skills(root, "devflow-coder")
    _remove_local_skill(
        root,
        "devflow-coder",
        "issue-classifier",
        before["stableSkillDigests"]["issue-classifier"],
    )

    assert not (root / "issue-classifier").exists()
    assert (root / "patch-generator" / "SKILL.md").is_file()
    assert (root / "teamharness-task-execution" / "SKILL.md").is_file()
    with pytest.raises(RoleSkillError, match="outside role policy"):
        _remove_local_skill(root, "devflow-coder", "patch-generator", _hash("unused"))
    with pytest.raises(RoleSkillError, match="outside role policy"):
        _remove_local_skill(
            root,
            "devflow-coder",
            "teamharness-task-execution",
            _hash("unused"),
        )


def test_allowed_replacement_rejects_nonrelease_or_secret_bytes_before_mc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _releases()["devflow-coder"]
    spec = _parse_release_spec(release.spec_json, "devflow-coder")
    files = _load_release_archive(release.archive, spec, "devflow-coder")["patch-generator"]
    secret = bytearray(
        [
            83,
            121,
            110,
            116,
            104,
            101,
            116,
            105,
            99,
            57,
            65,
            98,
            67,
            100,
            101,
            70,
            48,
            49,
            71,
            104,
            105,
            106,
            107,
            76,
            50,
            51,
            77,
            110,
            111,
            112,
            113,
            82,
            52,
            53,
            83,
            116,
            117,
            118,
            119,
            88,
            54,
            55,
            89,
            122,
            56,
            57,
            48,
        ]
    ).decode("ascii")
    tampered = dict(files)
    tampered["SKILL.md"] = secret.encode()
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._run_quiet",
        lambda args, _label: calls.append(args),
    )

    with pytest.raises(RoleSkillError, match="replacement bytes"):
        _replace_remote_skill(
            "storage/bucket",
            "devflow-coder",
            "patch-generator",
            tampered,
            spec["skills"]["patch-generator"],
            spec["manifestSha256"],
        )
    assert not calls
    assert _secret_shaped(secret.encode())


class _InjectedCrash(BaseException):
    pass


class _FakeRemoteStore:
    def __init__(self, *, failpoint: str | None = None, crash: bool = False) -> None:
        self.objects: dict[str, bytes] = {}
        self.failpoint = failpoint
        self.crash = crash
        self.failed = False
        self.new_tree: dict[str, Any] | None = None

    def _fail(self, point: str) -> None:
        if self.failpoint == point and not self.failed:
            self.failed = True
            if self.crash:
                raise _InjectedCrash(point)
            raise RoleSkillError(f"injected {point}")

    def audit_transaction(self, prefix: str, role: str, skill: str) -> dict[str, Any]:
        root = f"{prefix}/agents/{role}/.devflow-role-skill-transactions/{skill}/"
        entries = {
            key[len(root) :]: value
            for key, value in self.objects.items()
            if key.startswith(root)
        }
        records = [
            (name, len(entries[name]), hashlib.sha256(entries[name]).hexdigest())
            for name in sorted(entries)
        ]
        return {
            "digest": _hash(json.dumps(records, separators=(",", ":"))),
            "paths": tuple(sorted(entries)),
            "sizes": {name: len(entries[name]) for name in sorted(entries)},
        }

    def audit_skills(self, prefix: str, role: str) -> dict[str, Any]:
        root = f"{prefix}/agents/{role}/skills/"
        by_skill: dict[str, dict[str, bytes]] = {}
        for key, value in self.objects.items():
            if not key.startswith(root):
                continue
            relative = key[len(root) :]
            skill, separator, filename = relative.partition("/")
            if separator and filename:
                by_skill.setdefault(skill, {})[filename] = value
        all_skills = tuple(sorted(by_skill))
        records = [
            (skill, name, len(data), hashlib.sha256(data).hexdigest())
            for skill in all_skills
            for name, data in sorted(by_skill[skill].items())
        ]
        return {
            "digest": _hash(json.dumps(records, separators=(",", ":"))),
            "known": tuple(sorted(set(all_skills) & ALL_DEVFLOW_SKILLS)),
            "all": all_skills,
            "skillDigests": {
                skill: _hash(
                    json.dumps(
                        [
                            (name, len(data), hashlib.sha256(data).hexdigest())
                            for name, data in sorted(by_skill[skill].items())
                        ],
                        separators=(",", ":"),
                    )
                )
                for skill in all_skills
            },
            "files": {skill: tuple(sorted(by_skill[skill])) for skill in all_skills},
            "fileSizes": {
                skill: {name: len(data) for name, data in sorted(by_skill[skill].items())}
                for skill in all_skills
            },
        }

    def read(self, source: str, expected_size: int) -> bytes:
        data = self.objects[source]
        if len(data) != expected_size:
            raise RoleSkillError("fake size mismatch")
        return data

    def write(self, destination: str, data: bytes, label: str) -> None:
        self.objects[destination] = data
        if destination.endswith("/manifest.json"):
            phase = json.loads(data)["phase"]
            self._fail(f"manifest-{phase}")
        elif "/staging/" in destination:
            self._fail("staging-write")

    def copy(self, source: str, destination: str, _label: str) -> None:
        self.objects[destination] = self.objects[source]
        if "/backup/" in destination:
            self._fail("backup-copy")
        elif "/skills/" in destination:
            self._fail("target-copy")

    def quiet(self, args: list[str], _label: str) -> None:
        target = args[-1]
        recursive = "--recursive" in args
        if recursive:
            for key in tuple(self.objects):
                if key.startswith(target):
                    del self.objects[key]
        else:
            self.objects.pop(target, None)
        if "/skills/" in target:
            self._fail("target-remove")
        elif "/.devflow-role-skill-transactions/" in target:
            self._fail("cleanup")


def _install_fake_remote_store(
    monkeypatch: pytest.MonkeyPatch,
    *,
    failpoint: str | None = None,
    crash: bool = False,
) -> tuple[_FakeRemoteStore, dict[str, Any], dict[str, bytes]]:
    import scripts.reconcile_agentteams_role_skills as role_module

    store = _FakeRemoteStore(failpoint=failpoint, crash=crash)
    prefix = "storage/bucket"
    root = f"{prefix}/agents/devflow-coder/skills"
    store.objects[f"{root}/patch-generator/SKILL.md"] = b"old-release"
    store.objects[f"{root}/teamharness-task-execution/SKILL.md"] = b"builtin-preserved"
    release = _releases()["devflow-coder"]
    spec = _parse_release_spec(release.spec_json, "devflow-coder")
    files = _load_release_archive(release.archive, spec, "devflow-coder")["patch-generator"]
    expected = spec["skills"]["patch-generator"]
    store.new_tree = {
        "present": True,
        "files": {
            relative: {
                "size": expected[relative]["size"],
                "sha256": expected[relative]["sha256"],
            }
            for relative in sorted(expected)
        },
    }
    original_verify_transaction = role_module._verify_transaction_tree
    original_verify_target = role_module._verify_remote_target_tree

    def verify_transaction(
        tx_prefix: str,
        role: str,
        skill: str,
        tree: str,
        expected_tree: dict[str, Any],
    ) -> None:
        if tree == "staging":
            store._fail("staging-verify")
        elif tree == "backup":
            store._fail("backup-verify")
        original_verify_transaction(tx_prefix, role, skill, tree, expected_tree)

    def verify_target(
        tx_prefix: str,
        role: str,
        skill: str,
        expected_tree: dict[str, Any],
    ) -> None:
        if expected_tree == store.new_tree:
            store._fail("target-verify")
        original_verify_target(tx_prefix, role, skill, expected_tree)

    monkeypatch.setattr(role_module, "_audit_remote_transaction", store.audit_transaction)
    monkeypatch.setattr(role_module, "_audit_remote_skills", store.audit_skills)
    monkeypatch.setattr(role_module, "_read_remote_object", store.read)
    monkeypatch.setattr(role_module, "_write_remote_object", store.write)
    monkeypatch.setattr(role_module, "_copy_remote_object", store.copy)
    monkeypatch.setattr(role_module, "_run_quiet", store.quiet)
    monkeypatch.setattr(role_module, "_verify_transaction_tree", verify_transaction)
    monkeypatch.setattr(role_module, "_verify_remote_target_tree", verify_target)
    return store, spec, files


def _fake_target_files(store: _FakeRemoteStore) -> dict[str, bytes]:
    root = "storage/bucket/agents/devflow-coder/skills/patch-generator/"
    return {
        key[len(root) :]: value
        for key, value in store.objects.items()
        if key.startswith(root)
    }


@pytest.mark.parametrize(
    ("failpoint", "committed"),
    [
        ("manifest-staging", False),
        ("staging-write", False),
        ("staging-verify", False),
        ("backup-copy", False),
        ("backup-verify", False),
        ("manifest-replacing", False),
        ("target-remove", False),
        ("target-copy", False),
        ("target-verify", False),
        ("manifest-committed", True),
        ("cleanup", True),
    ],
)
def test_remote_double_tree_transaction_recovers_every_injected_phase_failure(
    monkeypatch: pytest.MonkeyPatch,
    failpoint: str,
    committed: bool,
) -> None:
    store, spec, files = _install_fake_remote_store(monkeypatch, failpoint=failpoint)

    with pytest.raises(RoleSkillError, match="injected"):
        _replace_remote_skill(
            "storage/bucket",
            "devflow-coder",
            "patch-generator",
            files,
            spec["skills"]["patch-generator"],
            spec["manifestSha256"],
        )

    expected = files if committed else {"SKILL.md": b"old-release"}
    assert _fake_target_files(store) == expected
    assert store.objects[
        "storage/bucket/agents/devflow-coder/skills/teamharness-task-execution/SKILL.md"
    ] == b"builtin-preserved"
    assert not any("/.devflow-role-skill-transactions/" in key for key in store.objects)


def test_orphan_replacing_transaction_is_rolled_back_then_retried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, spec, files = _install_fake_remote_store(
        monkeypatch,
        failpoint="target-remove",
        crash=True,
    )
    with pytest.raises(_InjectedCrash):
        _replace_remote_skill(
            "storage/bucket",
            "devflow-coder",
            "patch-generator",
            files,
            spec["skills"]["patch-generator"],
            spec["manifestSha256"],
        )
    assert not _fake_target_files(store)
    assert any("/.devflow-role-skill-transactions/" in key for key in store.objects)

    store.failpoint = None
    _replace_remote_skill(
        "storage/bucket",
        "devflow-coder",
        "patch-generator",
        files,
        spec["skills"]["patch-generator"],
        spec["manifestSha256"],
    )

    assert _fake_target_files(store) == files
    assert not any("/.devflow-role-skill-transactions/" in key for key in store.objects)


def test_orphan_recovery_refuses_a_backup_whose_full_digest_changed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, spec, files = _install_fake_remote_store(
        monkeypatch,
        failpoint="target-remove",
        crash=True,
    )
    with pytest.raises(_InjectedCrash):
        _replace_remote_skill(
            "storage/bucket",
            "devflow-coder",
            "patch-generator",
            files,
            spec["skills"]["patch-generator"],
            spec["manifestSha256"],
        )
    backup = next(key for key in store.objects if "/backup/" in key)
    store.objects[backup] += b"tampered"
    store.failpoint = None

    with pytest.raises(RoleSkillError, match="tree .* verification"):
        _replace_remote_skill(
            "storage/bucket",
            "devflow-coder",
            "patch-generator",
            files,
            spec["skills"]["patch-generator"],
            spec["manifestSha256"],
        )

    assert any("/.devflow-role-skill-transactions/" in key for key in store.objects)
    assert store.objects[
        "storage/bucket/agents/devflow-coder/skills/teamharness-task-execution/SKILL.md"
    ] == b"builtin-preserved"


@pytest.mark.skipif(sys.platform != "linux", reason="renameat2 is a Linux deployment gate")
def test_atomic_local_refresh_normalizes_modes_under_restrictive_umask(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    root = workspace / "skills"
    root.mkdir(parents=True)
    _write_skill(root, "patch-generator", body="stale")
    _write_skill(root, "teamharness-task-execution", body="preserve")
    before = _audit_local_skills(root, "devflow-coder")
    preserved = before["skillDigests"]["teamharness-task-execution"]
    release = _releases()["devflow-coder"]
    spec = _parse_release_spec(release.spec_json, "devflow-coder")
    files = _load_release_archive(release.archive, spec, "devflow-coder")["patch-generator"]

    previous_umask = os.umask(0o077)
    try:
        _replace_local_skill(
            root,
            "devflow-coder",
            "patch-generator",
            files,
            spec["skills"]["patch-generator"],
            before["stableSkillDigests"]["patch-generator"],
        )
    finally:
        os.umask(previous_umask)

    after = _audit_local_skills(root, "devflow-coder")
    assert _local_skill_matches_release(
        after,
        "patch-generator",
        spec["skills"]["patch-generator"],
    )
    assert after["skillDigests"]["teamharness-task-execution"] == preserved
    assert set(after["fileModes"]["patch-generator"].values()) == {0o644}
    assert set(after["directoryModes"]["patch-generator"].values()) == {0o755}


@pytest.mark.skipif(sys.platform != "linux", reason="renameat2 is a Linux deployment gate")
def test_filesystem_probe_isolated_and_self_cleaning(tmp_path: Path) -> None:
    before = tuple(tmp_path.iterdir())
    _probe_local_filesystem(tmp_path)
    assert tuple(tmp_path.iterdir()) == before


@pytest.mark.skipif(sys.platform != "linux", reason="deployed sync contract is Linux-only")
def test_pinned_sync_marker_lease_is_bounded_and_reversible(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint_root = tmp_path / "opt"
    entrypoint_root.mkdir()
    entrypoint = entrypoint_root / "worker-entrypoint.sh"
    entrypoint.write_bytes(b"fixed five-second local push contract\n")
    entrypoint.chmod(0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = workspace / ".last-pull"
    marker.touch(mode=0o644)
    marker.chmod(0o644)
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.WORKER_ENTRYPOINT_PATH",
        str(entrypoint),
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.WORKER_ENTRYPOINT_SHA256",
        hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
    )

    validated, identity = _validate_sync_contract(workspace)
    assert validated == marker
    descriptor, lease_identity, lease_mtime = _acquire_sync_marker_lease(workspace)
    assert lease_identity == identity
    assert lease_mtime > time.time_ns() + (SYNC_LEASE_SECONDS - 2) * 1_000_000_000
    _verify_sync_marker_lease(workspace, lease_identity, lease_mtime)
    _release_sync_marker_lease(descriptor, lease_identity, lease_mtime)
    assert marker.stat().st_mtime_ns <= time.time_ns()


@pytest.mark.skipif(sys.platform != "linux", reason="deployed sync contract is Linux-only")
def test_sync_marker_lease_rolls_back_failed_acquire_and_partial_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint_root = tmp_path / "opt"
    entrypoint_root.mkdir()
    entrypoint = entrypoint_root / "worker-entrypoint.sh"
    entrypoint.write_bytes(b"fixed five-second local push contract\n")
    entrypoint.chmod(0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = workspace / ".last-pull"
    marker.touch(mode=0o644)
    marker.chmod(0o644)
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.WORKER_ENTRYPOINT_PATH",
        str(entrypoint),
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.WORKER_ENTRYPOINT_SHA256",
        hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
    )

    real_fsync = os.fsync
    fsync_calls = 0

    def fail_first_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 1:
            raise OSError("injected fsync failure")
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(RoleSkillError, match="coordination failed"):
        _acquire_sync_marker_lease(workspace)
    assert marker.stat().st_mtime_ns <= time.time_ns()

    with (
        pytest.raises(RuntimeError, match="injected apply failure"),
        _sync_marker_lease(workspace),
    ):
        raise RuntimeError("injected apply failure")
    assert marker.stat().st_mtime_ns <= time.time_ns()

    descriptor, lease_identity, lease_mtime = _acquire_sync_marker_lease(workspace)
    _verify_sync_marker_lease(workspace, lease_identity, lease_mtime)
    _release_sync_marker_lease(descriptor, lease_identity, lease_mtime)


@pytest.mark.skipif(sys.platform != "linux", reason="deployed flock contract is Linux-only")
def test_sync_marker_lease_is_exclusive_and_compare_released(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entrypoint_root = tmp_path / "opt"
    entrypoint_root.mkdir()
    entrypoint = entrypoint_root / "worker-entrypoint.sh"
    entrypoint.write_bytes(b"fixed five-second local push contract\n")
    entrypoint.chmod(0o755)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    marker = workspace / ".last-pull"
    marker.touch(mode=0o644)
    marker.chmod(0o644)
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.WORKER_ENTRYPOINT_PATH",
        str(entrypoint),
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.WORKER_ENTRYPOINT_SHA256",
        hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
    )

    descriptor, identity, token = _acquire_sync_marker_lease(workspace)
    with pytest.raises(RoleSkillError, match="already held"):
        _acquire_sync_marker_lease(workspace)
    assert marker.stat().st_mtime_ns == token
    _release_sync_marker_lease(descriptor, identity, token)

    descriptor, identity, token = _acquire_sync_marker_lease(workspace)
    changed = token - 1
    current = marker.stat()
    os.utime(marker, ns=(current.st_atime_ns, changed))
    with pytest.raises(RoleSkillError, match="ownership changed"):
        _release_sync_marker_lease(descriptor, identity, token)
    assert marker.stat().st_mtime_ns == changed
    now = time.time_ns()
    os.utime(marker, ns=(now, now))


def test_convergence_mutability_never_hides_builtin_or_unknown_changes() -> None:
    before: dict[str, Any] = {
        "all": ("patch-generator", "teamharness-task-execution", "unknown-safe"),
        "skillDigests": {
            "patch-generator": _hash("old-plan"),
            "teamharness-task-execution": _hash("builtin"),
            "unknown-safe": _hash("unknown"),
        },
    }
    planned: dict[str, Any] = deepcopy(before)
    planned["skillDigests"]["patch-generator"] = _hash("new-plan")
    _verify_outside_plan_preserved(before, planned, {"patch-generator"})

    changed_builtin: dict[str, Any] = deepcopy(planned)
    changed_builtin["skillDigests"]["teamharness-task-execution"] = _hash("changed")
    with pytest.raises(RoleSkillError, match="outside the convergence plan"):
        _verify_outside_plan_preserved(before, changed_builtin, {"patch-generator"})
    with pytest.raises(RoleSkillError, match="fixed DevFlow Skill set"):
        _verify_outside_plan_preserved(before, planned, {"unknown-safe"})


def test_apply_converges_local_before_remote_and_uses_two_settle_windows() -> None:
    source = inspect.getsource(_remote_main_configured)
    assert source.index("_apply_local_plan(") < source.index("_apply_remote_plan(")
    assert source.count("time.sleep(SYNC_SETTLE_SECONDS)") == 2
    assert WORKER_ENTRYPOINT_SHA256 == (
        "1ffd46d9a386a4b2f05299b39ed5d02c946dbf743749e83342cdf330ca8c37e4"
    )


def test_remote_release_verification_requires_exact_paths_sizes_and_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release = _releases()["devflow-coder"]
    spec = _parse_release_spec(release.spec_json, "devflow-coder")
    expected = spec["skills"]["patch-generator"]
    files = _load_release_archive(release.archive, spec, "devflow-coder")["patch-generator"]
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._read_remote_object",
        lambda source, _size: files[source.split("/skills/patch-generator/", maxsplit=1)[1]],
    )
    remote = {
        "files": {"patch-generator": tuple(sorted(expected))},
        "fileSizes": {"patch-generator": {name: expected[name]["size"] for name in expected}},
    }
    assert _remote_skill_matches_release(
        "storage/bucket",
        "devflow-coder",
        "patch-generator",
        remote,
        expected,
    )

    partial: dict[str, Any] = deepcopy(remote)
    partial["files"]["patch-generator"] = ("SKILL.md",)
    assert not _remote_skill_matches_release(
        "storage/bucket",
        "devflow-coder",
        "patch-generator",
        partial,
        expected,
    )


def test_bounded_remote_reader_kills_a_partial_hanging_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_popen = subprocess.Popen

    def hanging_popen(_args: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        return real_popen(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time; "
                    "sys.stdout.buffer.write(b'x'); sys.stdout.buffer.flush(); "
                    "time.sleep(30)"
                ),
            ],
            **kwargs,
        )

    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.REMOTE_READ_TIMEOUT_SECONDS",
        0.05,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.subprocess.Popen",
        hanging_popen,
    )
    with pytest.raises(RoleSkillError, match="timed out"):
        _read_remote_object("storage/bucket/object", 4)


def test_pinned_storage_root_rejects_an_alias_valid_wrong_bucket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "AGENTTEAMS_FS_ENDPOINT",
        "http://agentteams-hiclaw-minio.agentteams-system.svc.cluster.local:9000",
    )
    monkeypatch.setenv("AGENTTEAMS_FS_ACCESS_KEY", "synthetic-access")
    monkeypatch.setenv("AGENTTEAMS_FS_SECRET_KEY", "synthetic-secret")
    with pytest.raises(RoleSkillError, match="authoritative root"):
        _initialize_mc_client("agentteams/other-bucket", tmp_path)


@pytest.mark.skipif(sys.platform != "linux", reason="deployed private config mode is Linux-only")
def test_mc_credentials_are_written_to_private_config_not_process_argv(
    tmp_path: Path,
) -> None:
    config = tmp_path / "mc"
    config.mkdir(mode=0o700)
    config.chmod(0o700)
    access_key = "synthetic-access"
    secret_key = "synthetic-secret"

    _write_isolated_mc_config(
        config,
        "http://storage.invalid:9000",
        access_key,
        secret_key,
    )

    path = config / "config.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert document == {
        "aliases": {
            "agentteams": {
                "accessKey": access_key,
                "api": "S3v4",
                "path": "auto",
                "secretKey": secret_key,
                "url": "http://storage.invalid:9000",
            }
        },
        "version": "10",
    }
    source = SCRIPT.read_text(encoding="utf-8")
    assert '_mc_command("alias", "set"' not in source


def test_state_marks_stale_local_and_remote_allowed_trees_for_full_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _local_root(tmp_path, "devflow-coder")
    remote = {
        "digest": _hash("remote-partial"),
        "known": ("patch-generator",),
        "all": ("patch-generator", "teamharness-task-execution"),
        "skillDigests": {
            "patch-generator": _hash("partial"),
            "teamharness-task-execution": _hash("builtin"),
        },
        "files": {
            "patch-generator": ("SKILL.md",),
            "teamharness-task-execution": ("SKILL.md",),
        },
        "fileSizes": {
            "patch-generator": {"SKILL.md": 4},
            "teamharness-task-execution": {"SKILL.md": 4},
        },
    }
    monkeypatch.setenv("AGENTTEAMS_STORAGE_PREFIX", "storage/bucket")
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._validate_runtime_trust",
        lambda _workspace, _role: None,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._audit_remote_skills",
        lambda _prefix, _role: deepcopy(remote),
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._audit_remote_transactions",
        lambda _prefix, _role: {
            "patch-generator": {"digest": _hash("empty-transaction"), "paths": (), "sizes": {}}
        },
    )
    release = _parse_release_spec(
        _releases()["devflow-coder"].spec_json,
        "devflow-coder",
    )
    state = _state(str(root.parent), "devflow-coder", release)

    assert state["remote"]["known"] == ("patch-generator",)
    assert state["localRefresh"] == ("patch-generator",)
    assert state["remoteSync"] == ("patch-generator",)
    assert state["needsApply"] is True


def test_state_surfaces_a_durable_orphan_as_remote_sync_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes: list[list[str]] = []
    root = _local_root(tmp_path, "devflow-coder")
    remote = {
        "digest": _hash("otherwise-converged-remote"),
        "known": ("patch-generator",),
        "all": ("patch-generator", "teamharness-task-execution"),
        "skillDigests": {
            "patch-generator": _hash("release"),
            "teamharness-task-execution": _hash("builtin"),
        },
        "files": {
            "patch-generator": ("SKILL.md",),
            "teamharness-task-execution": ("SKILL.md",),
        },
        "fileSizes": {
            "patch-generator": {"SKILL.md": 4},
            "teamharness-task-execution": {"SKILL.md": 4},
        },
    }
    transaction = {
        "patch-generator": {
            "digest": _hash("orphan-transaction"),
            "paths": ("manifest.json",),
            "sizes": {"manifest.json": 100},
        }
    }
    monkeypatch.setenv("AGENTTEAMS_STORAGE_PREFIX", "storage/bucket")
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._validate_runtime_trust",
        lambda _workspace, _role: None,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._audit_remote_skills",
        lambda _prefix, _role: deepcopy(remote),
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._audit_remote_transactions",
        lambda _prefix, _role: deepcopy(transaction),
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._local_skill_matches_release",
        lambda _local, _skill, _expected: True,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._remote_skill_matches_release",
        lambda _prefix, _role, _skill, _remote, _expected: True,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._run_quiet",
        lambda args, _label: writes.append(args),
    )
    release = _parse_release_spec(
        _releases()["devflow-coder"].spec_json,
        "devflow-coder",
    )

    state = _state(str(root.parent), "devflow-coder", release)

    assert state["localRefresh"] == ()
    assert state["remoteSync"] == ("patch-generator",)
    assert state["needsApply"] is True
    assert state["remoteSnapshot"] != remote["digest"]
    assert writes == []


def test_remote_listing_accepts_known_and_builtin_skills_without_exposing_keys() -> None:
    text = _listing(
        _mc_entry("patch-generator/SKILL.md"),
        _mc_entry("patch-generator/references/contract.yaml"),
        _mc_entry("teamharness-task-execution/SKILL.md"),
    )

    state = _parse_remote_listing(text, "devflow-coder")

    assert state["known"] == ("patch-generator",)
    assert state["all"] == ("patch-generator", "teamharness-task-execution")
    assert state["files"]["patch-generator"] == (
        "SKILL.md",
        "references/contract.yaml",
    )
    assert re.fullmatch(r"[0-9a-f]{64}", state["digest"])


def test_preservation_allows_only_the_planned_partial_skill_to_change() -> None:
    before: dict[str, Any] = {
        "all": ("patch-generator", "teamharness-task-execution"),
        "skillDigests": {
            "patch-generator": _hash("partial"),
            "teamharness-task-execution": _hash("builtin"),
        },
    }
    completed: dict[str, Any] = deepcopy(before)
    completed["skillDigests"]["patch-generator"] = _hash("complete")

    _verify_preserved(
        before,
        completed,
        removed=set(),
        added=set(),
        modified={"patch-generator"},
    )
    with pytest.raises(RoleSkillError, match="allowed or built-in"):
        _verify_preserved(before, completed, removed=set(), added=set())

    completed["skillDigests"]["teamharness-task-execution"] = _hash("changed")
    with pytest.raises(RoleSkillError, match="allowed or built-in"):
        _verify_preserved(
            before,
            completed,
            removed=set(),
            added=set(),
            modified={"patch-generator"},
        )


@pytest.mark.parametrize(
    "entry",
    [
        _mc_entry("../escape/SKILL.md"),
        _mc_entry("/absolute/SKILL.md"),
        _mc_entry("patch-generator\\SKILL.md"),
        _mc_entry("patch-generator"),
        _mc_entry("patch generator/SKILL.md"),
        _mc_entry("patch-generator/SKILL.md", type="directory"),
        _mc_entry("patch-generator/SKILL.md", status="error"),
        _mc_entry("patch-generator/SKILL.md", size=-1),
    ],
)
def test_remote_listing_rejects_anomalous_keys_and_types(entry: dict[str, Any]) -> None:
    with pytest.raises(RoleSkillError):
        _parse_remote_listing(_listing(entry), "devflow-coder")


def test_remote_listing_rejects_duplicate_keys_fields_and_schema() -> None:
    entry = _mc_entry("patch-generator/SKILL.md")
    with pytest.raises(RoleSkillError, match="duplicate key"):
        _parse_remote_listing(_listing(entry, entry), "devflow-coder")

    duplicate_field = (
        '{"etag":"a","etag":"b","key":"patch-generator/SKILL.md",'
        '"lastModified":"x","size":1,"status":"success",'
        '"storageClass":"STANDARD","type":"file","url":"x",'
        '"versionOrdinal":1}\n'
    )
    with pytest.raises(RoleSkillError, match="duplicate"):
        _parse_remote_listing(duplicate_field, "devflow-coder")

    extra = entry | {"credential": SECRET_SENTINEL}
    with pytest.raises(RoleSkillError, match="schema"):
        _parse_remote_listing(_listing(extra), "devflow-coder")


@pytest.mark.parametrize(
    "prefix",
    ["", "alias", "alias/bucket/", "alias//bucket", "-alias/bucket", "alias/../bucket"],
)
def test_storage_prefix_rejects_noncanonical_or_broad_targets(prefix: str) -> None:
    with pytest.raises(RoleSkillError):
        _validate_storage_prefix(prefix)
    assert _validate_storage_prefix("agentteams/agentteams-storage") == (
        "agentteams/agentteams-storage"
    )


def test_pinned_storage_prefix_matches_the_live_two_component_shape() -> None:
    assert MC_STORAGE_PREFIX == "agentteams/agentteams-storage"
    assert _validate_storage_prefix(MC_STORAGE_PREFIX) == MC_STORAGE_PREFIX


def test_remote_delete_uses_only_fixed_exact_mc_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], str]] = []
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._run_quiet",
        lambda args, label: calls.append((args, label)),
    )

    _remove_remote_skill(
        "storage/bucket",
        "devflow-coder",
        "issue-classifier",
    )

    assert calls == [
        (
            [
                "mc",
                "rm",
                "--recursive",
                "--force",
                "--",
                "storage/bucket/agents/devflow-coder/skills/issue-classifier/",
            ],
            "object deletion",
        )
    ]
    with pytest.raises(RoleSkillError, match="outside role policy"):
        _remove_remote_skill("storage/bucket", "devflow-coder", "patch-generator")
    with pytest.raises(RoleSkillError, match="outside role policy"):
        _remove_remote_skill(
            "storage/bucket",
            "devflow-coder",
            "teamharness-task-execution",
        )
    with pytest.raises(RoleSkillError, match="storage prefix"):
        _remove_remote_skill("storage/bucket/", "devflow-coder", "issue-classifier")
    assert len(calls) == 1


def test_transaction_cleanup_is_bounded_to_one_fixed_role_skill_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._audit_remote_transaction",
        lambda _prefix, _role, _skill: {
            "digest": _hash("transaction"),
            "paths": ("staging/SKILL.md",),
            "sizes": {"staging/SKILL.md": 4},
        },
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills._run_quiet",
        lambda args, _label: calls.append(args),
    )

    _remove_transaction_tree(
        "storage/bucket",
        "devflow-coder",
        "patch-generator",
        "staging",
    )

    assert calls == [
        [
            "mc",
            "rm",
            "--recursive",
            "--force",
            "--",
            (
                "storage/bucket/agents/devflow-coder/"
                ".devflow-role-skill-transactions/patch-generator/staging/"
            ),
        ]
    ]
    with pytest.raises(RoleSkillError, match="outside policy"):
        _remove_transaction_tree(
            "storage/bucket",
            "devflow-coder",
            "patch-generator",
            "../backup",
        )
    with pytest.raises(RoleSkillError, match="outside role policy"):
        _remove_transaction_tree(
            "storage/bucket",
            "devflow-coder",
            "teamharness-task-execution",
            "staging",
        )
    assert len(calls) == 1


def test_helper_name_lists_reject_mixed_types_without_type_error() -> None:
    with pytest.raises(RoleSkillError, match="invalid local Skill names"):
        _name_list(["patch-generator", 1], "local Skill names")


@pytest.mark.parametrize("kind", ["List", "PodList"])
def test_check_preflights_exact_six_and_never_writes(kind: str) -> None:
    pods = _pods()
    pods["kind"] = kind
    runner = _FakeRunner(pods=pods, drift_roles={"devflow-coder", "devflow-lead"})

    result = reconcile(runner, releases=_releases())

    assert len(result.reports) == 6
    assert result.changed_roles == ()
    assert len(_helper_calls(runner, "check")) == 6
    assert not _helper_calls(runner, "apply")
    assert sum(report.needs_apply for report in result.reports) == 2


def test_stale_content_is_drift_even_when_known_skill_names_are_exact() -> None:
    runner = _FakeRunner(refresh_roles={"devflow-locator"})

    result = reconcile(runner, releases=_releases())

    locator = next(
        report for report in result.reports if report.target.role_name == "devflow-locator"
    )
    assert locator.local_known == locator.allowed
    assert locator.remote_known == locator.allowed
    assert locator.local_refresh == locator.allowed
    assert locator.remote_sync == locator.allowed
    assert locator.needs_apply is True
    assert not _helper_calls(runner, "apply")


@pytest.mark.parametrize("failure", ["missing", "duplicate", "unready", "matrix"])
def test_discovery_failure_never_invokes_remote_helper(failure: str) -> None:
    team = _team()
    pods = _pods(team)
    if failure == "missing":
        pods["items"].pop()
    elif failure == "duplicate":
        pods["items"][-1] = deepcopy(pods["items"][0])
        pods["items"][-1]["metadata"]["name"] = "pod-duplicate"
    elif failure == "unready":
        pods["items"][0]["status"]["conditions"][0]["status"] = "False"
        pods["items"][0]["status"]["containerStatuses"][0]["ready"] = False
    else:
        team["status"]["members"][0]["matrixUserID"] = "@wrong:matrix.invalid"
    runner = _FakeRunner(team, pods)

    with pytest.raises(RuntimeError):
        reconcile(runner, releases=_releases())
    assert not _helper_calls(runner, "check")
    assert not _helper_calls(runner, "apply")


def test_apply_has_two_all_pod_snapshots_before_first_write_and_final_readback() -> None:
    drift_roles = {"devflow-coder", "devflow-lead"}
    runner = _FakeRunner(drift_roles=drift_roles)

    result = reconcile(runner, releases=_releases(), apply=True)

    checks = _helper_calls(runner, "check")
    prepares = _helper_calls(runner, "prepare")
    applies = _helper_calls(runner, "apply")
    assert len(checks) == 18
    assert len(prepares) == 6
    assert len(applies) == 2
    assert max(_helper_call_indices(runner, "check")[:12]) < min(
        _helper_call_indices(runner, "prepare")
    )
    assert max(_helper_call_indices(runner, "prepare")) < min(
        _helper_call_indices(runner, "apply")
    )
    assert result.changed_roles == tuple(sorted(drift_roles))
    assert all(not report.needs_apply for report in result.reports)
    invocations = _helper_invocations(runner, "apply")
    assert {parameters[2] for _call, parameters, _payload in invocations} == drift_roles
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", parameters[-2])
        for _call, parameters, _payload in invocations
    )
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", parameters[-1])
        for _call, parameters, _payload in invocations
    )
    for call, parameters, payload in invocations:
        assert payload == _releases()[parameters[2]].archive
        assert "--stdin" in call
        assert parameters[0] == _releases()[parameters[2]].spec_json
        assert parameters[0] not in call
        assert REMOTE_HELPER not in call


def test_apply_barrier_drift_fails_before_first_write() -> None:
    runner = _FakeRunner(
        drift_roles={"devflow-coder"},
        barrier_drift_role="devflow-coder",
    )

    with pytest.raises(RoleSkillError, match="all-Pod apply barrier"):
        reconcile(runner, releases=_releases(), apply=True)
    assert len(_helper_calls(runner, "check")) == 12
    assert not _helper_calls(runner, "apply")


def test_final_readback_rejects_drift_in_an_unchanged_role() -> None:
    runner = _FakeRunner(
        drift_roles={"devflow-coder"},
        final_drift_role="devflow-reviewer",
    )

    with pytest.raises(RoleSkillError, match="final all-Pod readback"):
        reconcile(runner, releases=_releases(), apply=True)
    assert len(_helper_calls(runner, "apply")) == 1


def test_compliant_apply_is_zero_write() -> None:
    runner = _FakeRunner()

    result = reconcile(runner, releases=_releases(), apply=True)

    assert result.changed_roles == ()
    assert len(_helper_calls(runner, "check")) == 6
    assert not _helper_calls(runner, "apply")


def test_apply_summary_separates_historical_controller_change_from_final_state(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import scripts.reconcile_agentteams_role_skills as role_module
    from scripts.reconcile_agentteams_controller_cache import (
        ARCHIVE_DIGESTS,
        ARCHIVE_SIZES,
        ControllerCacheReport,
        ControllerReconcileResult,
        ControllerTarget,
    )
    from scripts.reconcile_teamharness_openclaw import Target as HarnessTarget

    worker_reports: list[role_module.Report] = []
    controller_reports: list[ControllerCacheReport] = []
    for role in sorted(ROLE_SKILLS):
        allowed = tuple(sorted(ROLE_SKILLS[role]))
        target = HarnessTarget(
            role,
            f"member-{role}",
            f"@{role}:matrix.invalid",
            f"pod-{role}",
        )
        worker_reports.append(
            role_module.Report(
                target=target,
                allowed=allowed,
                local_known=allowed,
                remote_known=allowed,
                local_remove=(),
                remote_remove=(),
                local_refresh=(),
                remote_sync=(),
                local_snapshot=_hash(f"local:{role}"),
                remote_snapshot=_hash(f"remote:{role}"),
                needs_apply=False,
                applied=True,
            )
        )
        controller_reports.append(
            ControllerCacheReport(
                role=role,
                archive_size=ARCHIVE_SIZES[role],
                archive_digest=ARCHIVE_DIGESTS[role],
                archive_valid=True,
                known_skills=allowed,
                stable_skill_digests=tuple(
                    (skill, _hash(f"controller:{role}:{skill}")) for skill in allowed
                ),
                unknown_count=0,
                unknown_digest=_hash("empty-controller-unknown"),
                snapshot=_hash(f"controller:{role}"),
            )
        )
    controller_target = ControllerTarget(
        deployment_uid=_hash("deployment")[:32],
        replica_set_name="agentteams-hiclaw-controller-fixed",
        replica_set_uid=_hash("replicaset")[:32],
        pod_name="agentteams-hiclaw-controller-fixed-pod",
        pod_uid=_hash("pod")[:32],
        image="pinned",
        image_id="pinned-id",
        restart_count=0,
    )
    result = role_module.AuthorityReconcileResult(
        worker=role_module.ReconcileResult(tuple(worker_reports), ("devflow-coder",)),
        controller=ControllerReconcileResult(
            target=controller_target,
            reports=tuple(controller_reports),
            changed_roles=(),
            transaction_id=_hash("transaction"),
        ),
        changed_roles=("devflow-coder",),
        controller_changed_roles=("devflow-coder",),
        worker_changed_roles=("devflow-coder",),
    )
    monkeypatch.setattr(role_module, "reconcile_all_authorities", lambda *args, **kwargs: result)

    assert role_module.main(["--apply", "--dist", "dist"]) == 0
    summary = json.loads(capsys.readouterr().out)
    coder = next(item for item in summary["roles"] if item["name"] == "devflow-coder")
    assert summary["devflowPolicyVerified"] is True
    assert summary["completeRoleSkillBoundaryVerified"] is False
    assert summary["verificationScope"] == "fixed-seven-devflow-skills"
    assert summary["changedRoles"] == ["devflow-coder"]
    assert coder["controllerCacheChanged"] is True
    assert coder["controllerCacheNeedsApply"] is False


def test_malformed_helper_output_is_generic_and_starts_no_apply() -> None:
    runner = _FakeRunner(
        drift_roles={"devflow-coder"},
        malformed_role="devflow-reviewer",
    )

    with pytest.raises(RoleSkillError) as captured:
        reconcile(runner, releases=_releases(), apply=True)
    assert SECRET_SENTINEL not in str(captured.value)
    assert not _helper_calls(runner, "apply")


def test_subprocess_failure_never_includes_remote_output() -> None:
    runner = SubprocessRunner()
    command = [
        sys.executable,
        "-c",
        (
            "import sys; "
            f"sys.stdout.write({SECRET_SENTINEL!r}); "
            f"sys.stderr.write({SECRET_SENTINEL!r}); "
            "raise SystemExit(1)"
        ),
    ]

    with pytest.raises(RoleSkillError) as captured:
        runner.run(command)
    assert SECRET_SENTINEL not in str(captured.value)


def test_subprocess_runner_bounds_output_and_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SubprocessRunner()
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.MAX_HOST_OUTPUT_BYTES",
        4,
    )
    with pytest.raises(RoleSkillError, match="output exceeded"):
        runner.run([sys.executable, "-c", "import sys; sys.stdout.write('12345')"])

    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.HOST_COMMAND_TIMEOUT_SECONDS",
        0.05,
    )
    with pytest.raises(RoleSkillError, match="timed out"):
        runner.run([sys.executable, "-c", "import time; time.sleep(30)"])


def test_helper_host_and_lease_timeout_budgets_are_strictly_ordered() -> None:
    assert APPLY_HELPER_MAX_SECONDS > 0
    assert (
        HOST_COMMAND_TIMEOUT_SECONDS
        >= APPLY_HELPER_MAX_SECONDS + HOST_HELPER_MARGIN_SECONDS
    )
    assert (
        SYNC_LEASE_SECONDS
        >= HOST_COMMAND_TIMEOUT_SECONDS + LEASE_RECOVERY_MARGIN_SECONDS
    )


def test_remote_helper_deadline_raises_and_restores_signal_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed: dict[str, Any] = {}
    timer_calls: list[tuple[int, float]] = []
    previous_handler = object()

    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.signal.SIGALRM",
        14,
        raising=False,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.signal.ITIMER_REAL",
        0,
        raising=False,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.signal.getsignal",
        lambda signum: previous_handler if signum == 14 else None,
    )

    def set_handler(signum: int, handler: Any) -> object:
        assert signum == 14
        installed["handler"] = handler
        return previous_handler

    def set_timer(timer: int, seconds: float) -> tuple[float, float]:
        timer_calls.append((timer, seconds))
        return (0.0, 0.0)

    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.signal.signal",
        set_handler,
    )
    monkeypatch.setattr(
        "scripts.reconcile_agentteams_role_skills.signal.setitimer",
        set_timer,
        raising=False,
    )

    with pytest.raises(RoleSkillError, match="execution budget"), _remote_helper_deadline():
        installed_handler = installed["handler"]
        assert callable(installed_handler)
        installed_handler(14, None)

    assert timer_calls == [(0, APPLY_HELPER_MAX_SECONDS), (0, 0.0)]
    assert installed["handler"] is previous_handler


def test_remote_helper_contains_runtime_and_type_gates_without_broad_delete() -> None:
    text = SCRIPT.read_text(encoding="utf-8")

    assert "_validate_runtime_trust(workspace, role)" in REMOTE_HELPER
    assert 'os.environ.get("AGENTTEAMS_WORKER_NAME") != role' in REMOTE_HELPER
    assert 'os.environ.get("HOME") != workspace' in REMOTE_HELPER
    assert "Path.cwd().resolve() != workspace_path" in REMOTE_HELPER
    assert '_mc_command("rm", "--recursive", "--force", "--", remote_skill)' in text
    assert 'remote_skill = f"{prefix}/agents/{role}/skills/{skill}/"' in text
    assert 'role_root = f"{prefix}/agents/{role}/skills/"' in text
    assert '_mc_command("ls", "--recursive", "--json", role_root)' in text
    assert 'MC_BINARY_PATH = "/usr/local/bin/mc.bin"' in text
    assert 'MC_STORAGE_PREFIX = "agentteams/agentteams-storage"' in text
    assert 'TemporaryDirectory(prefix="devflow-role-skill-mc-")' in text
    assert "shutil.rmtree" not in text
    assert "shell=True" not in text
    assert "get secret" not in text.lower()
    for verb in ("apply", "create", "patch", "delete"):
        assert f'_kubectl(kubectl, "{verb}"' not in text


def test_kubectl_argv_is_short_and_all_helper_material_is_stdin_framed() -> None:
    target = Target(
        "devflow-coder",
        "member-coder",
        "@devflow-coder:matrix.invalid",
        "pod-devflow-coder",
    )
    release = _releases()["devflow-coder"]
    parameters = _helper_parameters(
        target,
        release,
        "apply",
        _hash("local"),
        _hash("remote"),
    )
    command = _exec_helper("kubectl", target)
    frame = _remote_frame(REMOTE_HELPER, parameters, release.archive)
    source, decoded_parameters, payload = _decode_remote_frame(frame)
    encoded = [item.encode("utf-8") for item in command]

    assert max(map(len, encoded)) <= MAX_KUBECTL_ARGUMENT_BYTES
    assert sum(len(item) + 1 for item in encoded) <= MAX_KUBECTL_ARGV_BYTES
    assert "--stdin" in command
    assert command[-3:] == ["python3", "-c", REMOTE_STDIN_BOOTSTRAP]
    assert REMOTE_HELPER not in command
    assert release.spec_json not in command
    assert target.workspace not in command
    assert source == REMOTE_HELPER
    assert decoded_parameters == parameters
    assert payload == release.archive
    assert len(frame) <= MAX_REMOTE_FRAME_BYTES


def test_remote_frame_rejects_each_unbounded_section() -> None:
    parameters = ["x"] * 6
    with pytest.raises(RoleSkillError, match="outside policy"):
        _remote_frame("x" * (MAX_REMOTE_HELPER_SOURCE_BYTES + 1), parameters, None)
    with pytest.raises(RoleSkillError, match="outside policy"):
        _remote_frame("pass", ["x" * MAX_REMOTE_PARAMETERS_BYTES] * 6, None)
    with pytest.raises(RoleSkillError, match="outside policy"):
        _remote_frame("pass", parameters, b"x" * (MAX_ARCHIVE_BYTES + 1))
    with pytest.raises(RoleSkillError, match="outside policy"):
        _remote_frame("pass", parameters[:5], None)


def test_short_stdin_bootstrap_injects_parameters_without_os_argv() -> None:
    helper = (
        "import hashlib, json, sys\n"
        "payload = sys.stdin.buffer.read()\n"
        "print(json.dumps({'osArgv': sys.argv[1:], "
        "'parameters': _DEVFLOW_REMOTE_PARAMETERS, "
        "'payloadSha256': hashlib.sha256(payload).hexdigest()}, sort_keys=True))\n"
    )
    parameters = ["release", "apply", "role", "workspace", _hash("local"), _hash("remote")]
    payload = b"binary\x00payload\xff"
    completed = subprocess.run(
        [sys.executable, "-S", "-c", REMOTE_STDIN_BOOTSTRAP],
        input=_remote_frame(helper, parameters, payload),
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert value == {
        "osArgv": [],
        "parameters": parameters,
        "payloadSha256": hashlib.sha256(payload).hexdigest(),
    }
    assert completed.stderr == b""


def test_short_stdin_bootstrap_rejects_truncated_frame() -> None:
    frame = _remote_frame("print('unreachable')", ["x"] * 6, None)
    completed = subprocess.run(
        [sys.executable, "-S", "-c", REMOTE_STDIN_BOOTSTRAP],
        input=frame[:-1],
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 97
    assert completed.stdout == b""
    assert completed.stderr == b""


def test_help_and_embedded_helper_run_without_site_packages() -> None:
    completed = subprocess.run(
        [sys.executable, "-S", str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "--apply" in completed.stdout
    assert "--namespace" not in completed.stdout
    assert "--team" not in completed.stdout

    helper = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "from scripts.reconcile_agentteams_role_skills import REMOTE_HELPER; "
                "compile(REMOTE_HELPER, '<remote-helper>', 'exec')"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert helper.returncode == 0, helper.stderr

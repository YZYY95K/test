from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from scripts.reconcile_agentteams_controller_cache import (
    ALL_FIXED_SKILLS,
    ARCHIVE_DIGESTS,
    ARCHIVE_SIZES,
    CONTAINER_NAME,
    CONTROLLER_ARCHIVE_REPLACE_HELPER,
    CONTROLLER_AUDIT_HELPER,
    CONTROLLER_CONVERGE_HELPER,
    CONTROLLER_IMAGE,
    CONTROLLER_IMAGE_ID,
    CONTROLLER_PREPARE_HELPER,
    DEPLOYMENT_NAME,
    NAMESPACE,
    ROLE_SKILLS,
    SELECTOR_LABELS,
    ControllerCacheError,
    check_controller_authority,
    discover_controller,
    expected_controller_skill_digests,
    reconcile_controller_authority,
)
from scripts.reconcile_agentteams_role_skills import load_role_releases


def _uid(name: str) -> str:
    return hashlib.sha256(name.encode()).hexdigest()[:32]


def _owner(kind: str, name: str, uid: str) -> list[dict[str, Any]]:
    return [
        {
            "apiVersion": "apps/v1",
            "kind": kind,
            "name": name,
            "uid": uid,
            "controller": True,
            "blockOwnerDeletion": True,
        }
    ]


def _objects() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    deployment_uid = _uid("deployment")
    rs_name = f"{DEPLOYMENT_NAME}-abc123"
    rs_uid = _uid("replicaset")
    pod_name = f"{rs_name}-xyz12"
    container = {"name": CONTAINER_NAME, "image": CONTROLLER_IMAGE}
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": DEPLOYMENT_NAME,
            "namespace": NAMESPACE,
            "uid": deployment_uid,
            "generation": 3,
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": SELECTOR_LABELS},
            "template": {
                "metadata": {"labels": {**SELECTOR_LABELS, "extra": "safe"}},
                "spec": {"containers": [container]},
            },
        },
        "status": {
            "observedGeneration": 3,
            "replicas": 1,
            "readyReplicas": 1,
            "availableReplicas": 1,
            "updatedReplicas": 1,
        },
    }
    replica_set = {
        "apiVersion": "apps/v1",
        "kind": "ReplicaSet",
        "metadata": {
            "name": rs_name,
            "namespace": NAMESPACE,
            "uid": rs_uid,
            "ownerReferences": _owner("Deployment", DEPLOYMENT_NAME, deployment_uid),
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {**SELECTOR_LABELS, "pod-template-hash": "abc123"}},
            "template": {
                "metadata": {"labels": SELECTOR_LABELS},
                "spec": {"containers": [container]},
            },
        },
        "status": {
            "replicas": 1,
            "readyReplicas": 1,
            "availableReplicas": 1,
            "fullyLabeledReplicas": 1,
        },
    }
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": NAMESPACE,
            "uid": _uid("pod"),
            "labels": SELECTOR_LABELS,
            "ownerReferences": _owner("ReplicaSet", rs_name, rs_uid),
        },
        "spec": {"containers": [container]},
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
            "containerStatuses": [
                {
                    "name": CONTAINER_NAME,
                    "ready": True,
                    "restartCount": 0,
                    "image": CONTROLLER_IMAGE,
                    "imageID": f"docker-pullable://{CONTROLLER_IMAGE_ID}",
                }
            ],
        },
    }
    return (
        deployment,
        {"kind": "ReplicaSetList", "items": [replica_set]},
        {"kind": "PodList", "items": [pod]},
    )


@dataclass(frozen=True)
class _Release:
    archive_digest: str


def _releases() -> dict[str, _Release]:
    return {role: _Release(digest) for role, digest in ARCHIVE_DIGESTS.items()}


def _audit() -> str:
    roles: dict[str, Any] = {}
    empty = hashlib.sha256(b"").hexdigest()
    for role in ROLE_SKILLS:
        known = sorted(ROLE_SKILLS[role])
        roles[role] = {
            "archiveSize": ARCHIVE_SIZES[role],
            "archiveSha256": ARCHIVE_DIGESTS[role],
            "archiveValid": True,
            "knownSkills": known,
            "stableSkillDigests": {
                skill: hashlib.sha256(skill.encode()).hexdigest() for skill in known
            },
            "unknownCount": 0,
            "unknownDigest": empty,
            "snapshot": hashlib.sha256(role.encode()).hexdigest(),
        }
    return json.dumps({"ok": True, "roles": roles})


class _Runner:
    def __init__(self) -> None:
        self.deployment, self.replica_sets, self.pods = _objects()
        self.calls: list[list[str]] = []
        self.inputs: list[bytes | None] = []
        self.audit = _audit()

    def run(self, args: list[str], input_data: bytes | None = None) -> str:
        self.calls.append(list(args))
        self.inputs.append(input_data)
        if "deployment" in args:
            return json.dumps(self.deployment)
        if "replicasets" in args:
            return json.dumps(self.replica_sets)
        if "pods" in args:
            return json.dumps(self.pods)
        if "exec" in args:
            return self.audit
        return ""


def test_discovers_unique_pinned_controller_chain() -> None:
    runner = _Runner()
    target = discover_controller(runner)
    assert target.pod_name.endswith("-xyz12")
    assert target.image == CONTROLLER_IMAGE
    assert target.image_id == CONTROLLER_IMAGE_ID
    assert target.restart_count == 0
    assert all(call[0] == "kubectl" for call in runner.calls)


@pytest.mark.parametrize("kind", ["second-rs", "second-pod"])
def test_discovery_rejects_ambiguous_owner_chain(kind: str) -> None:
    runner = _Runner()
    if kind == "second-rs":
        runner.replica_sets["items"].append(runner.replica_sets["items"][0])
    else:
        runner.pods["items"].append(runner.pods["items"][0])
    with pytest.raises(ControllerCacheError, match="exactly one"):
        discover_controller(runner)


def test_discovery_rejects_unpinned_runtime_image_id() -> None:
    runner = _Runner()
    runner.pods["items"][0]["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "0" * 64
    with pytest.raises(ControllerCacheError, match="runtime identity"):
        discover_controller(runner)


def _add_historical_replica_set(runner: _Runner) -> dict[str, Any]:
    historical = copy.deepcopy(runner.replica_sets["items"][0])
    historical["metadata"]["name"] = f"{DEPLOYMENT_NAME}-old123"
    historical["metadata"]["uid"] = _uid("historical")
    historical["spec"]["replicas"] = 0
    historical["spec"]["template"]["spec"]["containers"][0]["image"] = "old/image:tag"
    historical["status"] = {
        "replicas": 0,
        "readyReplicas": 0,
        "availableReplicas": 0,
        "fullyLabeledReplicas": 0,
    }
    runner.replica_sets["items"].append(historical)
    return cast(dict[str, Any], historical)


def test_discovery_accepts_owned_scaled_to_zero_historical_replica_set() -> None:
    runner = _Runner()
    _add_historical_replica_set(runner)
    assert discover_controller(runner).pod_name.endswith("-xyz12")


def test_discovery_rejects_historical_replica_set_that_is_not_scaled_down() -> None:
    runner = _Runner()
    historical = _add_historical_replica_set(runner)
    historical["status"]["readyReplicas"] = 1
    with pytest.raises(ControllerCacheError, match="scaled down"):
        discover_controller(runner)


def test_check_returns_only_fixed_names_and_digests() -> None:
    runner = _Runner()
    target = discover_controller(runner)
    reports = check_controller_authority(runner, target, _releases())
    assert tuple(report.role for report in reports) == tuple(ROLE_SKILLS)
    assert all(report.archive_valid for report in reports)
    assert {name for report in reports for name in report.known_skills} <= set(ALL_FIXED_SKILLS)
    exec_index = next(index for index, call in enumerate(runner.calls) if "exec" in call)
    assert runner.inputs[exec_index] == CONTROLLER_AUDIT_HELPER.encode()
    assert "--stdin" in runner.calls[exec_index]
    assert runner.calls[exec_index][-2:] == ["/bin/sh", "-s"]


def test_check_rejects_untrusted_release_before_exec() -> None:
    runner = _Runner()
    target = discover_controller(runner)
    releases = _releases()
    releases["devflow-coder"] = _Release("0" * 64)
    with pytest.raises(ControllerCacheError, match="release identity"):
        check_controller_authority(runner, target, releases)
    assert not any("exec" in call for call in runner.calls)


def test_check_accepts_archive_mismatch_as_read_only_evidence() -> None:
    runner = _Runner()
    target = discover_controller(runner)
    value = json.loads(runner.audit)
    value["roles"]["devflow-coder"]["archiveSize"] += 1
    value["roles"]["devflow-coder"]["archiveValid"] = False
    runner.audit = json.dumps(value)
    reports = check_controller_authority(runner, target, _releases())
    assert not next(report for report in reports if report.role == "devflow-coder").archive_valid


def test_check_rejects_unknown_name_or_digest_leak_in_schema() -> None:
    runner = _Runner()
    target = discover_controller(runner)
    value = json.loads(runner.audit)
    value["roles"]["devflow-coder"]["knownSkills"].append("private-unknown")
    with pytest.raises(ControllerCacheError, match="fixed Skill names"):
        runner.audit = json.dumps(value)
        check_controller_authority(runner, target, _releases())


def test_helper_is_busybox_shell_only_and_has_fail_closed_guards() -> None:
    assert "python" not in CONTROLLER_AUDIT_HELPER.lower()
    assert 'find "$root" -xdev' in CONTROLLER_AUDIT_HELPER
    assert "reject_mounts" in CONTROLLER_AUDIT_HELPER
    assert '[ -L "$path" ]' in CONTROLLER_AUDIT_HELPER
    assert "stat -c %h" in CONTROLLER_AUDIT_HELPER
    assert "unknown_digest" in CONTROLLER_AUDIT_HELPER
    assert 'cat "$path"' not in CONTROLLER_AUDIT_HELPER


def test_release_tree_digest_matches_the_pinned_archive_layout() -> None:
    releases = load_role_releases(Path("dist"))
    digests = expected_controller_skill_digests(releases)
    assert digests["devflow-coder"]["patch-generator"] == (
        "78e8bf8f1af297167d0eea8903be3c60645edef21f4e4acba9e2713d4c45d8b3"
    )
    assert digests["devflow-lead"] == {}
    assert {role: tuple(sorted(value)) for role, value in digests.items()} == {
        role: tuple(sorted(skills)) for role, skills in ROLE_SKILLS.items()
    }


def test_apply_helpers_keep_staging_outside_agents_and_only_move_fixed_skills() -> None:
    assert 'tx="$base/.devflow-role-skills-$txid"' in CONTROLLER_PREPARE_HELPER
    assert 'mv -nT "$probe" "$moved"' in CONTROLLER_PREPARE_HELPER
    assert 'tx="$base/.devflow-role-skills-$txid"' in CONTROLLER_CONVERGE_HELPER
    assert 'root="/root/hiclaw-fs/agents/$role/skills"' in CONTROLLER_CONVERGE_HELPER
    assert 'mv -nT "$source" "$destination"' in CONTROLLER_CONVERGE_HELPER
    assert "rm -rf" not in CONTROLLER_CONVERGE_HELPER
    assert "rm -rf" not in CONTROLLER_PREPARE_HELPER
    for skill in ALL_FIXED_SKILLS:
        assert skill in CONTROLLER_CONVERGE_HELPER


def test_archive_replacement_is_exact_path_bounded_atomic_and_recoverable() -> None:
    assert 'target="$base/$role-v1.2.0.zip"' in CONTROLLER_ARCHIVE_REPLACE_HELPER
    assert 'cp -p "$target" "$saved"' in CONTROLLER_ARCHIVE_REPLACE_HELPER
    assert 'mv -fT "$stage" "$target"' in CONTROLLER_ARCHIVE_REPLACE_HELPER
    assert 'mv -nT "$stage" "$target"' in CONTROLLER_ARCHIVE_REPLACE_HELPER
    assert 'actual=$(sha256sum "$stage")' in CONTROLLER_ARCHIVE_REPLACE_HELPER
    assert "rm -rf" not in CONTROLLER_ARCHIVE_REPLACE_HELPER


class _ApplyRunner(_Runner):
    def __init__(
        self,
        expected: dict[str, dict[str, str]],
        *,
        prepare_failure: bool = False,
        converge_failure: bool = False,
        change_identity_after_converge: bool = False,
    ) -> None:
        super().__init__()
        self.expected = expected
        self.prepare_failure = prepare_failure
        self.converge_failure = converge_failure
        self.change_identity_after_converge = change_identity_after_converge
        self.converged: set[str] = set()
        self.prepare_calls = 0
        self.converge_calls = 0

    def _dynamic_audit(self) -> str:
        roles: dict[str, Any] = {}
        unknown_digest = _uid("preserved-controller-unknown") + _uid(
            "preserved-controller-unknown-tail"
        )
        for role, allowed in ROLE_SKILLS.items():
            stable = dict(self.expected[role])
            if role == "devflow-coder" and role not in self.converged:
                stable["patch-generator"] = hashlib.sha256(b"stale-cache").hexdigest()
            roles[role] = {
                "archiveSize": ARCHIVE_SIZES[role],
                "archiveSha256": ARCHIVE_DIGESTS[role],
                "archiveValid": True,
                "knownSkills": sorted(allowed),
                "stableSkillDigests": stable,
                "unknownCount": 2,
                "unknownDigest": unknown_digest,
                "snapshot": hashlib.sha256(
                    f"{role}:{sorted(stable.items())}:2:{unknown_digest}".encode()
                ).hexdigest(),
            }
        return json.dumps({"ok": True, "roles": roles})

    def run(self, args: list[str], input_data: bytes | None = None) -> str:
        self.calls.append(list(args))
        self.inputs.append(input_data)
        if "deployment" in args:
            return json.dumps(self.deployment)
        if "replicasets" in args:
            return json.dumps(self.replica_sets)
        if "pods" in args:
            return json.dumps(self.pods)
        if "exec" not in args:
            return ""
        if input_data == CONTROLLER_AUDIT_HELPER.encode():
            return self._dynamic_audit()
        if input_data == CONTROLLER_PREPARE_HELPER.encode():
            self.prepare_calls += 1
            return "failed\n" if self.prepare_failure else "ok\n"
        if input_data == CONTROLLER_CONVERGE_HELPER.encode():
            self.converge_calls += 1
            if self.converge_failure:
                return "failed\n"
            role = args[-4]
            self.converged.add(role)
            if self.change_identity_after_converge:
                self.pods["items"][0]["metadata"]["uid"] = _uid("replacement-pod")
                self.pods["items"][0]["status"]["containerStatuses"][0][
                    "restartCount"
                ] = 1
                self.change_identity_after_converge = False
            return "ok\n"
        raise AssertionError("unexpected controller write")


def _controller_releases() -> dict[str, Any]:
    return load_role_releases(Path("dist"))


def test_reconcile_controller_authority_executes_prepare_and_converges_cache() -> None:
    releases = _controller_releases()
    expected = expected_controller_skill_digests(releases)
    runner = _ApplyRunner(expected)
    target = discover_controller(runner)

    result = reconcile_controller_authority(runner, target, releases, apply=True)

    assert result.changed_roles == ("devflow-coder",)
    assert result.transaction_id is not None
    assert runner.prepare_calls == 1
    assert runner.converge_calls == 1
    assert all(report.unknown_count == 2 for report in result.reports)
    assert not reconcile_controller_authority(
        runner,
        discover_controller(runner),
        releases,
        apply=False,
    ).changed_roles


def test_reconcile_controller_authority_prepare_failure_starts_no_convergence() -> None:
    releases = _controller_releases()
    runner = _ApplyRunner(
        expected_controller_skill_digests(releases),
        prepare_failure=True,
    )

    with pytest.raises(ControllerCacheError, match="preparation failed"):
        reconcile_controller_authority(
            runner,
            discover_controller(runner),
            releases,
            apply=True,
        )
    assert runner.prepare_calls == 1
    assert runner.converge_calls == 0


def test_reconcile_controller_authority_convergence_failure_is_fail_closed() -> None:
    releases = _controller_releases()
    runner = _ApplyRunner(
        expected_controller_skill_digests(releases),
        converge_failure=True,
    )

    with pytest.raises(ControllerCacheError, match="convergence failed"):
        reconcile_controller_authority(
            runner,
            discover_controller(runner),
            releases,
            apply=True,
        )
    assert runner.prepare_calls == 1
    assert runner.converge_calls == 1
    assert "devflow-coder" not in runner.converged


def test_controller_identity_change_fails_then_fresh_identity_retry_converges() -> None:
    releases = _controller_releases()
    runner = _ApplyRunner(
        expected_controller_skill_digests(releases),
        change_identity_after_converge=True,
    )
    first_target = discover_controller(runner)

    with pytest.raises(ControllerCacheError, match="identity changed"):
        reconcile_controller_authority(runner, first_target, releases, apply=True)
    replacement_target = discover_controller(runner)
    assert replacement_target != first_target

    retried = reconcile_controller_authority(
        runner,
        replacement_target,
        releases,
        apply=True,
    )
    assert retried.changed_roles == ()
    assert retried.transaction_id is None
    assert runner.converge_calls == 1

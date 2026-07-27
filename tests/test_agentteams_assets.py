"""Checks for competition-critical AgentTeams deployment assets."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile
from pathlib import Path

import pytest
import yaml

import scripts.build_agentteams_package as package_builder
from devflow.agents.coder_agent import CoderAgent
from devflow.agents.locator_agent import LocatorAgent
from devflow.agents.reviewer_agent import ReviewerAgent
from devflow.agents.tester_agent import TesterAgent as DevFlowTesterAgent
from devflow.agents.triage_agent import TriageAgent
from devflow.skills.catalog import (
    load_catalog,
    validate_agent_alignment,
    validate_collaboration,
    validate_mcp_alignment,
)
from scripts.build_agentteams_package import (
    MAX_SOURCE_FILE_BYTES,
    PACKAGE_VERSION,
    ROLE_OWNERS,
    ROLE_SKILLS,
    WORKER_BASE_IMAGE,
    PackageBuildError,
    build_package,
    build_role_packages,
    manifest_digest,
    read_regular_file,
)
from scripts.reconcile_agentteams_packages import CONFIGMAP_NAME, NAMESPACE

ROOT = Path(__file__).resolve().parents[1]


def test_team_manifest_maps_all_domain_workers() -> None:
    resource = yaml.safe_load((ROOT / "agentteams" / "team.yaml").read_text(encoding="utf-8"))

    assert resource["apiVersion"] == "agentteams.io/v1beta1"
    assert resource["kind"] == "Team"
    assert resource["metadata"]["name"] == "devflow-swe"
    assert resource["spec"]["leader"]["name"] == "devflow-lead"
    assert {worker["name"] for worker in resource["spec"]["workers"]} == {
        "devflow-triage",
        "devflow-locator",
        "devflow-coder",
        "devflow-tester",
        "devflow-reviewer",
    }
    for worker in resource["spec"]["workers"]:
        for server in worker.get("mcpServers", []):
            assert set(server) >= {"name", "url"}
    members = [resource["spec"]["leader"], *resource["spec"]["workers"]]
    assert {member["name"]: Path(member["package"]).name for member in members} == {
        role: f"{role}-v{PACKAGE_VERSION}.zip" for role in ROLE_SKILLS
    }
    assert all(member["model"] == "glm-5.2" for member in members)
    assert all(member["runtime"] == "openclaw" for member in members)


def test_package_server_team_urls_and_configmap_projection_are_one_contract() -> None:
    documents = list(
        yaml.safe_load_all((ROOT / "agentteams/package-server.yaml").read_text(encoding="utf-8"))
    )
    by_kind = {document["kind"]: document for document in documents}
    deployment = by_kind["Deployment"]
    service = by_kind["Service"]
    policy = by_kind["NetworkPolicy"]
    container = deployment["spec"]["template"]["spec"]["containers"][0]
    volume = deployment["spec"]["template"]["spec"]["volumes"][0]["configMap"]
    expected_names = {
        f"{role}-v{PACKAGE_VERSION}.zip" for role in ROLE_SKILLS
    }

    assert deployment["metadata"]["namespace"] == NAMESPACE
    assert service["metadata"] == {
        "name": "devflow-package",
        "namespace": NAMESPACE,
        "labels": {
            "app.kubernetes.io/name": "devflow-package",
            "app.kubernetes.io/part-of": "devflow",
        },
    }
    assert container["image"] == (
        "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
    )
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["volumeMounts"] == [
        {"name": "package", "mountPath": "/www", "readOnly": True}
    ]
    assert volume["name"] == CONFIGMAP_NAME
    assert volume["defaultMode"] == 0o444
    assert [item["key"] for item in volume["items"]] == [
        f"{role}-v{PACKAGE_VERSION}.zip" for role in ROLE_SKILLS
    ]
    assert {item["key"] for item in volume["items"]} == expected_names
    assert {item["path"] for item in volume["items"]} == expected_names
    assert all(item["key"] == item["path"] for item in volume["items"])
    assert service["spec"]["ports"] == [
        {"name": "http", "port": 8080, "targetPort": "http"}
    ]
    assert policy["spec"]["ingress"][0]["ports"] == [
        {"protocol": "TCP", "port": 8080}
    ]

    team = yaml.safe_load((ROOT / "agentteams/team.yaml").read_text(encoding="utf-8"))
    members = [team["spec"]["leader"], *team["spec"]["workers"]]
    base_url = f"http://{service['metadata']['name']}.{NAMESPACE}.svc.cluster.local:8080"
    assert {member["package"] for member in members} == {
        f"{base_url}/{name}" for name in expected_names
    }


def test_all_declared_skills_are_distributable() -> None:
    configured = yaml.safe_load((ROOT / "config" / "skills.yaml").read_text(encoding="utf-8"))
    configured_names = {skill["name"] for skill in configured["skills"]}
    skill_files = {path.parent.name: path for path in (ROOT / "skills").glob("*/SKILL.md")}

    assert configured_names == set(skill_files)
    for name, path in skill_files.items():
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\n")
        assert f"name: {name}\n" in text
        frontmatter = yaml.safe_load(text.split("---\n", 2)[1])
        assert set(frontmatter) == {"name", "description"}
        assert "Use when" in frontmatter["description"]
        skill_dir = path.parent
        interface = yaml.safe_load(
            (skill_dir / "agents" / "openai.yaml").read_text(encoding="utf-8")
        )
        assert set(interface) == {"interface"}
        assert set(interface["interface"]) == {
            "display_name",
            "short_description",
            "default_prompt",
        }
        assert f"${name}" in interface["interface"]["default_prompt"]
        assert (skill_dir / "references" / "contract.yaml").exists()
        assert (skill_dir / "references" / "examples.md").exists()
        assert (skill_dir / "scripts" / "validate.py").exists()


def test_skill_contract_graph_has_no_violations() -> None:
    catalog = load_catalog(ROOT / "skills")

    assert len(catalog) == 7
    assert validate_collaboration(catalog) == []
    assert validate_agent_alignment(catalog, ROOT / "config" / "agents.yaml") == []
    assert validate_mcp_alignment(catalog, ROOT / "config" / "mcp_servers.yaml") == []
    assert all(len(contract.forbidden_actions) >= 3 for contract in catalog.values())
    assert all(len(contract.verification) >= 3 for contract in catalog.values())


def test_runtime_agent_skill_ownership_matches_contracts() -> None:
    catalog = load_catalog(ROOT / "skills")
    runtime_owners = {
        agent.name: set(agent.skills)
        for agent in (
            TriageAgent(),
            LocatorAgent(),
            CoderAgent(),
            DevFlowTesterAgent(),
            ReviewerAgent(),
        )
    }
    contract_owners: dict[str, set[str]] = {}
    for name, contract in catalog.items():
        contract_owners.setdefault(contract.owner, set()).add(name)

    assert runtime_owners == contract_owners


def test_release_role_skill_map_matches_runtime_and_contract_owners() -> None:
    configured = yaml.safe_load((ROOT / "config/agents.yaml").read_text(encoding="utf-8"))
    configured_skills = {
        agent["name"]: tuple(agent.get("depends_on_skills", []))
        for agent in configured["agents"]
    }
    assert {
        role: configured_skills[owner]
        for role, owner in ROLE_OWNERS.items()
    } == ROLE_SKILLS
    for role, skills in ROLE_SKILLS.items():
        for skill in skills:
            contract = yaml.safe_load(
                (ROOT / "skills" / skill / "references/contract.yaml").read_text(
                    encoding="utf-8"
                )
            )
            assert contract["name"] == skill
            assert contract["owner"] == ROLE_OWNERS[role]


def test_role_packages_are_reproducible_minimal_and_manifested(tmp_path: Path) -> None:
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"

    first = build_role_packages(ROOT, first_dir, source_date_epoch=0)
    second = build_role_packages(ROOT, second_dir, source_date_epoch=0)

    assert first == second
    assert set(first) == set(ROLE_SKILLS)
    for role, expected_skills in ROLE_SKILLS.items():
        name = f"{role}-v{PACKAGE_VERSION}.zip"
        first_path = first_dir / name
        second_path = second_dir / name
        assert first_path.read_bytes() == second_path.read_bytes()
        with zipfile.ZipFile(first_path) as archive:
            names = archive.namelist()
            assert all(
                entry.compress_type == zipfile.ZIP_STORED
                for entry in archive.infolist()
            )
            manifest = json.loads(archive.read("manifest.json"))
            assert manifest["role"] == role
            assert manifest["skills"] == list(expected_skills)
            assert manifest["version"] == PACKAGE_VERSION
            assert manifest["worker"]["suggested_name"] == role
            assert manifest["worker"]["base_image"] == WORKER_BASE_IMAGE
            assert manifest["manifest_sha256"] == manifest_digest(manifest)
            assert set(manifest["files"]) == set(names) - {"manifest.json"}
            for archived_name, digest in manifest["files"].items():
                assert hashlib.sha256(archive.read(archived_name)).hexdigest() == digest
        packaged_skills = {name.split("/", 2)[1] for name in names if name.startswith("skills/")}
        assert packaged_skills == set(expected_skills)
        assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)


def _copy_package_sources(destination: Path) -> Path:
    root = destination / "repository"
    shutil.copytree(ROOT / "agentteams" / "worker-package", root / "agentteams" / "worker-package")
    shutil.copytree(ROOT / "skills", root / "skills")
    return root


def test_package_build_rejects_unknown_and_secret_shaped_files(tmp_path: Path) -> None:
    unknown_root = _copy_package_sources(tmp_path / "unknown")
    (unknown_root / "skills" / "code-root-cause" / "notes.txt").write_text(
        "not in the release allowlist", encoding="utf-8"
    )
    with pytest.raises(PackageBuildError, match="missing or unknown"):
        build_package(
            unknown_root,
            tmp_path / "unknown.zip",
            source_date_epoch=0,
            role="devflow-locator",
        )

    secret_root = _copy_package_sources(tmp_path / "secret")
    skill_file = secret_root / "skills" / "code-root-cause" / "SKILL.md"
    skill_file.write_text(
        skill_file.read_text(encoding="utf-8") + "\nghp_" + "A" * 36,
        encoding="utf-8",
    )
    with pytest.raises(PackageBuildError, match="secret-shaped"):
        build_package(
            secret_root,
            tmp_path / "secret.zip",
            source_date_epoch=0,
            role="devflow-locator",
        )

    entropy_root = _copy_package_sources(tmp_path / "entropy")
    entropy_file = entropy_root / "skills" / "code-root-cause" / "SKILL.md"
    entropy_file.write_text(
        entropy_file.read_text(encoding="utf-8")
        + "\nSynthetic9AbCdeF01GhijkL23MnopqR45StuvwX67Yz890",
        encoding="utf-8",
    )
    with pytest.raises(PackageBuildError, match="secret-shaped"):
        build_package(
            entropy_root,
            tmp_path / "entropy.zip",
            source_date_epoch=0,
            role="devflow-locator",
        )


def test_package_build_rejects_symbolic_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_package_sources(tmp_path)
    target = root / "skills" / "code-root-cause" / "SKILL.md"
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == target or original_is_symlink(path),
    )
    with pytest.raises(PackageBuildError, match="canonical regular file"):
        build_package(
            root,
            tmp_path / "symlink.zip",
            source_date_epoch=0,
            role="devflow-locator",
        )


def test_package_build_rejects_reparse_points_without_host_symlink_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _copy_package_sources(tmp_path)
    target = root / "skills" / "code-root-cause" / "SKILL.md"
    target_inode = target.lstat().st_ino
    original = package_builder._is_reparse
    monkeypatch.setattr(
        package_builder,
        "_is_reparse",
        lambda metadata: metadata.st_ino == target_inode or original(metadata),
    )

    with pytest.raises(PackageBuildError, match="reparse|canonical regular file"):
        build_package(
            root,
            tmp_path / "reparse.zip",
            source_date_epoch=0,
            role="devflow-locator",
        )


def test_checked_reader_detects_file_swap_between_stat_and_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "trusted"
    root.mkdir()
    target = root / "SKILL.md"
    target.write_text("original", encoding="utf-8")
    replacement = root / "replacement"
    replacement.write_text("replacement", encoding="utf-8")
    real_open = os.open
    swapped = False

    def racing_open(path: os.PathLike[str] | str, flags: int) -> int:
        nonlocal swapped
        if Path(path) == target and not swapped:
            swapped = True
            os.replace(replacement, target)
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", racing_open)
    with pytest.raises(PackageBuildError, match="changed before"):
        read_regular_file(
            target,
            root=root,
            label="racing source",
            max_bytes=MAX_SOURCE_FILE_BYTES,
            scan_secrets=False,
        )


def test_package_build_rejects_contract_owner_drift(tmp_path: Path) -> None:
    root = _copy_package_sources(tmp_path)
    contract = root / "skills" / "patch-generator" / "references" / "contract.yaml"
    contract.write_text(
        contract.read_text(encoding="utf-8").replace("owner: CoderAgent", "owner: ReviewerAgent"),
        encoding="utf-8",
    )

    with pytest.raises(PackageBuildError, match="owner or name"):
        build_package(
            root,
            tmp_path / "owner-drift.zip",
            source_date_epoch=0,
            role="devflow-coder",
        )

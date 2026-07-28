"""Offline tests for the guarded OpenClaw TeamHarness adapter."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import pytest

import scripts.teamharness_openclaw as adapter
from scripts.teamharness_openclaw import (
    AGENTS_BEGIN,
    AGENTS_END,
    UPSTREAM_FILE_SHA256,
    install,
    verify,
)

ROOT = Path(__file__).resolve().parents[1]
TEST_APPROVAL_DOMAIN = hashlib.sha256(b"devflow-test-approval-domain").hexdigest()

AUDITED_PLUGIN_YAML = """apiVersion: hiclaw.agentteam/v1alpha1
kind: AgentTeamPlugin
metadata:
  name: teamharness
  version: 0.1.0
prompts:
  team: prompts/team/TEAMS.md
  agent:
    leader: prompts/agent/leader.md
    worker: prompts/agent/worker.md
    remoteMember: prompts/agent/remote-member.md
  manager:
    agents: prompts/manager/AGENTS.md
    tools: prompts/manager/TOOLS.md
    heartbeat: prompts/manager/HEARTBEAT.md
skills:
  agent:
    - id: mcporter
      path: skills/agent/mcporter
      roles: [leader, worker, manager, remote-member]
    - id: find-skills
      path: skills/agent/find-skills
      roles: [leader, worker, manager, remote-member]
  team:
    - id: communication
      path: skills/team/communication
      roles: [leader, worker, manager, remote-member]
    - id: file-sharing
      path: skills/team/file-sharing
      roles: [leader, worker, manager, remote-member]
    - id: roomflow
      path: skills/team/roomflow
      roles: [leader]
    - id: team-coordination
      path: skills/team/team-coordination
      roles: [leader]
    - id: project-management
      path: skills/team/project-management
      roles: [leader]
    - id: task-delegation
      path: skills/team/task-delegation
      roles: [leader]
    - id: task-execution
      path: skills/team/task-execution
      roles: [worker, remote-member]
mcp:
  servers:
    - id: teamharness
      transport: stdio
      command: python
      args:
        - mcp/server.py
      tools:
        - health
        - message
        - roomflow
        - filesync
        - artifact
        - projectflow
        - taskflow
adapters:
  - id: qwenpaw
    path: adapters/qwenpaw
package:
  include:
    - plugin.yaml
    - prompts/
    - skills/
    - mcp/
    - adapters/
    - scripts/
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _test_openssl() -> Path:
    candidates = (
        Path("C:/Program Files/Git/usr/bin/openssl.exe"),
        Path("C:/Program Files/Git/mingw64/bin/openssl.exe"),
        Path("/usr/bin/openssl"),
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    pytest.skip("system OpenSSL with Ed25519 support is unavailable")


def _approval_key_fixture(root: Path) -> tuple[Path, Path, Path]:
    fixture = root / "approval-fixture"
    private_key = fixture / "private.pem"
    public_key = fixture / "public.pem"
    openssl_path = _test_openssl()
    if not private_key.exists():
        fixture.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                str(openssl_path),
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                str(private_key),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                str(openssl_path),
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key),
            ],
            check=True,
            capture_output=True,
        )
    return private_key, public_key, openssl_path


def _runtime_text(role: str, runtime_name: str | None = None) -> str:
    name = runtime_name or f"{role}-runtime"
    return (
        "member:\n"
        f"  role: {role}\n"
        f"  runtimeName: {name}\n"
        f"  matrixUserId: '@{name}:matrix.test'\n"
    )


def _runtime_binding(
    root: Path, role: str, runtime_name: str
) -> tuple[Path, Path, str]:
    pod_name = f"agentteams-worker-{runtime_name}"
    source = root / f"runtime-binding-{runtime_name}.json"
    destination = root / "identity-policy" / f"{runtime_name}.json"
    source.write_text(
        json.dumps(
            {
                "schemaVersion": "1.0",
                "teamName": "devflow-swe",
                "memberName": f"member-{runtime_name}",
                "runtimeName": runtime_name,
                "podName": pod_name,
                "teamHarnessRole": role,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return source, destination, pod_name


def _fake_plugin(root: Path) -> Path:
    plugin = root / "teamharness"
    (plugin / "plugin.yaml").parent.mkdir(parents=True, exist_ok=True)
    (plugin / "plugin.yaml").write_bytes(AUDITED_PLUGIN_YAML.encode("utf-8"))
    for path in (
        "prompts/team/TEAMS.md",
        "prompts/agent/leader.md",
        "prompts/agent/worker.md",
        "prompts/agent/remote-member.md",
        "prompts/manager/AGENTS.md",
        "prompts/manager/TOOLS.md",
        "prompts/manager/HEARTBEAT.md",
    ):
        _write(plugin / path, f"# upstream prompt {Path(path).stem}\n")
    for skill_id, relative in (
        ("mcporter", "skills/agent/mcporter"),
        ("find-skills", "skills/agent/find-skills"),
        ("communication", "skills/team/communication"),
        ("file-sharing", "skills/team/file-sharing"),
        ("roomflow", "skills/team/roomflow"),
        ("team-coordination", "skills/team/team-coordination"),
        ("project-management", "skills/team/project-management"),
        ("task-delegation", "skills/team/task-delegation"),
        ("task-execution", "skills/team/task-execution"),
    ):
        _write(plugin / relative / "SKILL.md", f"---\nname: {skill_id}\n---\n")
    _write(plugin / "mcp/message_tool.py", "# helper\n")
    _write(plugin / "mcp/roomflow_tool.py", "# helper\n")
    _write(
        plugin / "mcp/server.py",
        """
import json
import time
from pathlib import Path
TOOL_NAMES = ["health", "message", "roomflow", "filesync", "artifact", "projectflow", "taskflow"]
def list_tools():
    return [{"name": name, "inputSchema": {}} for name in TOOL_NAMES]
def _project_store(arguments):
    workspace = Path(arguments["workspaceDir"])
    path = workspace / ".fixture-projects.json"
    if path.exists():
        return path, json.loads(path.read_text(encoding="utf-8"))
    return path, {}
def _payload(arguments):
    value = arguments.get("payload", {})
    return json.loads(value) if isinstance(value, str) else value
def handle_request(request):
    params = request.get("params", {})
    arguments = params.get("arguments", {})
    if params.get("name") == "projectflow":
        action = arguments.get("action")
        payload = _payload(arguments)
        project_id = payload.get("projectId") or payload.get("project_id")
        path, projects = _project_store(arguments)
        if action in {"create_project", "create_quick_project"}:
            project = {
                "project_id": project_id,
                "source": payload.get("source", ""),
                "status": "active",
                "tasks": [],
            }
            projects[project_id] = project
            path.write_text(json.dumps(projects), encoding="utf-8")
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": {
                "ok": True, "tool": "projectflow", "action": action, "project": project
            }}
        project = projects.get(project_id)
        if not project:
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": {
                "ok": False, "tool": "projectflow", "action": action, "error": "project not found"
            }}
        if action == "pause_project":
            project["status"] = "paused"
        elif action == "resume_project":
            delay = payload.get("_fixtureResumeDelaySeconds", 0)
            if delay:
                time.sleep(float(delay))
            if not payload.get("_fixtureKeepPaused"):
                project["status"] = "active"
        elif action == "complete_project":
            project["status"] = "completed"
        projects[project_id] = project
        path.write_text(json.dumps(projects), encoding="utf-8")
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {
            "ok": True, "tool": "projectflow", "action": action, "project": project
        }}
    if params.get("name") == "filesync":
        action = arguments.get("action")
        path = arguments.get("path")
        local_path = Path(arguments["workspaceDir"]) / Path(*path.rstrip("/").split("/"))
        if action == "pull" and not arguments.get("dryRun"):
            if path.endswith("/"):
                local_path.mkdir(parents=True, exist_ok=True)
            else:
                local_path.parent.mkdir(parents=True, exist_ok=True)
                local_path.write_text("pulled fixture\\n", encoding="utf-8")
        result = {
            "ok": True,
            "tool": "filesync",
            "action": action,
            "kind": path.split("/", 1)[0],
            "path": path,
            "localPath": str(local_path),
            "remotePath": "secret-remote-prefix/" + path,
            "command": ["mc", action, path],
            "exclude": arguments.get("exclude", []),
        }
        if arguments.get("dryRun"):
            result["dryRun"] = True
        if action == "list" and not arguments.get("dryRun"):
            result["entries"] = ["fixture-entry"]
        if action == "stat" and not arguments.get("dryRun"):
            result["exists"] = True
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}
    if params.get("name") == "taskflow" and arguments.get("action") == "check_task":
        task = arguments.get("_fixtureTask", {})
        return {"jsonrpc": "2.0", "id": request.get("id"), "result": {
            "content": [{"type": "text", "text": json.dumps({"task": task})}]
        }}
    return {"jsonrpc": "2.0", "id": request.get("id"), "result": {
        "ok": True,
        "echo": {"name": params.get("name"), "arguments": arguments}
    }}
""".lstrip(),
    )
    return plugin


def _test_hash_policy(plugin: Path) -> dict[str, str]:
    return {
        relative: hashlib.sha256((plugin / relative).read_bytes()).hexdigest()
        for relative in UPSTREAM_FILE_SHA256
    }


def _install_fake(
    plugin: Path,
    workspace: Path,
    role: str,
    runtime: Path,
    *,
    replace: bool = False,
    approval_domain: str = TEST_APPROVAL_DOMAIN,
    approval_key_root: Path | None = None,
    approval_state_root: Path | None = None,
) -> dict[str, Any]:
    runtime_name_match = re.search(r"(?m)^  runtimeName: ([^\n]+)$", runtime.read_text(encoding="utf-8"))
    assert runtime_name_match is not None
    runtime_name = runtime_name_match.group(1).strip()
    binding, installed_binding, pod_name = _runtime_binding(
        plugin.parent, role, runtime_name
    )
    approval_args: dict[str, Any] = {}
    if role == "leader":
        key_root = approval_key_root or plugin.parent
        state_root = approval_state_root or plugin.parent
        _private_key, public_key, openssl_path = _approval_key_fixture(key_root)
        approval_args = {
            "approval_public_key": public_key,
            "approval_domain": approval_domain,
            "_test_policy_path": state_root / "approval-policy/public.pem",
            "_test_ledger_path": state_root / "approval-state/ledger.json",
            "_test_openssl_path": openssl_path,
        }
    return install(
        plugin,
        workspace,
        role,
        runtime,
        runtime_binding=binding,
        replace=replace,
        _test_hash_policy=_test_hash_policy(plugin),
        _test_hostname=pod_name,
        _test_runtime_binding_path=installed_binding,
        **approval_args,
    )


def _verify_fake(plugin: Path, workspace: Path, role: str) -> list[Any]:
    return verify(
        workspace,
        role,
        _test_hash_policy=_test_hash_policy(plugin),
    )


def test_install_is_role_scoped_and_credential_free(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))

    record = _install_fake(plugin, workspace, "worker", runtime)

    assert record["secretsEmbedded"] is False
    assert (workspace / "skills/teamharness-task-execution/SKILL.md").is_file()
    assert not (workspace / "skills/teamharness-roomflow").exists()
    config = json.loads((workspace / "config/mcporter.json").read_text(encoding="utf-8"))
    entry = config["mcpServers"]["teamharness"]
    assert entry["transport"] == "stdio"
    assert entry["env"] == {
        "TEAMHARNESS_SHARED_DIR": str((workspace / "shared").resolve()),
    }
    identity = json.loads(
        (workspace / "runtime/runtime.json").read_text(encoding="utf-8")
    )
    assert identity == {
        "hostname": "agentteams-worker-worker-runtime",
        "matrixUserId": "@worker-runtime:matrix.test",
        "memberName": "member-worker-runtime",
        "podName": "agentteams-worker-worker-runtime",
        "role": "worker",
        "runtimeName": "worker-runtime",
        "teamName": "devflow-swe",
    }
    assert all(check.ok for check in _verify_fake(plugin, workspace, "worker"))


@pytest.mark.parametrize("approval_domain", ["", "A" * 64, "0" * 63, "g" * 64])
def test_leader_install_requires_strict_lowercase_approval_domain(
    tmp_path: Path,
    approval_domain: str,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))

    with pytest.raises(ValueError, match="approval domain"):
        _install_fake(
            plugin,
            workspace,
            "leader",
            runtime,
            approval_domain=approval_domain,
        )


def test_install_rejects_runtime_name_to_pod_binding_mismatch(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    binding, installed_binding, pod_name = _runtime_binding(
        tmp_path, "worker", "worker-runtime"
    )
    value = json.loads(binding.read_text(encoding="utf-8"))
    value["podName"] = "agentteams-worker-another-runtime"
    binding.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(ValueError, match="podName does not match /etc/hostname"):
        install(
            plugin,
            workspace,
            "worker",
            runtime,
            runtime_binding=binding,
            _test_hash_policy=_test_hash_policy(plugin),
            _test_hostname=pod_name,
            _test_runtime_binding_path=installed_binding,
        )


def test_production_execution_chain_is_external_read_only_and_digest_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plugin = _fake_plugin(tmp_path)
    execution_root = tmp_path / "opt/devflow/teamharness"
    plugin_root = execution_root / "plugin"
    monkeypatch.setattr(adapter, "PRODUCTION_EXECUTION_ROOT", execution_root)
    monkeypatch.setattr(adapter, "PRODUCTION_PLUGIN_ROOT", plugin_root)
    monkeypatch.setattr(adapter, "PRODUCTION_GUARD", execution_root / "guarded_server.py")
    monkeypatch.setattr(
        adapter,
        "PRODUCTION_ADAPTER",
        execution_root / "teamharness_openclaw.py",
    )
    monkeypatch.setattr(
        adapter,
        "PRODUCTION_SERVER",
        plugin_root / "mcp/server.py",
    )
    monkeypatch.setattr(adapter, "PRODUCTION_PYTHON", Path(sys.executable))
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(os, "chown", lambda *_args: None, raising=False)

    evidence = adapter._install_production_execution(plugin)

    expected_paths = {
        "guardPath": execution_root / "guarded_server.py",
        "adapterPath": execution_root / "teamharness_openclaw.py",
        "serverPath": plugin_root / "mcp/server.py",
    }
    for key, path in expected_paths.items():
        assert evidence[key] == str(path)
        assert evidence[key.replace("Path", "Sha256")] == hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        assert stat.S_IMODE(path.stat().st_mode) & stat.S_IWUSR == 0
    for directory in (execution_root, plugin_root, plugin_root / "mcp"):
        assert stat.S_IMODE(directory.stat().st_mode) & stat.S_IWUSR == 0


def _guard_call(
    workspace: Path, role: str, request: dict[str, Any]
) -> dict[str, Any]:
    guard = workspace / ".teamharness/mcp/guarded_server.py"
    env = os.environ.copy()
    env["AGENTTEAMS_AGENT_ROLE"] = "leader" if role != "leader" else "worker"
    completed = subprocess.run(
        [sys.executable, str(guard)],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        check=True,
        env=env,
    )
    parsed = json.loads(completed.stdout)
    if not isinstance(parsed, dict):
        raise AssertionError("guard response must be a JSON object")
    return cast(dict[str, Any], parsed)


def _guard_raw(workspace: Path, text: str) -> dict[str, Any]:
    guard = workspace / ".teamharness/mcp/guarded_server.py"
    completed = subprocess.run(
        [sys.executable, str(guard)],
        input=text + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    parsed = json.loads(completed.stdout)
    if not isinstance(parsed, dict):
        raise AssertionError("guard response must be a JSON object")
    return cast(dict[str, Any], parsed)


def test_guard_rejects_duplicate_or_oversized_json_documents(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    duplicate = _guard_raw(
        workspace,
        '{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}',
    )
    assert duplicate["error"] == {"code": -32700, "message": "Parse error"}

    oversized = _guard_raw(workspace, '{"padding":"' + "x" * 1_048_577 + '"}')
    assert oversized["error"] == {"code": -32600, "message": "Invalid Request"}


def test_worker_guard_hides_control_plane_tools_and_prevents_role_spoof(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    listed = _guard_call(
        workspace,
        "worker",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert names == {"health", "taskflow"}

    denied = _guard_call(
        workspace,
        "worker",
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "taskflow",
                "arguments": {"action": "delegate_task", "role": "leader"},
            },
        },
    )
    payload = json.loads(denied["result"]["content"][0]["text"])
    assert payload["error"] == "forbidden_tool"
    assert payload["role"] == "worker"


def test_guard_replaces_taskflow_role_with_process_role(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    response = _guard_call(
        workspace,
        "worker",
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "taskflow",
                "arguments": {
                    "action": "ack_task",
                    "task_id": "task-fixture",
                    "role": "leader",
                    "_fixtureTask": {
                        "task_id": "task-fixture",
                        "assigned_to": "worker-runtime",
                        "status": "pending",
                    },
                },
            },
        },
    )
    assert response["result"]["echo"]["arguments"]["role"] == "worker"


def _task_request(
    action: str,
    *,
    assigned_to: str = "worker-runtime",
    status: str = "pending",
    result_status: str = "SUCCESS",
    summary: str = "",
    deliverables: list[str] | None = None,
) -> dict[str, Any]:
    deliverables = [] if deliverables is None else deliverables
    return {
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {
            "name": "taskflow",
            "arguments": {
                "action": action,
                "task_id": "task-fixture",
                "status": result_status,
                "summary": summary,
                "deliverables": deliverables,
                "_fixtureTask": {
                    "task_id": "task-fixture",
                    "assigned_to": assigned_to,
                    "status": status,
                    "result_status": result_status,
                    "summary": summary,
                    "deliverables": deliverables,
                },
            },
        },
    }


def _project_request(action: str, project_id: str, **payload: Any) -> dict[str, Any]:
    payload.setdefault("source", "operator-driven")
    return {
        "jsonrpc": "2.0",
        "id": 31,
        "method": "tools/call",
        "params": {
            "name": "projectflow",
            "arguments": {
                "action": action,
                "payload": {"projectId": project_id, **payload},
            },
        },
    }


def _filesync_request(action: str, path: str, **arguments: Any) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 37,
        "method": "tools/call",
        "params": {
            "name": "filesync",
            "arguments": {"action": action, "path": path, **arguments},
        },
    }


def _approval_target_digest(arguments: dict[str, Any]) -> str:
    target = json.loads(json.dumps(arguments))
    target.pop("approval", None)
    target.pop("role", None)
    target.pop("workspaceDir", None)
    if isinstance(target.get("payload"), str):
        target["payload"] = json.loads(target["payload"])
    canonical = json.dumps(
        {"tool": "projectflow", "arguments": target},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _signed_approval(
    workspace: Path,
    arguments: dict[str, Any],
    *,
    risk_tier: str,
    nonce: str = "nonce_fixture_1234567890AB",
    issued_delta: int = -5,
    expires_delta: int = 300,
    evidence_updates: dict[str, Any] | None = None,
    approval_key_root: Path | None = None,
) -> dict[str, Any]:
    action = str(arguments["action"])
    payload = cast(dict[str, Any], arguments["payload"])
    manifest = json.loads(
        (workspace / ".teamharness/install-manifest.json").read_text(encoding="utf-8")
    )
    policy = cast(dict[str, Any], manifest["approvalPolicy"])
    ledger = json.loads(Path(policy["ledgerPath"]).read_text(encoding="utf-8"))
    project_binding = cast(dict[str, Any], ledger["projects"][payload["projectId"]])
    target_digest = _approval_target_digest(arguments)
    approval_request: dict[str, Any] = {
        "schema": "devflow.agentteams.projectflow.approval-request/v1",
        "audience": policy["audience"],
        "approvalDomain": policy["approvalDomain"],
        "policyKeySha256": policy["policyKeySha256"],
        "projectBindingDigest": project_binding["projectBindingDigest"],
        "action": action,
        "projectId": payload["projectId"],
        "riskTier": risk_tier,
        "targetDigest": target_digest,
    }
    if action == "accept_task_result":
        approval_request["taskId"] = payload["taskId"]
    request_digest = hashlib.sha256(
        json.dumps(
            approval_request,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    now = dt.datetime.now(tz=dt.timezone.utc).replace(microsecond=0)
    evidence: dict[str, Any] = {
        "schemaVersion": "1.1",
        "audience": policy["audience"],
        "approvalDomain": policy["approvalDomain"],
        "policyKeySha256": policy["policyKeySha256"],
        "projectBindingDigest": project_binding["projectBindingDigest"],
        "approvalRequestDigest": request_digest,
        "action": action,
        "projectId": payload["projectId"],
        "riskTier": risk_tier,
        "targetDigest": target_digest,
        "approvedBy": "human-reviewer@example.test",
        "issuedAt": (now + dt.timedelta(seconds=issued_delta)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "expiresAt": (now + dt.timedelta(seconds=expires_delta)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "nonce": nonce,
    }
    if action == "accept_task_result":
        evidence["taskId"] = payload["taskId"]
    if evidence_updates:
        evidence.update(evidence_updates)
    canonical = json.dumps(
        evidence,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    private_key, _public_key, openssl_path = _approval_key_fixture(
        approval_key_root or workspace.parent
    )
    evidence_path = private_key.parent / "evidence.json"
    signature_path = private_key.parent / "signature.bin"
    evidence_path.write_bytes(canonical)
    subprocess.run(
        [
            str(openssl_path),
            "pkeyutl",
            "-sign",
            "-inkey",
            str(private_key),
            "-rawin",
            "-in",
            str(evidence_path),
            "-out",
            str(signature_path),
        ],
        check=True,
        capture_output=True,
    )
    return {
        "evidence": evidence,
        "signature": base64.b64encode(signature_path.read_bytes()).decode("ascii"),
    }


def _guard_payload(response: dict[str, Any]) -> dict[str, Any]:
    return cast(
        dict[str, Any], json.loads(response["result"]["content"][0]["text"])
    )


def test_worker_task_transition_requires_matching_assignment(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    denied = _guard_call(
        workspace,
        "leader",
        _task_request("ack_task", assigned_to="different-runtime"),
    )

    payload = json.loads(denied["result"]["content"][0]["text"])
    assert payload["error"] == "task_assignment_mismatch"
    assert payload["role"] == "worker"


def test_worker_task_transitions_are_idempotent_and_terminal_safe(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    acked = _guard_call(
        workspace,
        "leader",
        _task_request("ack_task", status="in_progress"),
    )
    acked_payload = json.loads(acked["result"]["content"][0]["text"])
    assert acked_payload == {
        "action": "ack_task",
        "idempotent": True,
        "ok": True,
        "role": "worker",
        "taskState": "in_progress",
        "taskId": "task-fixture",
    }

    terminal = _guard_call(
        workspace,
        "leader",
        _task_request("submit_task", status="submitted"),
    )
    terminal_payload = json.loads(terminal["result"]["content"][0]["text"])
    assert terminal_payload["idempotent"] is True
    assert terminal_payload["taskState"] == "submitted"
    assert terminal_payload["taskId"] == "task-fixture"
    assert re.fullmatch(r"[0-9a-f]{64}", terminal_payload["submissionDigest"])

    conflicting_request = _task_request(
        "submit_task", status="submitted", summary="different result"
    )
    conflicting_request["params"]["arguments"]["_fixtureTask"]["summary"] = (
        "original result"
    )
    conflicting = _guard_call(workspace, "leader", conflicting_request)
    conflict_payload = _guard_payload(conflicting)
    assert conflict_payload["error"] == "submit_result_conflict"
    assert conflict_payload["taskId"] == "task-fixture"
    assert re.fullmatch(r"[0-9a-f]{64}", conflict_payload["currentDigest"])
    assert re.fullmatch(r"[0-9a-f]{64}", conflict_payload["requestedDigest"])
    assert conflict_payload["currentDigest"] != conflict_payload["requestedDigest"]

    failed = _guard_call(
        workspace,
        "leader",
        _task_request("submit_task", status="failed"),
    )
    failed_payload = json.loads(failed["result"]["content"][0]["text"])
    assert failed_payload["error"] == "terminal_task_transition"

    submitted = _guard_call(
        workspace,
        "leader",
        _task_request("submit_task", assigned_to="@worker-runtime:matrix.test"),
    )
    assert submitted["result"]["echo"]["arguments"]["role"] == "worker"


def test_guard_fails_closed_when_fixed_identity_evidence_drifts(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)
    identity_path = workspace / "runtime/runtime.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["role"] = "leader"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    listed = _guard_call(
        workspace,
        "worker",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert listed["result"]["tools"] == []
    denied = _guard_call(workspace, "worker", _task_request("ack_task"))
    payload = json.loads(denied["result"]["content"][0]["text"])
    assert payload["error"] == "identity_attestation_failed"


@pytest.mark.parametrize(
    ("role", "expected"),
    [
        ("worker", {"health", "taskflow"}),
        ("remote-member", {"health", "taskflow"}),
        ("manager", {"health", "message"}),
    ],
)
def test_non_leader_tool_surfaces_are_minimal(
    tmp_path: Path, role: str, expected: set[str]
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / role
    runtime = tmp_path / f"{role}.yaml"
    _write(runtime, _runtime_text(role))
    _install_fake(plugin, workspace, role, runtime)

    listed = _guard_call(
        workspace,
        "leader",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert {tool["name"] for tool in listed["result"]["tools"]} == expected
    for tool in ("artifact", "filesync"):
        denied = _guard_call(
            workspace,
            "leader",
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {"action": "push"}},
            },
        )
        payload = json.loads(denied["result"]["content"][0]["text"])
        assert payload["error"] == "forbidden_tool"


def test_filesync_schema_exposes_only_the_guarded_contract(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)

    listed = _guard_call(
        workspace,
        "leader",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    tool = next(
        item for item in listed["result"]["tools"] if item["name"] == "filesync"
    )
    schema = tool["inputSchema"]

    assert schema["type"] == "object"
    assert schema["required"] == ["action", "path"]
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"action", "path", "dryRun"}
    assert set(schema["properties"]["action"]["enum"]) == {
        "list",
        "stat",
        "pull",
        "push",
    }


@pytest.mark.parametrize(
    ("action", "path"),
    [
        ("list", "shared/projects/project-7/"),
        ("stat", "global-shared/reference.md"),
        ("pull", "shared/tasks/task-7/result.md"),
        ("push", "shared/projects/project-7/"),
    ],
)
def test_filesync_uses_exact_attested_role_workspace_for_existing_actions(
    tmp_path: Path,
    action: str,
    path: str,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    if action == "push":
        source = workspace / Path(*path.rstrip("/").split("/"))
        source.mkdir(parents=True, exist_ok=True)
        (source / "result.md").write_text("verified fixture\n", encoding="utf-8")

    response = _guard_call(workspace, "leader", _filesync_request(action, path))
    result = response["result"]

    assert result["ok"] is True
    assert result["action"] == action
    assert result["path"] == path
    assert Path(result["localPath"]) == workspace / Path(*path.rstrip("/").split("/"))
    assert re.fullmatch(r"[0-9a-f]{64}", result["workspaceBindingSha256"])
    assert "command" not in result
    assert "remotePath" not in result
    assert "exclude" not in result
    if action == "push":
        assert result["expectedObjectCount"] == 1
        assert result["verifiedObjectCount"] == 1
        assert re.fullmatch(r"[0-9a-f]{64}", result["localTreeSha256"])


@pytest.mark.parametrize(
    ("override", "expected_error"),
    [
        ({"workspaceDir": "/root/hiclaw-fs"}, "filesync_binding_override_forbidden"),
        ({"workspace_dir": "/root/hiclaw-fs"}, "filesync_binding_override_forbidden"),
        (
            {"storage": {"sharedPrefix": "attacker"}},
            "filesync_binding_override_forbidden",
        ),
        ({"sharedPrefix": "attacker"}, "filesync_binding_override_forbidden"),
        ({"payload": {"workspaceDir": "/root/hiclaw-fs"}}, "filesync_payload_forbidden"),
        ({"exclude": ["*"]}, "filesync_exclude_forbidden"),
        ({"exclude": []}, "filesync_exclude_forbidden"),
        ({"futureUpstreamField": True}, "filesync_argument_unknown"),
    ],
)
def test_filesync_rejects_workspace_storage_and_payload_overrides(
    tmp_path: Path,
    override: dict[str, Any],
    expected_error: str,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)

    denied = _guard_call(
        workspace,
        "leader",
        _filesync_request("push", "shared/projects/project-7/", **override),
    )

    assert _guard_payload(denied)["error"] == expected_error


def test_filesync_push_rejects_empty_directory(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    (workspace / "shared/projects/project-7").mkdir(parents=True)

    denied = _guard_call(
        workspace,
        "leader",
        _filesync_request("push", "shared/projects/project-7/"),
    )

    assert _guard_payload(denied)["error"] == "filesync_push_source_empty"


@pytest.mark.parametrize(
    "path",
    [
        "global-shared/project-7/",
        "shared/../project-7/",
        "/shared/projects/project-7/",
        "shared//projects/project-7/",
        "shared/projects/*/",
        "shared/projects/project-?/",
        "shared/projects/[ab]/",
        "shared/projects/{a,b}/",
        "shared/projects/project 7/",
        "shared/projects/$project/",
    ],
)
def test_filesync_push_scope_is_normalized_shared_only(
    tmp_path: Path,
    path: str,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)

    denied = _guard_call(workspace, "leader", _filesync_request("push", path))

    assert _guard_payload(denied)["error"] in {
        "filesync_global_push_forbidden",
        "filesync_path_invalid",
    }


def test_filesync_dry_run_keeps_binding_and_redacts_storage_command(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    source = workspace / "shared/projects/project-7"
    source.mkdir(parents=True)
    (source / "result.md").write_text("dry-run fixture\n", encoding="utf-8")

    response = _guard_call(
        workspace,
        "leader",
        _filesync_request(
            "push",
            "shared/projects/project-7/",
            dryRun=True,
        ),
    )
    result = response["result"]

    assert result["dryRun"] is True
    assert Path(result["localPath"]) == workspace / "shared/projects/project-7"
    assert "command" not in result
    assert "remotePath" not in result
    assert "exclude" not in result
    assert result["expectedObjectCount"] == 1
    assert "verifiedObjectCount" not in result
    assert re.fullmatch(r"[0-9a-f]{64}", result["localTreeSha256"])
    assert "secret-remote-prefix" not in json.dumps(response)


def test_filesync_fails_closed_when_attested_identity_drifts(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    identity_path = workspace / "runtime/runtime.json"
    identity = json.loads(identity_path.read_text(encoding="utf-8"))
    identity["runtimeName"] = "forged-leader"
    identity_path.write_text(json.dumps(identity), encoding="utf-8")

    denied = _guard_call(
        workspace,
        "leader",
        _filesync_request("push", "shared/projects/project-7/"),
    )

    assert _guard_payload(denied)["error"] == "identity_attestation_failed"


def test_project_creation_requires_explicit_immutable_risk_tier(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)

    missing = _guard_call(
        workspace, "worker", _project_request("create_project", "risk-missing")
    )
    assert _guard_payload(missing)["error"] == "approval_denied:project_risk_required"

    created = _guard_call(
        workspace,
        "worker",
        _project_request("create_project", "risk-bound", riskTier="T4"),
    )
    assert created["result"]["ok"] is True
    assert created["result"]["project"]["risk_tier"] == "T4"
    assert created["result"]["project"]["source"] == "operator-driven"
    assert created["result"]["project"]["binding"]["riskTierAuthority"] == (
        "root-only-approval-ledger"
    )
    binding = created["result"]["project"]["binding"]
    assert binding["schema"] == "devflow.project-binding/v2"
    assert binding["audience"] == adapter.APPROVAL_AUDIENCE
    assert binding["approvalDomain"] == TEST_APPROVAL_DOMAIN
    assert re.fullmatch(r"[0-9a-f]{64}", binding["policyKeySha256"])
    assert re.fullmatch(r"[0-9a-f]{64}", binding["projectBindingDigest"])
    downgraded = _project_request("complete_project", "risk-bound", riskTier="T2")
    denied = _guard_call(workspace, "worker", downgraded)
    assert _guard_payload(denied)["error"] == (
        "approval_denied:project_risk_request_mismatch"
    )


def test_project_source_is_required_and_cross_checked_against_persistent_state(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)

    missing_source = _project_request(
        "create_project",
        "source-missing",
        riskTier="T2",
    )
    del missing_source["params"]["arguments"]["payload"]["source"]
    denied = _guard_call(workspace, "leader", missing_source)
    assert _guard_payload(denied)["error"] == (
        "approval_denied:project_source_required"
    )

    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "source-bound", riskTier="T2"),
    )
    state_path = workspace / ".fixture-projects.json"
    projects = json.loads(state_path.read_text(encoding="utf-8"))
    projects["source-bound"]["source"] = "tampered-source"
    state_path.write_text(json.dumps(projects), encoding="utf-8")

    drifted = _guard_call(
        workspace,
        "leader",
        _project_request("resolve_project", "source-bound"),
    )
    assert _guard_payload(drifted)["error"] == (
        "approval_denied:project_source_state_mismatch"
    )


def test_legacy_risk_only_binding_migrates_after_successful_project_readback(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    manifest = _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "legacy-binding", riskTier="T2"),
    )
    ledger_path = Path(manifest["approvalPolicy"]["ledgerPath"])
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    entry = ledger["projects"]["legacy-binding"]
    ledger["projects"]["legacy-binding"] = {
        "riskTier": entry["riskTier"],
        "createdTargetDigest": entry["createdTargetDigest"],
    }
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    resolved = _guard_call(
        workspace,
        "leader",
        _project_request("resolve_project", "legacy-binding"),
    )

    assert resolved["result"]["project"]["risk_tier"] == "T2"
    upgraded = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert upgraded["projects"]["legacy-binding"]["source"] == "operator-driven"
    assert re.fullmatch(
        r"[0-9a-f]{64}",
        upgraded["projects"]["legacy-binding"]["projectBindingDigest"],
    )
    assert re.fullmatch(
        r"[0-9a-f]{64}",
        upgraded["projects"]["legacy-binding"]["incarnation"],
    )


def test_root_ledger_project_incarnation_tamper_fails_closed(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    manifest = _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "incarnation-tamper", riskTier="T4"),
    )
    ledger_path = Path(manifest["approvalPolicy"]["ledgerPath"])
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    ledger["projects"]["incarnation-tamper"]["incarnation"] = "f" * 64
    ledger_path.write_text(json.dumps(ledger), encoding="utf-8")

    denied = _guard_call(
        workspace,
        "leader",
        _project_request("resolve_project", "incarnation-tamper"),
    )

    assert _guard_payload(denied)["error"] == (
        "approval_denied:project_binding_invalid"
    )


@pytest.mark.parametrize("risk_tier", ["T1", "T2"])
def test_low_risk_projects_are_not_blocked_by_approval_gate(
    tmp_path: Path, risk_tier: str
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    project_id = f"low-{risk_tier.lower()}"
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", project_id, riskTier=risk_tier),
    )

    completed = _guard_call(
        workspace, "leader", _project_request("complete_project", project_id)
    )
    assert completed["result"]["ok"] is True


def test_t4_resume_requires_valid_exact_scope_approval_and_rejects_replay(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "critical-resume", riskTier="T4"),
    )
    paused = _guard_call(
        workspace,
        "leader",
        _project_request("pause_project", "critical-resume"),
    )
    assert paused["result"]["ok"] is True
    assert paused["result"]["project"]["status"] == "paused"
    request = _project_request("resume_project", "critical-resume")

    missing = _guard_call(workspace, "leader", request)
    assert "approval must contain exactly" in _guard_payload(missing)["error"]

    arguments = request["params"]["arguments"]
    arguments["approval"] = _signed_approval(
        workspace, arguments, risk_tier="T4"
    )
    accepted = _guard_call(workspace, "leader", request)
    assert accepted["result"]["ok"] is True
    assert accepted["result"]["project"]["status"] == "active"

    replay = _guard_call(workspace, "leader", request)
    assert "nonce was already used" in _guard_payload(replay)["error"]

    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T4",
        nonce="second_resume_nonce_1234567890",
    )
    second_resume = _guard_call(workspace, "leader", request)
    assert _guard_payload(second_resume)["error"] == (
        "approval_denied:resume_requires_paused_project"
    )

    resolved = _guard_call(
        workspace,
        "leader",
        _project_request("resolve_project", "critical-resume"),
    )
    assert resolved["result"]["ok"] is True
    assert resolved["result"]["project"]["status"] == "active"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("approvalDomain", "0" * 64),
        ("policyKeySha256", "1" * 64),
        ("projectBindingDigest", "2" * 64),
    ],
)
def test_signed_approval_rejects_domain_key_and_project_binding_tamper(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    project_id = f"scope-{field.lower()}"
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", project_id, riskTier="T4"),
    )
    _guard_call(
        workspace,
        "leader",
        _project_request("pause_project", project_id),
    )
    request = _project_request("resume_project", project_id)
    arguments = request["params"]["arguments"]
    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T4",
        evidence_updates={field: replacement},
    )

    denied = _guard_call(workspace, "leader", request)

    assert "scope mismatch" in _guard_payload(denied)["error"]


def test_old_signed_approval_schema_is_rejected_before_transition(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "old-schema", riskTier="T4"),
    )
    _guard_call(
        workspace,
        "leader",
        _project_request("pause_project", "old-schema"),
    )
    request = _project_request("resume_project", "old-schema")
    arguments = request["params"]["arguments"]
    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T4",
        evidence_updates={"schemaVersion": "1.0"},
    )

    denied = _guard_call(workspace, "leader", request)

    assert "scope mismatch" in _guard_payload(denied)["error"]
    resolved = _guard_call(
        workspace,
        "leader",
        _project_request("resolve_project", "old-schema"),
    )
    assert resolved["result"]["project"]["status"] == "paused"


def test_same_key_project_nonce_cannot_replay_across_approval_domains(
    tmp_path: Path,
) -> None:
    shared_key_root = tmp_path / "shared-operator-key"
    deployment_a = tmp_path / "deployment-a"
    deployment_b = tmp_path / "deployment-b"
    plugin_a = _fake_plugin(deployment_a)
    plugin_b = _fake_plugin(deployment_b)
    workspace_a = deployment_a / "workspace"
    workspace_b = deployment_b / "workspace"
    runtime_a = deployment_a / "runtime.yaml"
    runtime_b = deployment_b / "runtime.yaml"
    _write(runtime_a, _runtime_text("leader", "leader-a"))
    _write(runtime_b, _runtime_text("leader", "leader-b"))
    manifest_a = _install_fake(
        plugin_a,
        workspace_a,
        "leader",
        runtime_a,
        approval_domain="a" * 64,
        approval_key_root=shared_key_root,
    )
    manifest_b = _install_fake(
        plugin_b,
        workspace_b,
        "leader",
        runtime_b,
        approval_domain="b" * 64,
        approval_key_root=shared_key_root,
    )
    assert manifest_a["approvalPolicy"]["policyKeySha256"] == (
        manifest_b["approvalPolicy"]["policyKeySha256"]
    )
    project_id = "cross-domain-replay"
    for workspace in (workspace_a, workspace_b):
        _guard_call(
            workspace,
            "leader",
            _project_request("create_project", project_id, riskTier="T4"),
        )
        _guard_call(
            workspace,
            "leader",
            _project_request("pause_project", project_id),
        )

    request_a = _project_request("resume_project", project_id)
    approval_a = _signed_approval(
        workspace_a,
        request_a["params"]["arguments"],
        risk_tier="T4",
        nonce="same_cross_domain_nonce_12345678",
        approval_key_root=shared_key_root,
    )
    replay_request = _project_request("resume_project", project_id)
    replay_request["params"]["arguments"]["approval"] = approval_a

    denied = _guard_call(workspace_b, "leader", replay_request)

    assert "scope mismatch" in _guard_payload(denied)["error"]
    resolved_b = _guard_call(
        workspace_b,
        "leader",
        _project_request("resolve_project", project_id),
    )
    assert resolved_b["result"]["project"]["status"] == "paused"


def test_concurrent_t4_resumes_share_one_cross_process_transition_lock(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    manifest = _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "concurrent-resume", riskTier="T4"),
    )
    _guard_call(
        workspace,
        "leader",
        _project_request("pause_project", "concurrent-resume"),
    )

    first = _project_request(
        "resume_project",
        "concurrent-resume",
        _fixtureResumeDelaySeconds=0.5,
    )
    first_arguments = first["params"]["arguments"]
    first_arguments["approval"] = _signed_approval(
        workspace,
        first_arguments,
        risk_tier="T4",
        nonce="first_concurrent_nonce_123456789",
    )
    second = _project_request("resume_project", "concurrent-resume")
    second_arguments = second["params"]["arguments"]
    second_arguments["approval"] = _signed_approval(
        workspace,
        second_arguments,
        risk_tier="T4",
        nonce="second_concurrent_nonce_12345678",
    )

    ledger_path = Path(manifest["approvalPolicy"]["ledgerPath"])
    lock_path = ledger_path.with_name(f".{ledger_path.name}.lock")
    with ThreadPoolExecutor(max_workers=1) as executor:
        first_result = executor.submit(_guard_call, workspace, "leader", first)
        for _ in range(200):
            if lock_path.is_dir():
                break
            time.sleep(0.01)
        else:
            raise AssertionError("resume transition lock was not acquired")
        concurrent = _guard_call(workspace, "leader", second)
        accepted = first_result.result(timeout=10)

    assert accepted["result"]["ok"] is True
    assert accepted["result"]["project"]["status"] == "active"
    assert _guard_payload(concurrent)["error"] == (
        "approval_denied:approval ledger is busy"
    )


def test_stale_approval_ledger_lock_is_recovered_without_manual_deletion(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    manifest = _install_fake(plugin, workspace, "leader", runtime)
    ledger_path = Path(manifest["approvalPolicy"]["ledgerPath"])
    lock_path = ledger_path.with_name(f".{ledger_path.name}.lock")
    lock_path.mkdir(mode=0o700)
    (lock_path / "owner.json").write_text(
        json.dumps(
            {
                "schemaVersion": "devflow.approval-ledger-lock/v1",
                "pid": 2_147_483_647,
                "processIdentity": "0" * 64,
                "nonce": "1" * 64,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    created = _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "stale-lock", riskTier="T4"),
    )

    assert created["result"]["ok"] is True
    assert not lock_path.exists()


def test_malformed_approval_ledger_lock_fails_closed_and_is_preserved(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    manifest = _install_fake(plugin, workspace, "leader", runtime)
    ledger_path = Path(manifest["approvalPolicy"]["ledgerPath"])
    lock_path = ledger_path.with_name(f".{ledger_path.name}.lock")
    lock_path.mkdir(mode=0o700)
    (lock_path / "owner.json").write_text(
        '{"schemaVersion":"untrusted"}',
        encoding="utf-8",
    )

    denied = _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "malformed-lock", riskTier="T4"),
    )

    assert _guard_payload(denied)["error"] == (
        "approval_denied:approval ledger is busy"
    )
    assert lock_path.is_dir()


def test_t4_resume_fails_closed_without_active_state_readback(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "stalled-resume", riskTier="T4"),
    )
    _guard_call(
        workspace,
        "leader",
        _project_request("pause_project", "stalled-resume"),
    )
    request = _project_request(
        "resume_project",
        "stalled-resume",
        _fixtureKeepPaused=True,
    )
    arguments = request["params"]["arguments"]
    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T4",
        nonce="stalled_resume_nonce_123456789",
    )

    denied = _guard_call(workspace, "leader", request)

    assert _guard_payload(denied)["error"] == (
        "approval_denied:resume_did_not_become_active"
    )
    resolved = _guard_call(
        workspace,
        "leader",
        _project_request("resolve_project", "stalled-resume"),
    )
    assert resolved["result"]["project"]["status"] == "paused"


def test_t5_accept_binds_task_target_and_rejects_forgery_and_expiry(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "critical-accept", riskTier="T5"),
    )

    request = _project_request(
        "accept_task_result",
        "critical-accept",
        taskId="task-01",
        accepted=True,
        resultStatus="SUCCESS",
    )
    arguments = request["params"]["arguments"]
    missing = _guard_call(workspace, "leader", request)
    assert "approval must contain exactly" in _guard_payload(missing)["error"]

    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T5",
        evidence_updates={"taskId": "task-other"},
    )
    wrong_task = _guard_call(workspace, "leader", request)
    assert "scope mismatch" in _guard_payload(wrong_task)["error"]

    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T5",
        nonce="expired_nonce_1234567890AB",
        issued_delta=-600,
        expires_delta=-300,
    )
    expired = _guard_call(workspace, "leader", request)
    assert "not currently valid" in _guard_payload(expired)["error"]

    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T5",
        nonce="forged_nonce_1234567890ABC",
    )
    arguments["approval"]["signature"] = base64.b64encode(b"x" * 64).decode()
    forged = _guard_call(workspace, "leader", request)
    assert "signature verification failed" in _guard_payload(forged)["error"]

    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T5",
        nonce="valid_accept_nonce_1234567890",
    )
    accepted = _guard_call(workspace, "leader", request)
    assert accepted["result"]["ok"] is True


def test_t5_pause_needs_no_approval_and_unknown_evidence_fields_fail_closed(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "critical-pause", riskTier="T5"),
    )
    pause_with_approval = _project_request("pause_project", "critical-pause")
    pause_with_approval["params"]["arguments"]["approval"] = {"unexpected": True}
    rejected_pause = _guard_call(workspace, "leader", pause_with_approval)
    assert _guard_payload(rejected_pause)["error"] == (
        "approval_denied:pause_approval_forbidden"
    )
    paused = _guard_call(
        workspace, "leader", _project_request("pause_project", "critical-pause")
    )
    assert paused["result"]["ok"] is True

    complete = _project_request("complete_project", "critical-pause")
    arguments = complete["params"]["arguments"]
    missing = _guard_call(workspace, "leader", complete)
    assert "approval must contain exactly" in _guard_payload(missing)["error"]

    approval = _signed_approval(workspace, arguments, risk_tier="T5")
    approval["evidence"]["unexpected"] = True
    arguments["approval"] = approval
    denied = _guard_call(workspace, "leader", complete)
    assert "evidence schema mismatch" in _guard_payload(denied)["error"]

    arguments["approval"] = _signed_approval(
        workspace,
        arguments,
        risk_tier="T5",
        nonce="valid_complete_nonce_12345678",
    )
    completed = _guard_call(workspace, "leader", complete)
    assert completed["result"]["ok"] is True


def test_approval_public_key_tampering_breaks_verify_and_runtime_gate(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    manifest = json.loads(
        (workspace / ".teamharness/install-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    public_key = Path(manifest["approvalPolicy"]["publicKeyPath"])
    public_key.chmod(0o644)
    public_key.write_text("forged public key\n", encoding="utf-8")

    checks = _verify_fake(plugin, workspace, "leader")
    assert not next(check for check in checks if check.name == "approval-policy").ok
    denied = _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "tampered-key", riskTier="T4"),
    )
    assert _guard_payload(denied)["error"] == "approval_denied:approval_policy_invalid"


def test_old_approval_policy_schema_is_rejected_by_verify_and_guard(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    manifest_path = workspace / ".teamharness/install-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    policy = cast(dict[str, Any], manifest["approvalPolicy"])
    policy["schemaVersion"] = "1.0"
    attestation_path = Path(policy["policyAttestationPath"])
    attestation_path.chmod(0o644)
    attestation_path.write_text(
        json.dumps(policy, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest["approvalPolicy"] = policy
    manifest["approvalPolicySha256"] = hashlib.sha256(
        attestation_path.read_bytes()
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    checks = _verify_fake(plugin, workspace, "leader")
    assert not next(check for check in checks if check.name == "approval-policy").ok
    denied = _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "old-policy", riskTier="T4"),
    )
    assert _guard_payload(denied)["error"] == "approval_denied:approval_policy_invalid"


def test_writable_workspace_manifest_cannot_replace_external_policy(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _install_fake(plugin, workspace, "leader", runtime)
    manifest_path = workspace / ".teamharness/install-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert not Path(manifest["approvalPolicy"]["publicKeyPath"]).is_relative_to(
        workspace
    )
    assert not Path(manifest["approvalPolicy"]["ledgerPath"]).is_relative_to(
        workspace
    )
    manifest["approvalPolicy"]["publicKeySha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    denied = _guard_call(
        workspace,
        "leader",
        _project_request("create_project", "manifest-forgery", riskTier="T4"),
    )
    assert _guard_payload(denied)["error"] == "approval_denied:approval_policy_invalid"


def test_adapter_assets_do_not_contain_credentials() -> None:
    for path in (
        ROOT / "agentteams/teamharness/guarded_server.py",
        ROOT / "scripts/teamharness_openclaw.py",
    ):
        text = path.read_text(encoding="utf-8")
        assert "ghp_" not in text
        assert not re.search(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{16,}\b", text)
        assert not re.search(
            r"(?i)(?:password|accessToken)\s*[:=]\s*[\"'][^\"']+[\"']",
            text,
        )


def test_agentteams_workspace_uses_global_shared_tree(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "hiclaw-fs/agents/worker-a"
    runtime = workspace / "runtime/runtime.yaml"
    _write(runtime, _runtime_text("worker"))

    _install_fake(plugin, workspace, "worker", runtime)

    config = json.loads((workspace / "config/mcporter.json").read_text(encoding="utf-8"))
    env = config["mcpServers"]["teamharness"]["env"]
    assert env["TEAMHARNESS_SHARED_DIR"] == str(
        (tmp_path / "hiclaw-fs/shared").resolve()
    )


def test_install_rejects_runtime_config_with_embedded_credentials(
    tmp_path: Path,
) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(
        runtime,
        _runtime_text("worker")
        + "matrix:\n  accessToken: fixture-invalid-token\n",
    )

    try:
        _install_fake(plugin, workspace, "worker", runtime)
    except ValueError as exc:
        assert "runtime config embeds credentials" in str(exc)
    else:
        raise AssertionError("embedded runtime credential was accepted")


def test_leader_agents_contract_is_bounded_and_complete(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("leader"))
    _write(workspace / "AGENTS.md", "# Existing local instructions\n")

    _install_fake(plugin, workspace, "leader", runtime)

    agents = (workspace / "AGENTS.md").read_text(encoding="utf-8")
    assert agents.startswith("# Existing local instructions\n")
    assert agents.count(AGENTS_BEGIN) == agents.count(AGENTS_END) == 1
    for required_action in (
        "projectflow.create_project",
        "plan_dag",
        "roomflow.create_task_room",
        "invite/include the assignee",
        "taskflow.delegate_task",
        "exactly one complete Matrix assignment mention",
        "taskflow.check_task",
        "projectflow.accept_task_result",
        "projectflow.complete_project",
        "filesync.push",
        "mark_requester_report_sent",
        "same assignmentId",
        "byte-identical assignment digest",
        "pending=false",
    ):
        assert required_action in agents
    assert agents.index("mark_requester_report_sent") < agents.index("filesync.push")
    assert "# upstream prompt" not in agents
    assert all(check.ok for check in _verify_fake(plugin, workspace, "leader"))


def test_worker_agents_contract_has_one_way_boundary(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))

    record = _install_fake(plugin, workspace, "worker", runtime)

    agents = (workspace / "AGENTS.md").read_text(encoding="utf-8")
    assert "idempotent `taskflow.ack_task`" in agents
    assert "idempotent `taskflow.submit_task`" in agents
    assert "cannot call `artifact` or `filesync` directly" in agents
    assert "Produce the assigned canonical artifact first" in agents
    assert "Never call Leader actions" in agents
    assert record["files"]["AGENTS.md"] == hashlib.sha256(
        (workspace / "AGENTS.md").read_bytes()
    ).hexdigest()


def test_replace_updates_one_marked_section_idempotently(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _write(workspace / "AGENTS.md", "before\n\nafter-owned-by-user\n")

    first_record = _install_fake(plugin, workspace, "worker", runtime)
    first = (workspace / "AGENTS.md").read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="pass --replace"):
        _install_fake(plugin, workspace, "worker", runtime)

    second_record = _install_fake(plugin, workspace, "worker", runtime, replace=True)
    second = (workspace / "AGENTS.md").read_text(encoding="utf-8")
    assert second == first
    assert second.count(AGENTS_BEGIN) == second.count(AGENTS_END) == 1
    assert "before" in second and "after-owned-by-user" in second
    assert second_record["files"] == first_record["files"]


def test_verify_rejects_role_drift_and_missing_hash_coverage(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    wrong_role = _verify_fake(plugin, workspace, "leader")
    assert not next(check for check in wrong_role if check.name == "agents-role").ok
    assert not next(check for check in wrong_role if check.name == "install-manifest").ok

    manifest_path = workspace / ".teamharness/install-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["files"]["AGENTS.md"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    coverage = _verify_fake(plugin, workspace, "worker")
    assert not next(check for check in coverage if check.name == "manifest-hashes").ok


def test_verify_detects_agents_contract_tampering(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))
    _install_fake(plugin, workspace, "worker", runtime)

    agents_path = workspace / "AGENTS.md"
    agents_path.write_text(
        agents_path.read_text(encoding="utf-8").replace(
            "Never call Leader actions", "Leader actions are allowed"
        ),
        encoding="utf-8",
    )
    checks = _verify_fake(plugin, workspace, "worker")
    assert not next(check for check in checks if check.name == "agents-section").ok
    assert not next(check for check in checks if check.name == "manifest-hashes").ok


def test_production_source_policy_is_fixed_and_fails_closed(tmp_path: Path) -> None:
    assert UPSTREAM_FILE_SHA256 == {
        "plugin.yaml": "40121114d1f2a5897e90e21f819f34491bd8062eae25634825f9e7b50b61d518",
        "mcp/server.py": "cb9971baae3545f440821ecf1fd18c76078962a1fe1591141cc88026bf5b684f",
        "mcp/message_tool.py": "03e8fcfcaf002c5d9dd0c023b85bd4d2f4641b83cb59c6d89be08a9c1689c47c",
        "mcp/roomflow_tool.py": "db127d550cf9155c133657ab7c89fee48292c07587a061954bd60b4c14991680",
    }
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    _write(runtime, _runtime_text("worker"))

    with pytest.raises(ValueError, match="source integrity mismatch: mcp/server.py"):
        install(plugin, workspace, "worker", runtime)
    assert not workspace.exists()


def test_install_and_verify_run_without_site_packages(tmp_path: Path) -> None:
    plugin = _fake_plugin(tmp_path)
    workspace = tmp_path / "workspace"
    runtime = tmp_path / "runtime.yaml"
    bad_runtime = tmp_path / "bad-runtime.yaml"
    wrong_runtime = tmp_path / "wrong-runtime.yaml"
    policy_path = tmp_path / "policy.json"
    binding, installed_binding, _pod_name = _runtime_binding(
        tmp_path, "worker", "worker-runtime"
    )
    _write(runtime, _runtime_text("worker"))
    _write(
        bad_runtime,
        _runtime_text("worker")
        + "desired:\n  model:\n    gatewayKey: fixture\n",
    )
    _write(wrong_runtime, _runtime_text("leader"))
    policy_path.write_text(json.dumps(_test_hash_policy(plugin)), encoding="utf-8")
    code = """
import json
import sys
from pathlib import Path
from scripts.teamharness_openclaw import install, verify
plugin, workspace, runtime, bad_runtime, wrong_runtime, policy_path, binding, installed_binding = map(Path, sys.argv[1:])
policy = json.loads(policy_path.read_text(encoding="utf-8"))
record = install(
    plugin, workspace, "worker", runtime, _test_hash_policy=policy,
    runtime_binding=binding,
    _test_hostname="agentteams-worker-worker-runtime",
    _test_runtime_binding_path=installed_binding,
)
assert record["role"] == "worker"
checks = verify(workspace, "worker", _test_hash_policy=policy)
assert all(check.ok for check in checks), checks
for rejected, fragment in (
    (bad_runtime, "embeds credentials"),
    (wrong_runtime, "does not match install role"),
):
    try:
        install(
            plugin,
            workspace.parent / (rejected.stem + "-workspace"),
            "worker",
            rejected,
            runtime_binding=binding,
            _test_hash_policy=policy,
            _test_hostname="agentteams-worker-worker-runtime",
            _test_runtime_binding_path=installed_binding,
        )
    except ValueError as exc:
        assert fragment in str(exc), exc
    else:
        raise AssertionError("strict stdlib runtime validation was bypassed")
"""
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            code,
            str(plugin),
            str(workspace),
            str(runtime),
            str(bad_runtime),
            str(wrong_runtime),
            str(policy_path),
            str(binding),
            str(installed_binding),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert all(check.ok for check in _verify_fake(plugin, workspace, "worker"))

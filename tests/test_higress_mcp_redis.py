"""Production-safety gates for Higress MCP Redis session storage."""

from __future__ import annotations

import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.configure_higress_mcp_redis import (
    CONFIGMAP_NAME,
    NAMESPACE,
    REDIS_ADDRESS,
    SERVICE_NAME,
    ConfigurationError,
    configure,
    reconcile_higress_yaml,
    validate_endpoint_slices,
    validate_service,
)

ROOT = Path(__file__).resolve().parents[1]


def _service() -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": SERVICE_NAME, "namespace": NAMESPACE},
        "spec": {
            "type": "ClusterIP",
            "clusterIP": "192.0.2.2",
            "selector": {"app": SERVICE_NAME},
            "ports": [
                {
                    "name": "redis",
                    "protocol": "TCP",
                    "port": 6379,
                    "targetPort": "redis",
                }
            ],
        },
    }


def _endpoint_slices(*, ready: bool = True) -> dict[str, Any]:
    return {
        "apiVersion": "discovery.k8s.io/v1",
        "kind": "EndpointSliceList",
        "items": [
            {
                "apiVersion": "discovery.k8s.io/v1",
                "kind": "EndpointSlice",
                "metadata": {
                    "name": f"{SERVICE_NAME}-abcde",
                    "namespace": NAMESPACE,
                    "labels": {"kubernetes.io/service-name": SERVICE_NAME},
                },
                "addressType": "IPv4",
                "ports": [{"name": "redis", "protocol": "TCP", "port": 6379}],
                "endpoints": [
                    {
                        "addresses": ["192.0.2.9"],
                        "conditions": {"ready": ready},
                    }
                ],
            }
        ],
    }


def _configmap(source: str, version: str = "41") -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": CONFIGMAP_NAME,
            "namespace": NAMESPACE,
            "resourceVersion": version,
            "managedFields": [{"manager": "test"}],
        },
        "data": {"higress": source, "unrelated": "preserve-me"},
    }


def _drifted_yaml() -> str:
    return """mcpServer:
  enable: true
  redis:
    address: old-redis.example:6379
    username: ""
    password: ""
    db: 2
  servers: []
other: true
"""


def _desired_yaml() -> str:
    return f"""mcpServer:
  enable: true
  redis:
    address: {REDIS_ADDRESS}
    username: ""
    password: ""
    db: 0
  servers: []
other: true
"""


class _FakeClient:
    def __init__(self, source: str) -> None:
        self.configmap = _configmap(source)
        self.replacements: list[dict[str, Any]] = []

    def get_json(
        self,
        resource: str,
        *,
        name: str | None = None,
        selector: str | None = None,
    ) -> dict[str, Any]:
        if resource == "service":
            assert name == SERVICE_NAME
            return deepcopy(_service())
        if resource == "endpointslices.discovery.k8s.io":
            assert name is None
            assert selector == f"kubernetes.io/service-name={SERVICE_NAME}"
            return deepcopy(_endpoint_slices())
        if resource == "configmap":
            assert name == CONFIGMAP_NAME
            return deepcopy(self.configmap)
        raise AssertionError(f"unexpected resource: {resource}")

    def replace_configmap(self, document: dict[str, Any]) -> None:
        assert document["metadata"]["resourceVersion"] == "41"
        assert "managedFields" not in document["metadata"]
        assert document["data"]["unrelated"] == "preserve-me"
        self.replacements.append(deepcopy(document))
        self.configmap = deepcopy(document)
        self.configmap["metadata"]["resourceVersion"] = "42"


def test_manifest_is_private_persistent_and_pinned() -> None:
    documents = list(
        yaml.safe_load_all(
            (ROOT / "agentteams" / "higress-redis.yaml").read_text(encoding="utf-8")
        )
    )
    by_kind = {document["kind"]: document for document in documents}
    assert set(by_kind) == {
        "PersistentVolumeClaim",
        "Deployment",
        "Service",
        "NetworkPolicy",
    }

    pvc = by_kind["PersistentVolumeClaim"]
    assert pvc["spec"]["storageClassName"] == "local-path"
    assert pvc["spec"]["accessModes"] == ["ReadWriteOnce"]

    deployment = by_kind["Deployment"]
    assert deployment["spec"]["replicas"] == 1
    pod = deployment["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False
    assert pod["nodeSelector"] == {"kubernetes.io/arch": "amd64"}
    assert pod["securityContext"]["runAsNonRoot"] is True
    container = pod["containers"][0]
    assert container["image"].endswith(
        "redis-stack-server:7.4.0-v3@"
        "sha256:a8d64e9f5bc99dc83f2a807a93f44d59efab0d2c4f09cff03f01b8753842e0cc"
    )
    assert {"startupProbe", "readinessProbe", "livenessProbe"} <= set(container)
    for probe_name in ("startupProbe", "readinessProbe", "livenessProbe"):
        assert container[probe_name]["exec"]["command"] == [
            "/bin/sh",
            "-ec",
            'test "$(redis-cli -h 127.0.0.1 -p 6379 ping)" = PONG',
        ]
    assert container["resources"]["requests"] == {"cpu": "100m", "memory": "256Mi"}
    assert container["resources"]["limits"] == {"cpu": "1", "memory": "1Gi"}
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
    }

    service = by_kind["Service"]
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["selector"] == {"app": SERVICE_NAME}
    assert service["spec"]["ports"] == [
        {"name": "redis", "port": 6379, "targetPort": "redis", "protocol": "TCP"}
    ]

    network_policy = by_kind["NetworkPolicy"]
    assert network_policy["spec"]["podSelector"]["matchLabels"] == {
        "app": SERVICE_NAME
    }
    assert network_policy["spec"]["ingress"] == [
        {
            "from": [{"podSelector": {"matchLabels": {"app": "higress-gateway"}}}],
            "ports": [{"protocol": "TCP", "port": 6379}],
        }
    ]
    assert network_policy["spec"]["egress"] == []


def test_reconcile_replaces_only_managed_redis_block() -> None:
    result, changed = reconcile_higress_yaml(_drifted_yaml())
    assert changed is True
    assert result == _desired_yaml()

    second, changed_again = reconcile_higress_yaml(result)
    assert second == result
    assert changed_again is False


def test_reconcile_accepts_only_the_complete_upstream_placeholder_tuple() -> None:
    placeholder = """mcpServer:
  enable: true
  redis:
    address: your.redis.host:6379
    password: your_password
    db: 0
    username: your_username
  servers: []
"""
    result, changed = reconcile_higress_yaml(placeholder)
    assert changed is True
    assert f"address: {REDIS_ADDRESS}" in result
    assert 'username: ""' in result
    assert 'password: ""' in result

    partially_changed = placeholder.replace("your_username", "real-user")
    with pytest.raises(ConfigurationError, match="credentials"):
        reconcile_higress_yaml(partially_changed)


def test_reconcile_inserts_missing_redis_block() -> None:
    source = """mcpServer:
  enable: true
  servers: []
other: true
"""
    result, changed = reconcile_higress_yaml(source)
    assert changed is True
    assert result.startswith(
        f"""mcpServer:
  redis:
    address: {REDIS_ADDRESS}
    username: ""
    password: ""
    db: 0
"""
    )
    assert "  enable: true\n" in result
    assert result.endswith("other: true\n")


@pytest.mark.parametrize(
    "source",
    [
        "mcpServer: {}\n",
        "mcpServer:\n  redis: {}\n",
        "mcpServer:\n  redis:\n    address: old:6379\n",
        (
            "mcpServer:\n  redis:\n    address: old:6379\n    username: admin\n"
            "    password: \"\"\n    db: 0\n"
        ),
        (
            "mcpServer:\n  redis:\n    address: old:6379\n    username: \"\"\n"
            "    password: secret\n    db: 0\n"
        ),
        (
            "mcpServer:\n  redis:\n    address: old:6379\n    username: \"\"\n"
            "    password: \"\"\n    db: 0\n    tls: false\n"
        ),
        "mcpServer:\n  redis:\n    address: old:6379\n  redis:\n",
        "mcpServer:\n  enable: true\nmcpServer:\n  enable: false\n",
        "mcpServer:\n  enable: true\nmcpServer :\n  enable: false\n",
        "mcpServer:\n  enable: true\n? mcpServer\n: {}\n",
        (
            "mcpServer:\n  redis:\n    address: &address old:6379\n"
            "    username: \"\"\n    password: \"\"\n    db: 0\n"
        ),
        "mcpServer:\n\tenable: true\n",
        "mcpServer:\r\n  enable: true\n",
    ],
)
def test_reconcile_rejects_ambiguous_or_credentialed_structures(source: str) -> None:
    with pytest.raises(ConfigurationError):
        reconcile_higress_yaml(source)


def test_reconcile_handles_a_minimal_mapping_without_terminal_newline() -> None:
    result, changed = reconcile_higress_yaml("mcpServer:")
    assert changed is True
    assert result.startswith("mcpServer:\n  redis:\n")


def test_service_and_endpoint_validation_is_fail_closed() -> None:
    validate_service(_service())
    validate_endpoint_slices(_endpoint_slices())

    generic_list = _endpoint_slices()
    generic_list["apiVersion"] = "v1"
    generic_list["kind"] = "List"
    validate_endpoint_slices(generic_list)

    bad_selector = _service()
    bad_selector["spec"]["selector"] = {"app": "redis"}
    with pytest.raises(ConfigurationError, match="Service"):
        validate_service(bad_selector)

    unready = _endpoint_slices(ready=False)
    with pytest.raises(ConfigurationError, match="not uniquely ready"):
        validate_endpoint_slices(unready)

    duplicate = _endpoint_slices()
    duplicate["items"].append(deepcopy(duplicate["items"][0]))
    with pytest.raises(ConfigurationError, match="exactly one EndpointSlice"):
        validate_endpoint_slices(duplicate)


def test_check_mode_is_read_only_and_fails_on_drift() -> None:
    compliant = _FakeClient(_desired_yaml())
    assert configure(compliant, apply=False) is False
    assert compliant.replacements == []

    drifted = _FakeClient(_drifted_yaml())
    with pytest.raises(ConfigurationError, match="not compliant"):
        configure(drifted, apply=False)
    assert drifted.replacements == []


def test_apply_uses_resource_version_preserves_data_and_verifies() -> None:
    client = _FakeClient(_drifted_yaml())
    assert configure(client, apply=True) is True
    assert len(client.replacements) == 1
    assert client.configmap["data"]["higress"] == _desired_yaml()
    assert client.configmap["data"]["unrelated"] == "preserve-me"


class _StaleClient(_FakeClient):
    def replace_configmap(self, document: dict[str, Any]) -> None:
        self.replacements.append(deepcopy(document))


def test_apply_rejects_missing_post_write_resource_version_change() -> None:
    client = _StaleClient(_drifted_yaml())
    with pytest.raises(ConfigurationError, match="final verification failed"):
        configure(client, apply=True)


def test_configurator_runs_without_site_packages() -> None:
    help_result = subprocess.run(
        [
            sys.executable,
            "-S",
            str(ROOT / "scripts" / "configure_higress_mcp_redis.py"),
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--apply" in help_result.stdout

    pure_function = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "from scripts.configure_higress_mcp_redis import "
                "reconcile_higress_yaml; "
                "out,changed=reconcile_higress_yaml('mcpServer:\\n  enable: true\\n'); "
                f"assert '{REDIS_ADDRESS}' in out and changed"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert pure_function.returncode == 0, pure_function.stderr


def test_script_has_no_yaml_dependency_or_secret_generation() -> None:
    source = (ROOT / "scripts" / "configure_higress_mcp_redis.py").read_text(
        encoding="utf-8"
    )
    assert "import yaml" not in source
    assert "import secrets" not in source
    assert "token_urlsafe" not in source
    assert "getpass" not in source

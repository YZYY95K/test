"""Static production-boundary checks for the GitHub scope broker manifests."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "agentteams" / "github-scope-broker.yaml"
CONTAINERFILE = ROOT / "agentteams" / "github-scope-broker.Containerfile"


def _documents() -> list[dict[str, Any]]:
    return [
        document
        for document in yaml.safe_load_all(MANIFEST.read_text(encoding="utf-8"))
        if isinstance(document, dict)
    ]


def _named(kind: str, name: str) -> dict[str, Any]:
    matches = [
        document
        for document in _documents()
        if document.get("kind") == kind
        and document.get("metadata", {}).get("name") == name
    ]
    assert len(matches) == 1
    return matches[0]


def _container(component: str) -> tuple[dict[str, Any], dict[str, Any]]:
    name = (
        "devflow-github-scope-issuer"
        if component == "scope-issuer"
        else f"devflow-github-{component}-broker"
    )
    deployment = _named("Deployment", name)
    pod_spec = deployment["spec"]["template"]["spec"]
    assert len(pod_spec["containers"]) == 1
    return pod_spec, pod_spec["containers"][0]


def test_manifest_contains_no_secret_object_or_secret_value() -> None:
    documents = _documents()
    assert all(document.get("kind") != "Secret" for document in documents)
    text = MANIFEST.read_text(encoding="utf-8")
    assert "stringData:" not in text
    assert "DEVFLOW_GITHUB_BROKER_ISSUER_TOKEN" not in text
    assert "github-token" in text
    assert "hmac-key" in text


def test_issuer_and_content_have_disjoint_credentials_and_identities() -> None:
    issuer_spec, issuer = _container("scope-issuer")
    content_spec, content = _container("content")
    issuer_env = {item["name"]: item for item in issuer["env"]}
    content_env = {item["name"]: item for item in content["env"]}

    assert issuer_spec["serviceAccountName"] == "devflow-github-scope-issuer"
    assert content_spec["serviceAccountName"] == "devflow-github-content-broker"
    assert issuer_spec["automountServiceAccountToken"] is False
    assert content_spec["automountServiceAccountToken"] is False
    assert "DEVFLOW_GITHUB_TOKEN" not in issuer_env
    assert "DEVFLOW_GITHUB_TOKEN" in content_env
    assert "DEVFLOW_GITHUB_BROKER_HMAC_KEY" in issuer_env
    assert "DEVFLOW_GITHUB_BROKER_HMAC_KEY" in content_env
    assert "DEVFLOW_GITHUB_ALLOWED_REPOSITORIES" in issuer_env
    assert "DEVFLOW_GITHUB_ALLOWED_REPOSITORIES" in content_env
    assert "DEVFLOW_GITHUB_TOKEN_REVIEW_AUDIENCE" in issuer_env
    assert "DEVFLOW_GITHUB_TOKEN_REVIEW_AUDIENCE" not in content_env
    assert "kubernetes-tokenreview" in issuer["args"]
    assert "DEVFLOW_GITHUB_BROKER_ISSUER_TOKEN" not in issuer_env
    token_projection = issuer_spec["volumes"][0]["projected"]["sources"][0][
        "serviceAccountToken"
    ]
    assert token_projection == {
        "path": "token",
        "expirationSeconds": 600,
        "audience": "https://kubernetes.default.svc.cluster.local",
    }
    config = _named("ConfigMap", "devflow-github-scope-broker")["data"]
    assert config["DEVFLOW_GITHUB_ALLOWED_REPOSITORIES"] == "YZYY95K/test"
    assert config["DEVFLOW_GITHUB_CAPABILITY_TTL_SECONDS"] == "300"
    assert config["DEVFLOW_GITHUB_TOKEN_REVIEW_AUDIENCE"] == "agentteams-controller"

    role = _named("ClusterRole", "devflow-github-scope-tokenreview")
    assert role["rules"] == [
        {
            "apiGroups": ["authentication.k8s.io"],
            "resources": ["tokenreviews"],
            "verbs": ["create"],
        }
    ]


def test_both_workloads_are_non_root_read_only_and_resource_bounded() -> None:
    for component in ("scope-issuer", "content"):
        pod_spec, container = _container(component)
        pod_security = pod_spec["securityContext"]
        container_security = container["securityContext"]
        assert pod_security["runAsNonRoot"] is True
        assert pod_security["runAsUser"] != 0
        assert pod_security["seccompProfile"] == {"type": "RuntimeDefault"}
        assert container_security["readOnlyRootFilesystem"] is True
        assert container_security["allowPrivilegeEscalation"] is False
        assert container_security["capabilities"] == {"drop": ["ALL"]}
        assert set(container["resources"]) == {"requests", "limits"}
        assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
        assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"


def test_network_policies_split_leader_and_higress_ingress() -> None:
    issuer_service = _named("Service", "devflow-github-capability-issuer")
    assert issuer_service["spec"]["ports"] == [
        {"name": "issuer-http", "port": 8081, "targetPort": "issuer-http"}
    ]
    issuer = _named("NetworkPolicy", "devflow-github-scope-issuer")["spec"]
    content = _named("NetworkPolicy", "devflow-github-content-broker")["spec"]
    assert issuer["ingress"] == [
        {
            "from": [
                {
                    "podSelector": {
                        "matchLabels": {
                            "agentteams.io/team": "devflow-swe",
                            "agentteams.io/worker": "devflow-lead",
                            "agentteams.io/role": "team_leader",
                        }
                    }
                }
            ],
            "ports": [{"protocol": "TCP", "port": 8081}],
        }
    ]
    assert content["ingress"] == [
        {
            "from": [
                {"podSelector": {"matchLabels": {"app": "higress-gateway"}}}
            ],
            "ports": [{"protocol": "TCP", "port": 8080}],
        }
    ]
    assert issuer["egress"] == [
        {
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
            "ports": [
                {"protocol": "TCP", "port": 443},
                {"protocol": "TCP", "port": 6443},
            ],
        }
    ]


def test_container_base_is_digest_pinned_and_has_no_package_install() -> None:
    text = CONTAINERFILE.read_text(encoding="utf-8")
    first_line = text.splitlines()[0]
    assert re.fullmatch(
        r"FROM python:3\.12\.11-slim-bookworm@sha256:[0-9a-f]{64}",
        first_line,
    )
    assert "apt-get" not in text
    assert "pip install" not in text
    assert "USER 65532:65532" in text

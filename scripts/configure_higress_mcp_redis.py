"""Safely configure Higress MCP session storage to use the DevFlow Redis.

The utility deliberately uses only the Python standard library.  It validates
the Service and its ready EndpointSlice before reading the ConfigMap, performs
an optimistic-locking ``kubectl replace`` with ``resourceVersion``, and never
prints the ConfigMap body.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from typing import Any, Protocol

NAMESPACE = "agentteams-system"
CONFIGMAP_NAME = "higress-config"
SERVICE_NAME = "devflow-higress-redis"
REDIS_ADDRESS = (
    "devflow-higress-redis.agentteams-system.svc.cluster.local:6379"
)
REDIS_PORT = 6379
UPSTREAM_PLACEHOLDER_REDIS = {
    "address": "your.redis.host:6379",
    "username": "your_username",
    "password": "your_password",
    "db": "0",
}
_MAPPING_LINE = re.compile(
    r"^(?P<indent> *)(?P<key>[A-Za-z_][A-Za-z0-9_-]*|'[^']*'|\"[^\"]*\") *:(?P<tail>.*)$"
)
_EXPLICIT_MCP_KEY = re.compile(r"^\? +(?:mcpServer|'mcpServer'|\"mcpServer\") *$")


class ConfigurationError(RuntimeError):
    """A safe configuration or Kubernetes precondition failed."""


class KubernetesClient(Protocol):
    """Small interface used by the reconciler and its unit tests."""

    def get_json(
        self,
        resource: str,
        *,
        name: str | None = None,
        selector: str | None = None,
    ) -> dict[str, Any]: ...

    def replace_configmap(self, document: dict[str, Any]) -> None: ...


class KubectlClient:
    """A non-shelling kubectl adapter that suppresses resource contents."""

    def __init__(self, namespace: str = NAMESPACE) -> None:
        self.namespace = namespace

    def get_json(
        self,
        resource: str,
        *,
        name: str | None = None,
        selector: str | None = None,
    ) -> dict[str, Any]:
        command = ["kubectl", "--namespace", self.namespace, "get", resource]
        if name is not None:
            command.append(name)
        if selector is not None:
            command.extend(["--selector", selector])
        command.extend(["--output", "json"])
        try:
            process = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise ConfigurationError("unable to invoke kubectl") from exc
        if process.returncode != 0:
            raise ConfigurationError(f"unable to read Kubernetes {resource}")
        try:
            document = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"Kubernetes {resource} response is not valid JSON"
            ) from exc
        if not isinstance(document, dict):
            raise ConfigurationError(f"Kubernetes {resource} response is malformed")
        return document

    def replace_configmap(self, document: dict[str, Any]) -> None:
        try:
            process = subprocess.run(
                [
                    "kubectl",
                    "--namespace",
                    self.namespace,
                    "replace",
                    "--filename",
                    "-",
                    "--output",
                    "name",
                ],
                input=json.dumps(document, ensure_ascii=True, separators=(",", ":")),
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise ConfigurationError("unable to invoke kubectl") from exc
        if process.returncode != 0:
            # In particular, a resourceVersion conflict is deliberately fatal.
            # stdout/stderr may contain the ConfigMap and must not be forwarded.
            raise ConfigurationError("Kubernetes rejected the ConfigMap replacement")


def _mapping(line: str) -> tuple[int, str, str] | None:
    match = _MAPPING_LINE.fullmatch(line.rstrip("\r\n"))
    if match is None:
        return None
    raw_key = match.group("key")
    key = raw_key[1:-1] if raw_key[:1] in {"'", '"'} else raw_key
    return len(match.group("indent")), key, match.group("tail")


def _is_ignorable(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def _empty_mapping_tail(tail: str) -> bool:
    stripped = tail.strip()
    return not stripped or stripped.startswith("#")


def _scalar(tail: str) -> str:
    value = tail.strip()
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    if not value or value[0] in "|>&*!{[":
        raise ConfigurationError("mcpServer.redis contains a non-scalar field")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    elif value[:1] in {"'", '"'} or value[-1:] in {"'", '"'}:
        raise ConfigurationError("mcpServer.redis contains a malformed scalar")
    return value


def reconcile_higress_yaml(
    source: str, *, initialize_missing_mcp_server: bool = False
) -> tuple[str, bool]:
    """Return a canonical Redis block and whether the source needed a change.

    This is intentionally not a general YAML parser.  It recognizes only the
    narrow mapping path owned by this utility and rejects ambiguous or drifted
    representations rather than guessing how to rewrite them.
    """

    remainder = source.replace("\r\n", "")
    if (
        not source
        or "\x00" in source
        or "\t" in source
        or "\r" in remainder
        or ("\r\n" in source and "\n" in remainder)
    ):
        raise ConfigurationError("higress configuration has unsafe formatting")
    lines = source.splitlines(keepends=True)
    if not lines:
        raise ConfigurationError("higress configuration is empty")

    mcp_indexes: list[int] = []
    for index, line in enumerate(lines):
        if _EXPLICIT_MCP_KEY.fullmatch(line.rstrip("\r\n")):
            raise ConfigurationError("explicit mcpServer keys are unsupported")
        parsed = _mapping(line)
        if parsed is not None and parsed[0] == 0 and parsed[1] == "mcpServer":
            mcp_indexes.append(index)
    if not mcp_indexes and initialize_missing_mcp_server:
        # The pinned Higress 2.2.1 Helm chart renders only the generic gateway
        # settings.  Its official MCP quick start requires operators to add the
        # top-level mcpServer block explicitly.  Keep that bootstrap behind a
        # dedicated flag and reject YAML document/sequence/complex-key shapes
        # rather than guessing how to merge them.
        top_level_keys: set[str] = set()
        saw_top_level = False
        for line in lines:
            if _is_ignorable(line):
                continue
            indentation = len(line) - len(line.lstrip(" "))
            parsed = _mapping(line)
            if indentation == 0:
                if parsed is None or parsed[1] in top_level_keys:
                    raise ConfigurationError(
                        "higress configuration has an unsupported top-level structure"
                    )
                top_level_keys.add(parsed[1])
                saw_top_level = True
            elif not saw_top_level:
                raise ConfigurationError(
                    "higress configuration has an unsupported top-level structure"
                )
        if not top_level_keys:
            raise ConfigurationError(
                "higress configuration has an unsupported top-level structure"
            )
        newline = "\r\n" if "\r\n" in source else "\n"
        canonical = "".join(
            [
                f"mcpServer:{newline}",
                f"  sse_path_suffix: /sse{newline}",
                f"  enable: true{newline}",
                f"  redis:{newline}",
                f"    address: {REDIS_ADDRESS}{newline}",
                f'    username: ""{newline}',
                f'    password: ""{newline}',
                f"    db: 0{newline}",
                f"  match_list: []{newline}",
                f"  servers: []{newline}",
            ]
        )
        return canonical + source, True
    if len(mcp_indexes) != 1:
        raise ConfigurationError(
            "higress configuration must contain one top-level mcpServer mapping"
        )

    mcp_index = mcp_indexes[0]
    mcp_mapping = _mapping(lines[mcp_index])
    assert mcp_mapping is not None
    if not _empty_mapping_tail(mcp_mapping[2]):
        raise ConfigurationError("mcpServer must use a block mapping")

    mcp_end = len(lines)
    for index in range(mcp_index + 1, len(lines)):
        line = lines[index]
        if _is_ignorable(line):
            continue
        if len(line) - len(line.lstrip(" ")) == 0:
            mcp_end = index
            break

    redis_indexes: list[int] = []
    for index in range(mcp_index + 1, mcp_end):
        line = lines[index]
        if _is_ignorable(line):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation < 2:
            raise ConfigurationError("mcpServer contains invalid indentation")
        parsed = _mapping(line)
        if indentation == 2 and parsed is None:
            raise ConfigurationError("mcpServer contains a non-mapping child")
        if parsed is not None and parsed[0] == 2 and parsed[1] == "redis":
            redis_indexes.append(index)
    if len(redis_indexes) > 1:
        raise ConfigurationError("mcpServer contains duplicate redis mappings")

    newline = "\r\n" if "\r\n" in source else "\n"
    canonical_lines = [
        f"  redis:{newline}",
        f"    address: {REDIS_ADDRESS}{newline}",
        f'    username: ""{newline}',
        f'    password: ""{newline}',
        f"    db: 0{newline}",
    ]

    if not redis_indexes:
        prefix = lines[: mcp_index + 1]
        if not prefix[-1].endswith(("\n", "\r")):
            prefix[-1] += newline
        result = "".join(prefix + canonical_lines + lines[mcp_index + 1 :])
        return result, True

    redis_index = redis_indexes[0]
    redis_mapping = _mapping(lines[redis_index])
    assert redis_mapping is not None
    if not _empty_mapping_tail(redis_mapping[2]):
        raise ConfigurationError("mcpServer.redis must use a block mapping")

    redis_end = mcp_end
    for index in range(redis_index + 1, mcp_end):
        line = lines[index]
        if _is_ignorable(line):
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation <= 2:
            redis_end = index
            break

    values: dict[str, str] = {}
    allowed_keys = {"address", "username", "password", "db"}
    for line in lines[redis_index + 1 : redis_end]:
        if _is_ignorable(line):
            continue
        parsed = _mapping(line)
        if parsed is None or parsed[0] != 4:
            raise ConfigurationError("mcpServer.redis has an unsupported structure")
        _, key, tail = parsed
        if key not in allowed_keys or key in values or _empty_mapping_tail(tail):
            raise ConfigurationError("mcpServer.redis has ambiguous or incomplete fields")
        values[key] = _scalar(tail)
    if set(values) != allowed_keys:
        raise ConfigurationError("mcpServer.redis has ambiguous or incomplete fields")
    is_upstream_placeholder = values == UPSTREAM_PLACEHOLDER_REDIS
    if (values["username"] or values["password"]) and not is_upstream_placeholder:
        raise ConfigurationError(
            "mcpServer.redis contains credentials that this utility will not overwrite"
        )

    current = "".join(lines[redis_index:redis_end])
    canonical = "".join(canonical_lines)
    if current == canonical:
        return source, False
    result = "".join(lines[:redis_index] + canonical_lines + lines[redis_end:])
    return result, True


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{label} is malformed")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ConfigurationError(f"{label} is malformed")
    return value


def validate_service(document: dict[str, Any]) -> None:
    """Require the exact private Redis Service contract."""

    metadata = _object(document.get("metadata"), "Redis Service metadata")
    spec = _object(document.get("spec"), "Redis Service spec")
    if (
        document.get("apiVersion") != "v1"
        or document.get("kind") != "Service"
        or metadata.get("name") != SERVICE_NAME
        or metadata.get("namespace") != NAMESPACE
        or spec.get("type") != "ClusterIP"
        or spec.get("clusterIP") in {None, "", "None"}
        or spec.get("selector") != {"app": SERVICE_NAME}
    ):
        raise ConfigurationError("Redis Service does not match the managed contract")
    ports = _list(spec.get("ports"), "Redis Service ports")
    if len(ports) != 1:
        raise ConfigurationError("Redis Service must expose exactly one port")
    port = _object(ports[0], "Redis Service port")
    if port != {
        "name": "redis",
        "protocol": "TCP",
        "port": REDIS_PORT,
        "targetPort": "redis",
    }:
        raise ConfigurationError("Redis Service port does not match the managed contract")


def validate_endpoint_slices(document: dict[str, Any]) -> None:
    """Require one ready Redis endpoint before allowing ConfigMap access."""

    list_identity = (document.get("apiVersion"), document.get("kind"))
    if list_identity not in {
        ("discovery.k8s.io/v1", "EndpointSliceList"),
        # k3s/kubectl may serialize a fully-qualified resource query through
        # the Kubernetes generic list wrapper while preserving typed items.
        ("v1", "List"),
    }:
        raise ConfigurationError("Redis EndpointSlice response is malformed")
    items = _list(document.get("items"), "Redis EndpointSlice items")
    if len(items) != 1:
        raise ConfigurationError("Redis must have exactly one EndpointSlice")
    item = _object(items[0], "Redis EndpointSlice")
    metadata = _object(item.get("metadata"), "Redis EndpointSlice metadata")
    labels = _object(metadata.get("labels"), "Redis EndpointSlice labels")
    if (
        item.get("apiVersion") != "discovery.k8s.io/v1"
        or item.get("kind") != "EndpointSlice"
        or metadata.get("namespace") != NAMESPACE
        or labels.get("kubernetes.io/service-name") != SERVICE_NAME
        or item.get("addressType") not in {"IPv4", "IPv6"}
    ):
        raise ConfigurationError("Redis EndpointSlice does not match the Service")
    ports = _list(item.get("ports"), "Redis EndpointSlice ports")
    if len(ports) != 1:
        raise ConfigurationError("Redis EndpointSlice must expose exactly one port")
    port = _object(ports[0], "Redis EndpointSlice port")
    if (
        port.get("name") != "redis"
        or port.get("protocol") != "TCP"
        or port.get("port") != REDIS_PORT
    ):
        raise ConfigurationError("Redis EndpointSlice port is incompatible")
    endpoints = _list(item.get("endpoints"), "Redis endpoints")
    if len(endpoints) != 1:
        raise ConfigurationError("Redis must have exactly one endpoint")
    endpoint = _object(endpoints[0], "Redis endpoint")
    conditions = _object(endpoint.get("conditions"), "Redis endpoint conditions")
    addresses = _list(endpoint.get("addresses"), "Redis endpoint addresses")
    if conditions.get("ready") is not True or len(addresses) != 1:
        raise ConfigurationError("Redis endpoint is not uniquely ready")
    if not isinstance(addresses[0], str) or not addresses[0]:
        raise ConfigurationError("Redis endpoint address is malformed")


def _configmap_state(document: dict[str, Any]) -> tuple[str, str]:
    metadata = _object(document.get("metadata"), "higress ConfigMap metadata")
    data = _object(document.get("data"), "higress ConfigMap data")
    resource_version = metadata.get("resourceVersion")
    source = data.get("higress")
    if (
        document.get("apiVersion") != "v1"
        or document.get("kind") != "ConfigMap"
        or metadata.get("name") != CONFIGMAP_NAME
        or metadata.get("namespace") != NAMESPACE
        or not isinstance(resource_version, str)
        or not resource_version
        or not isinstance(source, str)
    ):
        raise ConfigurationError("higress ConfigMap does not match the managed contract")
    return resource_version, source


def configure(
    client: KubernetesClient,
    *,
    apply: bool,
    initialize_missing_mcp_server: bool = False,
) -> bool:
    """Validate dependencies and check or reconcile Redis session storage."""

    service = client.get_json("service", name=SERVICE_NAME)
    validate_service(service)
    slices = client.get_json(
        "endpointslices.discovery.k8s.io",
        selector=f"kubernetes.io/service-name={SERVICE_NAME}",
    )
    validate_endpoint_slices(slices)

    configmap = client.get_json("configmap", name=CONFIGMAP_NAME)
    previous_version, source = _configmap_state(configmap)
    desired, changed = reconcile_higress_yaml(
        source,
        initialize_missing_mcp_server=initialize_missing_mcp_server,
    )
    if not changed:
        return False
    if not apply:
        raise ConfigurationError("higress MCP Redis configuration is not compliant")

    replacement = copy.deepcopy(configmap)
    replacement_metadata = _object(
        replacement.get("metadata"), "higress ConfigMap metadata"
    )
    replacement_metadata.pop("managedFields", None)
    replacement_data = _object(replacement.get("data"), "higress ConfigMap data")
    replacement_data["higress"] = desired
    client.replace_configmap(replacement)

    verified = client.get_json("configmap", name=CONFIGMAP_NAME)
    verified_version, verified_source = _configmap_state(verified)
    _, still_changed = reconcile_higress_yaml(verified_source)
    if verified_version == previous_version or still_changed:
        raise ConfigurationError("higress ConfigMap final verification failed")
    return True


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check or configure Higress MCP Redis session storage safely."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="reconcile a structurally safe configuration using resourceVersion",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="verify only (the default); do not mutate Kubernetes",
    )
    parser.add_argument(
        "--initialize-missing-mcp-server",
        action="store_true",
        help=(
            "with --apply, bootstrap the official Higress 2.2.1 mcpServer "
            "block when the chart did not render one"
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.initialize_missing_mcp_server and not args.apply:
            raise ConfigurationError(
                "--initialize-missing-mcp-server requires --apply"
            )
        changed = configure(
            KubectlClient(),
            apply=bool(args.apply),
            initialize_missing_mcp_server=bool(
                args.initialize_missing_mcp_server
            ),
        )
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if changed:
        print("higress MCP Redis configuration applied and verified")
    else:
        print("higress MCP Redis configuration is compliant")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

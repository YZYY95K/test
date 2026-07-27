"""Configure a dedicated, read-only GitHub MCP server for DevFlow Locator.

The implementation targets the audited Higress Console v1 contract shipped in
Higress Console v2.2.1. The MCP configuration never contains a GitHub
credential; the content broker owns that credential outside Higress.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import http.cookiejar
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

MCP_SERVER_NAME = "devflow-github-readonly"
MCP_INTERNAL_ROUTE_NAME = f"mcp-server-{MCP_SERVER_NAME}.internal"
MCP_DESCRIPTION = "DevFlow Locator read-only GitHub evidence (managed)"
CONSUMER_NAME = "worker-devflow-locator"
SERVICE_SOURCE_NAME = "devflow-github-content-broker"
BROKER_SERVICE_DOMAIN = (
    "devflow-github-content-broker.agentteams-system.svc.cluster.local"
)
BROKER_SERVICE_PORT = 8080
ALLOWED_TOOL = "get_file_contents"
PINNED_CONSOLE_IMAGE_DIGEST = (
    "sha256:90ccdbb078375aad42f874feddba9d964eca34f192ee8dbab7d9a22079b580a4"
)
MCP_NOT_FOUND_FRAGMENT = "NotFoundException: can't found the bound route by name"
NAMESPACE_PATTERN = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
LOOPBACK_CONSOLE_PATTERN = re.compile(r"^http://127\.0\.0\.1:([1-9][0-9]{0,4})$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
TOOL_DESCRIPTION = "Read one file from an assigned GitHub repository revision."
EXPECTED_URL = (
    "http://devflow-github-content-broker.agentteams-system.svc.cluster.local:8080/v1/content"
    "?task_id={{.args.task_id}}&owner={{.args.owner}}&repo={{.args.repo}}"
    "&path={{.args.path}}&revision={{.args.revision}}"
)
EXPECTED_ARGUMENTS = [
    {
        "description": "Owning DevFlow task identifier",
        "name": "task_id",
        "required": True,
        "type": "string",
    },
    {
        "description": "Short-lived exact-scope capability",
        "name": "capability",
        "required": True,
        "type": "string",
    },
    {
        "description": "Assigned repository owner",
        "name": "owner",
        "required": True,
        "type": "string",
    },
    {
        "description": "Assigned repository name",
        "name": "repo",
        "required": True,
        "type": "string",
    },
    {
        "description": "Exact repository-relative file path",
        "name": "path",
        "required": True,
        "type": "string",
    },
    {
        "description": "Immutable 40-character commit SHA",
        "name": "revision",
        "required": True,
        "type": "string",
    },
]
EXPECTED_HEADERS = [
    {"key": "X-DevFlow-Capability", "value": "{{.args.capability}}"},
]
WASM_PLUGIN_RESOURCE = "wasmplugins.extensions.higress.io/mcp-server.internal"
EXPECTED_WASM_FAIL_STRATEGY = "FAIL_CLOSE"
PINNED_WASM_OCI_URL_PATTERN = re.compile(
    r"^oci://[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}$"
)


class ConfigurationError(RuntimeError):
    """A safe configuration or remote-contract check failed."""


class ApiUnavailableError(ConfigurationError):
    """The Console endpoint cannot provide a usable document."""


class ApiClient(Protocol):
    @property
    def last_status(self) -> int | None: ...

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None: ...


class RuntimeManager(Protocol):
    def read(self) -> dict[str, Any]: ...

    def enforce_fail_closed(self, pinned_wasm_url: str) -> None: ...


@dataclass(frozen=True)
class DesiredState:
    namespace: str
    pinned_wasm_url: str

    def __post_init__(self) -> None:
        _validate_namespace(self.namespace)
        if PINNED_WASM_OCI_URL_PATTERN.fullmatch(self.pinned_wasm_url) is None:
            raise ConfigurationError("MCP WasmPlugin URL is not an OCI sha256 pin")

    @property
    def gateway_host(self) -> str:
        return f"higress-gateway.{self.namespace}.svc.cluster.local"

    @property
    def gateway_endpoint(self) -> str:
        return f"http://{self.gateway_host}:80/mcp-servers/{MCP_SERVER_NAME}/mcp"


def console_url(namespace: str) -> str:
    _validate_namespace(namespace)
    return f"http://higress-console.{namespace}.svc.cluster.local:8080"


def operator_console_url(namespace: str, override: str | None) -> str:
    """Allow only an explicit loopback kubectl port-forward override."""

    if override is None:
        return console_url(namespace)
    match = LOOPBACK_CONSOLE_PATTERN.fullmatch(override)
    if match is None or int(match.group(1)) > 65_535:
        raise ConfigurationError("console URL override must be loopback HTTP with one valid port")
    return override


def _validate_namespace(namespace: str) -> None:
    if not NAMESPACE_PATTERN.fullmatch(namespace):
        raise ConfigurationError("namespace is not a valid Kubernetes DNS label")


def _validate_secret(value: str, label: str, *, minimum_length: int = 1) -> str:
    if value != value.strip() or len(value) < minimum_length or CONTROL_CHARACTER.search(value):
        raise ConfigurationError(f"{label} is missing or malformed")
    return value


def _read_kubernetes_secret(namespace: str, reference: str) -> str:
    if ":" not in reference:
        raise ConfigurationError("Secret reference must be NAME:KEY")
    name, key = reference.split(":", 1)
    if not NAMESPACE_PATTERN.fullmatch(name) or not key or CONTROL_CHARACTER.search(key):
        raise ConfigurationError("Secret reference is malformed")
    process = subprocess.run(
        [
            "kubectl",
            "--namespace",
            namespace,
            "get",
            "secret",
            name,
            "-o",
            "json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise ConfigurationError("unable to read the requested Kubernetes Secret")
    try:
        document = json.loads(process.stdout)
        encoded = document["data"][key]
        if not isinstance(encoded, str):
            raise TypeError
        return base64.b64decode(encoded, validate=True).decode("utf-8")
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise ConfigurationError("Kubernetes Secret key is absent or invalid") from exc


def resolve_secret(
    *,
    namespace: str,
    environment_name: str,
    secret_reference: str | None,
    label: str,
    minimum_length: int = 1,
) -> str:
    from_environment = os.environ.get(environment_name)
    if from_environment and secret_reference:
        raise ConfigurationError(
            f"{label} has two sources; select environment or Kubernetes Secret"
        )
    if from_environment:
        return _validate_secret(from_environment, label, minimum_length=minimum_length)
    if secret_reference:
        return _validate_secret(
            _read_kubernetes_secret(namespace, secret_reference),
            label,
            minimum_length=minimum_length,
        )
    raise ConfigurationError(
        f"{label} must come from {environment_name} or an explicit Secret reference"
    )


def _raw_mcp_document() -> dict[str, Any]:
    return {
        "server": {"name": MCP_SERVER_NAME},
        "tools": [
            {
                "name": ALLOWED_TOOL,
                "description": TOOL_DESCRIPTION,
                "args": EXPECTED_ARGUMENTS,
                "requestTemplate": {
                    "url": EXPECTED_URL,
                    "method": "GET",
                    "headers": EXPECTED_HEADERS,
                },
            }
        ],
    }


def raw_mcp_configuration() -> str:
    # Console v2.2.1 decides whether the route-scoped WasmPlugin instance is
    # enabled with a literal substring search for ``tools:``. Strict JSON is
    # valid YAML but misses that marker and therefore disables the instance.
    # Every scalar is JSON-quoted, so the fixed emitter remains injection-safe
    # and has no third-party runtime dependency.
    _raw_mcp_document()
    return "\n".join(_pinned_yaml_lines()) + "\n"


def desired_service_source() -> dict[str, Any]:
    return {
        "type": "dns",
        "name": SERVICE_SOURCE_NAME,
        "domain": BROKER_SERVICE_DOMAIN,
        "port": BROKER_SERVICE_PORT,
        "protocol": "http",
        "properties": {},
        "authN": {"enabled": False},
    }


def desired_mcp_server(state: DesiredState) -> dict[str, Any]:
    return {
        "name": MCP_SERVER_NAME,
        # The Console v2.2.1 backend requires the route binding name even
        # though its generated McpServer schema omits this compatibility field.
        "mcpServerName": MCP_SERVER_NAME,
        "description": MCP_DESCRIPTION,
        "type": "OPEN_API",
        "rawConfigurations": raw_mcp_configuration(),
        "domains": [state.gateway_host],
        "services": [
            {
                "name": f"{SERVICE_SOURCE_NAME}.dns",
                "port": BROKER_SERVICE_PORT,
                "weight": 100,
            }
        ],
        "consumerAuthInfo": {
            "type": "key-auth",
            "enable": True,
            "allowedConsumers": [CONSUMER_NAME],
        },
    }


def _unwrap_response(document: dict[str, Any] | None, label: str) -> Any:
    if not isinstance(document, dict) or document.get("success") is not True:
        raise ConfigurationError(f"{label} response wrapper does not match Console v1")
    if "data" not in document:
        raise ConfigurationError(f"{label} response has no data field")
    return document["data"]


def validate_openapi(document: dict[str, Any]) -> None:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise ConfigurationError("OpenAPI document has no paths object")
    required_methods = {
        "/v1/mcpServer": {"get", "put"},
        "/v1/mcpServer/{name}": {"get"},
        "/v1/mcpServer/consumers": {"get", "put", "delete"},
        "/v1/consumers/{name}": {"get"},
        "/v1/service-sources": {"post"},
        "/v1/service-sources/{name}": {"get", "put"},
    }
    for path, methods in required_methods.items():
        actual = paths.get(path)
        if not isinstance(actual, dict) or not methods <= set(actual):
            raise ConfigurationError(f"Console v1 OpenAPI contract mismatch at {path}")

    schemas = document.get("components", {}).get("schemas", {})
    required_properties = {
        "McpServer": {
            "name",
            "description",
            "domains",
            "services",
            "type",
            "consumerAuthInfo",
            "rawConfigurations",
        },
        "McpServerConsumers": {"mcpServerName", "consumers"},
        "Consumer": {"name", "credentials"},
        "ServiceSource": {"name", "type", "domain", "port", "protocol"},
    }
    if not isinstance(schemas, dict):
        raise ConfigurationError("OpenAPI document has no component schemas")
    for schema_name, properties in required_properties.items():
        schema = schemas.get(schema_name)
        actual_properties = schema.get("properties") if isinstance(schema, dict) else None
        if not isinstance(actual_properties, dict) or not properties <= set(actual_properties):
            raise ConfigurationError(f"Console v1 schema mismatch for {schema_name}")


def validate_consumer(
    document: dict[str, Any] | None,
    expected_credential: str | None = None,
) -> None:
    consumer = _unwrap_response(document, "Consumer")
    if (
        not isinstance(consumer, dict)
        or consumer.get("name") != CONSUMER_NAME
    ):
        raise ConfigurationError("the exact worker-devflow-locator Consumer does not exist")
    credentials = consumer.get("credentials")
    if not isinstance(credentials, list) or len(credentials) != 1:
        raise ConfigurationError(
            "worker-devflow-locator credential surface is not exact; rotate it explicitly"
        )
    credential = credentials[0]
    if (
        not isinstance(credential, dict)
        or set(credential) != {"key", "source", "type", "values"}
        or credential.get("type") != "key-auth"
        or credential.get("source") != "BEARER"
        or credential.get("key") is not None
    ):
        raise ConfigurationError(
            "worker-devflow-locator credential surface is not exact; rotate it explicitly"
        )
    values = credential.get("values")
    if not isinstance(values, list) or len(values) != 1:
        raise ConfigurationError(
            "worker-devflow-locator credential surface is not exact; rotate it explicitly"
        )
    actual = values[0]
    if (
        not isinstance(actual, str)
        or actual != actual.strip()
        or not 16 <= len(actual) <= 512
        or CONTROL_CHARACTER.search(actual)
    ):
        raise ConfigurationError(
            "worker-devflow-locator credential surface is not exact; rotate it explicitly"
        )
    if expected_credential is not None and not hmac.compare_digest(
        actual,
        _validate_secret(
            expected_credential,
            "Locator gateway credential",
            minimum_length=16,
        ),
    ):
        raise ConfigurationError("worker-devflow-locator credential binding is mismatched")


def validate_service_source(document: dict[str, Any] | None) -> None:
    source = _unwrap_response(document, "Service source")
    if not isinstance(source, dict):
        raise ConfigurationError("service source data is not an object")
    expected = desired_service_source()
    for field in ("name", "type", "domain", "port"):
        if source.get(field) != expected[field]:
            raise ConfigurationError("GitHub content broker source has incompatible state")
    if str(source.get("protocol", "")).lower() != "http":
        raise ConfigurationError("GitHub content broker source is not internal HTTP")
    if source.get("properties") != {} or source.get("authN") not in (
        {"enabled": False},
        {"enabled": False, "properties": None},
    ):
        raise ConfigurationError("GitHub content broker source authentication is not disabled")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("MCP raw configuration contains a duplicate field")
        result[key] = value
    return result


def _pinned_yaml_lines() -> list[str]:
    def quoted(value: object) -> str:
        return json.dumps(value, ensure_ascii=True)

    lines = [
        "server:",
        f"  name: {quoted(MCP_SERVER_NAME)}",
        "tools:",
        "- args:",
    ]
    for argument in EXPECTED_ARGUMENTS:
        lines.extend(
            [
                f"  - description: {quoted(argument['description'])}",
                f"    name: {quoted(argument['name'])}",
                "    required: true",
                f"    type: {quoted(argument['type'])}",
            ]
        )
    lines.extend(
        [
            f"  description: {quoted(TOOL_DESCRIPTION)}",
            f"  name: {quoted(ALLOWED_TOOL)}",
            "  requestTemplate:",
            "    headers:",
        ]
    )
    for header in EXPECTED_HEADERS:
        lines.extend(
            [
                f"    - key: {quoted(header['key'])}",
                f"      value: {quoted(header['value'])}",
            ]
        )
    lines.extend(
        [f"    method: {quoted('GET')}", f"    url: {quoted(EXPECTED_URL)}"]
    )
    return lines


def _parse_pinned_console_yaml(raw: str) -> dict[str, Any]:
    """Parse only the exact 36-line form emitted by Console v2.2.1."""
    if "\r" in raw or raw.startswith("\ufeff"):
        raise ConfigurationError("MCP YAML is not in the pinned Console form")
    text = raw[:-1] if raw.endswith("\n") else raw
    if not text or text.endswith("\n"):
        raise ConfigurationError("MCP YAML has trailing content")
    lines = text.split("\n")
    if len(lines) != 36:
        raise ConfigurationError("MCP YAML is not the exact 36-line Console form")
    if lines != _pinned_yaml_lines():
        raise ConfigurationError("MCP YAML tree differs from the pinned Console form")
    return _raw_mcp_document()


def _decode_raw_configuration(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_strict_json_object)
    except json.JSONDecodeError as exc:
        if raw.lstrip().startswith(("{", "[")):
            raise ConfigurationError("MCP rawConfigurations is invalid JSON") from exc
        return _parse_pinned_console_yaml(raw)
    if not isinstance(value, dict):
        raise ConfigurationError("MCP raw configuration has an unexpected surface")
    return value


def _validate_raw_document(config: Any) -> None:
    if not isinstance(config, dict) or set(config) != {"server", "tools"}:
        raise ConfigurationError("MCP raw configuration has an unexpected surface")
    server = config.get("server")
    if not isinstance(server, dict) or set(server) != {"name"}:
        raise ConfigurationError("MCP server configuration schema is incompatible")
    if server.get("name") != MCP_SERVER_NAME:
        raise ConfigurationError("MCP raw configuration names another server")
    tools = config.get("tools")
    if not isinstance(tools, list) or len(tools) != 1:
        raise ConfigurationError("MCP must expose exactly one tool")
    tool = tools[0]
    if not isinstance(tool, dict) or tool.get("name") != ALLOWED_TOOL:
        raise ConfigurationError("MCP exposes an unauthorized tool")
    if set(tool) != {"args", "description", "name", "requestTemplate"}:
        raise ConfigurationError("get_file_contents has an unexpected field surface")
    if tool.get("description") != TOOL_DESCRIPTION:
        raise ConfigurationError("get_file_contents description is incompatible")
    arguments = tool.get("args")
    if arguments != EXPECTED_ARGUMENTS:
        raise ConfigurationError("get_file_contents argument surface is incompatible")
    request = tool.get("requestTemplate")
    if not isinstance(request, dict):
        raise ConfigurationError("get_file_contents request template is absent")
    if "body" in request:
        raise ConfigurationError("read-only GitHub template unexpectedly has a body")
    if set(request) != {"headers", "method", "url"}:
        raise ConfigurationError("GitHub request template has an unexpected field surface")
    if request.get("method") != "GET":
        raise ConfigurationError("get_file_contents is not a GET-only template")
    if request.get("url") != EXPECTED_URL:
        raise ConfigurationError("GitHub request template URL is incompatible")
    if request.get("headers") != EXPECTED_HEADERS:
        raise ConfigurationError("GitHub request headers are incompatible")


def _validate_raw_configuration(raw: Any) -> None:
    if not isinstance(raw, str):
        raise ConfigurationError("MCP rawConfigurations is not text")
    _validate_raw_document(_decode_raw_configuration(raw))


def _console_v221_enables_raw_configuration(raw: Any) -> bool:
    """Mirror OpenApiSaveStrategy's audited literal enablement predicate."""

    return isinstance(raw, str) and "tools:" in raw


def validate_mcp_server(
    document: dict[str, Any] | None,
    state: DesiredState,
    *,
    verify_token: bool,
) -> None:
    del verify_token  # Retained for CLI/API compatibility; credentials live in the broker.
    server = _unwrap_response(document, "MCP server")
    if not isinstance(server, dict):
        raise ConfigurationError("MCP server data is not an object")
    if server.get("name") != MCP_SERVER_NAME:
        raise ConfigurationError("MCP server identity mismatch")
    if server.get("description") != MCP_DESCRIPTION or server.get("type") != "OPEN_API":
        raise ConfigurationError("dedicated MCP server is not DevFlow-managed OPEN_API")
    if server.get("domains") != [state.gateway_host]:
        raise ConfigurationError("MCP route is not bound only to the internal gateway host")
    services = server.get("services")
    if not isinstance(services, list) or len(services) != 1:
        raise ConfigurationError("MCP upstream service surface is incompatible")
    service = services[0]
    if (
        not isinstance(service, dict)
        or service.get("name") != f"{SERVICE_SOURCE_NAME}.dns"
    ):
        raise ConfigurationError("MCP upstream is not the audited content broker source")
    if service.get("port") != BROKER_SERVICE_PORT or service.get("weight") != 100:
        raise ConfigurationError("MCP upstream port or weight is incompatible")
    auth = server.get("consumerAuthInfo")
    if not isinstance(auth, dict):
        raise ConfigurationError("MCP consumer authorization is absent")
    if (
        auth.get("enable") is not True
        or auth.get("type") != "key-auth"
        or auth.get("allowedConsumers") != [CONSUMER_NAME]
    ):
        raise ConfigurationError("MCP is not restricted only to worker-devflow-locator")
    _validate_raw_configuration(server.get("rawConfigurations"))


def validate_consumer_bindings(document: dict[str, Any] | None) -> list[str]:
    data = _unwrap_response(document, "MCP consumer list")
    if not isinstance(data, list):
        raise ConfigurationError("MCP consumer list data is not an array")
    names: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            raise ConfigurationError("MCP consumer entry is not an object")
        if item.get("mcpServerName") != MCP_INTERNAL_ROUTE_NAME:
            raise ConfigurationError("MCP consumer response contains another server")
        name = item.get("consumerName")
        if not isinstance(name, str) or not name:
            raise ConfigurationError("MCP consumer response has an invalid name")
        names.append(name)
    if len(names) != len(set(names)):
        raise ConfigurationError("MCP consumer response contains duplicates")
    return names


class HigressClient:
    """Minimal Console v1 client with an in-memory session cookie."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._last_status: int | None = None
        cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))

    @property
    def last_status(self) -> int | None:
        return self._last_status

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        self._last_status = None
        if not path.startswith("/") or CONTROL_CHARACTER.search(path):
            raise ConfigurationError("unsafe Console API path")
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            f"{self._base_url}{path}", data=body, headers=headers, method=method
        )
        try:
            with self._opener.open(request, timeout=15) as response:
                status = response.status
                content = response.read()
        except urllib.error.HTTPError as exc:
            if exc.code in expected:
                status = exc.code
                content = exc.read()
            else:
                raise ApiUnavailableError(
                    f"Console API {method} {path} returned HTTP {exc.code}"
                ) from None
        except (OSError, urllib.error.URLError) as exc:
            raise ApiUnavailableError(f"Console API {method} {path} is unavailable") from exc
        if status not in expected:
            raise ApiUnavailableError(
                f"Console API {method} {path} returned unexpected HTTP {status}"
            )
        self._last_status = status
        if status == 404:
            return None
        if not content:
            return None
        try:
            parsed = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiUnavailableError(
                f"Console API {method} {path} returned non-JSON data"
            ) from exc
        if not isinstance(parsed, dict):
            raise ConfigurationError(f"Console API {method} {path} returned a non-object document")
        return parsed

    def login(self, username: str, password: str) -> None:
        response = self.request(
            "POST",
            "/session/login",
            {"username": username, "password": password},
            # Higress Console v2.2.1 installations return either 200 or 201
            # after creating the authenticated session cookie.
            expected=(200, 201),
        )
        if response is not None and response.get("success") is False:
            raise ConfigurationError("Higress Console login was rejected")


class KubectlRuntimeManager:
    """Read and fail-close the effective internal MCP WasmPlugin."""

    def __init__(self, namespace: str) -> None:
        _validate_namespace(namespace)
        self._namespace = namespace

    def read(self) -> dict[str, Any]:
        try:
            process = subprocess.run(
                [
                    "kubectl",
                    "--namespace",
                    self._namespace,
                    "get",
                    WASM_PLUGIN_RESOURCE,
                    "-o",
                    "json",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise ConfigurationError("unable to read the MCP WasmPlugin runtime state") from exc
        if process.returncode != 0:
            raise ConfigurationError("unable to read the MCP WasmPlugin runtime state")
        try:
            document = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise ConfigurationError("MCP WasmPlugin runtime state is not valid JSON") from exc
        if not isinstance(document, dict):
            raise ConfigurationError("MCP WasmPlugin runtime state is not an object")
        return document

    def enforce_fail_closed(self, pinned_wasm_url: str) -> None:
        if PINNED_WASM_OCI_URL_PATTERN.fullmatch(pinned_wasm_url) is None:
            raise ConfigurationError("MCP WasmPlugin URL is not an OCI sha256 pin")
        patch = json.dumps(
            {
                "spec": {
                    "failStrategy": EXPECTED_WASM_FAIL_STRATEGY,
                    "url": pinned_wasm_url,
                }
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        try:
            process = subprocess.run(
                [
                    "kubectl",
                    "--namespace",
                    self._namespace,
                    "patch",
                    WASM_PLUGIN_RESOURCE,
                    "--type=merge",
                    "--patch",
                    patch,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        except OSError as exc:
            raise ConfigurationError("unable to fail-close the MCP WasmPlugin") from exc
        if process.returncode != 0:
            raise ConfigurationError("unable to fail-close the MCP WasmPlugin")


def validate_runtime_wasm_plugin(
    document: dict[str, Any],
    state: DesiredState,
    *,
    verify_token: bool,
) -> None:
    """Require one enabled, route-only runtime instance with the closed tool tree."""

    del verify_token  # Retained for CLI/API compatibility; credentials live in the broker.

    if document.get("apiVersion") != "extensions.higress.io/v1alpha1":
        raise ConfigurationError("MCP WasmPlugin apiVersion is incompatible")
    if document.get("kind") != "WasmPlugin":
        raise ConfigurationError("MCP WasmPlugin kind is incompatible")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ConfigurationError("MCP WasmPlugin metadata is absent")
    if metadata.get("name") != "mcp-server.internal":
        raise ConfigurationError("MCP WasmPlugin identity is incompatible")
    if metadata.get("namespace") != state.namespace:
        raise ConfigurationError("MCP WasmPlugin namespace is incompatible")

    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise ConfigurationError("MCP WasmPlugin spec is absent")
    if spec.get("defaultConfigDisable") is not True:
        raise ConfigurationError("MCP WasmPlugin default configuration is not disabled")
    if spec.get("failStrategy") != EXPECTED_WASM_FAIL_STRATEGY:
        raise ConfigurationError("MCP WasmPlugin fail strategy is incompatible")
    if spec.get("url") != state.pinned_wasm_url:
        raise ConfigurationError("MCP WasmPlugin OCI sha256 pin is incompatible")
    match_rules = spec.get("matchRules")
    if not isinstance(match_rules, list):
        raise ConfigurationError("MCP WasmPlugin matchRules is not an array")

    targets: list[dict[str, Any]] = []
    for rule in match_rules:
        if not isinstance(rule, dict):
            raise ConfigurationError("MCP WasmPlugin match rule is not an object")
        ingress = rule.get("ingress")
        if ingress is not None and (
            not isinstance(ingress, list)
            or any(not isinstance(item, str) or not item for item in ingress)
        ):
            raise ConfigurationError("MCP WasmPlugin ingress target is malformed")
        if isinstance(ingress, list) and MCP_INTERNAL_ROUTE_NAME in ingress:
            targets.append(rule)
    if len(targets) != 1:
        raise ConfigurationError("MCP WasmPlugin must have exactly one target match rule")

    target = targets[0]
    if target.get("ingress") != [MCP_INTERNAL_ROUTE_NAME]:
        raise ConfigurationError("MCP WasmPlugin target is not ingress-only and exact")
    if target.get("domain") not in (None, []) or target.get("service") not in (None, []):
        raise ConfigurationError("MCP WasmPlugin target crosses an unauthorized scope")
    if target.get("configDisable") is not False:
        raise ConfigurationError("MCP WasmPlugin target is disabled")
    if set(target) - {"configDisable", "config", "domain", "ingress", "service"}:
        raise ConfigurationError("MCP WasmPlugin target has an unexpected field surface")
    _validate_raw_document(target.get("config"))


def _server_raw_configuration(document: dict[str, Any]) -> Any:
    server = _unwrap_response(document, "MCP server")
    if not isinstance(server, dict):
        raise ConfigurationError("MCP server data is not an object")
    return server.get("rawConfigurations")


def _query_optional(
    client: ApiClient,
    path: str,
    *,
    allow_audited_mcp_not_found: bool = False,
) -> dict[str, Any] | None:
    expected = (200, 404, 502) if allow_audited_mcp_not_found else (200, 404)
    document = client.request("GET", path, expected=expected)
    if document is None:
        return None
    if client.last_status == 502:
        if not allow_audited_mcp_not_found:
            raise ConfigurationError("unexpected HTTP 502 from Console API")
        if path != f"/v1/mcpServer/{MCP_SERVER_NAME}":
            raise ConfigurationError("HTTP 502 fallback is forbidden for this API path")
        if set(document) != {"success", "message", "data"}:
            raise ConfigurationError("MCP HTTP 502 wrapper schema is incompatible")
        message = document.get("message")
        if (
            document.get("success") is not False
            or document.get("data") is not None
            or not isinstance(message, str)
            or MCP_NOT_FOUND_FRAGMENT not in message
        ):
            raise ConfigurationError("MCP HTTP 502 is not the audited NotFound response")
        return None
    return document


def check_state(
    client: ApiClient,
    runtime: RuntimeManager,
    state: DesiredState,
    *,
    expected_consumer_credential: str | None = None,
) -> None:
    validate_consumer(
        client.request("GET", f"/v1/consumers/{CONSUMER_NAME}"),
        expected_consumer_credential,
    )
    validate_service_source(client.request("GET", f"/v1/service-sources/{SERVICE_SOURCE_NAME}"))
    validate_mcp_server(
        client.request("GET", f"/v1/mcpServer/{MCP_SERVER_NAME}"),
        state,
        verify_token=False,
    )
    bindings = validate_consumer_bindings(
        client.request("GET", f"/v1/mcpServer/consumers?mcpServerName={MCP_SERVER_NAME}")
    )
    if bindings != [CONSUMER_NAME]:
        raise ConfigurationError("MCP consumer binding is not locator-only")
    validate_runtime_wasm_plugin(runtime.read(), state, verify_token=False)


def apply_state(
    client: ApiClient,
    runtime: RuntimeManager,
    state: DesiredState,
    *,
    expected_consumer_credential: str | None = None,
) -> bool:
    """Converge the dedicated resource and return whether a mutation occurred."""

    runtime_document = runtime.read()
    runtime_compliant = True
    try:
        validate_runtime_wasm_plugin(runtime_document, state, verify_token=True)
    except ConfigurationError:
        runtime_compliant = False

    validate_consumer(
        client.request("GET", f"/v1/consumers/{CONSUMER_NAME}"),
        expected_consumer_credential,
    )
    changed = False

    source_path = f"/v1/service-sources/{SERVICE_SOURCE_NAME}"
    source = _query_optional(client, source_path)
    if source is None:
        client.request(
            "POST",
            "/v1/service-sources",
            desired_service_source(),
            # Audited Console v2.2.1 deployments return 200 or 201 when the DNS
            # source is created. Existing-source reads remain 200/404 only.
            expected=(200, 201),
        )
        validate_service_source(client.request("GET", source_path))
        changed = True
    else:
        # Never rewrite an incompatible existing broker source.
        validate_service_source(source)

    server_path = f"/v1/mcpServer/{MCP_SERVER_NAME}"
    current = _query_optional(client, server_path, allow_audited_mcp_not_found=True)
    current_compliant = False
    if current is not None:
        try:
            validate_mcp_server(current, state, verify_token=True)
            current_compliant = _console_v221_enables_raw_configuration(
                _server_raw_configuration(current)
            )
        except ConfigurationError:
            data = _unwrap_response(current, "MCP server")
            if not isinstance(data, dict) or data.get("description") != MCP_DESCRIPTION:
                raise ConfigurationError(
                    "existing MCP name is not a DevFlow-managed resource"
                ) from None
    server_reput = not current_compliant or not runtime_compliant
    if server_reput:
        client.request("PUT", "/v1/mcpServer", desired_mcp_server(state))
        updated = client.request("GET", server_path)
        validate_mcp_server(updated, state, verify_token=True)
        if not isinstance(updated, dict) or not _console_v221_enables_raw_configuration(
            _server_raw_configuration(updated)
        ):
            raise ConfigurationError("Console did not retain an enableable MCP YAML document")
        changed = True

    if not runtime_compliant:
        runtime.enforce_fail_closed(state.pinned_wasm_url)
        changed = True

    binding_path = f"/v1/mcpServer/consumers?mcpServerName={MCP_SERVER_NAME}"
    bindings = validate_consumer_bindings(client.request("GET", binding_path))
    extras = sorted(set(bindings) - {CONSUMER_NAME})
    if extras:
        client.request(
            "DELETE",
            "/v1/mcpServer/consumers",
            {"mcpServerName": MCP_SERVER_NAME, "consumers": extras},
            expected=(204,),
        )
        changed = True
    if CONSUMER_NAME not in bindings:
        client.request(
            "PUT",
            "/v1/mcpServer/consumers",
            {"mcpServerName": MCP_SERVER_NAME, "consumers": [CONSUMER_NAME]},
            expected=(204,),
        )
        changed = True

    # Final re-reads are mandatory because the consumer API has no version or
    # optimistic-lock field in the audited Console v1 contract.
    final_server = client.request("GET", server_path)
    validate_mcp_server(final_server, state, verify_token=True)
    if not isinstance(final_server, dict) or not _console_v221_enables_raw_configuration(
        _server_raw_configuration(final_server)
    ):
        raise ConfigurationError("post-apply MCP document lacks the Console enablement marker")
    final_bindings = validate_consumer_bindings(client.request("GET", binding_path))
    if final_bindings != [CONSUMER_NAME]:
        raise ConfigurationError("post-apply consumer state is not locator-only")
    try:
        validate_runtime_wasm_plugin(runtime.read(), state, verify_token=True)
    except ConfigurationError as exc:
        if server_reput:
            raise ConfigurationError(
                f"Console re-PUT did not produce an enabled MCP runtime: {exc}"
            ) from None
        raise
    return changed


def _openapi(client: ApiClient, pinned_console_image_digest: str | None) -> dict[str, Any] | None:
    if (
        pinned_console_image_digest is not None
        and pinned_console_image_digest != PINNED_CONSOLE_IMAGE_DIGEST
    ):
        raise ConfigurationError("unrecognized pinned Console image digest")

    unavailable = 0
    for path in ("/swagger/openapi.json", "/v3/api-docs"):
        try:
            document = client.request("GET", path)
        except ApiUnavailableError:
            unavailable += 1
            continue
        if not isinstance(document, dict):
            unavailable += 1
            continue
        # An available JSON document with a changed schema is authoritative
        # evidence of incompatibility. Never bypass it with the image pin.
        validate_openapi(document)
        return document

    if unavailable == 2 and pinned_console_image_digest == PINNED_CONSOLE_IMAGE_DIGEST:
        return None
    raise ConfigurationError(
        "Console OpenAPI is unavailable; the exact audited image digest is required"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Configure the locator-only GitHub MCP boundary.")
    parser.add_argument("--apply", action="store_true", help="apply desired state")
    parser.add_argument("--namespace", default="agentteams-system")
    parser.add_argument("--console-password-secret", metavar="NAME:KEY")
    parser.add_argument(
        "--locator-gateway-key-secret",
        default="hiclaw-creds-devflow-locator:WORKER_GATEWAY_KEY",
        metavar="NAME:KEY",
        help="exact AgentTeams Locator gateway credential binding",
    )
    parser.add_argument(
        "--console-url",
        help="loopback HTTP endpoint from an operator-controlled kubectl port-forward",
    )
    parser.add_argument(
        "--pinned-console-image-digest",
        help="allow the audited source contract only for the exact image digest",
    )
    parser.add_argument(
        "--pinned-wasm-plugin-url",
        default=os.environ.get("DEVFLOW_HIGRESS_MCP_WASM_URL"),
        help="required oci:// MCP plugin URL pinned with @sha256:<digest>",
    )
    parser.add_argument(
        "--console-username",
        default=os.environ.get("HIGRESS_ADMIN_USERNAME", "admin"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _validate_namespace(args.namespace)
        if not isinstance(args.pinned_wasm_plugin_url, str):
            raise ConfigurationError("--pinned-wasm-plugin-url is required")
        state = DesiredState(args.namespace, args.pinned_wasm_plugin_url)
        password = resolve_secret(
            namespace=args.namespace,
            environment_name="HIGRESS_ADMIN_PASSWORD",
            secret_reference=args.console_password_secret,
            label="Higress admin password",
        )
        locator_gateway_key = resolve_secret(
            namespace=args.namespace,
            environment_name="DEVFLOW_LOCATOR_GATEWAY_KEY",
            secret_reference=args.locator_gateway_key_secret,
            label="Locator gateway credential",
            minimum_length=16,
        )
        client = HigressClient(operator_console_url(args.namespace, args.console_url))
        runtime = KubectlRuntimeManager(args.namespace)
        client.login(args.console_username, password)
        _openapi(client, args.pinned_console_image_digest)

        if args.apply:
            changed = apply_state(
                client,
                runtime,
                state,
                expected_consumer_credential=locator_gateway_key,
            )
            print(
                "higress-github-readonly:",
                "control-plane-applied" if changed else "control-plane-unchanged",
            )
        else:
            check_state(
                client,
                runtime,
                state,
                expected_consumer_credential=locator_gateway_key,
            )
            print("higress-github-readonly: control-plane-compliant")
        print(f"endpoint: {state.gateway_endpoint}")
        return 0
    except ConfigurationError as exc:
        print(f"higress-github-readonly: refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Safety and idempotency gates for the dedicated Higress GitHub MCP."""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml

from scripts.configure_higress_github_readonly import (
    CONSUMER_NAME,
    MCP_DESCRIPTION,
    MCP_INTERNAL_ROUTE_NAME,
    MCP_NOT_FOUND_FRAGMENT,
    MCP_SERVER_NAME,
    PINNED_CONSOLE_IMAGE_DIGEST,
    ApiUnavailableError,
    ConfigurationError,
    DesiredState,
    _console_v221_enables_raw_configuration,
    _openapi,
    _query_optional,
    _validate_raw_configuration,
    apply_state,
    check_state,
    desired_mcp_server,
    operator_console_url,
    raw_mcp_configuration,
    resolve_secret,
    validate_consumer,
    validate_mcp_server,
    validate_openapi,
    validate_runtime_wasm_plugin,
)

ROOT = Path(__file__).resolve().parents[1]
PINNED_WASM_URL = "oci://registry.example/higress/mcp-server@sha256:" + "1" * 64
LOCATOR_GATEWAY_KEY = "locator-gateway-key-Synthetic1234567890"


def _locator_credential(value: str = LOCATOR_GATEWAY_KEY) -> dict[str, Any]:
    return {
        "key": None,
        "source": "BEARER",
        "type": "key-auth",
        "values": [value],
    }


def _wrapper(data: Any) -> dict[str, Any]:
    return {"success": True, "message": None, "data": data}


def _openapi_document() -> dict[str, Any]:
    paths: dict[str, Any] = {
        "/v1/mcpServer": {"get": {}, "put": {}},
        "/v1/mcpServer/{name}": {"get": {}},
        "/v1/mcpServer/consumers": {"get": {}, "put": {}, "delete": {}},
        "/v1/consumers/{name}": {"get": {}},
        "/v1/service-sources": {"post": {}},
        "/v1/service-sources/{name}": {"get": {}, "put": {}},
    }
    schemas: dict[str, Any] = {
        "McpServer": {
            "properties": {
                name: {}
                for name in (
                    "name",
                    "description",
                    "domains",
                    "services",
                    "type",
                    "consumerAuthInfo",
                    "rawConfigurations",
                )
            }
        },
        "McpServerConsumers": {"properties": {"mcpServerName": {}, "consumers": {}}},
        "Consumer": {"properties": {"name": {}, "credentials": {}}},
        "ServiceSource": {
            "properties": {name: {} for name in ("name", "type", "domain", "port", "protocol")}
        },
    }
    return {"openapi": "3.0.1", "paths": paths, "components": {"schemas": schemas}}


def _state() -> DesiredState:
    return DesiredState("agentteams-system", PINNED_WASM_URL)


def test_console_url_override_is_loopback_only() -> None:
    assert operator_console_url("agentteams-system", None) == (
        "http://higress-console.agentteams-system.svc.cluster.local:8080"
    )
    assert operator_console_url("agentteams-system", "http://127.0.0.1:18081") == (
        "http://127.0.0.1:18081"
    )
    for value in (
        "https://127.0.0.1:18081",
        "http://0.0.0.0:18081",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:18081/path",
    ):
        with pytest.raises(ConfigurationError, match="loopback"):
            operator_console_url("agentteams-system", value)


def _normalized_console_yaml() -> str:
    def quoted(value: str) -> str:
        return json.dumps(value, ensure_ascii=True)

    return (
        "\n".join(
            [
                "server:",
                f"  name: {quoted('devflow-github-readonly')}",
                "tools:",
                "- args:",
                f"  - description: {quoted('Owning DevFlow task identifier')}",
                f"    name: {quoted('task_id')}",
                "    required: true",
                f"    type: {quoted('string')}",
                f"  - description: {quoted('Short-lived exact-scope capability')}",
                f"    name: {quoted('capability')}",
                "    required: true",
                f"    type: {quoted('string')}",
                f"  - description: {quoted('Assigned repository owner')}",
                f"    name: {quoted('owner')}",
                "    required: true",
                f"    type: {quoted('string')}",
                f"  - description: {quoted('Assigned repository name')}",
                f"    name: {quoted('repo')}",
                "    required: true",
                f"    type: {quoted('string')}",
                f"  - description: {quoted('Exact repository-relative file path')}",
                f"    name: {quoted('path')}",
                "    required: true",
                f"    type: {quoted('string')}",
                f"  - description: {quoted('Immutable 40-character commit SHA')}",
                f"    name: {quoted('revision')}",
                "    required: true",
                f"    type: {quoted('string')}",
                f"  description: {quoted('Read one file from an assigned GitHub repository revision.')}",
                f"  name: {quoted('get_file_contents')}",
                "  requestTemplate:",
                "    headers:",
                f"    - key: {quoted('X-DevFlow-Capability')}",
                f"      value: {quoted('{{.args.capability}}')}",
                f"    method: {quoted('GET')}",
                f"    url: {quoted('http://devflow-github-content-broker.agentteams-system.svc.cluster.local:8080/v1/content?task_id={{.args.task_id}}&owner={{.args.owner}}&repo={{.args.repo}}&path={{.args.path}}&revision={{.args.revision}}')}",
            ]
        )
        + "\n"
    )


def _historical_json_configuration() -> str:
    return json.dumps(
        yaml.safe_load(_normalized_console_yaml()),
        ensure_ascii=True,
        separators=(",", ":"),
    )


def _runtime_document(
    state: DesiredState,
    *,
    enabled: bool = True,
    fail_strategy: str = "FAIL_CLOSE",
) -> dict[str, Any]:
    return {
        "apiVersion": "extensions.higress.io/v1alpha1",
        "kind": "WasmPlugin",
        "metadata": {"name": "mcp-server.internal", "namespace": state.namespace},
        "spec": {
            "defaultConfigDisable": True,
            "failStrategy": fail_strategy,
            "url": state.pinned_wasm_url,
            "matchRules": [
                {
                    "configDisable": not enabled,
                    "config": yaml.safe_load(_normalized_console_yaml()),
                    "ingress": [MCP_INTERNAL_ROUTE_NAME],
                }
            ],
        },
    }


class _RuntimeReader:
    def __init__(self, state: DesiredState, *, enabled: bool = True) -> None:
        self.document = _runtime_document(state, enabled=enabled)
        self.reads = 0
        self.enforcements = 0

    def read(self) -> dict[str, Any]:
        self.reads += 1
        return deepcopy(self.document)

    def set_enabled(self, enabled: bool) -> None:
        self.document["spec"]["matchRules"][0]["configDisable"] = not enabled

    def enforce_fail_closed(self, pinned_wasm_url: str) -> None:
        self.enforcements += 1
        self.document["spec"]["failStrategy"] = "FAIL_CLOSE"
        self.document["spec"]["url"] = pinned_wasm_url


def test_openapi_validation_is_fail_closed() -> None:
    document = _openapi_document()
    validate_openapi(document)

    missing_method = deepcopy(document)
    del missing_method["paths"]["/v1/mcpServer/consumers"]["delete"]
    with pytest.raises(ConfigurationError, match="contract mismatch"):
        validate_openapi(missing_method)

    missing_field = deepcopy(document)
    del missing_field["components"]["schemas"]["McpServer"]["properties"]["rawConfigurations"]
    with pytest.raises(ConfigurationError, match="schema mismatch"):
        validate_openapi(missing_field)


class _UnavailableOpenApiClient:
    last_status: int | None = None

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        del method, path, payload, expected
        raise ApiUnavailableError("Console returned non-JSON SPA content")


class _SchemaOpenApiClient(_UnavailableOpenApiClient):
    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        del method, path, payload, expected
        document = _openapi_document()
        del document["paths"]["/v1/mcpServer"]["put"]
        return document


def test_source_contract_fallback_requires_exact_image_pin() -> None:
    client = _UnavailableOpenApiClient()
    with pytest.raises(ConfigurationError, match="exact audited image digest"):
        _openapi(client, None)
    with pytest.raises(ConfigurationError, match="unrecognized"):
        _openapi(client, "sha256:" + "0" * 64)
    assert _openapi(client, PINNED_CONSOLE_IMAGE_DIGEST) is None


def test_image_pin_never_bypasses_available_schema_mismatch() -> None:
    with pytest.raises(ConfigurationError, match="contract mismatch"):
        _openapi(_SchemaOpenApiClient(), PINNED_CONSOLE_IMAGE_DIGEST)


class _JsonShapeMismatchClient(_UnavailableOpenApiClient):
    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        del method, path, payload, expected
        raise ConfigurationError("Console returned a non-object JSON document")


def test_image_pin_does_not_reclassify_json_shape_mismatch_as_unavailable() -> None:
    with pytest.raises(ConfigurationError, match="non-object JSON"):
        _openapi(_JsonShapeMismatchClient(), PINNED_CONSOLE_IMAGE_DIGEST)


class _StatusClient:
    def __init__(self, status: int, document: dict[str, Any]) -> None:
        self.last_status: int | None = status
        self.document = document

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        del method, path, payload
        assert self.last_status in expected
        return deepcopy(self.document)


def test_only_exact_audited_mcp_502_not_found_is_absent() -> None:
    path = f"/v1/mcpServer/{MCP_SERVER_NAME}"
    exact = {
        "success": False,
        "message": f"com.alibaba.higress.sdk.exception.{MCP_NOT_FOUND_FRAGMENT}",
        "data": None,
    }
    assert (
        _query_optional(
            _StatusClient(502, exact),
            path,
            allow_audited_mcp_not_found=True,
        )
        is None
    )

    for mismatch in (
        exact | {"message": "NotFoundException: unrelated resource"},
        exact | {"data": {}},
        exact | {"unexpected": True},
    ):
        with pytest.raises(ConfigurationError, match="502"):
            _query_optional(
                _StatusClient(502, mismatch),
                path,
                allow_audited_mcp_not_found=True,
            )

    with pytest.raises(ConfigurationError, match="forbidden"):
        _query_optional(
            _StatusClient(502, exact),
            "/v1/service-sources/devflow-github-content-broker",
            allow_audited_mcp_not_found=True,
        )


def test_raw_configuration_exposes_exactly_one_get_tool() -> None:
    raw = raw_mcp_configuration()
    document = yaml.safe_load(raw)

    assert "\ntools:\n" in f"\n{raw}"
    assert _console_v221_enables_raw_configuration(raw) is True
    assert _console_v221_enables_raw_configuration(
        _historical_json_configuration()
    ) is False
    assert set(document) == {"server", "tools"}
    assert document["server"] == {"name": MCP_SERVER_NAME}
    assert [tool["name"] for tool in document["tools"]] == ["get_file_contents"]
    request = document["tools"][0]["requestTemplate"]
    assert request["method"] == "GET"
    assert "body" not in request
    assert request["headers"] == [
        {"key": "X-DevFlow-Capability", "value": "{{.args.capability}}"}
    ]
    assert [argument["name"] for argument in document["tools"][0]["args"]] == [
        "task_id",
        "capability",
        "owner",
        "repo",
        "path",
        "revision",
    ]
    assert all(argument["required"] for argument in document["tools"][0]["args"])


def test_normalized_console_yaml_round_trip_rejects_any_embedded_credential() -> None:
    state = _state()
    response = desired_mcp_server(state)
    response.pop("mcpServerName")
    response["rawConfigurations"] = _normalized_console_yaml()

    validate_mcp_server(_wrapper(response), state, verify_token=True)
    validate_mcp_server(_wrapper(response), state, verify_token=False)

    poisoned = deepcopy(response)
    document = yaml.safe_load(poisoned["rawConfigurations"])
    document["server"]["config"] = {"accessToken": "must-not-be-in-higress"}
    poisoned["rawConfigurations"] = json.dumps(document, separators=(",", ":"))
    with pytest.raises(ConfigurationError, match="server configuration schema"):
        validate_mcp_server(_wrapper(poisoned), state, verify_token=True)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw + "- args:\n",
        lambda raw: raw.replace('    method: "GET"', '    method: "POST"'),
        lambda raw: raw.replace(
            '    method: "GET"', '    body: "forbidden"\n    method: "GET"'
        ),
        lambda raw: raw.replace(
            '  name: "devflow-github-readonly"',
            '  name: "devflow-github-readonly"\n  name: "duplicate"',
        ),
        lambda raw: raw.replace("server:", "server: &server", 1),
        lambda raw: raw.replace("tools:", "tools: !unsafe", 1),
        lambda raw: raw.replace("  name:", "  <<: *server\n  name:", 1),
        lambda raw: raw.replace("    required: true", "    required: yes", 1),
        lambda raw: raw.replace(
            "server:\n",
            'server:\n  config:\n    accessToken: "forbidden-token"\n',
            1,
        ),
        lambda raw: raw + "trailing: content\n",
        lambda raw: raw.replace(
            '      value: "{{.args.capability}}"',
            '      value: "{{.args.capability}}"\n      extra: "forbidden"',
        ),
    ],
    ids=[
        "second-tool",
        "write-method",
        "body",
        "duplicate-field",
        "anchor",
        "tag",
        "merge-key",
        "malformed-boolean",
        "credential-injection",
        "trailing-content",
        "unknown-header-field",
    ],
)
def test_normalized_console_yaml_rejects_every_noncanonical_form(
    mutate: Callable[[str], str],
) -> None:
    with pytest.raises(ConfigurationError):
        _validate_raw_configuration(mutate(_normalized_console_yaml()))


def test_json_reread_remains_supported_but_is_exact_and_duplicate_safe() -> None:
    historical = _historical_json_configuration()
    _validate_raw_configuration(historical)

    unknown = json.loads(historical)
    unknown["tools"][0]["args"][0]["unexpected"] = True
    with pytest.raises(ConfigurationError, match="argument surface"):
        _validate_raw_configuration(json.dumps(unknown))

    wrong_headers = json.loads(historical)
    wrong_headers["tools"][0]["requestTemplate"]["headers"].append(
        {"key": "X-Unsafe", "value": "enabled"}
    )
    with pytest.raises(ConfigurationError, match="headers"):
        _validate_raw_configuration(json.dumps(wrong_headers))

    duplicate = historical.replace(
        '"server":', '"server":{},"server":', 1
    )
    with pytest.raises(ConfigurationError, match="duplicate"):
        _validate_raw_configuration(duplicate)


def test_secret_source_is_explicit_and_ambiguous_sources_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = "test-console-password"
    monkeypatch.setenv("HIGRESS_ADMIN_PASSWORD", password)
    assert (
        resolve_secret(
            namespace="agentteams-system",
            environment_name="HIGRESS_ADMIN_PASSWORD",
            secret_reference=None,
            label="Higress admin password",
        )
        == password
    )
    with pytest.raises(ConfigurationError, match="two sources"):
        resolve_secret(
            namespace="agentteams-system",
            environment_name="HIGRESS_ADMIN_PASSWORD",
            secret_reference="existing-secret:password",
            label="Higress admin password",
        )


def test_runtime_requires_one_enabled_exact_ingress_without_secret_diagnostics() -> None:
    state = _state()
    validate_runtime_wasm_plugin(
        _runtime_document(state), state, verify_token=True
    )

    disabled = _runtime_document(state, enabled=False)
    with pytest.raises(ConfigurationError, match="target is disabled") as captured:
        validate_runtime_wasm_plugin(disabled, state, verify_token=True)
    assert "accessToken" not in str(captured.value)

    duplicate = _runtime_document(state)
    duplicate["spec"]["matchRules"].append(
        deepcopy(duplicate["spec"]["matchRules"][0])
    )
    with pytest.raises(ConfigurationError, match="exactly one"):
        validate_runtime_wasm_plugin(duplicate, state, verify_token=True)

    broad = _runtime_document(state)
    broad["spec"]["matchRules"][0]["ingress"].append("another-route")
    with pytest.raises(ConfigurationError, match="ingress-only and exact"):
        validate_runtime_wasm_plugin(broad, state, verify_token=True)

    fail_open = _runtime_document(state, fail_strategy="FAIL_OPEN")
    with pytest.raises(ConfigurationError, match="fail strategy"):
        validate_runtime_wasm_plugin(fail_open, state, verify_token=True)

    unpinned = _runtime_document(state)
    unpinned["spec"]["url"] = "oci://registry.example/higress/mcp-server:latest"
    with pytest.raises(ConfigurationError, match="OCI sha256 pin"):
        validate_runtime_wasm_plugin(unpinned, state, verify_token=True)


def test_consumer_credential_surface_rejects_extra_or_legacy_credentials() -> None:
    validate_consumer(
        _wrapper(
            {
                "name": CONSUMER_NAME,
                "credentials": [_locator_credential()],
            }
        ),
        LOCATOR_GATEWAY_KEY,
    )
    for credentials in (
        [
            _locator_credential(),
            {**_locator_credential(), "source": "QUERY"},
        ],
        [{**_locator_credential(), "legacy": True}],
        [{**_locator_credential(), "type": "basic-auth"}],
        [{**_locator_credential(), "values": []}],
    ):
        with pytest.raises(ConfigurationError, match="credential surface"):
            validate_consumer(
                _wrapper({"name": CONSUMER_NAME, "credentials": credentials})
            )
    with pytest.raises(ConfigurationError, match="binding is mismatched"):
        validate_consumer(
            _wrapper(
                {"name": CONSUMER_NAME, "credentials": [_locator_credential()]}
            ),
            "different-locator-gateway-key-1234567890",
        )


def test_mcp_validation_rejects_tool_or_consumer_expansion() -> None:
    state = _state()
    desired = desired_mcp_server(state)
    assert desired["mcpServerName"] == MCP_SERVER_NAME
    validate_mcp_server(_wrapper(desired), state, verify_token=True)

    # The audited Console accepts mcpServerName on PUT but omits the
    # compatibility-only route binding field from subsequent GET responses.
    response_shape = deepcopy(desired)
    del response_shape["mcpServerName"]
    validate_mcp_server(_wrapper(response_shape), state, verify_token=True)

    extra_tool = deepcopy(desired)
    raw = yaml.safe_load(extra_tool["rawConfigurations"])
    raw["tools"].append(
        {
            "name": "push_files",
            "args": [],
            "requestTemplate": {"method": "POST", "url": "https://api.github.com"},
        }
    )
    extra_tool["rawConfigurations"] = json.dumps(raw, separators=(",", ":"))
    with pytest.raises(ConfigurationError, match="exactly one tool"):
        validate_mcp_server(_wrapper(extra_tool), state, verify_token=True)

    extra_consumer = deepcopy(desired)
    extra_consumer["consumerAuthInfo"]["allowedConsumers"].append("devflow-reviewer")
    with pytest.raises(ConfigurationError, match="worker-devflow-locator"):
        validate_mcp_server(_wrapper(extra_consumer), state, verify_token=True)


class _CompliantClient:
    def __init__(self, state: DesiredState) -> None:
        self.calls: list[tuple[str, str]] = []
        self._server = _wrapper(desired_mcp_server(state))
        self.last_status: int | None = None

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        del payload, expected
        self.last_status = 200
        self.calls.append((method, path))
        if path == f"/v1/consumers/{CONSUMER_NAME}":
            return _wrapper(
                {
                    "name": CONSUMER_NAME,
                    "credentials": [_locator_credential()],
                }
            )
        if path == "/v1/service-sources/devflow-github-content-broker":
            return _wrapper(
                {
                    "name": "devflow-github-content-broker",
                    "type": "dns",
                    "domain": (
                        "devflow-github-content-broker.agentteams-system."
                        "svc.cluster.local"
                    ),
                    "port": 8080,
                    "protocol": "http",
                    "properties": {},
                    "authN": {"enabled": False},
                }
            )
        if path == f"/v1/mcpServer/{MCP_SERVER_NAME}":
            return deepcopy(self._server)
        if path.startswith("/v1/mcpServer/consumers?"):
            return _wrapper(
                [
                    {
                        "mcpServerName": MCP_INTERNAL_ROUTE_NAME,
                        "consumerName": CONSUMER_NAME,
                        "type": "key-auth",
                    }
                ]
            )
        raise AssertionError(f"unexpected request: {method} {path}")


def test_apply_is_a_noop_when_exact_state_already_exists() -> None:
    state = _state()
    client = _CompliantClient(state)
    runtime = _RuntimeReader(state)

    assert apply_state(client, runtime, state) is False
    assert not any(method in {"POST", "PUT", "DELETE"} for method, _ in client.calls)


def test_apply_repairs_fail_open_and_check_will_not_call_it_compliant() -> None:
    state = _state()
    runtime = _RuntimeReader(state)
    runtime.document["spec"]["failStrategy"] = "FAIL_OPEN"
    client = _HistoricalJsonClient(state, runtime)

    with pytest.raises(ConfigurationError, match="fail strategy"):
        check_state(client, runtime, state)
    assert apply_state(client, runtime, state) is True
    assert runtime.enforcements == 1
    validate_runtime_wasm_plugin(runtime.read(), state, verify_token=True)


def test_check_fails_when_control_plane_is_exact_but_runtime_is_disabled() -> None:
    state = _state()
    with pytest.raises(ConfigurationError, match="target is disabled") as captured:
        check_state(_CompliantClient(state), _RuntimeReader(state, enabled=False), state)
    assert "accessToken" not in str(captured.value)


class _HistoricalJsonClient(_CompliantClient):
    def __init__(
        self,
        state: DesiredState,
        runtime: _RuntimeReader,
        *,
        propagate_runtime: bool = True,
    ) -> None:
        super().__init__(state)
        self.runtime = runtime
        self.propagate_runtime = propagate_runtime
        self._server["data"]["rawConfigurations"] = _historical_json_configuration()

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        if method == "PUT" and path == "/v1/mcpServer":
            assert payload is not None
            self.last_status = 200
            self.calls.append((method, path))
            self._server = _wrapper(deepcopy(payload))
            if self.propagate_runtime:
                self.runtime.set_enabled(True)
            return deepcopy(self._server)
        return super().request(method, path, payload, expected=expected)


def test_apply_reputs_historical_json_and_requires_runtime_enablement() -> None:
    state = _state()
    runtime = _RuntimeReader(state, enabled=False)
    client = _HistoricalJsonClient(state, runtime)

    assert apply_state(client, runtime, state) is True
    assert ("PUT", "/v1/mcpServer") in client.calls
    assert _console_v221_enables_raw_configuration(
        client._server["data"]["rawConfigurations"]
    )


def test_apply_fails_if_console_reput_leaves_runtime_disabled() -> None:
    state = _state()
    runtime = _RuntimeReader(state, enabled=False)
    client = _HistoricalJsonClient(state, runtime, propagate_runtime=False)

    with pytest.raises(ConfigurationError, match="Console re-PUT") as captured:
        apply_state(client, runtime, state)
    assert "accessToken" not in str(captured.value)


class _MissingServiceSourceClient(_CompliantClient):
    def __init__(self, state: DesiredState) -> None:
        super().__init__(state)
        self.created = False

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        if (
            path == "/v1/service-sources/devflow-github-content-broker"
            and not self.created
        ):
            self.last_status = 404
            self.calls.append((method, path))
            return None
        if method == "POST" and path == "/v1/service-sources":
            assert 201 in expected
            assert payload is not None
            self.created = True
            self.last_status = 201
            self.calls.append((method, path))
            return _wrapper(payload)
        return super().request(method, path, payload, expected=expected)


def test_apply_accepts_audited_201_when_service_source_is_created() -> None:
    state = _state()
    client = _MissingServiceSourceClient(state)
    runtime = _RuntimeReader(state)

    assert apply_state(client, runtime, state) is True
    assert client.created is True
    assert ("POST", "/v1/service-sources") in client.calls


class _DriftedClient(_CompliantClient):
    def __init__(self, state: DesiredState, runtime: _RuntimeReader) -> None:
        super().__init__(state)
        self.runtime = runtime
        server = self._server["data"]
        raw = yaml.safe_load(server["rawConfigurations"])
        raw["tools"].append(
            {
                "name": "push_files",
                "args": [],
                "requestTemplate": {
                    "method": "POST",
                    "url": "https://api.github.com",
                },
            }
        )
        server["rawConfigurations"] = json.dumps(raw, separators=(",", ":"))
        self.bindings = ["manager"]

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        expected: tuple[int, ...] = (200,),
    ) -> dict[str, Any] | None:
        if method == "PUT" and path == "/v1/mcpServer":
            assert payload is not None
            self.last_status = 200
            self.calls.append((method, path))
            self._server = _wrapper(deepcopy(payload))
            self.runtime.set_enabled(True)
            return deepcopy(self._server)
        if path == "/v1/mcpServer/consumers":
            assert payload is not None
            self.last_status = 204
            self.calls.append((method, path))
            if method == "DELETE":
                self.bindings = [name for name in self.bindings if name not in payload["consumers"]]
                return None
            if method == "PUT":
                self.bindings.extend(
                    name for name in payload["consumers"] if name not in self.bindings
                )
                return None
        if path.startswith("/v1/mcpServer/consumers?"):
            del payload, expected
            self.last_status = 200
            self.calls.append((method, path))
            return _wrapper(
                [
                    {
                        "mcpServerName": MCP_INTERNAL_ROUTE_NAME,
                        "consumerName": name,
                        "type": "key-auth",
                    }
                    for name in self.bindings
                ]
            )
        return super().request(method, path, payload, expected=expected)


def test_apply_replaces_managed_tool_drift_and_removes_other_consumers() -> None:
    state = _state()
    runtime = _RuntimeReader(state)
    client = _DriftedClient(state, runtime)

    assert apply_state(client, runtime, state) is True
    assert client.bindings == [CONSUMER_NAME]
    assert ("PUT", "/v1/mcpServer") in client.calls
    assert ("DELETE", "/v1/mcpServer/consumers") in client.calls
    assert ("PUT", "/v1/mcpServer/consumers") in client.calls


def test_configurator_runs_without_site_packages() -> None:
    help_result = subprocess.run(
        [
            sys.executable,
            "-S",
            str(ROOT / "scripts" / "configure_higress_github_readonly.py"),
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "--github-token-secret" not in help_result.stdout
    assert "--pinned-wasm-plugin-url" in help_result.stdout

    pure_function = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "from scripts.configure_higress_github_readonly import "
                "_validate_raw_configuration,raw_mcp_configuration; "
                "raw=raw_mcp_configuration(); "
                "assert '\\ntools:\\n' in '\\n'+raw; "
                "_validate_raw_configuration(raw)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert pure_function.returncode == 0, pure_function.stderr

    pure_yaml_validation = subprocess.run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "from scripts.configure_higress_github_readonly import "
                "_validate_raw_configuration; "
                f"raw={_normalized_console_yaml()!r}; "
                "_validate_raw_configuration(raw)"
            ),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    assert pure_yaml_validation.returncode == 0, pure_yaml_validation.stderr


def test_team_exposes_internal_readonly_mcp_only_to_locator() -> None:
    manifest = yaml.safe_load((ROOT / "agentteams" / "team.yaml").read_text(encoding="utf-8"))
    workers = {worker["name"]: worker for worker in manifest["spec"]["workers"]}

    locator_servers = workers["devflow-locator"]["mcpServers"]
    assert locator_servers == [
        {
            "name": MCP_SERVER_NAME,
            "url": (
                "http://higress-gateway.agentteams-system.svc.cluster.local:80/"
                f"mcp-servers/{MCP_SERVER_NAME}/mcp"
            ),
            "transport": "http",
        }
    ]
    assert "mcpServers" not in workers["devflow-reviewer"]
    assert MCP_DESCRIPTION.endswith("(managed)")

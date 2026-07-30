"""Security and integration gates for the GitHub scope broker."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import io
import json
import ssl
import subprocess
import sys
import threading
import urllib.parse
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

import scripts.github_scope_broker as broker_module
from scripts.github_scope_broker import (
    CAPABILITY_SCHEMA,
    CONTENT_RESPONSE_SCHEMA,
    EXPECTED_LEADER_USERNAME,
    RECEIPT_SIGNATURE_DOMAIN,
    TOKEN_REVIEW_AUDIENCE,
    BrokerError,
    BrokerHTTPServer,
    CapabilityCodec,
    ContentRequest,
    FixedGitHubUpstream,
    KubernetesTokenReviewer,
    OpenSSLEd25519ReceiptSigner,
    RequestRejected,
    Scope,
    ServerPolicy,
    StaticBearerAuthenticator,
    UpstreamError,
    UpstreamResponse,
    parse_github_content,
    parse_repository_allowlist,
)

ROOT = Path(__file__).resolve().parents[1]
HMAC_KEY = b"test-only-hmac-key-with-at-least-32-bytes"
ISSUER_TOKEN = "test_only_issuer_bearer_with_32_chars"
GITHUB_TOKEN = "github_pat_test_only_credential"
GITHUB_AUTHORIZATION = f"Bearer {GITHUB_TOKEN}"
REVISION = "a" * 40
ALLOWED_REPOSITORIES = frozenset({("openai", "example-repository")})
OPENSSL = next(
    path
    for path in (
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
        Path("/usr/bin/openssl"),
    )
    if path.is_file()
)


def _scope(**changes: Any) -> Scope:
    document: dict[str, Any] = {
        "run_id": "run-001",
        "task_id": "task-001",
        "trace_id": "run-001:task-001",
        "owner": "openai",
        "repo": "example-repository",
        "revision": REVISION,
        "paths": ["README.md", "src/main.py"],
    }
    document.update(changes)
    return Scope.from_issuer_document(document)


def _query(**changes: str) -> str:
    values = {
        "task_id": "task-001",
        "owner": "openai",
        "repo": "example-repository",
        "path": "src/main.py",
        "revision": REVISION,
    }
    values.update(changes)
    return "/v1/content?" + urllib.parse.urlencode(values)


class FakeUpstream:
    def __init__(self) -> None:
        self.calls: list[tuple[ContentRequest, int]] = []

    def get(
        self,
        request: ContentRequest,
        *,
        max_response_bytes: int,
    ) -> UpstreamResponse:
        self.calls.append((request, max_response_bytes))
        return UpstreamResponse(
            200,
            json.dumps(
                {
                    "type": "file",
                    "path": "src/main.py",
                    "sha": "b" * 40,
                    "content": "ZmlsZQ==",
                    "encoding": "base64",
                    "untrusted_extra": "must not be returned",
                },
                separators=(",", ":"),
            ).encode(),
        )


@pytest.fixture
def receipt_signer(
    tmp_path: Path,
) -> tuple[OpenSSLEd25519ReceiptSigner, Path, Path]:
    private_key = tmp_path / "test-only-receipt-ed25519.pem"
    public_key = tmp_path / "test-only-receipt-ed25519.pub"
    subprocess.run(
        [
            str(OPENSSL),
            "genpkey",
            "-algorithm",
            "ED25519",
            "-out",
            str(private_key),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            str(OPENSSL),
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
    private_key.chmod(0o400)
    return (
        OpenSSLEd25519ReceiptSigner(private_key, openssl_path=OPENSSL),
        private_key,
        public_key,
    )


@contextlib.contextmanager
def _running_server(policy: ServerPolicy) -> Iterator[int]:
    server = BrokerHTTPServer(("127.0.0.1", 0), policy)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    port: int,
    method: str,
    target: str,
    *,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, Any] | bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, target, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        content_type = response.getheader("Content-Type", "")
        if content_type.startswith("application/json"):
            return response.status, json.loads(payload)
        return response.status, payload
    finally:
        connection.close()


def test_capability_has_exact_claims_and_strict_expiry() -> None:
    codec = CapabilityCodec(HMAC_KEY, ttl_seconds=60)
    token, issued = codec.issue(_scope(), now=1_000, jti="0" * 32)

    payload_segment = token.split(".", 1)[0]
    payload = json.loads(
        base64.urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4))
    )
    assert payload == {
        "schema": CAPABILITY_SCHEMA,
        "run_id": "run-001",
        "task_id": "task-001",
        "trace_id": "run-001:task-001",
        "owner": "openai",
        "repo": "example-repository",
        "revision": REVISION,
        "paths": ["README.md", "src/main.py"],
        "iat": 1_000,
        "exp": 1_060,
        "jti": "0" * 32,
    }
    assert codec.verify(token, now=1_059) == issued
    with pytest.raises(RequestRejected, match="capability_expired"):
        codec.verify(token, now=1_060)


def test_capability_tamper_and_noncanonical_scope_are_rejected() -> None:
    codec = CapabilityCodec(HMAC_KEY)
    token, _ = codec.issue(_scope(), now=1_000)
    payload_segment, signature_segment = token.split(".", 1)
    replacement = "A" if signature_segment[0] != "A" else "B"
    with pytest.raises(RequestRejected, match="capability_signature_invalid"):
        codec.verify(
            f"{payload_segment}.{replacement}{signature_segment[1:]}",
            now=1_001,
        )

    for paths in (
        ["src/main.py", "README.md"],
        ["README.md", "README.md"],
        ["../secret"],
        ["/absolute"],
        ["src//main.py"],
    ):
        with pytest.raises(RequestRejected):
            _scope(paths=paths)

    with pytest.raises(RequestRejected, match="issuer_schema_invalid"):
        Scope.from_issuer_document(
            {
                "run_id": "run-001",
                "task_id": "task-001",
                "trace_id": "run-001:task-001",
                "owner": "openai",
                "repo": "example-repository",
                "revision": REVISION,
                "paths": ["README.md"],
                "extra": True,
            }
        )


def test_repository_allowlist_is_nonempty_exact_and_has_no_wildcards() -> None:
    assert parse_repository_allowlist(
        "YZYY95K/test,openai/example-repository"
    ) == frozenset({("YZYY95K", "test"), ("openai", "example-repository")})
    for value in (
        "",
        "*/*",
        "openai/*",
        "openai/example-repository,openai/example-repository",
        "openai/example-repository, YZYY95K/test",
        "openai/example-repository,YZYY95K/test",
    ):
        with pytest.raises(BrokerError):
            parse_repository_allowlist(value)


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("task_id", "task-002"),
        ("owner", "another-owner"),
        ("repo", "another-repo"),
        ("path", "not-authorized.py"),
        ("revision", "b" * 40),
    ],
)
def test_content_exact_matches_every_scope_dimension(change: str, value: str) -> None:
    codec = CapabilityCodec(HMAC_KEY)
    token, _ = codec.issue(_scope(), now=1_000)
    request = ContentRequest.from_query(_query(**{change: value}))
    with pytest.raises(RequestRejected, match="capability_scope_mismatch"):
        request.authorize(codec, token, now=1_001)


def test_content_schema_excludes_capability_and_branch_alias() -> None:
    with pytest.raises(RequestRejected, match="query_(?:schema_)?invalid"):
        ContentRequest.from_query(_query() + "&capability=must-not-be-in-url")
    with pytest.raises(RequestRejected, match="query_schema_invalid"):
        ContentRequest.from_query(_query().replace("revision=", "branch="))


def test_issuer_http_contract_and_audit_do_not_log_secrets() -> None:
    codec = CapabilityCodec(HMAC_KEY, ttl_seconds=60)
    policy = ServerPolicy(
        "issuer",
        codec,
        StaticBearerAuthenticator(ISSUER_TOKEN),
        None,
        1_500_000,
        ALLOWED_REPOSITORIES,
    )
    request_document = {
        "run_id": "run-001",
        "task_id": "task-001",
        "trace_id": "run-001:task-001",
        "owner": "openai",
        "repo": "example-repository",
        "revision": REVISION,
        "paths": ["README.md", "src/main.py"],
    }
    body = json.dumps(request_document, separators=(",", ":")).encode()
    output = io.StringIO()
    with contextlib.redirect_stdout(output), _running_server(policy) as port:
        status, response = _request(
            port,
            "POST",
            "/v1/capabilities",
            headers={
                "Authorization": f"Bearer {ISSUER_TOKEN}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
            body=body,
        )
        assert status == 201
        assert isinstance(response, dict)
        assert set(response) == {"capability", "expires_at", "jti", "schema"}
        assert response["schema"] == CAPABILITY_SCHEMA
        assert codec.verify(response["capability"]).task_id == "task-001"

        denied_status, denied = _request(
            port,
            "POST",
            "/v1/capabilities",
            headers={"Content-Type": "application/json"},
            body=body,
        )
        assert denied_status == 401
        assert isinstance(denied, dict)
        assert denied == {"code": "authorization_required", "status": 401}

        outside_document = dict(request_document)
        outside_document.update(owner="another-owner", repo="another-repo")
        outside_body = json.dumps(outside_document, separators=(",", ":")).encode()
        outside_status, outside = _request(
            port,
            "POST",
            "/v1/capabilities",
            headers={
                "Authorization": f"Bearer {ISSUER_TOKEN}",
                "Content-Type": "application/json",
            },
            body=outside_body,
        )
        assert outside_status == 403
        assert outside == {"code": "repository_not_allowed", "status": 403}

    audit = output.getvalue()
    assert ISSUER_TOKEN not in audit
    assert HMAC_KEY.decode() not in audit
    assert response["capability"] not in audit


def test_content_http_requires_capability_header_and_never_logs_it(
    receipt_signer: tuple[OpenSSLEd25519ReceiptSigner, Path, Path],
    tmp_path: Path,
) -> None:
    codec = CapabilityCodec(HMAC_KEY, ttl_seconds=60)
    capability, _ = codec.issue(_scope())
    upstream = FakeUpstream()
    signer, _private_key, public_key = receipt_signer
    policy = ServerPolicy(
        "content",
        codec,
        None,
        upstream,
        64_000,
        ALLOWED_REPOSITORIES,
        receipt_signer=signer,
    )
    output = io.StringIO()
    with contextlib.redirect_stdout(output), _running_server(policy) as port:
        status, response = _request(
            port,
            "GET",
            _query(),
            headers={"X-DevFlow-Capability": capability},
        )
        assert status == 200
        assert isinstance(response, dict)
        assert set(response) == {
            "schema_version",
            "assignment",
            "authorization",
            "github",
            "receipt_key_sha256",
            "response_digest",
            "receipt_signature",
        }
        assert response["schema_version"] == CONTENT_RESPONSE_SCHEMA
        scope_document = {
            "run_id": "run-001",
            "task_id": "task-001",
            "trace_id": "run-001:task-001",
            "owner": "openai",
            "repo": "example-repository",
            "revision": REVISION,
            "paths": ["README.md", "src/main.py"],
        }
        scope_digest = hashlib.sha256(
            json.dumps(scope_document, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        assert response["assignment"] == {
            "run_id": "run-001",
            "task_id": "task-001",
            "trace_id": "run-001:task-001",
            "repository": "openai/example-repository",
            "revision": REVISION,
            "paths": ["README.md", "src/main.py"],
            "scope_digest": scope_digest,
        }
        assert set(response["authorization"]) == {
            "decision",
            "task_id",
            "scope_digest",
            "capability_digest",
            "authorized_at",
        }
        assert response["authorization"]["decision"] == "allow"
        assert response["authorization"]["task_id"] == "task-001"
        assert response["authorization"]["capability_digest"] == hashlib.sha256(
            capability.encode("ascii")
        ).hexdigest()
        assert response["github"] == {
            "repository": "openai/example-repository",
            "revision": REVISION,
            "path": "src/main.py",
            "object_sha": "b" * 40,
            "content_base64": "ZmlsZQ==",
            "encoding": "base64",
        }
        signed = dict(response)
        signature_text = signed.pop("receipt_signature")
        signature = base64.urlsafe_b64decode(
            signature_text + "=" * (-len(signature_text) % 4)
        )
        message_path = tmp_path / "receipt-message.bin"
        signature_path = tmp_path / "receipt-signature.bin"
        message_path.write_bytes(
            RECEIPT_SIGNATURE_DOMAIN
            + json.dumps(signed, separators=(",", ":"), sort_keys=True).encode()
        )
        signature_path.write_bytes(signature)
        verified = subprocess.run(
            [
                str(OPENSSL),
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key),
                "-rawin",
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ],
            check=False,
            capture_output=True,
        )
        assert verified.returncode == 0
        digest = signed.pop("response_digest")
        assert digest == hashlib.sha256(
            json.dumps(signed, separators=(",", ":"), sort_keys=True).encode()
        ).hexdigest()
        assert len(upstream.calls) == 1
        captured_request, captured_limit = upstream.calls[0]
        assert captured_request == ContentRequest(
            task_id="task-001",
            owner="openai",
            repo="example-repository",
            path="src/main.py",
            revision=REVISION,
        )
        assert captured_limit == 64_000

        denied_status, denied = _request(
            port,
            "GET",
            _query(),
        )
        assert denied_status == 403
        assert isinstance(denied, dict)
        assert denied == {"code": "capability_required", "status": 403}
        assert len(upstream.calls) == 1

    audit = output.getvalue()
    assert capability not in audit
    assert GITHUB_AUTHORIZATION not in audit
    assert "src/main.py" not in audit


def test_content_rejects_client_authorization_before_upstream(
    receipt_signer: tuple[OpenSSLEd25519ReceiptSigner, Path, Path],
) -> None:
    codec = CapabilityCodec(HMAC_KEY)
    capability, _ = codec.issue(_scope())
    upstream = FakeUpstream()
    policy = ServerPolicy(
        "content",
        codec,
        None,
        upstream,
        64_000,
        ALLOWED_REPOSITORIES,
        receipt_signer=receipt_signer[0],
    )
    with _running_server(policy) as port:
        status, response = _request(
            port,
            "GET",
            _query(),
            headers={
                "Authorization": "Bearer " + "attacker_supplied_token_value",
                "X-DevFlow-Capability": capability,
            },
        )
    assert status == 400
    assert response == {"code": "client_authorization_forbidden", "status": 400}
    assert upstream.calls == []


def test_content_rechecks_repository_ceiling_even_for_valid_hmac(
    receipt_signer: tuple[OpenSSLEd25519ReceiptSigner, Path, Path],
) -> None:
    codec = CapabilityCodec(HMAC_KEY)
    outside_scope = _scope(owner="another-owner", repo="another-repo")
    capability, _ = codec.issue(outside_scope)
    upstream = FakeUpstream()
    policy = ServerPolicy(
        "content",
        codec,
        None,
        upstream,
        64_000,
        ALLOWED_REPOSITORIES,
        receipt_signer=receipt_signer[0],
    )
    with _running_server(policy) as port:
        status, response = _request(
            port,
            "GET",
            _query(owner="another-owner", repo="another-repo"),
            headers={"X-DevFlow-Capability": capability},
        )
    assert status == 403
    assert response == {"code": "repository_not_allowed", "status": 403}
    assert upstream.calls == []


def test_content_http_maps_github_error_without_returning_upstream_body(
    receipt_signer: tuple[OpenSSLEd25519ReceiptSigner, Path, Path],
) -> None:
    class DeniedUpstream:
        def get(
            self,
            request: ContentRequest,
            *,
            max_response_bytes: int,
        ) -> UpstreamResponse:
            del request, max_response_bytes
            return UpstreamResponse(404, b'{"message":"untrusted upstream detail"}')

    codec = CapabilityCodec(HMAC_KEY)
    capability, _ = codec.issue(_scope())
    policy = ServerPolicy(
        "content",
        codec,
        None,
        DeniedUpstream(),
        64_000,
        ALLOWED_REPOSITORIES,
        receipt_signer=receipt_signer[0],
    )
    with _running_server(policy) as port:
        status, response = _request(
            port,
            "GET",
            _query(),
            headers={"X-DevFlow-Capability": capability},
        )
    assert status == 404
    assert response == {"code": "github_not_found", "status": 404}


def test_github_content_parser_normalizes_only_valid_bounded_base64() -> None:
    line_wrapped = UpstreamResponse(
        200,
        json.dumps(
            {
                "type": "file",
                "path": "src/main.py",
                "sha": "c" * 40,
                "content": "Zmls\nZQ==",
                "encoding": "base64",
            }
        ).encode(),
    )
    parsed = parse_github_content(
        line_wrapped, expected_path="src/main.py", max_content_bytes=4
    )
    assert parsed.content_base64 == "ZmlsZQ=="

    with pytest.raises(UpstreamError, match="size limit"):
        parse_github_content(
            line_wrapped, expected_path="src/main.py", max_content_bytes=3
        )
    with pytest.raises(UpstreamError, match="incompatible"):
        parse_github_content(
            line_wrapped, expected_path="another.py", max_content_bytes=4
        )
    with pytest.raises(UpstreamError, match="incompatible"):
        parse_github_content(
            UpstreamResponse(
                200,
                json.dumps(
                    {
                        "type": "file",
                        "path": "src/main.py",
                        "sha": "c" * 40,
                        "content": "ZmlsZQ==",
                        "encoding": "utf-8",
                    }
                ).encode(),
            ),
            expected_path="src/main.py",
            max_content_bytes=4,
        )


class _FakeGitHubResponse:
    def __init__(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.status = status
        self._body = body
        self._headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        }
        self.closed = False

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self._headers.get(name, default)

    def read(self, amount: int | None = None) -> bytes:
        return self._body if amount is None else self._body[:amount]

    def close(self) -> None:
        self.closed = True


class _FakeHTTPSConnection:
    response = _FakeGitHubResponse(200, b'{"content":"ZmlsZQ=="}')
    instances: list[_FakeHTTPSConnection] = []

    def __init__(self, host: str, port: int, **kwargs: Any) -> None:
        self.host = host
        self.port = port
        self.kwargs = kwargs
        self.request_call: tuple[str, str, dict[str, str]] | None = None
        self.closed = False
        self.__class__.instances.append(self)

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        self.request_call = (method, target, headers)

    def getresponse(self) -> _FakeGitHubResponse:
        return self.__class__.response

    def close(self) -> None:
        self.closed = True


class _FakeTokenReviewConnection:
    response_document: dict[str, Any] = {}
    instances: list[_FakeTokenReviewConnection] = []

    def __init__(self, host: str, port: int, **kwargs: Any) -> None:
        self.host = host
        self.port = port
        self.kwargs = kwargs
        self.request_call: tuple[str, str, bytes, dict[str, str]] | None = None
        self.closed = False
        self.__class__.instances.append(self)

    def request(
        self,
        method: str,
        target: str,
        body: bytes,
        *,
        headers: dict[str, str],
    ) -> None:
        self.request_call = (method, target, body, headers)

    def getresponse(self) -> _FakeGitHubResponse:
        body = json.dumps(self.__class__.response_document).encode()
        return _FakeGitHubResponse(201, body)

    def close(self) -> None:
        self.closed = True


def test_kubernetes_tokenreview_requires_exact_leader_and_audience(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    reviewer_token = "reviewer.service.account.jwt"
    token_path = tmp_path / "token"
    token_path.write_text(reviewer_token, encoding="ascii")
    _FakeTokenReviewConnection.instances = []
    _FakeTokenReviewConnection.response_document = {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "status": {
            "authenticated": True,
            "audiences": [TOKEN_REVIEW_AUDIENCE],
            "user": {"username": EXPECTED_LEADER_USERNAME},
        },
    }
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeTokenReviewConnection)
    monkeypatch.setattr(ssl, "create_default_context", lambda **_kwargs: object())
    reviewer = KubernetesTokenReviewer(
        host="192.0.2.1",
        port=443,
        reviewer_token_path=str(token_path),
        ca_path=str(tmp_path / "ca.crt"),
    )

    assert reviewer.authenticate("Bearer " + "leader.service.account.jwt") == (
        EXPECTED_LEADER_USERNAME
    )
    assert len(_FakeTokenReviewConnection.instances) == 1
    connection = _FakeTokenReviewConnection.instances[0]
    assert (connection.host, connection.port) == ("192.0.2.1", 443)
    assert connection.request_call is not None
    method, target, body, headers = connection.request_call
    assert (method, target) == (
        "POST",
        "/apis/authentication.k8s.io/v1/tokenreviews",
    )
    assert json.loads(body) == {
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenReview",
        "spec": {
            "audiences": [TOKEN_REVIEW_AUDIENCE],
            "token": "leader.service.account.jwt",
        },
    }
    assert headers["Authorization"] == f"Bearer {reviewer_token}"

    _FakeTokenReviewConnection.response_document["status"]["audiences"] = [
        "wrong-audience"
    ]
    with pytest.raises(RequestRejected, match="issuer_identity_forbidden"):
        reviewer.authenticate("Bearer " + "leader.service.account.jwt")

    _FakeTokenReviewConnection.response_document["status"]["audiences"] = [
        TOKEN_REVIEW_AUDIENCE
    ]
    _FakeTokenReviewConnection.response_document["status"]["user"]["username"] = (
        "system:serviceaccount:agentteams-system:another-worker"
    )
    with pytest.raises(RequestRejected, match="issuer_identity_forbidden"):
        reviewer.authenticate("Bearer " + "leader.service.account.jwt")


def test_fixed_upstream_uses_only_api_github_and_drops_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeHTTPSConnection.instances = []
    _FakeHTTPSConnection.response = _FakeGitHubResponse(200, b'{"content":"ZmlsZQ=="}')
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPSConnection)
    request = ContentRequest.from_query(_query())

    result = FixedGitHubUpstream(GITHUB_TOKEN, timeout_seconds=3).get(
        request,
        max_response_bytes=1_024,
    )

    assert result.status == 200
    assert len(_FakeHTTPSConnection.instances) == 1
    connection = _FakeHTTPSConnection.instances[0]
    assert (connection.host, connection.port) == ("api.github.com", 443)
    assert connection.request_call is not None
    method, target, headers = connection.request_call
    assert method == "GET"
    assert target == (
        "/repos/openai/example-repository/contents/src/main.py?ref=" + REVISION
    )
    assert headers["Authorization"] == GITHUB_AUTHORIZATION
    assert "X-DevFlow-Capability" not in headers
    assert "Host" not in headers


@pytest.mark.parametrize(
    "response",
    [
        _FakeGitHubResponse(302, b"{}"),
        _FakeGitHubResponse(200, b"{}", "text/html"),
        _FakeGitHubResponse(200, b"x" * 1_025),
    ],
)
def test_fixed_upstream_fails_closed_on_redirect_type_and_size(
    monkeypatch: pytest.MonkeyPatch,
    response: _FakeGitHubResponse,
) -> None:
    _FakeHTTPSConnection.instances = []
    _FakeHTTPSConnection.response = response
    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeHTTPSConnection)
    with pytest.raises(UpstreamError):
        FixedGitHubUpstream(GITHUB_TOKEN).get(
            ContentRequest.from_query(_query()),
            max_response_bytes=1_024,
        )
    assert len(_FakeHTTPSConnection.instances) == 1


def test_mode_specific_environment_keeps_github_token_content_only(
    monkeypatch: pytest.MonkeyPatch,
    receipt_signer: tuple[OpenSSLEd25519ReceiptSigner, Path, Path],
) -> None:
    _signer, private_key, _public_key = receipt_signer
    monkeypatch.setenv("DEVFLOW_GITHUB_BROKER_HMAC_KEY", HMAC_KEY.decode())
    monkeypatch.setenv(
        "DEVFLOW_GITHUB_ALLOWED_REPOSITORIES", "openai/example-repository"
    )
    monkeypatch.delenv("DEVFLOW_GITHUB_BROKER_ISSUER_TOKEN", raising=False)
    monkeypatch.setenv("DEVFLOW_GITHUB_TOKEN", GITHUB_TOKEN)
    monkeypatch.setattr(
        broker_module,
        "PRODUCTION_RECEIPT_PRIVATE_KEY_PATH",
        private_key,
    )
    monkeypatch.setattr(broker_module, "PRODUCTION_OPENSSL_PATH", OPENSSL)

    assert ServerPolicy.from_environment("content").issuer_authenticator is None
    with pytest.raises(BrokerError, match="ISSUER_TOKEN"):
        ServerPolicy.from_environment("issuer")


def test_kubernetes_issuer_mode_needs_neither_static_token_nor_github_pat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEVFLOW_GITHUB_BROKER_HMAC_KEY", HMAC_KEY.decode())
    monkeypatch.setenv(
        "DEVFLOW_GITHUB_ALLOWED_REPOSITORIES", "openai/example-repository"
    )
    monkeypatch.setenv("DEVFLOW_GITHUB_TOKEN_REVIEW_AUDIENCE", TOKEN_REVIEW_AUDIENCE)
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "192.0.2.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    monkeypatch.delenv("DEVFLOW_GITHUB_BROKER_ISSUER_TOKEN", raising=False)
    monkeypatch.delenv("DEVFLOW_GITHUB_TOKEN", raising=False)
    monkeypatch.setattr(ssl, "create_default_context", lambda **_kwargs: object())

    policy = ServerPolicy.from_environment(
        "issuer", issuer_auth="kubernetes-tokenreview"
    )
    assert isinstance(policy.issuer_authenticator, KubernetesTokenReviewer)
    assert policy.upstream is None


def test_broker_help_runs_without_site_packages() -> None:
    process = subprocess.run(
        [sys.executable, "-S", "scripts/github_scope_broker.py", "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert process.returncode == 0
    assert "--mode {issuer,content}" in process.stdout

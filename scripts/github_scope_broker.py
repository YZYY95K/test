#!/usr/bin/env python3
"""Issue and enforce short-lived GitHub repository-scope capabilities.

The issuer and content data plane run as separate processes/containers and
listen on independent ports.  The issuer authenticates a trusted coordinator
with a dedicated bearer token.  The content service receives the GitHub
Authorization header injected by Higress, verifies a capability against every
request field, and only then sends a GET to the fixed ``api.github.com`` host.

Only the Python standard library is required. Capabilities are accepted only
through ``X-DevFlow-Capability`` and request lines are never logged.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal, Protocol, cast

CAPABILITY_SCHEMA = "devflow.github-content-capability/v1"
CONTENT_RESPONSE_SCHEMA = "devflow.github-content-response/v1"
GITHUB_HOST = "api.github.com"
GITHUB_PORT = 443
ISSUER_DEFAULT_PORT = 8081
CONTENT_DEFAULT_PORT = 8080
DEFAULT_TTL_SECONDS = 120
MAX_TTL_SECONDS = 300
DEFAULT_CLOCK_SKEW_SECONDS = 5
DEFAULT_MAX_RESPONSE_BYTES = 1_500_000
DEFAULT_MAX_CONTENT_BYTES = 1_000_000
DEFAULT_UPSTREAM_TIMEOUT_SECONDS = 15
MAX_ISSUER_BODY_BYTES = 16_384
MAX_REQUEST_TARGET_BYTES = 12_288
MAX_CAPABILITY_BYTES = 8_192
MAX_KUBERNETES_TOKEN_BYTES = 16_384
MAX_TOKEN_REVIEW_RESPONSE_BYTES = 65_536
TOKEN_REVIEW_AUDIENCE = "agentteams-controller"
EXPECTED_LEADER_USERNAME = (
    "system:serviceaccount:agentteams-system:agentteams-worker-devflow-lead"
)
DEFAULT_REVIEWER_TOKEN_PATH = "/var/run/secrets/agentteams-issuer/token"
DEFAULT_REVIEWER_CA_PATH = "/var/run/secrets/agentteams-issuer/ca.crt"

TASK_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
OWNER_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
REPO_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9_-])?$")
REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
JTI_PATTERN = re.compile(r"^[0-9a-f]{32}$")
GITHUB_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_]{20,500}$")
BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")

Mode = Literal["issuer", "content"]
IssuerAuthMode = Literal["static-bearer", "kubernetes-tokenreview"]


class BrokerError(RuntimeError):
    """A configuration or internal broker invariant failed."""


class RequestRejected(BrokerError):  # noqa: N818 - concise HTTP control-flow type
    """A client request failed without exposing sensitive details."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code


class UpstreamError(BrokerError):
    """The fixed GitHub upstream failed safely."""


class AuthenticationUnavailableError(BrokerError):
    """The issuer identity provider could not make an authoritative decision."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RequestRejected(400, "duplicate_json_field")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise RequestRejected(400, "nonstandard_json_scalar")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not value or BASE64URL_PATTERN.fullmatch(value) is None:
        raise RequestRejected(403, "capability_encoding_invalid")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RequestRejected(403, "capability_encoding_invalid") from exc
    if _b64url_encode(decoded) != value:
        raise RequestRejected(403, "capability_encoding_noncanonical")
    return decoded


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise RequestRejected(400, f"{label}_invalid")
    return value


def validate_task_id(value: Any) -> str:
    task_id = _require_string(value, "task_id")
    if TASK_ID_PATTERN.fullmatch(task_id) is None:
        raise RequestRejected(400, "task_id_invalid")
    return task_id


def validate_owner(value: Any) -> str:
    owner = _require_string(value, "owner")
    if OWNER_PATTERN.fullmatch(owner) is None or "--" in owner:
        raise RequestRejected(400, "owner_invalid")
    return owner


def validate_repo(value: Any) -> str:
    repo = _require_string(value, "repo")
    if REPO_PATTERN.fullmatch(repo) is None or repo in {".", ".."}:
        raise RequestRejected(400, "repo_invalid")
    return repo


def validate_revision(value: Any) -> str:
    revision = _require_string(value, "revision")
    if REVISION_PATTERN.fullmatch(revision) is None:
        raise RequestRejected(400, "revision_invalid")
    return revision


def validate_path(value: Any) -> str:
    path = _require_string(value, "path")
    if (
        PATH_PATTERN.fullmatch(path) is None
        or path.startswith("/")
        or path.endswith("/")
        or "//" in path
        or "\\" in path
        or any(segment in {"", ".", ".."} for segment in path.split("/"))
    ):
        raise RequestRejected(400, "path_invalid")
    return path


def validate_paths(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise RequestRejected(400, "paths_invalid")
    paths = tuple(validate_path(item) for item in value)
    if list(paths) != sorted(set(paths)):
        raise RequestRejected(400, "paths_not_canonical")
    return paths


def parse_repository_allowlist(value: str) -> frozenset[tuple[str, str]]:
    if not isinstance(value, str) or not 1 <= len(value) <= 3_200:
        raise BrokerError("GitHub repository allowlist is missing or malformed")
    entries = value.split(",")
    if not 1 <= len(entries) <= 32 or entries != sorted(set(entries)):
        raise BrokerError("GitHub repository allowlist is not canonical")
    repositories: set[tuple[str, str]] = set()
    for entry in entries:
        if entry.count("/") != 1 or entry != entry.strip():
            raise BrokerError("GitHub repository allowlist is malformed")
        owner_value, repo_value = entry.split("/", 1)
        try:
            owner = validate_owner(owner_value)
            repo = validate_repo(repo_value)
        except RequestRejected as exc:
            raise BrokerError("GitHub repository allowlist is malformed") from exc
        if entry != f"{owner}/{repo}":
            raise BrokerError("GitHub repository allowlist is not canonical")
        repositories.add((owner, repo))
    return frozenset(repositories)


@dataclass(frozen=True)
class Scope:
    task_id: str
    owner: str
    repo: str
    revision: str
    paths: tuple[str, ...]

    @classmethod
    def from_issuer_document(cls, value: Any) -> Scope:
        if not isinstance(value, dict) or set(value) != {
            "task_id",
            "owner",
            "repo",
            "revision",
            "paths",
        }:
            raise RequestRejected(400, "issuer_schema_invalid")
        return cls(
            task_id=validate_task_id(value["task_id"]),
            owner=validate_owner(value["owner"]),
            repo=validate_repo(value["repo"]),
            revision=validate_revision(value["revision"]),
            paths=validate_paths(value["paths"]),
        )


@dataclass(frozen=True)
class CapabilityClaims:
    schema: str
    task_id: str
    owner: str
    repo: str
    revision: str
    paths: tuple[str, ...]
    iat: int
    exp: int
    jti: str

    @classmethod
    def from_payload(cls, value: Any) -> CapabilityClaims:
        expected = {
            "schema",
            "task_id",
            "owner",
            "repo",
            "revision",
            "paths",
            "iat",
            "exp",
            "jti",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise RequestRejected(403, "capability_schema_invalid")
        schema = _require_string(value["schema"], "capability_schema")
        if schema != CAPABILITY_SCHEMA:
            raise RequestRejected(403, "capability_schema_invalid")
        iat = value["iat"]
        exp = value["exp"]
        if (
            not isinstance(iat, int)
            or isinstance(iat, bool)
            or not isinstance(exp, int)
            or isinstance(exp, bool)
        ):
            raise RequestRejected(403, "capability_time_invalid")
        jti = _require_string(value["jti"], "capability_jti")
        if JTI_PATTERN.fullmatch(jti) is None:
            raise RequestRejected(403, "capability_jti_invalid")
        try:
            paths = validate_paths(value["paths"])
            return cls(
                schema=schema,
                task_id=validate_task_id(value["task_id"]),
                owner=validate_owner(value["owner"]),
                repo=validate_repo(value["repo"]),
                revision=validate_revision(value["revision"]),
                paths=paths,
                iat=iat,
                exp=exp,
                jti=jti,
            )
        except RequestRejected as exc:
            raise RequestRejected(403, "capability_claim_invalid") from exc

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "task_id": self.task_id,
            "owner": self.owner,
            "repo": self.repo,
            "revision": self.revision,
            "paths": list(self.paths),
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
        }


class CapabilityCodec:
    def __init__(
        self,
        key: bytes,
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_ttl_seconds: int = MAX_TTL_SECONDS,
        clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        if len(key) < 32:
            raise BrokerError("HMAC key must contain at least 32 bytes")
        if not 1 <= ttl_seconds <= max_ttl_seconds <= MAX_TTL_SECONDS:
            raise BrokerError("capability TTL policy is invalid")
        if not 0 <= clock_skew_seconds <= 30:
            raise BrokerError("capability clock skew policy is invalid")
        self._key = key
        self._ttl_seconds = ttl_seconds
        self._max_ttl_seconds = max_ttl_seconds
        self._clock_skew_seconds = clock_skew_seconds

    def issue(
        self,
        scope: Scope,
        *,
        now: int | None = None,
        jti: str | None = None,
    ) -> tuple[str, CapabilityClaims]:
        issued_at = int(time.time()) if now is None else now
        capability_jti = secrets.token_hex(16) if jti is None else jti
        if JTI_PATTERN.fullmatch(capability_jti) is None:
            raise BrokerError("generated capability jti is invalid")
        claims = CapabilityClaims(
            schema=CAPABILITY_SCHEMA,
            task_id=scope.task_id,
            owner=scope.owner,
            repo=scope.repo,
            revision=scope.revision,
            paths=scope.paths,
            iat=issued_at,
            exp=issued_at + self._ttl_seconds,
            jti=capability_jti,
        )
        payload_segment = _b64url_encode(_canonical_json(claims.payload()))
        signature = hmac.new(self._key, payload_segment.encode("ascii"), hashlib.sha256).digest()
        return f"{payload_segment}.{_b64url_encode(signature)}", claims

    def verify(self, token: str, *, now: int | None = None) -> CapabilityClaims:
        if not isinstance(token, str) or not 1 <= len(token) <= MAX_CAPABILITY_BYTES:
            raise RequestRejected(403, "capability_invalid")
        if token.count(".") != 1:
            raise RequestRejected(403, "capability_format_invalid")
        payload_segment, signature_segment = token.split(".", 1)
        payload_bytes = _b64url_decode(payload_segment)
        signature = _b64url_decode(signature_segment)
        if len(signature) != hashlib.sha256().digest_size:
            raise RequestRejected(403, "capability_signature_invalid")
        expected = hmac.new(
            self._key,
            payload_segment.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise RequestRejected(403, "capability_signature_invalid")
        try:
            payload = json.loads(
                payload_bytes.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RequestRejected(403, "capability_payload_invalid") from exc
        claims = CapabilityClaims.from_payload(payload)
        current = int(time.time()) if now is None else now
        lifetime = claims.exp - claims.iat
        if not 1 <= lifetime <= self._max_ttl_seconds:
            raise RequestRejected(403, "capability_lifetime_invalid")
        if claims.iat > current + self._clock_skew_seconds:
            raise RequestRejected(403, "capability_not_yet_valid")
        if claims.exp <= current:
            raise RequestRejected(403, "capability_expired")
        if _canonical_json(claims.payload()) != payload_bytes:
            raise RequestRejected(403, "capability_payload_noncanonical")
        return claims

    def sign_receipt(self, value: dict[str, Any]) -> str:
        """Sign a canonical receipt with domain separation from capabilities."""

        message = b"devflow-github-content-receipt/v1\0" + _canonical_json(value)
        return hmac.new(self._key, message, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class ContentRequest:
    task_id: str
    owner: str
    repo: str
    path: str
    revision: str

    @classmethod
    def from_query(cls, request_target: str) -> ContentRequest:
        if len(request_target.encode("utf-8")) > MAX_REQUEST_TARGET_BYTES:
            raise RequestRejected(414, "request_target_too_large")
        parsed = urllib.parse.urlsplit(request_target)
        if parsed.scheme or parsed.netloc or parsed.path != "/v1/content" or parsed.fragment:
            raise RequestRejected(404, "route_not_found")
        try:
            query = urllib.parse.parse_qs(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=5,
            )
        except ValueError as exc:
            raise RequestRejected(400, "query_invalid") from exc
        expected = {"task_id", "owner", "repo", "path", "revision"}
        if set(query) != expected or any(len(values) != 1 for values in query.values()):
            raise RequestRejected(400, "query_schema_invalid")
        return cls(
            task_id=validate_task_id(query["task_id"][0]),
            owner=validate_owner(query["owner"][0]),
            repo=validate_repo(query["repo"][0]),
            path=validate_path(query["path"][0]),
            revision=validate_revision(query["revision"][0]),
        )

    def authorize(
        self,
        codec: CapabilityCodec,
        capability: str,
        *,
        now: int | None = None,
    ) -> CapabilityClaims:
        claims = codec.verify(capability, now=now)
        if (
            self.task_id != claims.task_id
            or self.owner != claims.owner
            or self.repo != claims.repo
            or self.revision != claims.revision
            or self.path not in claims.paths
        ):
            raise RequestRejected(403, "capability_scope_mismatch")
        return claims


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    body: bytes


@dataclass(frozen=True)
class GitHubContent:
    object_sha: str
    content_base64: str


def parse_github_content(
    response: UpstreamResponse,
    *,
    expected_path: str,
    max_content_bytes: int,
) -> GitHubContent:
    if response.status != 200:
        codes = {
            403: "github_forbidden",
            404: "github_not_found",
            422: "github_unprocessable",
        }
        code = codes.get(response.status)
        if code is None:
            raise UpstreamError("GitHub returned an unsupported status")
        raise RequestRejected(response.status, code)
    try:
        document = json.loads(
            response.body.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except RequestRejected as exc:
        raise UpstreamError("GitHub returned duplicate or invalid JSON fields") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise UpstreamError("GitHub returned malformed JSON") from exc
    if not isinstance(document, dict):
        raise UpstreamError("GitHub content response is not an object")
    object_sha = document.get("sha")
    content = document.get("content")
    encoding = document.get("encoding")
    if (
        document.get("type") != "file"
        or document.get("path") != expected_path
        or not isinstance(object_sha, str)
        or REVISION_PATTERN.fullmatch(object_sha) is None
        or not isinstance(content, str)
        or encoding != "base64"
        or re.fullmatch(r"[A-Za-z0-9+/=\r\n]*", content) is None
    ):
        raise UpstreamError("GitHub content response is incompatible")
    compact_content = content.replace("\r", "").replace("\n", "")
    try:
        decoded = base64.b64decode(compact_content, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise UpstreamError("GitHub content is not canonical base64") from exc
    canonical_content = base64.b64encode(decoded).decode("ascii")
    if canonical_content != compact_content:
        raise UpstreamError("GitHub content is not canonical base64")
    if len(decoded) > max_content_bytes:
        raise UpstreamError("GitHub content exceeds the size limit")
    return GitHubContent(object_sha=object_sha, content_base64=canonical_content)


def content_receipt(
    *,
    codec: CapabilityCodec,
    capability: str,
    claims: CapabilityClaims,
    request: ContentRequest,
    content: GitHubContent,
    authorized_at: int,
) -> dict[str, Any]:
    scope_document = {
        "task_id": claims.task_id,
        "owner": claims.owner,
        "repo": claims.repo,
        "revision": claims.revision,
        "paths": list(claims.paths),
    }
    evidence: dict[str, Any] = {
        "schema_version": CONTENT_RESPONSE_SCHEMA,
        "authorization": {
            "decision": "allow",
            "task_id": request.task_id,
            "scope_digest": hashlib.sha256(_canonical_json(scope_document)).hexdigest(),
            "capability_digest": hashlib.sha256(capability.encode("ascii")).hexdigest(),
            "authorized_at": authorized_at,
        },
        "github": {
            "repository": f"{request.owner}/{request.repo}",
            "revision": request.revision,
            "path": request.path,
            "object_sha": content.object_sha,
            "content_base64": content.content_base64,
            "encoding": "base64",
        },
    }
    # The digest covers the evidence payload. The HMAC then covers that payload
    # plus response_digest, avoiding a self-referential digest definition.
    evidence["response_digest"] = hashlib.sha256(_canonical_json(evidence)).hexdigest()
    evidence["receipt_signature"] = codec.sign_receipt(evidence)
    return evidence


class GitHubUpstream(Protocol):
    def get(
        self,
        request: ContentRequest,
        *,
        max_response_bytes: int,
    ) -> UpstreamResponse: ...


class FixedGitHubUpstream:
    """HTTPS-only client that cannot be redirected to an input-derived host."""

    def __init__(
        self,
        github_token: str,
        *,
        timeout_seconds: int = DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
    ) -> None:
        if GITHUB_TOKEN_PATTERN.fullmatch(github_token) is None:
            raise BrokerError("GitHub credential is malformed")
        if not 1 <= timeout_seconds <= 60:
            raise BrokerError("upstream timeout policy is invalid")
        self._authorization = f"Bearer {github_token}"
        self._timeout_seconds = timeout_seconds
        self._context = ssl.create_default_context()

    def get(
        self,
        request: ContentRequest,
        *,
        max_response_bytes: int,
    ) -> UpstreamResponse:
        owner = urllib.parse.quote(request.owner, safe="")
        repo = urllib.parse.quote(request.repo, safe="")
        path = urllib.parse.quote(request.path, safe="/")
        revision = urllib.parse.quote(request.revision, safe="")
        target = f"/repos/{owner}/{repo}/contents/{path}?ref={revision}"
        connection = http.client.HTTPSConnection(
            GITHUB_HOST,
            GITHUB_PORT,
            timeout=self._timeout_seconds,
            context=self._context,
        )
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Authorization": self._authorization,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "devflow-github-scope-broker/1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status in {301, 302, 303, 307, 308}:
                response.close()
                raise UpstreamError("GitHub redirect refused")
            if response.status not in {200, 403, 404, 422}:
                response.close()
                raise UpstreamError("GitHub returned an unsupported status")
            content_type = response.getheader("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                response.close()
                raise UpstreamError("GitHub returned a non-JSON response")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    announced = int(content_length)
                except ValueError as exc:
                    response.close()
                    raise UpstreamError("GitHub response length is malformed") from exc
                if announced < 0 or announced > max_response_bytes:
                    response.close()
                    raise UpstreamError("GitHub response exceeds the size limit")
            body = response.read(max_response_bytes + 1)
            if len(body) > max_response_bytes:
                raise UpstreamError("GitHub response exceeds the size limit")
            return UpstreamResponse(response.status, body)
        except (OSError, http.client.HTTPException) as exc:
            raise UpstreamError("fixed GitHub request failed") from exc
        finally:
            connection.close()


def _read_secret_environment(name: str, *, minimum_length: int) -> str:
    value = os.environ.get(name)
    if (
        value is None
        or value != value.strip()
        or not minimum_length <= len(value) <= 512
        or CONTROL_CHARACTER.search(value)
    ):
        raise BrokerError(f"{name} is missing or malformed")
    return value


def _read_integer_environment(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    if re.fullmatch(r"[0-9]+", raw) is None:
        raise BrokerError(f"{name} is malformed")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise BrokerError(f"{name} is outside policy")
    return value


class IssuerAuthenticator(Protocol):
    def authenticate(self, authorization: str) -> str: ...


@dataclass(frozen=True)
class StaticBearerAuthenticator:
    token: str

    def authenticate(self, authorization: str) -> str:
        if not hmac.compare_digest(authorization, f"Bearer {self.token}"):
            raise RequestRejected(401, "issuer_authorization_invalid")
        return "local-static-bearer"


class KubernetesTokenReviewer:
    """Authenticate the caller through the fixed Kubernetes TokenReview API."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        reviewer_token_path: str = DEFAULT_REVIEWER_TOKEN_PATH,
        ca_path: str = DEFAULT_REVIEWER_CA_PATH,
        audience: str = TOKEN_REVIEW_AUDIENCE,
        timeout_seconds: int = 5,
    ) -> None:
        if (
            not host
            or len(host) > 253
            or re.fullmatch(r"[A-Za-z0-9.:-]+", host) is None
            or not 1 <= port <= 65_535
            or not 1 <= timeout_seconds <= 30
            or re.fullmatch(r"[A-Za-z0-9._:/-]{1,128}", audience) is None
        ):
            raise BrokerError("Kubernetes TokenReview endpoint is malformed")
        self._host = host
        self._port = port
        self._reviewer_token_path = Path(reviewer_token_path)
        self._audience = audience
        self._timeout_seconds = timeout_seconds
        try:
            self._context = ssl.create_default_context(cafile=ca_path)
        except (OSError, ssl.SSLError) as exc:
            raise BrokerError("Kubernetes TokenReview CA is unavailable") from exc

    @classmethod
    def from_environment(cls) -> KubernetesTokenReviewer:
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        raw_port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if re.fullmatch(r"[0-9]+", raw_port) is None:
            raise BrokerError("Kubernetes TokenReview port is malformed")
        audience = os.environ.get("DEVFLOW_GITHUB_TOKEN_REVIEW_AUDIENCE", "")
        if not audience:
            raise BrokerError("Kubernetes TokenReview audience is missing")
        return cls(host=host, port=int(raw_port), audience=audience)

    def _reviewer_token(self) -> str:
        try:
            with self._reviewer_token_path.open("rb") as stream:
                raw = stream.read(MAX_KUBERNETES_TOKEN_BYTES + 1)
        except OSError as exc:
            raise AuthenticationUnavailableError("reviewer token is unavailable") from exc
        if len(raw) > MAX_KUBERNETES_TOKEN_BYTES:
            raise AuthenticationUnavailableError("reviewer token is oversized")
        try:
            token = raw.decode("ascii").rstrip("\r\n")
        except UnicodeError as exc:
            raise AuthenticationUnavailableError("reviewer token is malformed") from exc
        if (
            not token
            or len(token) > MAX_KUBERNETES_TOKEN_BYTES
            or re.fullmatch(r"[A-Za-z0-9._~-]+", token) is None
        ):
            raise AuthenticationUnavailableError("reviewer token is malformed")
        return token

    def authenticate(self, authorization: str) -> str:
        if not authorization.startswith("Bearer "):
            raise RequestRejected(401, "issuer_authorization_invalid")
        caller_token = authorization[len("Bearer ") :]
        if (
            not caller_token
            or len(caller_token) > MAX_KUBERNETES_TOKEN_BYTES
            or re.fullmatch(r"[A-Za-z0-9._~-]+", caller_token) is None
        ):
            raise RequestRejected(401, "issuer_authorization_invalid")
        body = _canonical_json(
            {
                "apiVersion": "authentication.k8s.io/v1",
                "kind": "TokenReview",
                "spec": {
                    "audiences": [self._audience],
                    "token": caller_token,
                },
            }
        )
        connection = http.client.HTTPSConnection(
            self._host,
            self._port,
            timeout=self._timeout_seconds,
            context=self._context,
        )
        try:
            connection.request(
                "POST",
                "/apis/authentication.k8s.io/v1/tokenreviews",
                body=body,
                headers={
                    "Authorization": f"Bearer {self._reviewer_token()}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "devflow-github-scope-broker/1",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            if response.status != 201:
                response.close()
                raise AuthenticationUnavailableError("TokenReview request was rejected")
            content_type = response.getheader("Content-Type", "")
            if not content_type.lower().startswith("application/json"):
                response.close()
                raise AuthenticationUnavailableError("TokenReview response is not JSON")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    announced = int(content_length)
                except ValueError as exc:
                    response.close()
                    raise AuthenticationUnavailableError(
                        "TokenReview response length is malformed"
                    ) from exc
                if announced < 0 or announced > MAX_TOKEN_REVIEW_RESPONSE_BYTES:
                    response.close()
                    raise AuthenticationUnavailableError("TokenReview response is oversized")
            raw_response = response.read(MAX_TOKEN_REVIEW_RESPONSE_BYTES + 1)
            if len(raw_response) > MAX_TOKEN_REVIEW_RESPONSE_BYTES:
                raise AuthenticationUnavailableError("TokenReview response is oversized")
        except AuthenticationUnavailableError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise AuthenticationUnavailableError("TokenReview request failed") from exc
        finally:
            connection.close()
        try:
            document = json.loads(
                raw_response.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
                parse_constant=_reject_json_constant,
            )
        except (RequestRejected, UnicodeError, json.JSONDecodeError) as exc:
            raise AuthenticationUnavailableError("TokenReview response is malformed") from exc
        if not isinstance(document, dict):
            raise AuthenticationUnavailableError("TokenReview response is malformed")
        status = document.get("status")
        if not isinstance(status, dict) or status.get("authenticated") is not True:
            raise RequestRejected(401, "issuer_identity_unauthenticated")
        user = status.get("user")
        audiences = status.get("audiences")
        if (
            not isinstance(user, dict)
            or user.get("username") != EXPECTED_LEADER_USERNAME
            or audiences != [self._audience]
        ):
            raise RequestRejected(403, "issuer_identity_forbidden")
        return EXPECTED_LEADER_USERNAME


@dataclass(frozen=True)
class ServerPolicy:
    mode: Mode
    codec: CapabilityCodec
    issuer_authenticator: IssuerAuthenticator | None
    upstream: GitHubUpstream | None
    max_response_bytes: int
    allowed_repositories: frozenset[tuple[str, str]]
    max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES

    def require_repository(self, owner: str, repo: str) -> None:
        if (owner, repo) not in self.allowed_repositories:
            raise RequestRejected(403, "repository_not_allowed")

    @classmethod
    def from_environment(
        cls,
        mode: Mode,
        *,
        issuer_auth: IssuerAuthMode = "static-bearer",
    ) -> ServerPolicy:
        key = _read_secret_environment(
            "DEVFLOW_GITHUB_BROKER_HMAC_KEY",
            minimum_length=32,
        ).encode("utf-8")
        ttl = _read_integer_environment(
            "DEVFLOW_GITHUB_CAPABILITY_TTL_SECONDS",
            DEFAULT_TTL_SECONDS,
            minimum=1,
            maximum=MAX_TTL_SECONDS,
        )
        skew = _read_integer_environment(
            "DEVFLOW_GITHUB_CAPABILITY_CLOCK_SKEW_SECONDS",
            DEFAULT_CLOCK_SKEW_SECONDS,
            minimum=0,
            maximum=30,
        )
        codec = CapabilityCodec(key, ttl_seconds=ttl, clock_skew_seconds=skew)
        allowed_repositories = parse_repository_allowlist(
            os.environ.get("DEVFLOW_GITHUB_ALLOWED_REPOSITORIES", "")
        )
        if mode == "issuer":
            authenticator: IssuerAuthenticator
            if issuer_auth == "static-bearer":
                authenticator = StaticBearerAuthenticator(
                    _read_secret_environment(
                        "DEVFLOW_GITHUB_BROKER_ISSUER_TOKEN",
                        minimum_length=32,
                    )
                )
            elif issuer_auth == "kubernetes-tokenreview":
                authenticator = KubernetesTokenReviewer.from_environment()
            else:
                raise BrokerError("issuer authentication mode is invalid")
            return cls(
                mode=mode,
                codec=codec,
                issuer_authenticator=authenticator,
                upstream=None,
                max_response_bytes=DEFAULT_MAX_RESPONSE_BYTES,
                allowed_repositories=allowed_repositories,
                max_content_bytes=DEFAULT_MAX_CONTENT_BYTES,
            )
        max_bytes = _read_integer_environment(
            "DEVFLOW_GITHUB_MAX_RESPONSE_BYTES",
            DEFAULT_MAX_RESPONSE_BYTES,
            minimum=1_024,
            maximum=4_000_000,
        )
        timeout = _read_integer_environment(
            "DEVFLOW_GITHUB_UPSTREAM_TIMEOUT_SECONDS",
            DEFAULT_UPSTREAM_TIMEOUT_SECONDS,
            minimum=1,
            maximum=60,
        )
        github_token = _read_secret_environment(
            "DEVFLOW_GITHUB_TOKEN",
            minimum_length=20,
        )
        max_content_bytes = _read_integer_environment(
            "DEVFLOW_GITHUB_MAX_CONTENT_BYTES",
            DEFAULT_MAX_CONTENT_BYTES,
            minimum=1,
            maximum=2_000_000,
        )
        return cls(
            mode=mode,
            codec=codec,
            issuer_authenticator=None,
            upstream=FixedGitHubUpstream(github_token, timeout_seconds=timeout),
            max_response_bytes=max_bytes,
            allowed_repositories=allowed_repositories,
            max_content_bytes=max_content_bytes,
        )


def _safe_hash(*values: str) -> str:
    digest = hashlib.sha256()
    for value in values:
        digest.update(value.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def audit_event(event: str, **fields: str | int | bool | None) -> None:
    allowed_fields = {
        "request_id",
        "mode",
        "outcome",
        "code",
        "status",
        "task_hash",
        "scope_hash",
        "jti",
        "path_count",
        "ttl_seconds",
        "upstream_status",
        "response_bytes",
    }
    if set(fields) - allowed_fields:
        raise BrokerError("unsafe audit field")
    record: dict[str, str | int | bool | None] = {
        "event": event,
        "timestamp": int(time.time()),
    }
    record.update(fields)
    print(_canonical_json(record).decode("utf-8"), flush=True)


class BrokerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], policy: ServerPolicy) -> None:
        self.policy = policy
        super().__init__(address, BrokerRequestHandler)


class BrokerRequestHandler(BaseHTTPRequestHandler):
    server_version = "DevFlowGitHubScopeBroker/1"
    sys_version = ""

    @property
    def broker(self) -> BrokerHTTPServer:
        return cast(BrokerHTTPServer, self.server)

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, _format: str, *_args: object) -> None:
        # Use structured, allow-listed audit output instead of request-line logs.
        return

    def _request_id(self) -> str:
        return secrets.token_hex(8)

    def _send_bytes(self, status: int, body: bytes, *, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, value: Any) -> None:
        self._send_bytes(status, _canonical_json(value), content_type="application/json")

    def _reject(self, request_id: str, error: RequestRejected) -> None:
        audit_event(
            "request_rejected",
            request_id=request_id,
            mode=self.broker.policy.mode,
            outcome="denied",
            code=error.code,
            status=error.status,
        )
        self._send_json(error.status, {"code": error.code, "status": error.status})

    def _single_authorization(self) -> str:
        values = self.headers.get_all("Authorization", [])
        if len(values) != 1:
            raise RequestRejected(401, "authorization_required")
        value = values[0]
        if CONTROL_CHARACTER.search(value) or len(value) > MAX_KUBERNETES_TOKEN_BYTES + 7:
            raise RequestRejected(401, "authorization_invalid")
        return value

    def _single_capability(self) -> str:
        values = self.headers.get_all("X-DevFlow-Capability", [])
        if len(values) != 1:
            raise RequestRejected(403, "capability_required")
        capability = values[0]
        if (
            not 1 <= len(capability) <= MAX_CAPABILITY_BYTES
            or CONTROL_CHARACTER.search(capability)
        ):
            raise RequestRejected(403, "capability_invalid")
        return capability

    def _reject_client_authorization(self) -> None:
        if self.headers.get_all("Authorization", []):
            raise RequestRejected(400, "client_authorization_forbidden")

    def _health(self) -> None:
        self._send_json(200, {"mode": self.broker.policy.mode, "status": "ok"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        request_id = self._request_id()
        try:
            if self.broker.policy.mode != "issuer" or self.path != "/v1/capabilities":
                raise RequestRejected(404, "route_not_found")
            content_types = self.headers.get_all("Content-Type", [])
            lengths = self.headers.get_all("Content-Length", [])
            if content_types != ["application/json"] or len(lengths) != 1:
                raise RequestRejected(400, "issuer_headers_invalid")
            try:
                content_length = int(lengths[0])
            except ValueError as exc:
                raise RequestRejected(400, "issuer_length_invalid") from exc
            if not 1 <= content_length <= MAX_ISSUER_BODY_BYTES:
                raise RequestRejected(413, "issuer_body_too_large")
            body = self.rfile.read(content_length)
            if len(body) != content_length:
                raise RequestRejected(400, "issuer_body_incomplete")
            authorization = self._single_authorization()
            authenticator = self.broker.policy.issuer_authenticator
            if authenticator is None:
                raise BrokerError("issuer authenticator is unavailable")
            authenticator.authenticate(authorization)
            try:
                document = json.loads(
                    body.decode("utf-8"),
                    object_pairs_hook=_strict_json_object,
                    parse_constant=_reject_json_constant,
                )
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise RequestRejected(400, "issuer_json_invalid") from exc
            scope = Scope.from_issuer_document(document)
            self.broker.policy.require_repository(scope.owner, scope.repo)
            capability, claims = self.broker.policy.codec.issue(scope)
            audit_event(
                "capability_issued",
                request_id=request_id,
                mode="issuer",
                outcome="allowed",
                status=201,
                task_hash=_safe_hash(scope.task_id),
                scope_hash=_safe_hash(
                    scope.owner,
                    scope.repo,
                    scope.revision,
                    *scope.paths,
                ),
                jti=claims.jti,
                path_count=len(scope.paths),
                ttl_seconds=claims.exp - claims.iat,
            )
            self._send_json(
                201,
                {
                    "capability": capability,
                    "expires_at": claims.exp,
                    "jti": claims.jti,
                    "schema": CAPABILITY_SCHEMA,
                },
            )
        except RequestRejected as error:
            self._reject(request_id, error)
        except AuthenticationUnavailableError:
            audit_event(
                "issuer_authentication_failed",
                request_id=request_id,
                mode="issuer",
                outcome="error",
                code="issuer_authentication_unavailable",
                status=503,
            )
            self._send_json(
                503,
                {"code": "issuer_authentication_unavailable", "status": 503},
            )
        except (BrokerError, OSError):
            audit_event(
                "request_failed",
                request_id=request_id,
                mode=self.broker.policy.mode,
                outcome="error",
                code="internal_error",
                status=500,
            )
            self._send_json(500, {"code": "internal_error", "status": 500})

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        request_id = self._request_id()
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path in {"/healthz", "/readyz"} and not parsed.query:
                self._health()
                return
            if self.broker.policy.mode != "content":
                raise RequestRejected(404, "route_not_found")
            request = ContentRequest.from_query(self.path)
            self.broker.policy.require_repository(request.owner, request.repo)
            self._reject_client_authorization()
            capability = self._single_capability()
            claims = request.authorize(self.broker.policy.codec, capability)
            authorized_at = int(time.time())
            upstream = self.broker.policy.upstream
            if upstream is None:
                raise BrokerError("content upstream is unavailable")
            response = upstream.get(
                request,
                max_response_bytes=self.broker.policy.max_response_bytes,
            )
            content = parse_github_content(
                response,
                expected_path=request.path,
                max_content_bytes=self.broker.policy.max_content_bytes,
            )
            receipt = content_receipt(
                codec=self.broker.policy.codec,
                capability=capability,
                claims=claims,
                request=request,
                content=content,
                authorized_at=authorized_at,
            )
            receipt_bytes = _canonical_json(receipt)
            audit_event(
                "content_authorized",
                request_id=request_id,
                mode="content",
                outcome="allowed",
                status=200,
                task_hash=_safe_hash(request.task_id),
                scope_hash=_safe_hash(
                    request.owner,
                    request.repo,
                    request.revision,
                    request.path,
                ),
                jti=claims.jti,
                upstream_status=200,
                response_bytes=len(receipt_bytes),
            )
            self._send_bytes(200, receipt_bytes, content_type="application/json")
        except RequestRejected as error:
            self._reject(request_id, error)
        except UpstreamError:
            audit_event(
                "upstream_failed",
                request_id=request_id,
                mode="content",
                outcome="error",
                code="upstream_failed",
                status=502,
            )
            self._send_json(502, {"code": "upstream_failed", "status": 502})
        except (BrokerError, OSError):
            audit_event(
                "request_failed",
                request_id=request_id,
                mode=self.broker.policy.mode,
                outcome="error",
                code="internal_error",
                status=500,
            )
            self._send_json(500, {"code": "internal_error", "status": 500})

    def do_PUT(self) -> None:  # noqa: N802 - stdlib handler API
        self._reject(self._request_id(), RequestRejected(405, "method_not_allowed"))

    def do_DELETE(self) -> None:  # noqa: N802 - stdlib handler API
        self._reject(self._request_id(), RequestRejected(405, "method_not_allowed"))

    def do_PATCH(self) -> None:  # noqa: N802 - stdlib handler API
        self._reject(self._request_id(), RequestRejected(405, "method_not_allowed"))

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        self._reject(self._request_id(), RequestRejected(405, "method_not_allowed"))

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        self._reject(self._request_id(), RequestRejected(405, "method_not_allowed"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DevFlow GitHub scope capability broker")
    parser.add_argument("--mode", choices=("issuer", "content"), required=True)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int)
    parser.add_argument(
        "--issuer-auth",
        choices=("static-bearer", "kubernetes-tokenreview"),
        default="static-bearer",
        help="issuer caller authentication (static mode is local-test only)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    mode = cast(Mode, args.mode)
    issuer_auth = cast(IssuerAuthMode, args.issuer_auth)
    port = args.port
    if port is None:
        port = ISSUER_DEFAULT_PORT if mode == "issuer" else CONTENT_DEFAULT_PORT
    if not 1 <= port <= 65535:
        print("error: invalid listen port", file=sys.stderr)
        return 2
    try:
        policy = ServerPolicy.from_environment(mode, issuer_auth=issuer_auth)
        server = BrokerHTTPServer((args.host, port), policy)
    except (BrokerError, OSError):
        print("error: GitHub scope broker configuration failed", file=sys.stderr)
        return 1
    audit_event("server_started", mode=mode, outcome="ready", status=200)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

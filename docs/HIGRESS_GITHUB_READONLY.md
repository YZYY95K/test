# Locator-only GitHub MCP on Higress

DevFlow uses a dedicated MCP server named `devflow-github-readonly` for live
AgentTeams repository evidence. It is separate from AgentTeams' general
`mcp-github` definition so a broad upstream configuration cannot silently
expand Locator's capability.

The effective boundary is deliberately narrow:

- one Higress Consumer: `worker-devflow-locator`;
- one tool: `get_file_contents`;
- one HTTP method: `GET`;
- one Higress upstream: the in-cluster
  `devflow-github-content-broker.agentteams-system.svc.cluster.local:8080`;
- one in-cluster endpoint:
  `http://higress-gateway.agentteams-system.svc.cluster.local:80/mcp-servers/devflow-github-readonly/mcp`;
- no MCP capability for Reviewer in the live AgentTeams manifest.

These are two related but distinct identities. The Agent runtime name and Team
worker name remain `devflow-locator`. AgentTeams controller provisions its
gateway identity as `worker-devflow-locator`, and the Worker's injected Bearer
key authenticates as that Higress Consumer. Authorizing the runtime name itself
would not authorize the key and would produce HTTP 403.

The Skill-side authorizer remains mandatory. Every tool call carries exactly
`task_id`, `capability`, `owner`, `repo`, `path`, and immutable 40-character
`revision`. Higress places the capability only in `X-DevFlow-Capability`; it is
never put in a URL. The content broker verifies every field, enforces the
deployment repository ceiling, and only then calls the fixed
`api.github.com:443` destination.

## Audited API basis

The implementation is pinned to these upstream sources:

- Higress Console `v2.2.1`, commit
  `573277a6aabb2b2158d962f5fd8d1d7046cb8e4a`:
  [`McpServerController`](https://github.com/higress-group/higress-console/blob/v2.2.1/backend/console/src/main/java/com/alibaba/higress/console/controller/mcp/McpServerController.java),
  [`ConsumersController`](https://github.com/higress-group/higress-console/blob/v2.2.1/backend/console/src/main/java/com/alibaba/higress/console/controller/ConsumersController.java),
  and
  [`ServiceSourceController`](https://github.com/higress-group/higress-console/blob/v2.2.1/backend/console/src/main/java/com/alibaba/higress/console/controller/ServiceSourceController.java);
- the same release's
  [`OpenApiSaveStrategy`](https://github.com/higress-group/higress-console/blob/v2.2.1/backend/sdk/src/main/java/com/alibaba/higress/sdk/service/mcp/save/OpenApiSaveStrategy.java)
  and
  [`KubernetesModelConverter`](https://github.com/higress-group/higress-console/blob/v2.2.1/backend/sdk/src/main/java/com/alibaba/higress/sdk/service/kubernetes/KubernetesModelConverter.java),
  which define MCP enablement and the effective WasmPlugin shape;
- AgentTeams `v1.2.0-beta.1`, commit
  `78d0ceda336befa6e62bf89fc1a6b08b965e128d`, whose
  [`setup-higress.sh`](https://github.com/agentscope-ai/AgentTeams/blob/v1.2.0-beta.1/manager/scripts/init/setup-higress.sh)
  documents the Console v1 MCP payload and GitHub DNS service source.

Before any mutation, the script tries `/swagger/openapi.json` and
`/v3/api-docs` and requires the exact v1 paths, methods, and model fields it
uses. The audited live Console serves SPA HTML from both paths. The default is
therefore refusal. Source-contract fallback is available only when the operator
explicitly supplies the exact audited image digest:

```text
sha256:90ccdbb078375aad42f874feddba9d964eca34f192ee8dbab7d9a22079b580a4
```

The script compares the complete value and rejects every other digest. This is
not automatic image discovery: the operator must first verify the running Pod
image. The pin permits fallback only when both documentation endpoints are
non-JSON or unavailable. If either endpoint returns JSON with a changed schema,
the mismatch remains blocking and the pin cannot bypass it.

The audited deployment returns HTTP 201 as well as 200 from session login and
returns HTTP 201 when creating a DNS service source. Those codes are accepted
only for those exact operations; unrelated reads and writes keep their narrow
response contracts. A missing MCP server is unusually reported as HTTP 502.
Only the exact Console wrapper with `success=false`, `data=null`, and
a message containing
`NotFoundException: can't found the bound route by name` is treated as absent,
and only for `GET /v1/mcpServer/devflow-github-readonly`. Every other 502 is an
error. Missing service sources continue to require the normal HTTP 404.

The request also carries `mcpServerName` equal to `name`. AgentTeams' pinned
Console backend requires this route-binding compatibility field even though
the generated `McpServer` schema in the bundled API reference omits it. The
Console also omits this compatibility-only field from later GET responses, so
response validation binds identity through `name`, the dedicated route, exact
domain/service surface, and the Locator-only consumer list.
For that consumer list, the pinned Console returns the deterministic internal
route name `mcp-server-devflow-github-readonly.internal`; requests still use
the logical `devflow-github-readonly` name. No other returned route name is
accepted.

Unknown wrappers, malformed configuration, an existing name collision, or an
incompatible `devflow-github-content-broker` service source also stops the run.

The script has no third-party runtime dependency. A Console v2.2.1 defect makes
the concrete spelling security-relevant: `OpenApiSaveStrategy` enables the
route-scoped plugin only when `rawConfigurations` literally contains
`tools:`. Strict JSON is valid YAML but lacks that substring, so the Console
writes `configDisable: true` and traffic bypasses MCP tool handling. PUT now
emits a deterministic, fully closed 36-line YAML document containing the bare
`tools:` key. Every string is JSON-style double-quoted to prevent scalar or
indentation injection. The tree contains no PAT, `Authorization` header, or
server credential configuration.

The pinned Console normalizes that YAML on GET into the same 36-line block
document with `server`, then `tools`; the single tool starts with the
indentless `- args:` form. DevFlow accepts that observed form without
installing PyYAML, but it does not expose a general YAML parser. Historical
strict-JSON GET values remain readable and are checked for semantic equality,
but apply deliberately re-PUTs them as the enableable YAML spelling.

The GET validator recognizes exactly two encodings of the same closed tree:

- strict JSON, with duplicate object names rejected;
- the exact Console v2.2.1 36-line YAML spelling, including key order,
  indentation, six ordered required string arguments, the managed tool name
  and description, the single capability header, the fixed content-broker URL,
  and `GET`.

The Console emits every string as a canonical JSON-style double-quoted YAML
scalar. Any injected server `config`, access token, `Authorization` header, or
additional argument/header is rejected.
A second tool, a write method, a body, duplicate or unknown fields, changed
descriptions or headers, anchors, aliases, tags, merge keys, unquoted or
non-canonical scalars, blank suffixes, and any trailing document content all
fail closed.
JSON GET responses remain supported, but must represent the same exact values;
JSON is not a looser compatibility path. CI proves import, help, deterministic
YAML rendering, and normalized-YAML validation under `python -S`.

Console equality alone is not success. Check and apply also perform a read-only
`kubectl get wasmplugins.extensions.higress.io/mcp-server.internal -o json` and
require the effective CR to have `defaultConfigDisable: true`,
`failStrategy: FAIL_CLOSE`, an exact `oci://...@sha256:<64-lowerhex>` URL supplied
through `--pinned-wasm-plugin-url`, and exactly one match rule for
`mcp-server-devflow-github-readonly.internal`. That rule must target only that
Ingress, have `configDisable: false`, and contain the exact one-tool
configuration above. Apply first asks Console to regenerate the rule with a
re-PUT and then merge-patches only `spec.failStrategy` and `spec.url`. A final
reread is mandatory. Console or controller reconciliation can later overwrite
those fields, so production must run this check continuously; a later
`FAIL_OPEN` state is drift, never compliance.

## Credential boundary

Higress never stores or forwards the GitHub token. The content broker alone
reads `DEVFLOW_GITHUB_TOKEN` from the pre-created
`Secret/devflow-github-scope-broker` key `github-token`; it rejects any client
`Authorization` header and constructs the upstream header from its in-memory
server credential. The issuer Deployment does not mount that key. Both broker
processes also require the non-secret, canonical repository ceiling
`DEVFLOW_GITHUB_ALLOWED_REPOSITORIES` (production: `YZYY95K/test`) and enforce
it independently.

The Console administrator password is accepted through
`HIGRESS_ADMIN_PASSWORD` or `--console-password-secret NAME:KEY`. Secret values
are read through `kubectl get secret -o json`, decoded only in process memory,
and never passed as command-line arguments. The effective WasmPlugin
configuration is likewise inspected only in process memory. The session cookie
is also kept in memory. Command output, request bodies, response bodies, tokens,
and cookies are never logged.

The issuer accepts the Leader's projected ServiceAccount JWT and submits it to
Kubernetes TokenReview with audience `agentteams-controller`. It requires the
exact username
`system:serviceaccount:agentteams-system:agentteams-worker-devflow-lead`.
Static issuer bearer mode exists only for local tests and is absent from the
production manifest. The shared HMAC key signs short-lived capabilities and
content receipts; neither bearer tokens nor capabilities appear in audit logs.

## Broker wire contracts

Issuer request: `POST /v1/capabilities`, exact `Content-Type:
application/json`, Leader JWT in `Authorization: Bearer ...`, and exactly these
JSON fields:

```json
{"task_id":"...","owner":"YZYY95K","repo":"test","revision":"<40-lowerhex>","paths":["README.md"]}
```

`paths` must contain 1–32 sorted, unique, canonical repository-relative paths.
Success is HTTP 201 with exactly `schema`, `capability`, `expires_at`, and
`jti`; the schema is `devflow.github-content-capability/v1`.

Content request: `GET /v1/content` with exactly the query fields `task_id`,
`owner`, `repo`, `path`, and `revision`, plus one
`X-DevFlow-Capability` header. Client `Authorization` is forbidden. Success is
a fixed `devflow.github-content-response/v1` receipt containing only the
authorization decision/digests, repository coordinates, object SHA, canonical
Base64 content, `response_digest`, and `receipt_signature`. The response digest
is SHA-256 of canonical `{schema_version, authorization, github}`. The receipt
signature is a domain-separated HMAC-SHA256 over that payload plus
`response_digest`. All error bodies are exactly `{code, status}`; upstream
GitHub bodies are never returned.

## Run safely

Run the script from a trusted process that can resolve Kubernetes service DNS,
reach `higress-console.agentteams-system.svc.cluster.local:8080`, and has
permission to get and narrowly patch the internal `WasmPlugin`. The default
mode is read-only and needs no GitHub token:

```bash
export HIGRESS_ADMIN_PASSWORD='<from a trusted secret injector>'
python scripts/configure_higress_github_readonly.py \
  --pinned-console-image-digest \
  sha256:90ccdbb078375aad42f874feddba9d964eca34f192ee8dbab7d9a22079b580a4 \
  --pinned-wasm-plugin-url \
  'oci://<audited-mcp-plugin>@sha256:<verified-64-lowerhex-digest>'
```

Apply after the broker image has been built, digest-pinned, and the pre-created
Secret has been injected out of band:

```bash
export HIGRESS_ADMIN_PASSWORD='<injected>'
kubectl apply -f agentteams/github-scope-broker.yaml
python scripts/configure_higress_github_readonly.py --apply \
  --pinned-console-image-digest \
  sha256:90ccdbb078375aad42f874feddba9d964eca34f192ee8dbab7d9a22079b580a4 \
  --pinned-wasm-plugin-url \
  'oci://<audited-mcp-plugin>@sha256:<verified-64-lowerhex-digest>'
```

The Console password can instead come from an existing Secret without
materializing it in a command line:

```bash
python scripts/configure_higress_github_readonly.py --apply \
  --pinned-console-image-digest \
  sha256:90ccdbb078375aad42f874feddba9d964eca34f192ee8dbab7d9a22079b580a4 \
  --pinned-wasm-plugin-url \
  'oci://<audited-mcp-plugin>@sha256:<verified-64-lowerhex-digest>' \
  --console-password-secret '<secret-name>:<key>'
```

Do not use shell tracing, redirect environment output, or expose the Console
Service outside the cluster.

## Idempotency and concurrency

Apply mode first requires the existing `worker-devflow-locator` Consumer to
have exactly one credential with the exact surface
`{type: key-auth, source: BEARER}`. Extra or legacy credentials are blocking
and must be explicitly rotated at the AgentTeams identity source; this script
does not guess replacement credential material. It creates the broker DNS
source only when absent and never rewrites an incompatible source. It leaves
the server untouched only when the Console representation is enableable and
semantically exact **and** the runtime rule is enabled, fail-closed, and pinned.
Historical JSON, disabled runtime state, or configuration drift causes a
Console re-PUT, but only for a resource carrying DevFlow's managed description.

The Console v1 MCP consumer API has no resource version or optimistic locking.
The script therefore uses a dedicated server, removes every non-Locator
binding, adds Locator when missing, and performs mandatory final re-reads. Any
concurrent drift or unexpected response fails the run instead of being
reported as success.

Successful default-mode output is named `control-plane-compliant`, not
end-to-end. End-to-end evidence additionally requires an external MCP
initialize/tools-list exchange, one authorized immutable-revision read, an
incorrect-scope denial, and a TokenReview identity denial.

## Durable MCP session Redis

Higress MCP session storage is a separate infrastructure boundary from the
GitHub tool credential. The official Higress MCP documentation defines Redis
`username` and `password` as optional. DevFlow therefore does **not** generate,
store, print, or rotate a Redis password. It uses empty values and limits reachability
at the Kubernetes network boundary instead:

- a private `ClusterIP` Service on TCP 6379;
- ingress only from same-namespace Pods labelled `app=higress-gateway`;
- no Redis Pod egress;
- no ServiceAccount token mount;
- non-root execution, dropped Linux capabilities, and the runtime-default
  seccomp profile;
- a digest-pinned official Higress `redis-stack-server:7.4.0-v3` amd64 image;
- AOF persistence on a `local-path` `ReadWriteOnce` volume.

Source: [Higress MCP Server Docker quick start](https://higress.io/docs/ai/mcp-quick-start_docker/).

Apply the storage asset and wait for its single replica to become ready before
changing the shared Higress configuration:

```bash
kubectl apply -f agentteams/higress-redis.yaml
kubectl --namespace agentteams-system rollout status \
  deployment/devflow-higress-redis
python scripts/configure_higress_mcp_redis.py --apply
python scripts/configure_higress_mcp_redis.py --check
```

Check mode is the default and never writes; run it before apply when an
expected non-zero drift result is useful for change-control evidence. Both
modes first require the exact
private Service contract and exactly one ready EndpointSlice. Apply mode then
accepts only an unambiguous block-style `mcpServer.redis` structure, refuses to
overwrite any non-empty Redis credential, and replaces the ConfigMap with its
existing Kubernetes `resourceVersion`. The only exception is the complete,
fixed AgentTeams placeholder tuple (`your.redis.host:6379`, `your_username`,
`your_password`, DB 0); a partially changed tuple remains blocking. A
concurrent write therefore fails
instead of being lost. A final re-read must show both a new resource version
and the canonical state. Kubernetes command output and ConfigMap contents are
never printed.

The generated address is fixed to
`devflow-higress-redis.agentteams-system.svc.cluster.local:6379`, with database
`0` and empty `username`/`password`. Do not expose the Service, add broader
NetworkPolicy peers, or copy Redis values into Agent prompts. Confirm that the
cluster's CNI actually enforces Kubernetes NetworkPolicy before deployment.

This one-replica `local-path` setup is intentionally suitable for the current
single-node AgentTeams environment, not for high availability. A production
multi-node cluster should replace it with an HA Redis service and encrypted,
authenticated transport under a separately audited configuration contract.

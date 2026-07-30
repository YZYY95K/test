# Server experiment runbook — 2026-07-30

This is a procedure for a future run. It does **not** claim that this source was
uploaded, a service was started, or an experiment completed.

## 1. Prepare the fixed candidate inputs

Use a Linux systemd host. Stage the reviewed repository outside `/root`, `/home`, and
`/run/user`, for example `/opt/devflow`. Create the virtual environment outside the
repository too; an in-repository `.venv`, ignored `.env`, cache, egg-info, or any other
ignored file makes source identity fail closed.

```bash
cd /opt/devflow
uv venv /opt/devflow-venv --python 3.12
uv pip sync --python /opt/devflow-venv/bin/python \
  --require-hashes requirements/dev.lock.txt
find /opt/devflow-venv -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
find /opt/devflow-venv -type d -name __pycache__ -empty -delete
git status --porcelain=v1 --untracked-files=all
git ls-files --others --ignored --exclude-standard
git ls-files -v | awk '$1 != "H" { print; bad=1 } END { exit bad }'
```

The repository checks must print nothing. `/opt`, the virtual-environment entry and
target, and every parent directory must be root-owned and not group/world writable.
Do not install DevFlow in editable mode;
the runner imports the committed `src` tree directly. Every installed distribution
must match the lock by name/version and pass per-file SHA-256 RECORD verification.
This binds a root-owned installed snapshot tree; it does **not** prove that each
installed file came from the wheel hash recorded in the lock.
Unclaimed `sitecustomize.py`, `usercustomize.py`, `.pth`, source, binary, package
directory, or bytecode is rejected. `sitecustomize.py`, `usercustomize.py`, `.pyc`,
and `.pyo` are always forbidden. The sole `.pth` exception is coverage 7.15.2's
RECORD-owned `a1_coverage.pth` with SHA-256
`f1498191b7f52180654ccdb6195233612805e26344100c093058343ea04afd36`; any other
owner, version, name, or byte is rejected. Normal child Python startup may execute
that exact conditional hook, but the allowlisted environment does not set
`COVERAGE_PROCESS_START` or `COVERAGE_PROCESS_CONFIG`, so it does not activate
coverage startup. Keep `PYTHONDONTWRITEBYTECODE=1` during the run.

Dependencies must be fully installed before launch. Launcher and runner never install
or download packages. Do not use `uv venv --seed`: the runner does not require a pip
module inside the venv, and seed-only `pip`, `setuptools`, or `wheel` distributions are
rejected unless they are explicitly pinned by the lock. Installed inventory comes
only from the pre-activation `importlib.metadata` + RECORD snapshot audit, not from a
`python -m pip list` probe.

## 2. Review the launcher trust root

`scripts/start_server_experiments.py` is the small pre-isolation trust-root program.
It must be reviewed and hashed as part of the fixed commit. It imports only the Python
standard library and may read/hash the launcher, runner, and dependency lock; it does
not execute candidate modules, dependency modules, Git, pip, or project CLIs before
systemd isolation. It refuses to run unless Python has both isolated and no-site modes.

## 3. Start the recommended managed private-network run

The output is fixed to systemd's state directory. Its parent is created and managed by
`StateDirectory=devflow-experiments`; the run directory itself must not exist.

```bash
/opt/devflow-venv/bin/python -I -S \
  /opt/devflow/scripts/start_server_experiments.py \
  --python-entry /opt/devflow-venv/bin/python \
  --output /var/lib/devflow-experiments/finals-20260730-001 \
  --run-id finals-20260730-001 \
  --network-mode network_namespace_isolated
```

The launcher requests a detached DynamicUser systemd unit with `PrivateNetwork`, an
empty capability set, `NoNewPrivileges`, `ProtectHome`, `ProtectSystem=strict`,
private devices/tmp, hidden systemd/container-control sockets, control-group killing,
and bounded memory, task count, and runtime. It waits a bounded interval for matching
`PLAN.json` and `HEARTBEAT.json`; failure stops the unit. Failure to durably write the
adjacent launch receipt also stops it. Every systemd launch error, timeout, rejected
request, handshake failure, and receipt failure triggers `systemctl stop` followed by
a bounded `systemctl is-active` readback. An unverified stop is reported as such and
must be treated as a failed, unsafe launch. The service persists after SSH disconnect.

The systemd unit starts the runner with `python -I -S`. Before adding explicit venv
site-packages paths to `sys.path`, the standard-library-only bootstrap checks
`pyvenv.cfg`, rejects system-site-packages, audits every RECORD and unknown entry, and
binds the root-owned installed snapshot. Only after that audit may packaging or any
project/dependency CLI execute.

The runner verifies a distinct network namespace, absence of `CAP_NET_ADMIN` and
`CAP_SYS_ADMIN`, non-root execution, and `NoNewPrivileges`. This proves the requested
namespace/capability policy boundary; it is **not** a test of every possible outbound
connection and must not be described as the host network being disconnected.
The private namespace deliberately permits only IPv4/IPv6 loopback in addition to
Unix sockets (`IPAddressDeny=any` plus explicit `127.0.0.0/8` and `::1/128` allows),
because OTLP, broker, and infrastructure tests start local listeners. No host or
external network interface is added to the namespace.

On Linux, `network_available_credentials_stripped` also requires the managed
DynamicUser systemd unit but deliberately omits private-network/IP restrictions.
Linux without systemd is rejected; it never falls back, including when invoked as
root. Detached fallback exists only on Windows, where networking and disconnect
persistence are explicitly weaker and filesystem credential isolation is not verified.

## 4. Monitor progress

Use the unit and receipt printed by the launcher. `HEARTBEAT.json` reports running
steps and ends at `sealing`; a heartbeat alone is never completion authority.

```bash
python -m json.tool /var/lib/devflow-experiments/finals-20260730-001/HEARTBEAT.json
systemctl status devflow-experiment-<normalized-id>-<hash>.service
journalctl --unit=devflow-experiment-<normalized-id>-<hash>.service --follow
```

The runner is a Linux child subreaper. After every command—including normal exit—it
terminates and reaps remaining descendants, verifies that none remain, and records the
cleanup result. systemd `KillMode=control-group` is the outer safety net.

## 5. Verify and collect evidence

Only a non-empty valid `COMPLETION.json`, written through a reserved descriptor after
checksums and directory sealing, is authoritative.

```bash
cd /var/lib/devflow-experiments/finals-20260730-001
sha256sum --check SHA256SUMS
python -m json.tool PLAN.json
python -m json.tool SUMMARY.json
python -m json.tool COMPLETION.json
python -m json.tool role-packages-determinism.json
```

After copying the evidence directory, run the independent standard-library verifier
as the primary one-command integrity check:

```bash
/usr/bin/python3 -I -S /opt/devflow/scripts/run_server_experiments.py \
  --verify-output /absolute/path/to/copied/finals-20260730-001
```

It read-only revalidates canonical `COMPLETION.json`, its `SHA256SUMS` binding and
exact file inventory, PLAN/SUMMARY/HEARTBEAT hashes, every ordered receipt and
predecessor, result-to-plan argv, stored stdout/stderr hashes, terminal artifact tree,
both role-package set documents, and the determinism document. Exit code zero means
the copied output is internally consistent; inspect `experimentPassed` separately.
The verifier does not authenticate the adjacent launch receipt or add an external
signature/WORM guarantee.

Verify every numbered receipt's predecessor hash, common plan hash, and result/log
hashes. Require `SUMMARY.json.passed: true`,
`sameRunInternalConsistencyVerified: true`, unchanged installed-files digest, and
`role-packages-determinism.json.deterministic: true`. Copy the entire sealed output and
its adjacent hidden launch receipt. Never merge run IDs or reuse a partial directory.

## Honest limits

- Receipt links and checksums prove same-run internal consistency. They are not an
  external signature, transparency-log anchor, immutable filesystem, or WORM store.
- Runtime child environments omit provider/repository credential variables and `.env`
  loading. Arbitrary credential-file inaccessibility is not claimed.
- No LLM or embedding provider is called. `repositoryRepairAgentExecutions` remains
  **0**; manifest/fixture validation is not a successful repository-repair run.
- Local gates are not live AgentTeams Team Room, signed T4 resume, human approval, or
  model-backed repository benchmark evidence.
- A hard-killed runner is not resumable. Use a new run ID and output directory.
- `MemoryMax`, `TasksMax`, `RuntimeMaxSec`, file-count limits, per-file limits, and
  post-step total-byte checks are enforced, but this runner has no portable hard disk
  quota while a step is executing. Use a dedicated host or quota-limited filesystem/
  partition and monitor free space; post-step evidence limits are not a substitute for
  an execution-time filesystem quota.

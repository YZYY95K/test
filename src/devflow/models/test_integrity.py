"""Typed evidence produced by the server-owned test-integrity gate."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

TEST_INTEGRITY_POLICY: Literal["immutable-baseline-tests/v1"] = (
    "immutable-baseline-tests/v1"
)
TEST_ISOLATION_BOUNDARY: Literal[
    "stdlib-temporary-directory-process-only-not-os-sandbox"
] = "stdlib-temporary-directory-process-only-not-os-sandbox"
TEST_INTEGRITY_IGNORED_PARTS = (
    ".devflow",
    ".git",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
)
TEST_INTEGRITY_CONTROL_NAMES = (
    ".coveragerc",
    "jest.config.js",
    "jest.config.json",
    "jest.config.mjs",
    "jest.config.ts",
    "playwright.config.js",
    "playwright.config.ts",
    "pyproject.toml",
    "pytest.ini",
    "setup.cfg",
    "tox.ini",
    "vitest.config.js",
    "vitest.config.mjs",
    "vitest.config.ts",
)
TEST_INTEGRITY_PYTHON_OUTCOME_CALLS = (
    "pytest.skip",
    "pytest.xfail",
    "unittest.expectedFailure",
    "unittest.skip",
    "unittest.skipIf",
    "unittest.skipUnless",
)
TEST_INTEGRITY_PYTHON_OUTCOME_DECORATORS = (
    *TEST_INTEGRITY_PYTHON_OUTCOME_CALLS,
    "pytest.mark.skip",
    "pytest.mark.skipif",
    "pytest.mark.xfail",
)
TEST_INTEGRITY_PYTHON_COLLECTION_HOOKS = (
    "pytest_collection_modifyitems",
    "pytest_ignore_collect",
)
TEST_INTEGRITY_PYTHON_COLLECTION_ASSIGNMENTS = (
    "__test__",
    "collect_ignore",
    "collect_ignore_glob",
)
TEST_INTEGRITY_NON_PYTHON_OUTCOME_MARKERS = (
    ".skip(",
    ".skip;",
    ".todo(",
    ".xfail(",
    "@ignore",
    "xit(",
    "xdescribe(",
    "xtest(",
)

_POLICY_SPEC: dict[str, object] = {
    "policy": TEST_INTEGRITY_POLICY,
    "baseline": "existing test and test-control files are immutable",
    "candidate": "new tests may be added but may not contain outcome-control directives",
    "execution": "baseline and candidate run in separate disposable repository copies",
    "attestation": "pre/post protected manifests and server-owned command are digest-bound",
    "isolation": TEST_ISOLATION_BOUNDARY,
    "ignored_parts": TEST_INTEGRITY_IGNORED_PARTS,
    "test_control_names": TEST_INTEGRITY_CONTROL_NAMES,
    "python_outcome_calls": TEST_INTEGRITY_PYTHON_OUTCOME_CALLS,
    "python_outcome_decorators": TEST_INTEGRITY_PYTHON_OUTCOME_DECORATORS,
    "python_collection_hooks": TEST_INTEGRITY_PYTHON_COLLECTION_HOOKS,
    "python_collection_assignments": TEST_INTEGRITY_PYTHON_COLLECTION_ASSIGNMENTS,
    "non_python_outcome_markers": TEST_INTEGRITY_NON_PYTHON_OUTCOME_MARKERS,
}


def canonical_integrity_digest(value: object) -> str:
    """Return the canonical SHA-256 used by test-integrity evidence."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


TEST_INTEGRITY_POLICY_DIGEST = canonical_integrity_digest(_POLICY_SPEC)


class TestIntegrityAttestation(BaseModel):
    """Deterministic CI evidence that protected tests remained immutable.

    This is a self-attestation from the trusted CI/CD MCP boundary, not a
    cryptographic signature and not proof of container or operating-system
    isolation.  Its digests make the exact policy, command, and protected-file
    state auditable by downstream agents and the hash-chain audit log.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    policy: Literal["immutable-baseline-tests/v1"] = TEST_INTEGRITY_POLICY
    policy_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    command_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_baseline_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_pre_run_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_post_run_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    added_tests_manifest_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_protected_file_count: StrictInt = Field(ge=0, le=1_000_000)
    added_test_file_count: StrictInt = Field(ge=0, le=1_000_000)
    full_suite: StrictBool
    verified: StrictBool
    isolation_boundary: Literal[
        "stdlib-temporary-directory-process-only-not-os-sandbox"
    ] = TEST_ISOLATION_BOUNDARY

    @model_validator(mode="after")
    def _verify_attestation_claims(self) -> TestIntegrityAttestation:
        if self.policy_digest != TEST_INTEGRITY_POLICY_DIGEST:
            raise ValueError("policy_digest does not bind the supported integrity policy")
        if self.verified and (
            self.baseline_manifest_digest
            != self.candidate_baseline_manifest_digest
        ):
            raise ValueError("verified attestation requires an immutable baseline manifest")
        if self.verified and (
            self.candidate_pre_run_manifest_digest
            != self.candidate_post_run_manifest_digest
        ):
            raise ValueError("verified attestation requires an immutable execution manifest")
        return self


__all__ = [
    "TEST_INTEGRITY_POLICY",
    "TEST_INTEGRITY_POLICY_DIGEST",
    "TEST_INTEGRITY_CONTROL_NAMES",
    "TEST_INTEGRITY_IGNORED_PARTS",
    "TEST_INTEGRITY_NON_PYTHON_OUTCOME_MARKERS",
    "TEST_INTEGRITY_PYTHON_COLLECTION_ASSIGNMENTS",
    "TEST_INTEGRITY_PYTHON_COLLECTION_HOOKS",
    "TEST_INTEGRITY_PYTHON_OUTCOME_CALLS",
    "TEST_INTEGRITY_PYTHON_OUTCOME_DECORATORS",
    "TEST_ISOLATION_BOUNDARY",
    "TestIntegrityAttestation",
    "canonical_integrity_digest",
]

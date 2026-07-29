"""Fail-closed tests for the immutable baseline CI policy."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from devflow.agents.coder_agent import CoderAgent
from devflow.exceptions import AgentError, MCPError
from devflow.mcp.cicd import IsolatedTestService
from devflow.models.patch import ChangeType, FileChange, Patch
from devflow.models.test_integrity import (
    TEST_INTEGRITY_POLICY_DIGEST,
    TEST_ISOLATION_BOUNDARY,
)
from devflow.models.test_integrity import (
    TestIntegrityAttestation as IntegrityAttestation,
)


def _change(
    path: str,
    change_type: ChangeType,
    *,
    original: str | None,
    current: str | None,
) -> FileChange:
    if change_type is ChangeType.CREATE:
        headers = f"--- /dev/null\n+++ b/{path}\n"
    elif change_type is ChangeType.DELETE:
        headers = f"--- a/{path}\n+++ /dev/null\n"
    else:
        headers = f"--- a/{path}\n+++ b/{path}\n"
    return FileChange(
        file_path=path,
        change_type=change_type,
        original_content=original,
        new_content=current,
        diff=headers,
    )


def _patch(*changes: FileChange) -> Patch:
    return Patch(
        branch_name="devflow/integrity-test",
        changes=list(changes),
        commit_message="test: exercise integrity gate",
        description="A deterministic integrity-gate fixture.",
    )


def _repository(root: Path, *, broken: bool = True) -> tuple[Path, str, str]:
    repository = root / "repo"
    repository.mkdir()
    source = "def add(a, b):\n    return a - b\n" if broken else "def add(a, b):\n    return a + b\n"
    test = (
        "import unittest\n"
        "from calculator import add\n"
        "class CalculatorTests(unittest.TestCase):\n"
        "    def test_add(self):\n"
        "        self.assertEqual(add(2, 3), 5)\n"
    )
    (repository / "calculator.py").write_text(source, encoding="utf-8")
    (repository / "test_calculator.py").write_text(test, encoding="utf-8")
    return repository, source, test


def _service(repository: Path, command: tuple[str, ...] | None = None) -> IsolatedTestService:
    return IsolatedTestService(
        repository,
        command or (sys.executable, "-m", "unittest", "discover", "-v"),
        timeout_seconds=30,
    )


@pytest.mark.parametrize(
    ("change_type", "message"),
    [
        (ChangeType.MODIFY, "immutable tests"),
        (ChangeType.DELETE, "delete a test file"),
    ],
)
def test_coder_cannot_modify_or_delete_an_existing_test(
    change_type: ChangeType,
    message: str,
) -> None:
    original = "def test_value():\n    assert False\n"
    current = None if change_type is ChangeType.DELETE else "def test_value():\n    assert True\n"
    candidate = _patch(
        _change(
            "tests/test_value.py",
            change_type,
            original=original,
            current=current,
        )
    )

    with pytest.raises(AgentError, match=message):
        CoderAgent._validate_patch(candidate)


@pytest.mark.parametrize(
    "content",
    [
        "import pytest\npytest.skip('hide failure')\n",
        "import pytest\n@pytest.mark.xfail\ndef test_value():\n    assert False\n",
        "import unittest\n@unittest.skip('hide failure')\ndef test_value():\n    pass\n",
        "collect_ignore = ['test_real.py']\n",
        "def pytest_collection_modifyitems(items):\n    items.clear()\n",
    ],
)
def test_coder_rejects_new_skip_xfail_and_collection_bypasses(content: str) -> None:
    candidate = _patch(
        _change(
            "tests/test_padding.py",
            ChangeType.CREATE,
            original=None,
            current=content,
        )
    )

    with pytest.raises(AgentError, match="control their outcome"):
        CoderAgent._validate_patch(candidate)


def test_coder_rejects_test_outcome_control_hidden_in_source() -> None:
    original = "def calculate():\n    return 0\n"
    candidate = _patch(
        _change(
            "calculator.py",
            ChangeType.MODIFY,
            original=original,
            current="import pytest\npytest.xfail('manufactured green')\n",
        )
    )

    with pytest.raises(AgentError, match="control their outcome"):
        CoderAgent._validate_patch(candidate)


def test_coder_allows_a_new_test_with_real_assertions() -> None:
    candidate = _patch(
        _change(
            "tests/test_new_behavior.py",
            ChangeType.CREATE,
            original=None,
            current=(
                "from calculator import add\n\n"
                "def test_negative_values():\n"
                "    assert add(-2, -3) == -5\n"
            ),
        )
    )

    CoderAgent._validate_patch(candidate)


@pytest.mark.asyncio
@pytest.mark.parametrize("change_type", [ChangeType.MODIFY, ChangeType.DELETE])
async def test_ci_rechecks_existing_test_immutability_when_coder_is_bypassed(
    tmp_path: Path,
    change_type: ChangeType,
) -> None:
    repository, _source, original_test = _repository(tmp_path)
    changed_test = (
        None
        if change_type is ChangeType.DELETE
        else "def test_manufactured_green():\n    assert True\n"
    )
    candidate = _patch(
        _change(
            "test_calculator.py",
            change_type,
            original=original_test,
            current=changed_test,
        )
    )

    with pytest.raises(MCPError, match="test_integrity_violation"):
        await _service(repository).run_tests(candidate, full_suite=True)

    assert (repository / "test_calculator.py").read_text(encoding="utf-8") == original_test


@pytest.mark.asyncio
async def test_ci_rejects_new_test_control_file(tmp_path: Path) -> None:
    repository, _source, _test = _repository(tmp_path)
    candidate = _patch(
        _change(
            "conftest.py",
            ChangeType.CREATE,
            original=None,
            current="collect_ignore = ['test_calculator.py']\n",
        )
    )

    with pytest.raises(MCPError, match="test_control_file_changed"):
        await _service(repository).run_tests(candidate, full_suite=True)


@pytest.mark.asyncio
async def test_success_attests_policy_command_and_immutable_manifests(tmp_path: Path) -> None:
    repository, original, original_test = _repository(tmp_path)
    candidate = _patch(
        _change(
            "calculator.py",
            ChangeType.MODIFY,
            original=original,
            current="def add(a, b):\n    return a + b\n",
        )
    )
    service = _service(repository)

    first = await service.run_tests(candidate, full_suite=True)
    second = await service.run_tests(candidate, full_suite=True)

    assert first.passed == 1
    assert first.integrity_attestation is not None
    attestation = first.integrity_attestation
    assert attestation.verified is True
    assert attestation.policy_digest == TEST_INTEGRITY_POLICY_DIGEST
    assert attestation.baseline_manifest_digest == attestation.candidate_baseline_manifest_digest
    assert (
        attestation.candidate_pre_run_manifest_digest
        == attestation.candidate_post_run_manifest_digest
    )
    assert attestation.baseline_protected_file_count == 1
    assert attestation.added_test_file_count == 0
    assert attestation.isolation_boundary == TEST_ISOLATION_BOUNDARY
    assert second.integrity_attestation == attestation
    assert (repository / "calculator.py").read_text(encoding="utf-8") == original
    assert (repository / "test_calculator.py").read_text(encoding="utf-8") == original_test


@pytest.mark.asyncio
async def test_honest_new_test_is_digest_bound_without_changing_baseline(tmp_path: Path) -> None:
    repository, source, _test = _repository(tmp_path, broken=False)
    new_test = (
        "import unittest\n"
        "from calculator import add\n"
        "class MoreTests(unittest.TestCase):\n"
        "    def test_negative(self):\n"
        "        self.assertEqual(add(-2, -3), -5)\n"
    )
    candidate = _patch(
        _change(
            "tests/test_more.py",
            ChangeType.CREATE,
            original=None,
            current=new_test,
        )
    )

    result = await _service(repository).run_tests(candidate, full_suite=True)

    assert result.passed == 1
    assert result.integrity_attestation is not None
    assert result.integrity_attestation.added_test_file_count == 1
    assert (
        result.integrity_attestation.baseline_manifest_digest
        == result.integrity_attestation.candidate_baseline_manifest_digest
    )
    assert not (repository / "tests" / "test_more.py").exists()
    assert (repository / "calculator.py").read_text(encoding="utf-8") == source


@pytest.mark.asyncio
async def test_test_process_mutation_is_detected_but_canonical_repo_is_untouched(
    tmp_path: Path,
) -> None:
    repository, original, original_test = _repository(tmp_path)
    candidate = _patch(
        _change(
            "calculator.py",
            ChangeType.MODIFY,
            original=original,
            current="def add(a, b):\n    return a + b\n",
        )
    )
    script = (
        "from pathlib import Path; "
        "source=Path('calculator.py').read_text(); "
        "target=Path('test_calculator.py'); "
        "target.write_text('def test_fake(): pass\\n') if 'a + b' in source else None"
    )

    with pytest.raises(MCPError, match="candidate_tests_mutated_during_execution"):
        await _service(repository, (sys.executable, "-c", script)).run_tests(
            candidate,
            full_suite=True,
        )

    assert (repository / "calculator.py").read_text(encoding="utf-8") == original
    assert (repository / "test_calculator.py").read_text(encoding="utf-8") == original_test


def test_verified_attestation_cannot_claim_mismatched_manifests() -> None:
    common = {
        "schema_version": "1.0",
        "policy": "immutable-baseline-tests/v1",
        "policy_digest": TEST_INTEGRITY_POLICY_DIGEST,
        "command_digest": "a" * 64,
        "baseline_manifest_digest": "b" * 64,
        "candidate_baseline_manifest_digest": "c" * 64,
        "candidate_pre_run_manifest_digest": "d" * 64,
        "candidate_post_run_manifest_digest": "d" * 64,
        "added_tests_manifest_digest": "e" * 64,
        "baseline_protected_file_count": 1,
        "added_test_file_count": 0,
        "full_suite": True,
        "verified": True,
        "isolation_boundary": TEST_ISOLATION_BOUNDARY,
    }

    with pytest.raises(ValidationError, match="immutable baseline manifest"):
        IntegrityAttestation.model_validate(common)

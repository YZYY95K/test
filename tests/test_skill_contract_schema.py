"""Fail-closed checks for machine-readable Skill protocol extensions."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from devflow.skills.catalog import load_catalog
from devflow.skills.contracts import SkillContract

ROOT = Path(__file__).resolve().parents[1]


def _contract(name: str) -> dict[str, Any]:
    path = ROOT / "skills" / name / "references" / "contract.yaml"
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_catalog_preserves_typed_retry_protocol_extensions() -> None:
    catalog = load_catalog(ROOT / "skills")

    test_runner = catalog["test-runner"]
    assert test_runner.failure_evidence is not None
    assert test_runner.failure_evidence.schema_version == "1.2"
    assert test_runner.failure_handoff is not None
    assert test_runner.failure_handoff.consumer == "TeamLeader"
    assert test_runner.retry_protocol is not None
    assert test_runner.retry_protocol.patch_attempts.maximum_total == 3

    patch_generator = catalog["patch-generator"]
    assert patch_generator.retry_handoff is not None
    assert patch_generator.retry_handoff.producer == "TeamLeader"
    assert patch_generator.retry_handoff.attempt_bounds.maximum_total == 3


@pytest.mark.parametrize(
    ("name", "mutation"),
    [
        ("test-runner", lambda value: value.update({"unknown_protocol": {}})),
        (
            "test-runner",
            lambda value: value["failure_evidence"]["bounds"].update(
                {"unbounded_output": 1}
            ),
        ),
        (
            "patch-generator",
            lambda value: value["retry_handoff"].update({"test_result": "raw"}),
        ),
    ],
)
def test_contract_rejects_unknown_protocol_vocabulary(
    name: str,
    mutation: Any,
) -> None:
    value = copy.deepcopy(_contract(name))
    mutation(value)

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SkillContract.model_validate(value)


def test_test_runner_requires_mediated_failure_protocol() -> None:
    missing = copy.deepcopy(_contract("test-runner"))
    missing.pop("failure_evidence")
    with pytest.raises(ValidationError, match="requires failure_evidence"):
        SkillContract.model_validate(missing)

    bypass = copy.deepcopy(_contract("test-runner"))
    regression = next(
        item for item in bypass["failures"] if item["code"] == "TEST_REGRESSION"
    )
    regression["route_to"] = "CoderAgent"
    with pytest.raises(ValidationError, match="must route through TeamLeader"):
        SkillContract.model_validate(bypass)


def test_patch_generator_requires_exact_retry_owner_and_budget() -> None:
    missing = copy.deepcopy(_contract("patch-generator"))
    missing.pop("retry_handoff")
    with pytest.raises(ValidationError, match="requires retry_handoff"):
        SkillContract.model_validate(missing)

    wrong_owner = copy.deepcopy(_contract("patch-generator"))
    wrong_owner["retry_handoff"]["producer"] = "TesterAgent"
    with pytest.raises(ValidationError, match="Input should be 'TeamLeader'"):
        SkillContract.model_validate(wrong_owner)

    excessive = copy.deepcopy(_contract("patch-generator"))
    excessive["retry_handoff"]["attempt_bounds"]["maximum_total"] = 9
    with pytest.raises(ValidationError, match="Input should be 3"):
        SkillContract.model_validate(excessive)

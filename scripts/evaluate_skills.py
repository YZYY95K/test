"""Score DevFlow Skills against an explicit 100-point quality gate."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from devflow.skills.catalog import load_catalog, validate_collaboration

RUBRIC = {
    "spec_compliance": 15,
    "trigger_precision": 10,
    "contract_clarity": 15,
    "operational_basis": 10,
    "boundary_security": 15,
    "failure_handling": 10,
    "collaboration": 10,
    "validation": 10,
    "context_efficiency": 5,
}


@dataclass
class SkillScore:
    """One reproducible Skill evaluation."""

    name: str
    score: int
    qualified: bool
    critical_failures: list[str]
    deductions: list[str]
    dimensions: dict[str, int]


def _frontmatter(text: str) -> dict[str, Any]:
    if not text.startswith("---\n"):
        return {}
    _, block, _ = text.split("---\n", 2)
    parsed = yaml.safe_load(block)
    return parsed if isinstance(parsed, dict) else {}


def evaluate(skill_dir: Path) -> SkillScore:
    """Evaluate one Skill package without model judgment."""

    text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
    meta = _frontmatter(text)
    contract = load_catalog(skill_dir.parent)[skill_dir.name]
    dimensions = dict(RUBRIC)
    deductions: list[str] = []
    critical: list[str] = []

    def deduct(dimension: str, points: int, reason: str) -> None:
        dimensions[dimension] = max(0, dimensions[dimension] - points)
        deductions.append(f"{dimension} -{points}: {reason}")

    if set(meta) != {"name", "description"}:
        deduct("spec_compliance", 15, "frontmatter must contain only name/description")
        critical.append("invalid frontmatter")
    if meta.get("name") != skill_dir.name or contract.name != skill_dir.name:
        deduct("spec_compliance", 15, "package, metadata, and contract names differ")
        critical.append("identity mismatch")
    ui_path = skill_dir / "agents" / "openai.yaml"
    if not ui_path.exists():
        deduct("spec_compliance", 5, "agents/openai.yaml missing")
    else:
        ui = yaml.safe_load(ui_path.read_text(encoding="utf-8")) or {}
        interface = ui.get("interface", {})
        prompt = str(interface.get("default_prompt", ""))
        description = str(interface.get("short_description", ""))
        if f"${skill_dir.name}" not in prompt or not (25 <= len(description) <= 64):
            deduct("spec_compliance", 4, "UI prompt/description is not discovery-ready")

    description = str(meta.get("description", ""))
    if "Use when" not in description:
        deduct("trigger_precision", 6, "description lacks explicit Use when trigger")
    if len(contract.invoke_when) < 2 or len(contract.refuse_when) < 2:
        deduct("trigger_precision", 4, "positive and negative triggers are incomplete")

    if len(contract.input.required_fields) < 3:
        deduct("contract_clarity", 6, "input contract is underspecified")
    if len(contract.output.required_fields) < 3:
        deduct("contract_clarity", 6, "output contract is underspecified")
    if contract.input.type == contract.output.type:
        deduct("contract_clarity", 3, "input/output artifact boundary is ambiguous")
    if not contract.dependencies or not contract.release.rollback:
        deduct("contract_clarity", 3, "dependencies or release rollback is missing")

    if "## Procedure" not in text or "## Decision rules" not in text:
        deduct("operational_basis", 6, "procedure or decision rules missing")
    validator = skill_dir / "scripts" / "validate.py"
    if not validator.exists():
        deduct("operational_basis", 4, "deterministic validator missing")
        critical.append("no executable validation")

    if "## Boundaries" not in text:
        deduct("boundary_security", 5, "boundary disclosure missing from core instructions")
    if len(contract.forbidden_actions) < 3:
        deduct("boundary_security", 6, "fewer than three explicit forbidden actions")
    if len(contract.allowed_actions) < 2:
        deduct("boundary_security", 4, "allowed action surface is unclear")

    if len(contract.failures) < 3:
        deduct("failure_handling", 4, "failure matrix has fewer than three cases")
    if any(not rule.route_to or not rule.event for rule in contract.failures):
        deduct("failure_handling", 6, "failure route or event is missing")

    if len(contract.handoffs) < 2:
        deduct("collaboration", 5, "success and non-success handoffs are incomplete")
    if not any(rule.on == "success" for rule in contract.handoffs):
        deduct("collaboration", 5, "no success consumer is declared")

    examples = skill_dir / "references" / "examples.md"
    if len(contract.verification) < 3:
        deduct("validation", 4, "fewer than three evidence gates")
    if not examples.exists():
        deduct("validation", 6, "capability examples missing")
    else:
        example_text = examples.read_text(encoding="utf-8")
        required = {"## Success", "## Failure", "## Boundary"}
        if not required <= set(example_text.splitlines()):
            deduct("validation", 4, "success/failure/boundary examples incomplete")

    if len(text.splitlines()) > 500:
        deduct("context_efficiency", 3, "SKILL.md exceeds 500 lines")
    if (
        "references/contract.yaml" not in text
        or "references/examples.md" not in text
    ):
        deduct("context_efficiency", 2, "progressive-disclosure links are incomplete")

    score = sum(dimensions.values())
    return SkillScore(
        name=skill_dir.name,
        score=score,
        qualified=score >= 90 and not critical,
        critical_failures=critical,
        deductions=deductions,
        dimensions=dimensions,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    skills_dir = args.root / "skills"
    catalog = load_catalog(skills_dir)
    graph_violations = validate_collaboration(catalog)
    results = [
        evaluate(skill_dir)
        for skill_dir in sorted(skills_dir.iterdir())
        if (skill_dir / "SKILL.md").exists()
    ]
    qualified = all(result.qualified for result in results) and not graph_violations
    payload = {
        "rubric_version": "1.0",
        "qualification_threshold": 90,
        "qualified": qualified,
        "graph_violations": graph_violations,
        "skills": [asdict(result) for result in results],
    }
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for result in results:
            status = "PASS" if result.qualified else "FAIL"
            print(f"{status} {result.name}: {result.score}/100")
            for deduction in result.deductions:
                print(f"  {deduction}")
        for violation in graph_violations:
            print(f"GRAPH FAIL: {violation}")
    return 0 if qualified else 1


if __name__ == "__main__":
    raise SystemExit(main())

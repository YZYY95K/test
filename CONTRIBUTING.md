# Contributing to DevFlow

Contributions should preserve DevFlow's evidence-first and least-privilege
design. Open an issue before changing an artifact schema, approval rule, or
Agent boundary.

## Development check

Use Python 3.10 through 3.12 and run:

```powershell
python -m pip install -e ".[dev]"
ruff check .
mypy src scripts tests
pytest -q
python scripts/evaluate_skills.py
python -m devflow.cli demo
```

## Skill changes

- Keep `SKILL.md` focused on the operational procedure.
- Put detailed contracts and examples one level below `references/`.
- Update the semantic contract version when behavior changes.
- Add deterministic success, failure, and boundary tests.
- Do not weaken a security or human-approval gate to make an evaluation pass.
- Regenerate `agents/openai.yaml` when discovery metadata changes.

Pull requests must explain the user-visible effect, risk, verification
evidence, compatibility impact, and rollback path.

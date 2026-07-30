#!/usr/bin/env python3
"""Fail-closed migration shim for the retired Worker-local Tester CI installer.

Finals use ``scripts/reconcile_agentteams_tester_cicd.py`` to deploy the
independent CI service.  A Worker-local installer cannot safely hold the
Ed25519 key used to prove claims made by that Worker, so this compatibility
entry point deliberately performs no installation or compliance claim.

The fixed-argv parser remains importable for contract regression tests and for
operators migrating old policy files.  It never accepts a shell command.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_server() -> ModuleType:
    """Load only the parser primitives from source or the fixed image path."""

    try:
        from agentteams.cicd import tester_server

        return tester_server
    except ModuleNotFoundError:
        production = Path("/opt/devflow/agentteams-cicd/tester_server.py")
        spec = importlib.util.spec_from_file_location(
            "_devflow_production_tester_cicd",
            production,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("Tester CI/CD parser source is unavailable") from None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except (OSError, ImportError) as exc:
            raise RuntimeError("Tester CI/CD parser source is unavailable") from exc
        return module


cicd = _load_server()

CONFIRMATION = "INSTALL_TESTER_ONLY_AGENTTEAMS_CICD"
RECONCILER = "scripts/reconcile_agentteams_tester_cicd.py"


class InstallError(RuntimeError):
    """The retired topology cannot be installed or truthfully verified."""


def _commands(raw: str) -> dict[str, list[str]]:
    """Parse the two fixed argv vectors without enabling shell evaluation."""

    try:
        value = json.loads(
            raw,
            object_pairs_hook=cicd._strict_object,
            parse_constant=cicd._reject_constant,
        )
    except (json.JSONDecodeError, cicd.BoundaryError) as exc:
        raise InstallError("test command policy is invalid") from exc
    if not isinstance(value, dict) or set(value) != {"focused", "full"}:
        raise InstallError("test command policy requires focused and full")
    try:
        parsed = {
            name: cicd._command(value[name], f"{name}_command")
            for name in ("focused", "full")
        }
    except cicd.BoundaryError as exc:
        raise InstallError("test command policy is invalid") from exc
    return {name: list(arguments) for name, arguments in parsed.items()}


def build_policy(**_arguments: Any) -> dict[str, Any]:
    """Refuse to mint a policy for the retired same-Worker topology."""

    raise InstallError(
        f"Worker-local policy generation is retired; use {RECONCILER}"
    )


def install(**_arguments: Any) -> dict[str, Any]:
    """Refuse mutation; only the isolated Deployment reconciler may install."""

    raise InstallError(f"Worker-local installation is retired; use {RECONCILER}")


def check() -> dict[str, Any]:
    """Refuse to label a Worker-local process as an independent CI boundary."""

    raise InstallError(f"Worker-local verification is retired; use {RECONCILER}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Retired Worker-local Tester CI shim; use the isolated AgentTeams "
            "Tester CI reconciler."
        )
    )
    parser.add_argument("--apply", action="store_true", help="always fails closed")
    parser.add_argument(
        "--source",
        type=Path,
        default=Path("agentteams/cicd/tester_server.py"),
        help="legacy compatibility argument; never installed",
    )
    parser.add_argument("--expected-source-sha256")
    parser.add_argument("--revision")
    parser.add_argument("--repository-archive-sha256")
    parser.add_argument("--test-commands-json")
    parser.add_argument("--confirm")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.apply:
            if (
                args.confirm != CONFIRMATION
                or not args.expected_source_sha256
                or not args.revision
                or not args.repository_archive_sha256
                or not args.test_commands_json
            ):
                raise InstallError(
                    "apply requires exact confirmation, source digest, revision, "
                    "repository archive digest, and commands"
                )
            _commands(args.test_commands_json)
            result = install()
        else:
            if any(
                value is not None
                for value in (
                    args.expected_source_sha256,
                    args.revision,
                    args.repository_archive_sha256,
                    args.test_commands_json,
                    args.confirm,
                )
            ):
                raise InstallError("check mode does not accept apply-only values")
            result = check()
    except InstallError as exc:
        print(f"error: Tester CI/CD boundary failed safely: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Command-line entry point for DevFlow."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from devflow.config import get_settings
from devflow.demo import run_demo

console = Console()


@click.group()
def main() -> None:
    """DevFlow — auditable multi-agent software issue resolution."""


@main.command()
@click.option(
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False),
    help="Directory for the JSON evidence report.",
)
def demo(output_dir: Path | None) -> None:
    """Run the credential-free, deterministic end-to-end demonstration."""

    report, report_path = asyncio.run(run_demo(output_dir))
    tests = report["test_result"]
    review = report["review"]
    collaboration = report["collaboration_ledger"]
    route_snapshot = collaboration["snapshot"]
    audit_chain = collaboration["audit_chain"]
    table = Table(title="DevFlow demo result")
    table.add_column("Gate")
    table.add_column("Result")
    table.add_row("Classification", report["classification"]["complexity_level"])
    table.add_row("Root cause", report["located_context"]["root_cause"]["file"])
    table.add_row("Tests", f'{tests["passed"]}/{tests["total"]} passed')
    table.add_row("Review", review["decision"])
    table.add_row(
        "Experience",
        "stored" if report["experience"]["stored"] else "degraded",
    )
    table.add_row(
        "Agent routes",
        f'{route_snapshot["succeeded"]}/6 sealed',
    )
    table.add_row(
        "Audit chain",
        f'{audit_chain["entries"]} entries / '
        f'{"valid" if audit_chain["valid"] else "INVALID"}',
    )
    table.add_row("Events", str(len(report["events"])))
    console.print(table)
    console.print(f"Evidence: [link=file://{report_path.resolve()}]{report_path.resolve()}[/link]")


@main.command()
def validate() -> None:
    """Load and validate all project configuration files."""

    settings = get_settings()
    console.print(
        json.dumps(
            {
                "agents": len(settings.agents),
                "skills_configured": len(settings.skills.get("skills", [])),
                "mcp_servers": len(settings.mcp_servers.get("servers", {})),
                "status": "valid",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()

"""Typer CLI for agent-action-guard."""

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

import guard
from guard.schema import Action

app = typer.Typer(
    name="agent-action-guard",
    help="Screen AI agent tool calls and return allow/block/warn verdicts before execution.",
    no_args_is_help=True,
)
console = Console()


def _print_decision(decision: guard.Decision) -> None:
    table = Table(title="Verdict", show_header=True, header_style="bold")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    table.add_row("verdict", decision.verdict)
    table.add_row("reason", decision.reason)
    table.add_row("confidence", f"{decision.confidence:.2f}")
    table.add_row("action_hash", decision.action_hash)
    table.add_row("rule_id", decision.rule_id or "")
    console.print(table)


@app.command()
def check(
    action: Annotated[
        str,
        typer.Option("--action", help="JSON-encoded Action payload."),
    ],
    allowlist: Annotated[
        Path | None,
        typer.Option("--allowlist", help="YAML allowlist path for rule/command overrides."),
    ] = None,
) -> None:
    """Evaluate a proposed action and print a structured verdict."""
    payload = json.loads(action)
    parsed = Action.model_validate(payload)
    decision = guard.evaluate_with_allowlist(parsed, allowlist)
    _print_decision(decision)


@app.command()
def serve(
    port: Annotated[int, typer.Option("--port", help="HTTP port for the guard server.")] = 9099,
) -> None:
    """Start the FastAPI guard server (SSE + /check endpoint)."""
    raise NotImplementedError("serve implemented in Task 3")


@app.command()
def audit(
    log: Annotated[
        Path,
        typer.Option("--log", help="Path to the JSONL audit log."),
    ] = Path("guard.jsonl"),
) -> None:
    """Render a markdown summary report from an audit log."""
    raise NotImplementedError


@app.command()
def bench() -> None:
    """Run the labeled dataset bench harness and print metrics."""
    raise NotImplementedError


@app.command()
def version() -> None:
    """Print the installed package version."""
    typer.echo(guard.__version__)

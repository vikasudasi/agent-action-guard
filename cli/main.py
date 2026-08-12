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
    no_classifier: Annotated[
        bool,
        typer.Option(
            "--no-classifier",
            help="Skip classifier merge; use fixed rule confidences only (fully deterministic).",
        ),
    ] = False,
) -> None:
    """Evaluate a proposed action and print a structured verdict."""
    payload = json.loads(action)
    parsed = Action.model_validate(payload)
    allowlist_path = str(allowlist) if allowlist is not None else None
    decision = guard.evaluate_with_allowlist(
        parsed,
        allowlist_path,
        use_classifier=not no_classifier,
    )
    _print_decision(decision)


@app.command()
def serve(
    port: Annotated[int, typer.Option("--port", help="HTTP port for the guard server.")] = 9099,
    log: Annotated[
        Path,
        typer.Option("--log", help="Path to the JSONL audit log."),
    ] = Path("guard.jsonl"),
) -> None:
    """Start the FastAPI guard server (SSE + /check endpoint)."""
    try:
        import uvicorn

        from guard.audit import AuditLog
        from guard.server import create_app
    except ImportError as exc:
        raise typer.BadParameter(
            "serve dependencies are required. Install with: pip install -e '.[serve]'"
        ) from exc

    audit_log = AuditLog(log)
    api = create_app(audit_log=audit_log)
    uvicorn.run(api, host="127.0.0.1", port=port, log_level="info")


@app.command()
def audit(
    log: Annotated[
        Path,
        typer.Option("--log", help="Path to the JSONL audit log."),
    ] = Path("guard.jsonl"),
) -> None:
    """Render a markdown summary report from an audit log."""
    from guard.audit import render_markdown

    typer.echo(render_markdown(log), nl=False)


@app.command()
def bench(
    output: Annotated[
        Path,
        typer.Option("--output", help="Path for the JSON bench report."),
    ] = Path("bench_report.json"),
    no_classifier: Annotated[
        bool,
        typer.Option(
            "--no-classifier",
            help="Evaluate with rules only (fixed confidences).",
        ),
    ] = False,
) -> None:
    """Run the labeled dataset bench harness and print metrics."""
    from eval.dataset import DATASET
    from guard.bench import format_markdown_table, run_bench, write_report

    report = run_bench(DATASET, use_classifier=not no_classifier)
    write_report(report, output)
    typer.echo(format_markdown_table(report))
    if not report["meets_target"]:
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Print the installed package version."""
    typer.echo(guard.__version__)

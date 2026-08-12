"""Typer CLI for agent-action-guard."""

import json
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

import guard
from guard.adapters import TARGETS, adapter_script
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


def _load_json(path: Path) -> dict[str, Any]:
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass
    return {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _hook_config_path(target: str, base: Path) -> Path:
    if target == "claude-code":
        return base / ".claude" / "settings.json"
    if target == "cursor":
        return base / "hooks.json"
    return base / ".kiro" / "hooks" / "guard.json"


def _write_hook_config(target: str, script_path: Path, base: Path) -> Path:
    """Write the harness hook config; returns the config file path."""
    command = str(script_path)
    if target == "claude-code":
        path = _hook_config_path(target, base)
        data = _load_json(path)
        hooks = data.setdefault("hooks", {})
        hooks["PreToolUse"] = [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}
        ]
        _write_json(path, data)
        return path
    if target == "cursor":
        path = _hook_config_path(target, base)
        data = _load_json(path)
        hooks = data.setdefault("hooks", {})
        hooks["preToolUse"] = [
            {"matcher": "Shell|Write|MCP", "hooks": [{"type": "command", "command": command}]}
        ]
        _write_json(path, data)
        return path
    path = _hook_config_path(target, base)
    data = _load_json(path)
    data["PreToolUse"] = [{"matchers": ["execute_bash", "fs_write"], "command": command}]
    _write_json(path, data)
    return path


hooks_app = typer.Typer(
    name="hooks",
    help="Install agent-action-guard as a pre-tool-use hook into an agent harness.",
    no_args_is_help=True,
)
app.add_typer(hooks_app)


@hooks_app.command("install")
def hooks_install(
    target: Annotated[
        str, typer.Option("--target", help="Harness target; one of: claude-code, cursor, kiro.")
    ],
    target_dir: Annotated[
        Path,
        typer.Option("--dir", "--target-dir", help="Base directory to write harness config into."),
    ] = Path("."),
    url: Annotated[
        str, typer.Option("--url", help="Optional guard server base URL to bake into the script.")
    ] = "",
) -> None:
    """Write a harness hook config and the runnable guard adapter script."""
    if target not in TARGETS:
        raise typer.BadParameter(
            f"unknown target {target!r}; expected one of: {', '.join(TARGETS)}"
        )

    hooks_dir = target_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    script_path = hooks_dir / f"agent-action-guard-{target}.py"
    script_path.write_text(adapter_script(target, default_url=url), encoding="utf-8")
    script_path.chmod(0o755)

    config_path = _write_hook_config(target, script_path, target_dir)

    typer.echo(f"Installed agent-action-guard hook for target '{target}'")
    typer.echo(f"  config : {config_path}")
    typer.echo(f"  adapter: {script_path}")
    typer.echo("  verdicts: block -> harness-native deny; allow/warn -> exit 0")
    typer.echo("  network mode: set AGENT_ACTION_GUARD_URL=<serve base URL> to use POST /check")

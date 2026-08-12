# agent-action-guard

## Name

`agent-action-guard`

## Description

Local, auditable action-safety guard for AI agents. Screens proposed tool calls (shell, file, network, git, MCP) and returns structured `allow`, `block`, or `warn` verdicts with a reason, confidence score, and stable `action_hash` before auto-execution runs.

Use this skill when wiring agent loops, CI gates, or HTTP middleware that must inspect agent actions; when documenting how to call `check`, `serve`, `audit`, or `bench`; or when integrating the pydantic `Action` schema from `guard.schema`.

## Commands

| Command | Purpose |
|---------|---------|
| `agent-action-guard check --action '<json>'` | Evaluate one action; print Rich verdict table |
| `agent-action-guard check --action '<json>' --allowlist path.yaml` | Evaluate with allowlist (Task 2) |
| `agent-action-guard serve --port 9099` | FastAPI + SSE server (Task 3 stub) |
| `agent-action-guard audit --log guard.jsonl` | Markdown report from audit log (Task 3 stub) |
| `agent-action-guard bench` | Dataset bench metrics (Task 4 stub) |
| `agent-action-guard version` | Print package version |
| `agent-action-guard --help` | List all subcommands |

## Action JSON schema

Required field: `type` — one of `shell`, `file`, `network`, `mcp`, `git`.

Optional fields: `command`, `args` (list, default `[]`), `path`, `url`, `method`, `tool`, `tool_args` (dict), `cwd` (default `"."`), `source`.

```python
from guard.schema import Action

action = Action(type="shell", command="echo hi")
action.to_hash()  # stable SHA-256 hex
```

## Usage examples

### Install

```bash
pip install -e ".[dev]"
```

### Version

```bash
agent-action-guard version
# 0.1.0
```

### Check a shell command

```bash
agent-action-guard check --action '{"type":"shell","command":"echo hi"}'
```

Expected verdict in 0.1.0 (stub evaluator): `allow`, reason `no rules matched`, confidence `0.50`.

### Check a file action

```bash
agent-action-guard check --action '{"type":"file","path":"src/main.py","args":["read"]}'
```

### Check a network action

```bash
agent-action-guard check --action '{"type":"network","url":"https://api.example.com/v1/data","method":"GET"}'
```

### Check an MCP tool call

```bash
agent-action-guard check --action '{"type":"mcp","tool":"read_file","tool_args":{"path":"README.md"}}'
```

### Development verify

```bash
make verify
```

Runs `ruff check`, `ruff format --check`, `mypy guard cli`, and `pytest -q`.

## Python API (0.1.0)

```python
import guard
from guard.schema import Action

action = Action.model_validate({"type": "shell", "command": "echo hi"})
decision = guard.evaluate(action)
# decision.verdict, decision.reason, decision.confidence, decision.action_hash
```

## Stubs (not yet implemented)

- `serve` → `NotImplementedError: serve implemented in Task 3`
- `audit` → `NotImplementedError`
- `bench` → `NotImplementedError`

## Project layout

- `guard/schema.py` — `Action` pydantic model
- `guard/decision.py` — `Decision`, `Verdict`
- `guard/__init__.py` — `evaluate()` facade, `__version__`
- `cli/main.py` — Typer CLI entry (`agent-action-guard` console script)

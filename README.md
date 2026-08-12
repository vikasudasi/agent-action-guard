# agent-action-guard 🛡️

Local, auditable action-safety guard that screens AI agent tool calls and returns structured `allow` / `block` / `warn` verdicts before auto-execution.

[![CI](https://github.com/vikasudasi/agent-action-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/vikasudasi/agent-action-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Problem

AI coding agents increasingly run with auto-execution enabled: shell commands, file writes, network calls, git operations, and MCP tools can fire without a human in the loop. A mistaken or adversarial prompt can trigger credential exfiltration, destructive filesystem operations, or force-pushed git history in seconds.

`agent-action-guard` sits in the path between "agent decided to act" and "action executes." It inspects a proposed action, applies deterministic rules (and an optional classifier in later releases), and returns a verdict with a reason and confidence score. The design mirrors the trust layer behind Anthropic's Claude Code auto-mode classifier, which blocks a large share of dangerous queries compared to manual review.

## Quickstart

```bash
pip install -e .
agent-action-guard version
```

```
0.1.0
```

```bash
agent-action-guard check --action '{"type":"shell","command":"echo hi"}'
```

```
                    Verdict
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field       ┃ Value                                                        ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ verdict     │ allow                                                        │
│ reason      │ no rules matched                                             │
│ confidence  │ 0.50                                                         │
│ action_hash │ (64-char SHA-256 hex of canonical action JSON)               │
│ rule_id     │                                                              │
└─────────────┴──────────────────────────────────────────────────────────────┘
```

Rich prints the full `action_hash` on one line (64 hex characters). Derive it with:

```bash
python3 -c "from guard.schema import Action; print(Action(type='shell',command='echo hi').to_hash())"
```

```bash
agent-action-guard --help
```

```
 Usage: agent-action-guard [OPTIONS] COMMAND [ARGS]...

 Screen AI agent tool calls and return allow/block/warn verdicts before execution.

╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --help          Show this message and exit.                                  │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Commands ───────────────────────────────────────────────────────────────────╮
│ check     Evaluate a proposed action and print a structured verdict.         │
│ serve     Start the FastAPI guard server (SSE + /check endpoint).            │
│ audit     Render a markdown summary report from an audit log.                │
│ bench     Run the labeled dataset bench harness and print metrics.           │
│ version   Print the installed package version.                               │
╰──────────────────────────────────────────────────────────────────────────────╯
```

## Installation

### From source (recommended during development)

```bash
git clone https://github.com/vikasudasi/agent-action-guard.git
cd agent-action-guard
pip install -e ".[dev]"
```

### Optional dependency groups

| Group    | Install command              | Includes                          |
|----------|------------------------------|-----------------------------------|
| default  | `pip install -e .`             | CLI, schema, Typer, Rich, PyYAML  |
| `serve`  | `pip install -e ".[serve]"`    | FastAPI, uvicorn (Task 3)         |
| `dev`    | `pip install -e ".[dev]"`      | pytest, ruff, mypy                |
| `all`    | `pip install -e ".[all]"`      | serve + dev                       |

### Verify installation

```bash
agent-action-guard version
```

```
0.1.0
```

## CLI Reference

### `agent-action-guard check`

Evaluate a single proposed action from JSON.

| Option        | Type   | Default | Description                                      |
|---------------|--------|---------|--------------------------------------------------|
| `--action`    | string | required| JSON-encoded `Action` payload                    |
| `--allowlist` | path   | none    | YAML allowlist (applied in Task 2)               |

```bash
agent-action-guard check --action '{"type":"file","path":"README.md","args":["read"]}'
```

```
                    Verdict
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Field       ┃ Value                                                        ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ verdict     │ allow                                                        │
│ reason      │ no rules matched                                             │
│ confidence  │ 0.50                                                         │
│ action_hash │ …                                                            │
│ rule_id     │                                                              │
└─────────────┴──────────────────────────────────────────────────────────────┘
```

### `agent-action-guard serve`

Start the HTTP guard server (FastAPI + SSE). **Stub in 0.1.0** — implemented in Task 3.

| Option   | Type | Default | Description        |
|----------|------|---------|--------------------|
| `--port` | int  | `9099`  | HTTP listen port   |

```bash
agent-action-guard serve --port 9099
```

```
NotImplementedError: serve implemented in Task 3
```

### `agent-action-guard audit`

Render a markdown report from a JSONL audit log. **Stub in 0.1.0** — implemented in Task 3.

| Option  | Type | Default       | Description           |
|---------|------|---------------|-----------------------|
| `--log` | path | `guard.jsonl` | Path to audit log     |

```bash
agent-action-guard audit --log guard.jsonl
```

```
NotImplementedError
```

### `agent-action-guard bench`

Run the labeled eval dataset and print precision/recall metrics. **Stub in 0.1.0** — implemented in Task 4.

```bash
agent-action-guard bench
```

```
NotImplementedError
```

### `agent-action-guard version`

Print the package version string.

```bash
agent-action-guard version
```

```
0.1.0
```

## Output Formats

### JSON verdict (future `serve` / `--json` flag)

When the HTTP `/check` endpoint ships (Task 3), responses follow this shape:

```json
{
  "verdict": "allow",
  "reason": "no rules matched",
  "confidence": 0.5,
  "action_hash": "8f3c2a1b…",
  "rule_id": null
}
```

| Field          | Type              | Description                                      |
|----------------|-------------------|--------------------------------------------------|
| `verdict`      | `allow\|block\|warn` | Final decision                                   |
| `reason`       | string            | Human-readable explanation                       |
| `confidence`   | float             | 0.0–1.0 dangerousness / confidence               |
| `action_hash`  | string            | SHA-256 hex of canonical action JSON             |
| `rule_id`      | string \| null    | Matching rule identifier, if any               |

### Rich table (CLI default)

The `check` command prints a Rich table with the same fields for terminal review.

### JSONL audit line (Task 3)

Each audited decision will append one line:

```json
{
  "timestamp": "2026-08-12T15:42:00.000000+00:00",
  "action_hash": "…",
  "verdict": "block",
  "reason": "rm -rf on sensitive path",
  "confidence": 0.92,
  "rule_id": "shell_rm_rf",
  "action": {"type": "shell", "command": "rm -rf /"}
}
```

## Feature / Detection Layers

| Module              | What It Checks                                      | Example                                      |
|---------------------|-----------------------------------------------------|----------------------------------------------|
| `guard/schema.py`   | Validates action shape (type, paths, URLs, MCP)     | Reject malformed JSON before evaluation      |
| `guard/rules.py`    | Deterministic dangerous-action signatures (Task 2)  | `rm -rf /`, credential exfil domains         |
| `guard/classifier.py` | Heuristic dangerousness score (Task 2)            | Pipe-to-shell patterns boost confidence      |
| `guard/decision.py` | Verdict + reason + confidence dataclass           | `block` with `rule_id` and `action_hash`     |
| `guard/audit.py`    | JSONL writer + markdown report (Task 3)             | Append every `/check` result to `guard.jsonl`|
| `guard/server.py`   | FastAPI `/check`, `/events`, `/health` (Task 3)     | Agent POSTs action, receives verdict JSON    |
| `eval/dataset.py`   | Labeled benign/dangerous actions (Task 4)           | Bench harness block-rate on dangerous set    |

## Architecture

```
  Agent proposes action (JSON)
           │
           ▼
  ┌────────────────────┐
  │  Action (pydantic) │  ← guard/schema.py
  └─────────┬──────────┘
            │
            ▼
  ┌────────────────────┐
  │  Rule engine       │  ← guard/rules.py (Task 2)
  │  (15+ signatures)  │
  └─────────┬──────────┘
            │
            ▼
  ┌────────────────────┐
  │  Classifier merge  │  ← guard/classifier.py (Task 2)
  └─────────┬──────────┘
            │
            ▼
  ┌────────────────────┐
  │  Decision          │  ← guard/decision.py
  │  allow/block/warn  │
  └─────────┬──────────┘
            │
     ┌──────┴──────┐
     ▼             ▼
  CLI (Rich)   Audit JSONL + SSE (Task 3)
```

1. **Parse** — Incoming JSON is validated into an `Action` model; invalid payloads fail fast.
2. **Hash** — `action.to_hash()` produces a stable SHA-256 for audit correlation.
3. **Rules** — Each registered rule tests the action; highest severity wins (block > warn > allow).
4. **Classifier** — Optional heuristic score adjusts confidence (Task 2).
5. **Allowlist** — YAML overrides can downgrade specific rules or commands (Task 2).
6. **Emit** — CLI table, HTTP JSON, JSONL audit line, or SSE event depending on entry point.

## Use Cases

### Pre-flight check in a shell hook

Before running an agent-proposed command, pipe JSON into `check`:

```bash
agent-action-guard check --action '{"type":"shell","command":"npm test","cwd":"/app"}'
```

Use the `verdict` field to gate execution in your agent loop.

### CI gate for autonomous PR bots

A bot opening PRs can screen file writes:

```bash
agent-action-guard check --action '{"type":"file","path":".github/workflows/ci.yml","args":["write"]}'
```

Block or warn before the write lands (once rules ship in Task 2).

### Network call screening

Screen outbound requests before the agent fetches a URL:

```bash
agent-action-guard check --action '{"type":"network","url":"https://example.com/api","method":"POST"}'
```

Credential-exfil domains will be blocked by the rule engine in Task 2.

### Long-running guard service (Task 3)

Agents stream actions to a local guard:

```bash
agent-action-guard serve --port 9099
```

`POST /check` returns JSON verdicts; `GET /events` streams SSE for streaming agents.

## Development

### Commands

```bash
make install    # pip install -e ".[dev]"
make lint       # ruff check + format --check
make typecheck  # mypy guard cli
make test       # pytest -q
make verify     # lint + typecheck + test
```

### Project tree

```
agent-action-guard/
├── cli/main.py              # Typer entry: check, serve, audit, bench, version
├── guard/
│   ├── __init__.py          # evaluate() facade, __version__
│   ├── schema.py            # pydantic Action model
│   ├── decision.py          # Verdict + Decision
│   ├── rules.py             # (Task 2) rule engine
│   ├── classifier.py        # (Task 2) scorer + merger
│   ├── audit.py             # (Task 3) JSONL + markdown
│   └── server.py            # (Task 3) FastAPI
├── eval/dataset.py          # (Task 4) bench dataset
├── tests/                   # pytest suite
├── .github/workflows/ci.yml
├── pyproject.toml
├── Makefile
├── README.md
├── CHANGELOG.md
└── SKILL.md
```

### Adding a new rule (Task 2)

1. Open `guard/rules.py` and add a `Rule` dataclass entry with `rule_id`, `name`, `severity`, and `matcher`.
2. Implement `matcher(action: Action) -> bool` using type-specific fields (`command`, `url`, `path`, `tool`).
3. Register the rule in the `RULES` list.
4. Add paired tests in `tests/test_rules.py` — one dangerous action that triggers, one benign action that passes.
5. If the rule is noisy, document an allowlist key in your YAML config.

## FAQ

**Will this block legitimate development commands?**

Task 2 rules target high-risk patterns (`rm -rf`, credential paths, exfil hosts). Benign commands like `echo`, `npm test`, and read-only file access should pass. Tune with YAML allowlists when needed.

**Does 0.1.0 include the rule engine?**

No. Version 0.1.0 is scaffold-only: `check` always returns `allow` with reason `no rules matched`. Rules land in Task 2.

**What Python versions are supported?**

Python 3.11 and newer (`requires-python = ">=3.11"`).

**Can I run this in production today?**

Use 0.1.0 for integration testing and CLI wiring. Production gating requires Task 2 rules and your own allowlist policy.

**How is `action_hash` computed?**

Canonical JSON (`sort_keys=True`, compact separators) of the `Action` model is SHA-256 hashed. Identical payloads always produce the same hash.

**What happens if I call `serve` or `bench` now?**

They are registered in `--help` but raise `NotImplementedError` with a message pointing to the implementing task.

**Is network access required?**

No. Evaluation is fully local. The optional `serve` mode only listens on the port you configure (default 9099).

**How does this compare to human review?**

The goal is automated screening at scale — similar to auto-mode classifiers — with auditable JSONL logs for post-incident review.

**Where do MCP tool calls fit?**

`Action.type = "mcp"` with `tool` and `tool_args` fields. Dangerous MCP tool name patterns are covered in Task 2 rules.

## Resources

- [Anthropic — Claude Code auto-mode](https://docs.anthropic.com/en/docs/claude-code) — context for agent auto-execution
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — tool-call surface guarded by this project
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — agent security risks
- [FastAPI](https://fastapi.tiangolo.com/) — HTTP layer for `serve` (Task 3)
- [Pydantic v2](https://docs.pydantic.dev/) — `Action` schema validation

## License + Footer

MIT License — see [LICENSE](LICENSE) when published.

**agent-action-guard** — screen agent actions before they run.

Repository: [https://github.com/vikasudasi/agent-action-guard](https://github.com/vikasudasi/agent-action-guard)

# agent-action-guard 🛡️

Local, auditable action-safety guard that screens AI agent tool calls and returns structured `allow` / `block` / `warn` verdicts before auto-execution.

[![CI](https://github.com/vikasudasi/agent-action-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/vikasudasi/agent-action-guard/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Problem

AI coding agents increasingly run with auto-execution enabled: shell commands, file writes, network calls, git operations, and MCP tools can fire without a human in the loop. A mistaken or adversarial prompt can trigger credential exfiltration, destructive filesystem operations, or force-pushed git history in seconds.

`agent-action-guard` sits in the path between "agent decided to act" and "action executes." It inspects a proposed action, applies 28 deterministic rules plus an offline heuristic classifier, and returns a verdict with a reason and confidence score. The design mirrors the trust layer behind Anthropic's Claude Code auto-mode classifier, which blocks a large share of dangerous queries compared to manual review.

## Quickstart

```bash
pip install -e ".[dev]"
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
│ confidence  │ 0.95                                                         │
│ action_hash │ (64-char SHA-256 hex of canonical action JSON)               │
│ rule_id     │                                                              │
└─────────────┴──────────────────────────────────────────────────────────────┘
```

```bash
agent-action-guard check --action '{"type":"shell","command":"rm -rf /tmp/build"}'
```

```
│ verdict     │ block                                                        │
│ reason      │ Recursive force delete: Avoid `rm -rf`; use safer deletion … │
│ confidence  │ 0.95                                                         │
│ rule_id     │ shell-rm-rf                                                  │
```

## Table of Contents

- [Installation](#installation)
- [CLI Reference](#cli-reference)
- [HTTP API](#http-api-serve)
- [Output Formats](#output-formats)
- [Feature / Detection Layers](#feature--detection-layers)
- [Architecture](#architecture)
- [Use Cases](#use-cases)
- [Development](#development)
- [FAQ](#faq)
- [Resources](#resources)
- [License + Footer](#license--footer)

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
| `serve`  | `pip install -e ".[serve]"`    | FastAPI, uvicorn                  |
| `dev`    | `pip install -e ".[dev]"`      | pytest, ruff, mypy, httpx         |
| `all`    | `pip install -e ".[all]"`      | serve + dev (minus types-PyYAML)  |

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

| Option            | Type   | Default | Description                                      |
|-------------------|--------|---------|--------------------------------------------------|
| `--action`        | string | required| JSON-encoded `Action` payload                    |
| `--allowlist`     | path   | none    | YAML allowlist for rule/command downgrades       |
| `--no-classifier` | flag   | off     | Rules-only fixed confidences (block/warn/allow)    |

**Benign shell command:**

```bash
agent-action-guard check --action '{"type":"shell","command":"echo hi"}'
```

```
│ verdict     │ allow                                                        │
│ reason      │ no rules matched                                             │
│ confidence  │ 0.95                                                         │
```

**Dangerous shell command:**

```bash
agent-action-guard check --action '{"type":"shell","command":"rm -rf /"}'
```

```
│ verdict     │ block                                                        │
│ rule_id     │ shell-rm-rf                                                  │
│ confidence  │ 0.95                                                         │
```

**Allowlist override** (downgrades `block` → `warn` for scoped build cleanup):

`allowlist.yaml`:

```yaml
rules:
  - shell-rm-rf
commands:
  - rm -rf /tmp/build
```

```bash
agent-action-guard check \
  --action '{"type":"shell","command":"rm -rf /tmp/build"}' \
  --allowlist allowlist.yaml
```

```
│ verdict     │ warn                                                         │
│ reason      │ Recursive force delete: … (allowlisted; downgraded from block) │
│ rule_id     │ shell-rm-rf                                                  │
```

**Rules-only mode:**

```bash
agent-action-guard check --action '{"type":"shell","command":"echo hi"}' --no-classifier
```

```
│ confidence  │ 0.50                                                         │
```

### `agent-action-guard serve`

Start the HTTP guard server (FastAPI + SSE + JSONL audit).

| Option   | Type | Default       | Description           |
|----------|------|---------------|-----------------------|
| `--port` | int  | `9099`        | HTTP listen port      |
| `--log`  | path | `guard.jsonl` | JSONL audit log path  |

Requires the `serve` extra: `pip install -e ".[serve]"`.

```bash
agent-action-guard serve --port 9099 --log guard.jsonl
```

```
INFO:     Started server process [12345]
INFO:     Uvicorn running on http://127.0.0.1:9099 (Press CTRL+C to quit)
```

### `agent-action-guard audit`

Render a markdown summary report from a JSONL audit log.

| Option  | Type | Default       | Description           |
|---------|------|---------------|-----------------------|
| `--log` | path | `guard.jsonl` | Path to audit log     |

```bash
agent-action-guard audit --log guard.jsonl
```

```
# Agent Action Guard — Audit Report

**Log:** `guard.jsonl`
**Total decisions:** 3

## Verdict counts
| Verdict | Count |
|---------|------:|
| allow   | 1     |
| block   | 2     |
...
```

### `agent-action-guard bench`

Run the labeled eval dataset through the decision engine and print metrics.

| Option            | Type | Default            | Description                          |
|-------------------|------|--------------------|--------------------------------------|
| `--output`        | path | `bench_report.json`| JSON report output path              |
| `--no-classifier` | flag | off                | Rules-only evaluation                |

```bash
agent-action-guard bench
```

```
# Bench Report

## Overall metrics
| Metric | Value |
| --- | ---: |
| Total samples | 87 |
| Recall (dangerous block rate) | 100.00% |
| Meets target | yes |
```

Exits with code `1` if dangerous block-rate falls below 80%.

```bash
agent-action-guard bench --no-classifier --output /tmp/bench_report.json
```

### `agent-action-guard version`

```bash
agent-action-guard version
```

```
0.1.0
```

## HTTP API (`serve`)

Install serve dependencies first: `pip install -e ".[serve]"`.

| Method | Path       | Description                                              |
|--------|------------|----------------------------------------------------------|
| `POST` | `/check`   | Body: Action JSON → verdict JSON                         |
| `GET`  | `/events`  | SSE `text/event-stream` of verdicts as `/check` runs     |
| `GET`  | `/health`  | Liveness probe `{"status":"ok"}`                         |

### `POST /check`

**Allow (benign action):**

```bash
curl -s -X POST http://127.0.0.1:9099/check \
  -H 'Content-Type: application/json' \
  -d '{"type":"shell","command":"echo hi"}'
```

```json
{
  "verdict": "allow",
  "reason": "no rules matched",
  "confidence": 0.95,
  "action_hash": "<64-char-sha256-hex>"
}
```

**Block (dangerous action):**

```bash
curl -s -X POST http://127.0.0.1:9099/check \
  -H 'Content-Type: application/json' \
  -d '{"type":"shell","command":"rm -rf /"}'
```

```json
{
  "verdict": "block",
  "reason": "Recursive force delete: Avoid `rm -rf`; use safer deletion tools or scoped paths with confirmation.",
  "confidence": 0.95,
  "action_hash": "<64-char-sha256-hex>"
}
```

**Malformed body (HTTP 400):**

```bash
curl -s -X POST http://127.0.0.1:9099/check \
  -H 'Content-Type: application/json' \
  -d '{"command":"missing type field"}'
```

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "type"],
      "msg": "Field required"
    }
  ]
}
```

### `GET /health`

```bash
curl -s http://127.0.0.1:9099/health
```

```json
{"status":"ok"}
```

### `GET /events` (SSE)

```bash
curl -N http://127.0.0.1:9099/events
```

```
data: {"action_hash":"…","confidence":0.95,"reason":"no rules matched","verdict":"allow"}

```

Each `/check` appends one JSONL audit line and publishes the verdict to connected SSE clients.

## Output Formats

### JSON verdict (`/check` and Python API)

```json
{
  "verdict": "block",
  "reason": "Recursive force delete: Avoid `rm -rf`; …",
  "confidence": 0.95,
  "action_hash": "8f3c2a1b…"
}
```

| Field          | Type                 | Description                                      |
|----------------|----------------------|--------------------------------------------------|
| `verdict`      | `allow\|block\|warn` | Final decision                                   |
| `reason`       | string               | Human-readable explanation                       |
| `confidence`   | float                | 0.0–1.0 confidence in the verdict                |
| `action_hash`  | string               | SHA-256 hex of canonical action JSON             |
| `rule_id`      | string \| null       | Matching rule ID (CLI table only; omitted in HTTP)|

### Rich table (CLI default)

The `check` command prints a Rich table with verdict, reason, confidence, action hash, and rule ID.

### JSONL audit line

Each audited decision appends one line:

```json
{
  "timestamp": "2026-08-12T15:42:00.000000+00:00",
  "action_hash": "…",
  "verdict": "block",
  "reason": "Recursive force delete: …",
  "confidence": 0.95,
  "rule_id": "shell-rm-rf",
  "action": {"type": "shell", "command": "rm -rf /", "args": [], "cwd": "."}
}
```

Render reports with `agent-action-guard audit --log guard.jsonl`.

## Feature / Detection Layers

| Module                | What It Checks                                      | Example                                      |
|-----------------------|-----------------------------------------------------|----------------------------------------------|
| `guard/schema.py`     | Validates action shape (type, paths, URLs, MCP)     | Reject malformed JSON before evaluation      |
| `guard/rules.py`      | 28 deterministic dangerous-action signatures        | `rm -rf /`, credential exfil domains         |
| `guard/classifier.py` | Offline heuristic dangerousness score + merge       | Boosts block confidence on pipe-to-shell       |
| `guard/decision.py`   | Verdict + reason + confidence dataclass             | `block` with `rule_id` and `action_hash`     |
| `guard/audit.py`      | JSONL writer + markdown report                      | Append every `/check` result to `guard.jsonl`|
| `guard/server.py`     | FastAPI `/check`, `/events`, `/health`              | Agent POSTs action, receives verdict JSON    |
| `eval/dataset.py`     | 42 dangerous + 45 benign labeled actions            | Bench harness block-rate on dangerous set    |
| `guard/bench.py`      | Precision, recall, F1, per-category breakdown       | `agent-action-guard bench`                   |

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
  │  Rule engine       │  ← guard/rules.py (28 rules)
  │  block > warn      │
  └─────────┬──────────┘
            │
            ▼
  ┌────────────────────┐
  │  Classifier merge  │  ← guard/classifier.py (offline)
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
  CLI (Rich)   Audit JSONL + SSE
```

1. **Parse** — Incoming JSON is validated into an `Action` model; invalid payloads return HTTP 400.
2. **Hash** — `action.to_hash()` produces a stable SHA-256 for audit correlation.
3. **Rules** — Each registered rule tests the action; highest severity wins (block > warn > allow).
4. **Classifier** — Weighted feature heuristics adjust confidence; block rules cannot be downgraded.
5. **Allowlist** — YAML overrides downgrade matched rules/commands one severity level.
6. **Emit** — CLI table, HTTP JSON, JSONL audit line, or SSE event depending on entry point.

## Harness Integration (pre-tool-use hooks)

`agent-action-guard` ships a production integration layer that installs the
guard as a **pre-tool-use hook** in real agent harnesses — the action is
screened before it executes. The hook reads the harness's hook payload on
stdin, normalises it into the canonical [`Action`](guard/schema.py) schema
(via `guard/adapters.py`), evaluates it, and emits the harness-native deny
signal when the action is blocked.

```bash
# Claude Code  -> writes .claude/settings.json + hooks/agent-action-guard-claude-code.py
agent-action-guard hooks install --target claude-code --dir /path/to/project

# Cursor       -> writes hooks.json + hooks/agent-action-guard-cursor.py
agent-action-guard hooks install --target cursor --dir /path/to/project

# Kiro         -> writes .kiro/hooks/guard.json + hooks/agent-action-guard-kiro.py
agent-action-guard hooks install --target kiro --dir /path/to/project
```

Each install writes a thin per-target adapter script into `hooks/` under the
target directory and wires the harness config file to run it on every tool
call. The same scripts are committed at the repo root under [`hooks/`](hooks/).

### Local vs. network mode

By default the adapter resolves the verdict **locally** (imports `guard` and
calls the rule engine directly). To evaluate against a running
`agent-action-guard serve` endpoint instead, set:

```bash
export AGENT_ACTION_GUARD_URL=http://127.0.0.1:9099
```

When set, the adapter `POST`s the serialised `Action` JSON to
`<url>/check` and uses the returned `verdict` / `reason`. Local mode is the
default and requires no server.

### Deny signals

| Harness      | Block behavior                                                        |
| ------------ | --------------------------------------------------------------------- |
| Claude Code  | prints `hookSpecificOutput` JSON (deny) and exits `0`                 |
| Cursor       | prints the same expressive deny JSON and exits `0`                    |
| Kiro         | writes the reason to stderr and exits `2`                             |
| Allow / warn | exit `0`, no decision JSON                                            |

The adapters fail-open: if the guard itself errors (bad payload, network
timeout, import issue) the hook exits `0` rather than breaking your agent.

### Worked example (Claude Code; Cursor reuses the same shape)

Install into a project, then feed the adapter a hook payload. For a dangerous
`Bash` call the hook returns:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/repo"}' \
  | hooks/agent-action-guard-claude-code.py
```

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "Recursive force delete: Avoid `rm -rf`; use safer deletion tools or scoped paths with confirmation."}}
```

A benign call (`echo hi`) prints nothing and exits `0`.

> **Hermes:** we integrate Hermes Agent (hermes-agent) separately from these
> harness hooks — see the Hermes plugin/guard wiring rather than these
> per-harness hooks for that runtime.

## Use Cases

### Pre-flight check in a shell hook

```bash
agent-action-guard check --action '{"type":"shell","command":"npm test","cwd":"/app"}'
```

Gate execution on `verdict` in your agent loop.

### CI gate for autonomous PR bots

```bash
agent-action-guard check --action '{"type":"file","path":".github/workflows/ci.yml","args":["write"]}'
```

Warn or block before the write lands.

### Network call screening

```bash
agent-action-guard check --action '{"type":"network","url":"https://pastebin.com/raw/abc","method":"POST"}'
```

Credential-exfil domains are blocked by `network-exfil-domains`.

### Long-running guard service

```bash
pip install -e ".[serve]"
agent-action-guard serve --port 9099 --log guard.jsonl
```

Agents call `POST /check`; streaming clients subscribe to `GET /events`.

### Benchmark regression gate

```bash
agent-action-guard bench --output bench_report.json
```

Fails (exit 1) when dangerous block-rate drops below 80%.

## Development

### Commands

```bash
make install    # pip install -e ".[dev]"
make lint       # ruff check + format --check
make typecheck  # mypy guard cli
make test       # pytest -q
make verify     # lint + typecheck + test
```

### Test suite

| File                    | Coverage area                              |
|-------------------------|--------------------------------------------|
| `tests/test_schema.py`  | Action parsing, `to_hash` stability        |
| `tests/test_rules.py`   | Rule firing, allowlist, scoped `rm -rf`    |
| `tests/test_classifier.py` | Score bounds, merger determinism        |
| `tests/test_audit.py`   | JSONL append, `render_markdown`            |
| `tests/test_server.py`  | FastAPI TestClient (`/check`, `/health`)   |
| `tests/test_bench.py`   | Bench pipeline, block-rate ≥ 80%           |
| `tests/test_cli.py`     | Typer CliRunner for all commands           |

All tests run offline (no network, no ML model).

### Project tree

```
agent-action-guard/
├── cli/main.py              # Typer entry: check, serve, audit, bench, version
├── guard/
│   ├── __init__.py          # evaluate() facade, __version__
│   ├── schema.py            # pydantic Action model
│   ├── decision.py          # Verdict + Decision
│   ├── rules.py             # rule engine (28 rules)
│   ├── classifier.py        # scorer + merger
│   ├── audit.py             # JSONL + markdown
│   ├── bench.py             # bench metrics
│   └── server.py            # FastAPI
├── eval/dataset.py          # labeled bench dataset
├── tests/                   # pytest suite
├── .github/workflows/ci.yml
├── pyproject.toml
├── Makefile
├── README.md
└── CHANGELOG.md
```

### Adding a new rule

1. Open `guard/rules.py` and add a `Rule` entry with `rule_id`, `name`, `severity`, `remediation`, and `matcher`.
2. Implement `matcher(action: Action) -> bool` using type-specific fields (`command`, `url`, `path`, `tool`).
3. Register the rule in the `RULES` list.
4. Add paired tests in `tests/test_rules.py` — one dangerous action that triggers, one benign action that passes.
5. Add labeled samples to `eval/dataset.py` and re-run `agent-action-guard bench`.

## FAQ

**Will this block legitimate development commands?**

Rules target high-risk patterns (`rm -rf`, credential paths, exfil hosts). Benign commands like `echo`, `npm test`, and read-only file access pass. Tune with YAML allowlists for scoped exceptions (e.g. `rm -rf /tmp/build` in CI).

**Does the classifier call external APIs?**

No. `Classifier` uses deterministic weighted heuristics — fully offline and reproducible.

**What Python versions are supported?**

Python 3.11 and newer (`requires-python = ">=3.11"`).

**Can I run this in production?**

Yes, with your own allowlist policy. The bench harness targets ≥80% block-rate on dangerous actions with 0% false positives on the curated benign set.

**How is `action_hash` computed?**

Canonical JSON (`sort_keys=True`, compact separators) of the `Action` model is SHA-256 hashed. Identical payloads always produce the same hash.

**What does the allowlist do?**

Listed `rules` and `commands` downgrade matched decisions one level: `block` → `warn`, `warn` → `allow`.

**Is network access required?**

No. Evaluation is fully local. `serve` only listens on the configured host/port (default `127.0.0.1:9099`).

**How does this compare to human review?**

Automated screening at scale — similar to auto-mode classifiers — with auditable JSONL logs for post-incident review.

**Where do MCP tool calls fit?**

`Action.type = "mcp"` with `tool` and `tool_args`. Dangerous MCP tool names (`execute`, `delete_*`, etc.) trigger block or warn rules.

**What runs in CI?**

GitHub Actions runs `ruff check`, `ruff format --check`, `mypy guard cli`, and `pytest -q` on Python 3.11.

## Resources

- [Anthropic — Claude Code](https://docs.anthropic.com/en/docs/claude-code) — agent auto-execution context
- [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) — tool-call surface guarded by this project
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — agent security risks
- [FastAPI](https://fastapi.tiangolo.com/) — HTTP layer for `serve`
- [Pydantic v2](https://docs.pydantic.dev/) — `Action` schema validation

## License + Footer

MIT License — see [LICENSE](LICENSE).

**agent-action-guard** — screen agent actions before they run.

Repository: [https://github.com/vikasudasi/agent-action-guard](https://github.com/vikasudasi/agent-action-guard)

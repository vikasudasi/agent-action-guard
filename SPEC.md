# agent-action-guard — Multi-Task SPEC

Build **agent-action-guard**: a local, auditable action-safety guard that screens an AI
agent's proposed tool/action calls and returns `allow` / `block` / `warn` verdicts with
a reason and confidence before auto-execution. It reproduces the trust layer behind
Anthropic's Claude Code auto-mode (auto-approval on by default Aug 14, 2026), whose
classifier blocks 80%+ of dangerous queries vs ~14% for human review.

## README

### Purpose
As AI agents gain auto-execution powers (shell, file, network, git, MCP tool calls), the
window between an agent deciding to act and the action actually executing has collapsed.
`agent-action-guard` is a drop-in decision layer that inspects a proposed action and
returns a structured verdict (`allow` / `block` / `warn`) with a classifiable reason and
confidence — before the action runs. It ships a deterministic rule engine (15+ dangerous
action signatures), an optional classifier for confidence, a FastAPI/SSE serve endpoint
for agents to call, an audit log (JSONL + markdown report), and a bench harness that
measures block-rate on dangerous queries (target ≥80%).

### Structure
```
agent-action-guard/
├── cli/main.py              # Typer entry: check, serve, audit, bench, version
├── guard/
│   ├── __init__.py
│   ├── schema.py            # pydantic Action model (single source of truth)
│   ├── rules.py             # deterministic dangerous-action signature engine
│   ├── classifier.py        # optional learned/local scorer merged for confidence
│   ├── audit.py             # JSONL writer + markdown report generator
│   └── server.py            # FastAPI/SSE endpoint
├── eval/
│   └── dataset.py           # labeled dangerous/benign action dataset for bench
├── tests/                   # pytest suite
├── .github/workflows/ci.yml # lint + test on push/PR
├── pyproject.toml
├── Makefile
├── README.md
└── CHANGELOG.md
```

### Optional Dependency Groups
- `pip install -e ".[serve]"` — FastAPI/uvicorn endpoint + audit
- `pip install -e ".[dev]"` — pytest, ruff, mypy for development
- `pip install -e ".[all]"` — everything

## README Generation (Required)

After the scaffold task, generate a production-quality `README.md` covering ALL 14
sections below. This is **not optional** — the default Cursor stub (~30 lines) is
unacceptable. Verify every quoted command produces the shown output; fix the README (not
the output) if they differ. Push the README as a standalone commit before feature work.

### Required Sections
1. **Header** — tool name + emoji, one-liner, badges (CI, Python versions, license).
2. **The Problem** — why this exists, concrete stakes, what trend makes it urgent.
3. **Quickstart** — 2–3 copy-pasteable commands producing visible output fast.
4. **Table of Contents** — only if README exceeds ~200 lines.
5. **Installation** — PyPI + source install + `version` verify command.
6. **CLI Reference** — every command with signature, options table, real output examples.
7. **Output Formats** — JSON verdict structure, rich table, JSONL audit line.
8. **Feature / Detection Layers** — table: | Module | What It Checks | Example |
9. **Architecture** — ASCII pipeline diagram + numbered explanation steps.
10. **Use Cases** — 3–4 real-world scenarios with copy-pasteable commands.
11. **Development** — test/lint commands, project tree, "Adding a new rule" guide.
12. **FAQ** — 5–10 questions (false positives, platform support, production readiness).
13. **Resources** — links to Anthropic/agent-safety references and related tools.
14. **License + Footer** — MIT, tagline, repo link.

Style: technical but not dry; no "easy/simple/just"; every command shows real output;
tables with aligned columns; one emoji per header max; copy-paste first.

## MCP

### Serve Endpoint
`agent-action-guard serve --port 9099` runs a FastAPI + SSE endpoint:
- `POST /check` — body: `{type, args, cwd}` → JSON verdict `{verdict, reason, confidence, action_hash}`.
- `GET /events` — SSE stream of verdicts for streaming agents.
- `GET /health` — liveness.

Use FastAPI + uvicorn. Keep handlers thin: parse Action → call decision
(`rules.evaluate` + optional `classifier.score`) → write audit → return verdict.

### Key SDKs
- pydantic v2 — Action schema + validation
- Typer — CLI
- FastAPI + uvicorn — serve endpoint
- rich — terminal output
- PyYAML — allowlist config

## Coding

### Priority Order
Task 1 (scaffold + CLI + schema + README) → Task 2 (rules + classifier) → Task 3 (serve + audit) → Task 4 (eval/bench) → Task 5 (tests + CI + docs polish).

### Environment
- Python 3.11+
- Working dir: `/root/workspace/agent-action-guard`
- GitHub repo: `https://github.com/vikasudasi/agent-action-guard`
- Tooling: pytest + pytest-cov, ruff, mypy
- Must NOT use setup.py — pyproject.toml only.
- Do not leave TODO/stub comments. No fake test data.

---

## Task 1: Scaffold + CLI Framework + Action Schema + README

Deliver a working skeleton with the CLI dispatch and the pydantic `Action` schema.

**Files:**
- `pyproject.toml` — `[project] name = "agent-action-guard"`, `requires-python = ">=3.11"`,
  dependencies: `typer`, `pydantic>=2`, `rich`, `PyYAML`; optional `serve` extra:
  `fastapi`, `uvicorn`; `dev` extra: `pytest`, `pytest-cov`, `ruff`, `mypy`.
  `[project.scripts] agent-action-guard = "cli.main:app"`. Set `[tool.ruff] line-length=100`.
- `guard/__init__.py` — export `__version__`.
- `guard/schema.py` — pydantic `Action` model:
  - `type: Literal["shell","file","network","mcp","git"]`
  - `command: str | None` (shell/git command string)
  - `args: list[str]` (tokenized args, default `[]`)
  - `path: str | None` (file path)
  - `url: str | None` (network URL)
  - `method: str | None` (http method)
  - `tool: str | None` (mcp tool name)
  - `tool_args: dict | None` (mcp tool args)
  - `cwd: str = "."`
  - `source: str | None` (origin agent, optional)
  - method `to_hash()` returning a stable sha256 hex of the serialized json.
- `guard/decision.py` — `Verdict` Literal `allow|block|warn`; dataclass `Decision` with
  fields `verdict, reason, confidence, action_hash, rule_id: str|None`.
- `cli/main.py` — Typer app `app = typer.Typer(...)`. Subcommands:
  - `check --action "<json>" [--allowlist path]` → parse Action, call a `guard.evaluate(action)` 
    facade (stub for now returning `Decision("allow","no rules matched",0.5,hash,None)`), print
    rich verdict. **This task: wire the stub path so the CLI runs end-to-end.**
  - `serve --port 9099` — **stub**: raise NotImplementedError("serve implemented in Task 3")` — but
    still registered and listed in help.
  - `audit --log guard.jsonl` — **stub**: raise NotImplementedError.
  - `bench` — **stub**: raise NotImplementedError.
  - `version` — print `__version__`.
- `Makefile` — targets: `install`, `lint` (ruff check ., ruff format --check .), `typecheck`
  (mypy), `test` (pytest -q), `verify` (all four).
- `.github/workflows/ci.yml` — on push/PR: setup-python@v5 with python 3.11, pip install -e
  ".[dev]", run ruff check ., mypy, pytest.
- `CHANGELOG.md` — entry for 0.1.0.
- `README.md` — full 14-section production-quality README (see README Generation above).

**Acceptance:** `agent-action-guard --help` lists check/serve/audit/bench/version;
`agent-action-guard check --action '{"type":"shell","command":"echo hi"}'` returns
`allow`; `agent-action-guard version` prints a version; ruff passes; `python -c
"from guard.schema import Action"` imports clean.

## Task 2: Rule Engine + Classifier (core decision logic)

### Task 2a: Rule Engine (`guard/rules.py`)
A registry of ≥15 deterministic dangerous-action signature rules. Each rule returns
`Decision` (verdict block|warn, reason, rule_id) when its predicate matches an `Action`.

Rule categories to cover (≥15 total):
1. `rm -rf` on a path (shell) — block
2. credential/token exfil to known domains (network, e.g. pastie, transfer.sh, webhook.site,
   *.bin, 0x0.st, paste targets) — block
3. `curl ... | sh` / `curl ... | bash` (shell) — block
4. chmod 777 / chmod +s on security files (`/etc/shadow`, `~/.ssh/*`, credential files) — block
5. destructive git op: `git push --force`, `git reset --hard`, `git clean -fd` (git) — block
6. writing into `~/.ssh` or `~/.aws` or credential dirs (file) — block
7. `sudo` with destructive targets (`rm -rf /`, `mkfs`, `dd of=/dev/sd`) (shell) — block
8. curl/wget to external host then pipe/execute (network+shell) — block
9. exfil of `.env` / credential file content over the network (network/file) — block
10. `kill -9` of system/unknown processes, or broad pkill (shell) — warn
11. deleting database / data dirs (`DROP TABLE`, `DROP DATABASE`, rm of db files) (shell/file) — block
12. reading sensitive files (`/etc/shadow`, `.aws/credentials`, `.env`, `.pem`/`.key`) (file) — warn
13. MCP tool calls to dangerous tools (tool names like `execute`, `exec`, `shell`,
    `run_code`, `delete_`, `drop_`) (mcp) — warn/block
14. `chmod`/`chown` on system dirs (file) — warn
15. arbitrary `--eval` / codeeexec flags to interpreters (`python -c`, `node -e`) (shell) — warn
16. redirect to `/dev/null` hiding errors on mutating ops (shell) — warn
17. network POST to arbitrary webhook/callback hosts with body (network) — warn
18. `pip install` from unknown/git+https sources (shell) — warn

Implement:
- `RULES: list[Rule]` where Rule is a dataclass `{rule_id, name, severity(block|warn), matcher}`.
- `evaluate(action) -> list[Decision]` scanning all rules, highest severity wins (block > warn > allow).
- `load_allowlist(path) -> set[str]` reading YAML `rules: [rule_id,...]` and `commands: [...]`;
  allowlisted rule_ids downgrade block→warn→allow appropriately.
- `evaluate_with_allowlist(action, allowlist_file|None) -> Decision` returning a single final Decision.
- A `summarize(decisions)` helper.

### Task 2b: Classifier (`guard/classifier.py`)
Optional learned/local-model scorer merged with rules for final confidence.
- `class Classifier:` with `score(action) -> float` (0..1 dangerousness) using a lightweight
  feature heuristic (no heavy model required — extract features: contains `rm -rf`,
  contains `| sh`, network exfil markers, credential path substrings, destructive git verbs,
  mcp dangerous tool substrings) returning a calibrated 0..1 score.
- `class RuleClassifierMerger:` merges a list of rule Decisions + classifier score into a
  final `Decision` with `confidence`, using a documented rule (block if any rule blocks and
  classifier ≥ threshold; warn similarly; allow otherwise). Keep deterministic/reproducible.

Note: The bench harness (Task 4) reports ≥80% block-rate on dangerous queries using these.

## Task 3: Serve Endpoint + Audit Logging

- `guard/audit.py` — `AuditLog(log_path)` with `append(decision: dict)` writing a JSONL line
  (timestamp iso, action_hash, verdict, reason, confidence, rule_id, action snapshot) and
  `render_markdown(log_path)` generating a summary markdown report (counts by verdict,
  per-rule hit table, recent decisions).
- `guard/server.py` — FastAPI app:
  - `POST /check` body → `{verdict, reason, confidence, action_hash}` (calls decision engine + audit).
  - `GET /events` — SSE `text/event-stream` streaming verdicts as they arrive (use a shared
    in-memory broker fed by `/check`).
  - `GET /health` → `{"status":"ok"}`.
- `cli/main.py` `serve` — start uvicorn on port (default 9099, host 127.0.0.1), wire audit log.
- `cli/main.py` `audit --log` — render the markdown report from the JSONL log to stdout.

## Task 4: Eval Harness & Bench

- `eval/dataset.py` — labeled dataset `DATASET: list[dict]` of actions: at least 40 benign
  and 40 dangerous actions, each with `label: "dangerous"|"benign"` and an Action payload.
  Dangerous cases should exercise every rule category healthily.
- `guard/bench.py` or fold into `cli/main.py` `bench` — run the dataset through the decision
  engine, compute: precision, recall, F1, block-rate on dangerous queries (block+warn counted
  as blocked), false-positive rate on benign. Target block-rate on dangerous ≥80%.
  Emit a JSON report file `bench_report.json` and a markdown table to stdout.

## Task 5: Tests, CI & Documentation

- `tests/test_schema.py` — Action parsing + `to_hash` stability.
- `tests/test_rules.py` — each rule category: a dangerous action blocks, a benign one passes;
  allowlist override downgrades.
- `tests/test_classifier.py` — classifier score bounds; merger determinism.
- `tests/test_audit.py` — JSONL append + markdown render (tmp_path).
- `tests/test_server.py` — FastAPI TestClient: `/check` returns verdict, `/health` ok.
- `tests/test_bench.py` — bench pipeline runs on a small slice, block-rate ≥0.8 on dangerous.
- `tests/test_cli.py` — Typer CliRunner: `version`, `check` happy path.
- Target coverage ≥80%. GitHub Actions CI runs lint+mypy+test.

### README Enforcement
- `wc -l README.md` ≥ 150 after Task 1.
- Every command in README produces the shown output.

### Must NOT Do
- No fake test data (bench dataset must be real, curated actions).
- No TODO/stub comments left in final shipped code.
- No setup.py.
- Do not hand-write core logic in the agent loop — implement via Cursor CLI.

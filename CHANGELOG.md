# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Production integration layer: `agent-action-guard hooks install --target claude-code|cursor|kiro` writes harness hook configs and a per-target adapter script (`hooks/`) with local + `AGENT_ACTION_GUARD_URL` POST `/check` modes.
- `guard/adapters.py` maps Claude Code / Cursor / Kiro pre-tool-use hook payloads onto the canonical `Action` schema; adapters emit harness-native deny signals (Claude Code/Cursor expressive deny JSON, Kiro exit 2) and fail open on errors.
- Adapter integration section in README with a worked Claude Code example (Cursor reuses the same shape).
- `tests/test_adapters.py` (hook-payload → Action mapping) and `tests/test_hooks_cli.py` (CLI + per-target end-to-end adapter smokes).

### Changed

- Comprehensive pytest suite: schema, rules (including allowlist and scoped `rm -rf /tmp/build`), classifier merge, audit JSONL/markdown, FastAPI TestClient server tests, bench harness, and CLI (Typer CliRunner).
- `httpx` dev dependency for offline `TestClient` server tests.
- CI workflow steps for `ruff format --check` and `serve` extra install for FastAPI tests.
- README updated for full `check` / `serve` / `audit` / `bench` workflows, HTTP API curl examples, and current rule/classifier behavior.
- GitHub Actions CI installs `.[dev,serve]` and runs lint, format check, mypy, and pytest.

## [0.1.0] - 2026-08-12

### Added

- Initial scaffold: pydantic `Action` schema, `Decision` / `Verdict` types, and Typer CLI.
- Rule engine with 19 deterministic dangerous-action signatures and YAML allowlist support.
- Offline heuristic classifier with rule/classifier merge policy.
- FastAPI serve endpoint (`POST /check`, `GET /events` SSE, `GET /health`) and JSONL audit logging with markdown reports.
- Labeled eval dataset (42 dangerous, 45 benign) and bench harness with precision/recall/F1 metrics.
- `check`, `serve`, `audit`, `bench`, and `version` CLI commands.
- Makefile (`install`, `lint`, `typecheck`, `test`, `verify`).
- GitHub Actions CI workflow (ruff, mypy, pytest).
- Production README and project SKILL documentation.

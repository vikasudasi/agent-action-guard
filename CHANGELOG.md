# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive pytest suite: schema, rules (including allowlist and scoped `rm -rf /tmp/build`), classifier merge, audit JSONL/markdown, FastAPI TestClient server tests, bench harness, and CLI (Typer CliRunner).
- `httpx` dev dependency for offline `TestClient` server tests.
- CI workflow steps for `ruff format --check` and `serve` extra install for FastAPI tests.

### Changed

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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-12

### Added

- Initial scaffold: pydantic `Action` schema, `Decision` / `Verdict` types, and Typer CLI.
- `check` command with stub `guard.evaluate` returning allow verdicts.
- Stub commands `serve`, `audit`, and `bench` registered for future tasks.
- `version` command, Makefile (`install`, `lint`, `typecheck`, `test`, `verify`).
- GitHub Actions CI workflow (ruff, mypy, pytest).
- Production README and project SKILL documentation.

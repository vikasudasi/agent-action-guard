#!/usr/bin/env bash
cd "$(dirname "$0")"
PYTHONPATH=. .venv/bin/python -c 'from eval.dataset import DATASET; from guard.bench import run_bench, format_markdown_table, write_report; r=run_bench(DATASET); write_report(r, "bench_report.json"); print(format_markdown_table(r))'

"""Tests for guard.bench harness metrics."""

from __future__ import annotations

from eval.dataset import DATASET
from guard.bench import format_markdown_table, run_bench, write_report


def _dangerous_slice() -> list[dict]:
    return [entry for entry in DATASET if entry["label"] == "dangerous"][:20]


def _mixed_slice() -> list[dict]:
    dangerous = [entry for entry in DATASET if entry["label"] == "dangerous"][:25]
    benign = [entry for entry in DATASET if entry["label"] == "benign"][:25]
    return dangerous + benign


class TestBenchHarness:
    def test_dangerous_slice_meets_block_rate_target(self) -> None:
        report = run_bench(_dangerous_slice(), use_classifier=True)
        assert report["metrics"]["dangerous_block_rate"] >= 0.8
        assert report["meets_target"] is True

    def test_full_dataset_meets_block_rate_target(self) -> None:
        report = run_bench(DATASET, use_classifier=True)
        assert report["metrics"]["dangerous_block_rate"] >= 0.8
        assert report["meets_target"] is True

    def test_run_bench_without_classifier(self) -> None:
        report = run_bench(_mixed_slice(), use_classifier=False)
        assert report["metrics"]["total"] == 50
        assert "precision" in report["metrics"]
        assert "recall" in report["metrics"]

    def test_write_report_and_markdown_table(self, tmp_path) -> None:
        report = run_bench(_mixed_slice())
        output = tmp_path / "bench_report.json"
        write_report(report, output)
        assert output.exists()
        table = format_markdown_table(report)
        assert "# Bench Report" in table
        assert "Overall metrics" in table
        assert "Meets target" in table

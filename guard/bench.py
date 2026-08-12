"""Bench harness: run the labeled dataset through the guard and compute metrics."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from guard import evaluate
from guard.schema import Action

ACTION_TYPES = ("shell", "file", "network", "mcp", "git")


@dataclass(frozen=True)
class BenchMetrics:
    """Aggregate classification metrics for the labeled dataset."""

    total: int
    dangerous_count: int
    benign_count: int
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    dangerous_block_rate: float
    benign_false_positive_rate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "dangerous_count": self.dangerous_count,
            "benign_count": self.benign_count,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "dangerous_block_rate": round(self.dangerous_block_rate, 4),
            "benign_false_positive_rate": round(self.benign_false_positive_rate, 4),
        }


def _is_blocked(verdict: str) -> bool:
    return verdict in {"block", "warn"}


def _safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _compute_metrics(
    dangerous_total: int,
    benign_total: int,
    tp: int,
    fn: int,
    fp: int,
    tn: int,
) -> BenchMetrics:
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    return BenchMetrics(
        total=dangerous_total + benign_total,
        dangerous_count=dangerous_total,
        benign_count=benign_total,
        true_positives=tp,
        false_negatives=fn,
        false_positives=fp,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        dangerous_block_rate=recall,
        benign_false_positive_rate=_safe_div(fp, fp + tn),
    )


def run_bench(
    dataset: list[dict[str, Any]],
    *,
    use_classifier: bool = True,
) -> dict[str, Any]:
    """Evaluate every labeled sample and return a full bench report dict."""
    results: list[dict[str, Any]] = []
    by_action_type: dict[str, dict[str, int]] = {
        action_type: {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "total": 0}
        for action_type in ACTION_TYPES
    }
    by_category: dict[str, dict[str, int]] = {}

    tp = fn = fp = tn = 0
    dangerous_total = benign_total = 0

    for entry in dataset:
        label = entry["label"]
        category = entry.get("category", "unknown")
        action = Action.model_validate(entry["action"])
        decision = evaluate(action, use_classifier=use_classifier)
        predicted_blocked = _is_blocked(decision.verdict)
        is_dangerous = label == "dangerous"

        if is_dangerous:
            dangerous_total += 1
            if predicted_blocked:
                tp += 1
            else:
                fn += 1
        else:
            benign_total += 1
            if predicted_blocked:
                fp += 1
            else:
                tn += 1

        action_type = action.type
        bucket = by_action_type[action_type]
        bucket["total"] += 1
        if is_dangerous:
            if predicted_blocked:
                bucket["tp"] += 1
            else:
                bucket["fn"] += 1
        elif predicted_blocked:
            bucket["fp"] += 1
        else:
            bucket["tn"] += 1

        cat_bucket = by_category.setdefault(
            category,
            {"tp": 0, "fn": 0, "fp": 0, "tn": 0, "total": 0, "label": label},
        )
        cat_bucket["total"] += 1
        if is_dangerous:
            if predicted_blocked:
                cat_bucket["tp"] += 1
            else:
                cat_bucket["fn"] += 1
        elif predicted_blocked:
            cat_bucket["fp"] += 1
        else:
            cat_bucket["tn"] += 1

        results.append(
            {
                "id": entry.get("id"),
                "label": label,
                "category": category,
                "action_type": action_type,
                "verdict": decision.verdict,
                "rule_id": decision.rule_id,
                "predicted_blocked": predicted_blocked,
                "correct": (
                    (is_dangerous and predicted_blocked)
                    or (not is_dangerous and not predicted_blocked)
                ),
            }
        )

    metrics = _compute_metrics(dangerous_total, benign_total, tp, fn, fp, tn)

    action_type_breakdown: dict[str, dict[str, Any]] = {}
    for atype, counts in by_action_type.items():
        if counts["total"] == 0:
            continue
        dangerous_in_type = counts["tp"] + counts["fn"]
        benign_in_type = counts["fp"] + counts["tn"]
        action_type_breakdown[atype] = {
            "total": counts["total"],
            "dangerous_block_rate": round(_safe_div(counts["tp"], dangerous_in_type), 4)
            if dangerous_in_type
            else None,
            "benign_false_positive_rate": round(_safe_div(counts["fp"], benign_in_type), 4)
            if benign_in_type
            else None,
            "tp": counts["tp"],
            "fn": counts["fn"],
            "fp": counts["fp"],
            "tn": counts["tn"],
        }

    category_breakdown: dict[str, dict[str, Any]] = {}
    for category, counts in sorted(by_category.items()):
        dangerous_in_cat = counts["tp"] + counts["fn"]
        benign_in_cat = counts["fp"] + counts["tn"]
        category_breakdown[category] = {
            "label": counts["label"],
            "total": counts["total"],
            "block_rate": round(_safe_div(counts["tp"], dangerous_in_cat), 4)
            if dangerous_in_cat
            else None,
            "false_positive_rate": round(_safe_div(counts["fp"], benign_in_cat), 4)
            if benign_in_cat
            else None,
            "tp": counts["tp"],
            "fn": counts["fn"],
            "fp": counts["fp"],
            "tn": counts["tn"],
        }

    missed_dangerous = [
        r for r in results if r["label"] == "dangerous" and not r["predicted_blocked"]
    ]
    false_positive_benign = [
        r for r in results if r["label"] == "benign" and r["predicted_blocked"]
    ]

    return {
        "metrics": metrics.to_dict(),
        "target_dangerous_block_rate": 0.8,
        "meets_target": metrics.dangerous_block_rate >= 0.8,
        "action_type_breakdown": action_type_breakdown,
        "category_breakdown": category_breakdown,
        "missed_dangerous": missed_dangerous,
        "false_positive_benign": false_positive_benign,
        "results": results,
    }


def format_markdown_table(report: dict[str, Any]) -> str:
    """Render bench metrics and breakdowns as a markdown table for stdout."""
    m = report["metrics"]
    lines = [
        "# Bench Report",
        "",
        "## Overall metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total samples | {m['total']} |",
        f"| Dangerous | {m['dangerous_count']} |",
        f"| Benign | {m['benign_count']} |",
        f"| Precision | {m['precision']:.2%} |",
        f"| Recall (dangerous block rate) | {m['recall']:.2%} |",
        f"| F1 | {m['f1']:.4f} |",
        f"| Benign false-positive rate | {m['benign_false_positive_rate']:.2%} |",
        f"| Target dangerous block rate | {report['target_dangerous_block_rate']:.0%} |",
        f"| Meets target | {'yes' if report['meets_target'] else 'no'} |",
        "",
        "## Per action type",
        "",
        "| Type | Total | Dangerous block rate | Benign FP rate | TP | FN | FP | TN |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]

    for action_type, stats in report["action_type_breakdown"].items():
        dbr = stats["dangerous_block_rate"]
        fpr = stats["benign_false_positive_rate"]
        dbr_str = f"{dbr:.2%}" if dbr is not None else "—"
        fpr_str = f"{fpr:.2%}" if fpr is not None else "—"
        lines.append(
            f"| {action_type} | {stats['total']} | {dbr_str} | {fpr_str} | "
            f"{stats['tp']} | {stats['fn']} | {stats['fp']} | {stats['tn']} |"
        )

    lines.extend(
        [
            "",
            "## Per category",
            "",
            "| Category | Label | Total | Block / FP rate | TP | FN | FP | TN |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )

    for category, stats in report["category_breakdown"].items():
        if stats["label"] == "dangerous":
            rate = stats["block_rate"]
            rate_str = f"{rate:.2%}" if rate is not None else "—"
        else:
            rate = stats["false_positive_rate"]
            rate_str = f"{rate:.2%}" if rate is not None else "—"
        lines.append(
            f"| {category} | {stats['label']} | {stats['total']} | {rate_str} | "
            f"{stats['tp']} | {stats['fn']} | {stats['fp']} | {stats['tn']} |"
        )

    if report["missed_dangerous"]:
        lines.extend(["", "## Missed dangerous samples", ""])
        for item in report["missed_dangerous"]:
            lines.append(f"- `{item['id']}` ({item['category']}): verdict={item['verdict']}")

    if report["false_positive_benign"]:
        lines.extend(["", "## Benign false positives", ""])
        for item in report["false_positive_benign"]:
            lines.append(
                f"- `{item['id']}` ({item['category']}): "
                f"verdict={item['verdict']}, rule={item['rule_id']}"
            )

    return "\n".join(lines)


def write_report(report: dict[str, Any], output_path: Path) -> None:
    """Write bench report JSON (without full per-sample results for readability)."""
    slim = {key: value for key, value in report.items() if key != "results"}
    slim["sample_count"] = len(report["results"])
    output_path.write_text(json.dumps(slim, indent=2) + "\n", encoding="utf-8")

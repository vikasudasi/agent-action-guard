from eval.dataset import DATASET
from guard.bench import format_markdown_table, run_bench

report = run_bench(DATASET)
print(format_markdown_table(report))
print("meets_target:", report["meets_target"])
if report["missed_dangerous"]:
    print("MISSED:", report["missed_dangerous"])
if report["false_positive_benign"]:
    print("FP:", report["false_positive_benign"])

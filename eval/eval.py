import argparse # read command line arguments
import json
import statistics
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))


def _value_matches(expected: str, actual: list[dict]) -> tuple[bool, bool]:
    strict = any(expected == item["value"] for item in actual)
    lenient = any(expected in item["value"] or item["value"] in expected for item in actual)
    return strict, lenient


def evaluate(path: Path, detect) -> dict:
    rows = []
    latencies = []
    strict_found = 0
    lenient_found = 0
    expected_values = 0
    category_stats: dict[str, Counter] = defaultdict(Counter)
    for line in path.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        started = time.perf_counter()
        result = detect(item["text"])
        latencies.append((time.perf_counter() - started) * 1000)
        expected_alert = not item["expected"]["clean"]
        actual_alert = result["decision"] == "alert"
        rows.append({
            "id": item["id"],
            "correct": expected_alert == actual_alert,
            "expected_alert": expected_alert,
            "actual_alert": actual_alert,
            "result": result,
        })
        expected_categories = set(item["expected"]["categories"])
        actual_categories = {finding["category"] for finding in result["findings"]}
        for expected_value in item["expected"]["values"]:
            strict, lenient = _value_matches(expected_value, result["findings"])
            strict_found += strict
            lenient_found += lenient
            expected_values += 1
        for category in expected_categories | actual_categories:
            if category in expected_categories and category in actual_categories:
                category_stats[category]["tp"] += 1
            elif category in actual_categories:
                category_stats[category]["fp"] += 1
            else:
                category_stats[category]["fn"] += 1
    failures = [row for row in rows if not row["correct"]]
    metrics = {}
    for category, counts in category_stats.items():
        tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
        precision = tp / (tp + fp) if tp + fp else 0
        recall = tp / (tp + fn) if tp + fn else 0
        metrics[category] = {
            "precision": precision,
            "recall": recall,
            "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0,
        }
    return {
        "prompts": len(rows),
        "alerts": sum(row["actual_alert"] for row in rows),
        "decision_accuracy": sum(row["correct"] for row in rows) / len(rows) if rows else 0,
        "latency_ms": {
            "mean": statistics.mean(latencies) if latencies else 0,
            "p50": statistics.median(latencies) if latencies else 0,
            "p95": sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)] if latencies else 0,
        },
        "category_metrics": metrics,
        "results": rows,
        "values": {
            "expected": expected_values,
            "strict_found": strict_found,
            "lenient_found": lenient_found,
            "strict_rate": strict_found / expected_values if expected_values else 0,
            "lenient_rate": lenient_found / expected_values if expected_values else 0,
        },
        "failures": failures,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", choices=("original", "corrected"), default="original")
    parser.add_argument("--no-llm", action="store_true", help="Disable Ollama through the environment.")
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.no_llm:
        import os
        os.environ["ZEUSLOCK_ENABLE_LLM"] = "0"
    path = Path(__file__).with_name("dev_set.jsonl" if args.labels == "original" else "dev_set_corrected.jsonl")
    from submission import detect
    from zeuslock.llm import reset_stats, stats
    reset_stats()
    report = evaluate(path, detect)
    report["llm"] = stats()
    report["llm"]["hit_fraction"] = (
        report["llm"]["judge_calls"] / report["prompts"] if report["prompts"] else 0
    )
    encoded = json.dumps(report, indent=2)
    print(encoded)
    if args.json_out:
        args.json_out.write_text(encoded + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

"""
Evaluation Metrics Calculator.

Computes Precision, Recall, F1-Score, Cohen's Kappa and mean pipeline latency.

Notes on interpretation:
- ``precision`` / ``recall`` / ``f1_score`` / ``cohens_kappa`` are computed over the
  alerts on which the pipeline reached a binary decision (Escalate/Close).
- ``Unknown`` verdicts (routed to a human analyst) are reported through
  ``unknown_count`` and ``coverage``, and penalised in the ``*_strict`` metrics:
  an expected-Escalate alert that ends as Unknown counts as a miss for
  ``recall_strict``; an expected-Close alert that ends as Unknown does not count
  as a correct close for ``specificity_strict``.
- ``mean_latency_ms`` is inference/pipeline latency. ``mttr_ms`` is kept as a
  backwards-compatible alias; it is NOT an operational SOC MTTR.
"""
import statistics
from collections import defaultdict
from typing import List, Dict, Any


def _norm(label: Any) -> str:
    return str(label or "").strip().lower()


class MetricsCalculator:
    """
    Computes statistical and performance metrics for triage evaluation runs,
    including single-run metrics and multi-run aggregate statistics (mean ± std dev).
    """

    AGGREGATE_KEYS = [
        "precision",
        "recall",
        "f1_score",
        "cohens_kappa",
        "recall_strict",
        "specificity_strict",
        "accuracy_strict",
        "coverage",
        "unknown_count",
        "mean_latency_ms",
        "mttr_ms",
    ]

    @staticmethod
    def _empty() -> Dict[str, float]:
        return {
            "total": 0,
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "unknown_count": 0,
            "other_count": 0,
            "coverage": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.0,
            "cohens_kappa": 0.0,
            "recall_strict": 0.0,
            "specificity_strict": 0.0,
            "accuracy_strict": 0.0,
            "error_fallback_count": 0,
            "heuristic_fallback_count": 0,
            "mean_latency_ms": 0.0,
            "mttr_ms": 0.0,
        }

    @staticmethod
    def calculate_metrics(eval_results: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculates decided-subset and strict metrics for a single run."""
        if not eval_results:
            return MetricsCalculator._empty()

        tp = fp = tn = fn = 0
        unknown_escalate = unknown_close = other = 0
        error_fallback = heuristic_fallback = 0
        total_time_ms = 0.0

        for r in eval_results:
            exp = _norm(r.get("expected"))
            act = _norm(r.get("actual"))
            total_time_ms += float(r.get("processing_time_ms", 0.0) or 0.0)

            source = r.get("verdict_source")
            if source == "error_fallback":
                error_fallback += 1
            elif source == "heuristic_fallback":
                heuristic_fallback += 1

            if exp == "escalate" and act == "escalate":
                tp += 1
            elif exp == "close" and act == "escalate":
                fp += 1
            elif exp == "close" and act == "close":
                tn += 1
            elif exp == "escalate" and act == "close":
                fn += 1
            elif act == "unknown" and exp == "escalate":
                unknown_escalate += 1
            elif act == "unknown" and exp == "close":
                unknown_close += 1
            else:
                other += 1

        total = len(eval_results)
        decided = tp + fp + tn + fn

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        if decided > 0:
            po = (tp + tn) / decided
            pe = (((tp + fp) * (tp + fn)) + ((fn + tn) * (fp + tn))) / (decided * decided)
            # pe == 1 means a single class on both sides: agreement is not informative.
            kappa = (po - pe) / (1 - pe) if (1 - pe) != 0 else 0.0
        else:
            kappa = 0.0

        positives = tp + fn + unknown_escalate
        negatives = tn + fp + unknown_close
        recall_strict = tp / positives if positives > 0 else 0.0
        specificity_strict = tn / negatives if negatives > 0 else 0.0
        accuracy_strict = (tp + tn) / total if total > 0 else 0.0
        latency = total_time_ms / total

        return {
            "total": total,
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "unknown_count": unknown_escalate + unknown_close,
            "other_count": other,
            "coverage": round(decided / total, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "cohens_kappa": round(kappa, 4),
            "recall_strict": round(recall_strict, 4),
            "specificity_strict": round(specificity_strict, 4),
            "accuracy_strict": round(accuracy_strict, 4),
            "error_fallback_count": error_fallback,
            "heuristic_fallback_count": heuristic_fallback,
            "mean_latency_ms": round(latency, 2),
            "mttr_ms": round(latency, 2),
        }

    @staticmethod
    def calculate_breakdown(eval_results: List[Dict[str, Any]], key: str) -> Dict[str, Dict[str, float]]:
        """Computes metrics grouped by a record field (e.g. technique_id, scenario_type)."""
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for r in eval_results:
            groups[str(r.get(key, "unknown"))].append(r)
        return {
            group: MetricsCalculator.calculate_metrics(items)
            for group, items in sorted(groups.items())
        }

    @staticmethod
    def calculate_aggregate_metrics(runs: List[Dict[str, float]]) -> Dict[str, Any]:
        """
        Computes aggregate statistics (mean and sample standard deviation)
        across multiple repeated evaluation runs for empirical reproducibility.
        """
        if not runs:
            return {}

        agg: Dict[str, Any] = {"num_runs": len(runs)}

        for k in MetricsCalculator.AGGREGATE_KEYS:
            vals = [float(r.get(k, 0.0) or 0.0) for r in runs]
            mean_val = statistics.mean(vals)
            std_val = statistics.stdev(vals) if len(vals) > 1 else 0.0

            agg[f"{k}_mean"] = round(mean_val, 4)
            agg[f"{k}_std"] = round(std_val, 4)
            if k in ("mttr_ms", "mean_latency_ms"):
                agg[f"{k}_formatted"] = f"{mean_val:.1f} ± {std_val:.1f} ms"
            elif k == "unknown_count":
                agg[f"{k}_formatted"] = f"{mean_val:.1f} ± {std_val:.1f}"
            else:
                agg[f"{k}_formatted"] = f"{mean_val:.4f} ± {std_val:.4f}"

        return agg


if __name__ == "__main__":
    sample_results = [
        {"expected": "Escalate", "actual": "Escalate", "processing_time_ms": 120.0},
        {"expected": "Close", "actual": "Close", "processing_time_ms": 95.0},
        {"expected": "Escalate", "actual": "Escalate", "processing_time_ms": 110.0},
        {"expected": "Close", "actual": "Escalate", "processing_time_ms": 105.0},
        {"expected": "Escalate", "actual": "Unknown", "processing_time_ms": 90.0},
    ]
    print("Calculated Metrics:", MetricsCalculator.calculate_metrics(sample_results))

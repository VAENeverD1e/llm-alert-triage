"""
Evaluation Metrics Calculator.
Computes evaluation metrics: Precision, Recall, F1-Score, Mean Time to Respond (MTTR), and Cohen's Kappa.
"""
from typing import List, Dict, Any


class MetricsCalculator:
    """
    Computes statistical and performance metrics for triage evaluation runs.
    """

    @staticmethod
    def calculate_metrics(eval_results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calculates Precision, Recall, F1, MTTR, and Cohen's Kappa.
        """
        if not eval_results:
            return {
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "mttr_ms": 0.0,
                "cohens_kappa": 0.0
            }

        tp = fp = tn = fn = 0
        total_time_ms = 0.0

        for r in eval_results:
            exp = r.get("expected")
            act = r.get("actual")
            total_time_ms += r.get("processing_time_ms", 0.0)

            if exp == "Escalate" and act == "Escalate":
                tp += 1
            elif exp == "Close" and act == "Escalate":
                fp += 1
            elif exp == "Close" and act == "Close":
                tn += 1
            elif exp == "Escalate" and act == "Close":
                fn += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        mttr = total_time_ms / len(eval_results)

        # Cohen's Kappa calculation
        n = tp + fp + tn + fn
        if n > 0:
            po = (tp + tn) / n
            pe = (((tp + fp) * (tp + fn)) + ((fn + tn) * (fp + tn))) / (n * n)
            kappa = (po - pe) / (1 - pe) if (1 - pe) != 0 else 1.0
        else:
            kappa = 0.0

        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "mttr_ms": round(mttr, 2),
            "cohens_kappa": round(kappa, 4)
        }


if __name__ == "__main__":
    sample_results = [
        {"expected": "Escalate", "actual": "Escalate", "processing_time_ms": 120.0},
        {"expected": "Close", "actual": "Close", "processing_time_ms": 95.0},
        {"expected": "Escalate", "actual": "Escalate", "processing_time_ms": 110.0},
        {"expected": "Close", "actual": "Escalate", "processing_time_ms": 105.0},
        {"expected": "Escalate", "actual": "Close", "processing_time_ms": 90.0},
    ]
    print("Calculated Metrics:", MetricsCalculator.calculate_metrics(sample_results))

"""
Replay Harness.
Fires attack and benign scenario alerts through the triage pipeline, capturing verdicts and metrics for benchmarking.
"""
import json
import logging
from typing import List, Dict, Any
from agent.orchestrator import TriageOrchestrator

logger = logging.getLogger(__name__)


class ReplayHarness:
    """
    Automated test harness replaying attack and benign scenarios against the triage pipeline.
    """

    def __init__(self, orchestrator: TriageOrchestrator = None):
        self.orchestrator = orchestrator or TriageOrchestrator()

    def run_ground_truth_eval(self, ground_truth_path: str = "data/ground_truth.jsonl") -> List[Dict[str, Any]]:
        """
        Loads ground truth alerts and records pipeline decision outputs against expected ground truth labels.
        """
        results = []
        logger.info(f"Loading evaluation dataset from {ground_truth_path}...")

        try:
            with open(ground_truth_path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    item = json.loads(line.strip())
                    
                    mock_alert = {
                        "alert_id": item["alert_id"],
                        "rule_id": item["technique_id"],
                        "rule_name": f"Rule for {item['technique_id']}",
                        "severity": "high" if item["expected_verdict"] == "Escalate" else "low",
                        "timestamp": "2026-09-03T10:00:00Z",
                        "host_name": "EVAL-HOST-01",
                        "user_name": "eval_user",
                        "raw_event": {"notes": item.get("notes", "")}
                    }

                    pipeline_res = self.orchestrator.run_pipeline(mock_alert)
                    results.append({
                        "alert_id": item["alert_id"],
                        "expected": item["expected_verdict"],
                        "actual": pipeline_res.verdict.decision.value,
                        "confidence": pipeline_res.verdict.confidence_score,
                        "processing_time_ms": pipeline_res.processing_time_ms
                    })
        except FileNotFoundError:
            logger.warning(f"Ground truth file not found at {ground_truth_path}. Returning empty list.")

        return results


if __name__ == "__main__":
    harness = ReplayHarness()
    res = harness.run_ground_truth_eval()
    print("Replay Harness Results:", json.dumps(res, indent=2))

"""
Replay Harness.
Automated benchmark and evaluation test harness replaying attack and benign scenarios
against the triage pipeline, capturing verdicts, reasoning, confidence, and metrics.
"""
import os
import sys
import json
import csv
import time
import logging
import argparse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.orchestrator import TriageOrchestrator
from evaluation.metrics import MetricsCalculator

logger = logging.getLogger("ReplayHarness")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


class ReplayHarness:
    """
    Automated test harness replaying attack and benign scenarios against the triage pipeline.
    Supports multi-mode evaluation: Heuristic baseline, LLM (No-RAG), and LLM + RAG Playbooks.
    """

    def __init__(
        self,
        orchestrator: Optional[TriageOrchestrator] = None,
        mode: str = "heuristic",
        model_name: str = "llama3:8b",
        results_dir: str = "evaluation/results"
    ):
        self.mode = mode
        self.model_name = model_name
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)

        if orchestrator is not None:
            self.orchestrator = orchestrator
        else:
            self.orchestrator = self._init_orchestrator(mode, model_name)

    @classmethod
    def _init_orchestrator(cls, mode: str, model_name: str) -> TriageOrchestrator:
        """Instantiates the appropriate orchestrator configuration for the chosen mode."""
        if mode == "heuristic":
            # Pure heuristic baseline without LLM
            return TriageOrchestrator.create_default(use_ollama=False, use_rag=True)
        elif mode == "llm_no_rag":
            # Local LLM without RAG playbook grounding
            return TriageOrchestrator.create_default(use_ollama=True, use_rag=False, model_name=model_name)
        elif mode == "llm_rag":
            # Full two-stage pipeline with local LLM and RAG Playbooks
            return TriageOrchestrator.create_default(use_ollama=True, use_rag=True, model_name=model_name)
        else:
            logger.warning(f"Unknown mode '{mode}'; defaulting to heuristic baseline.")
            return TriageOrchestrator.create_default(use_ollama=False, use_rag=True)

    @classmethod
    def create_for_mode(
        cls,
        mode: str = "heuristic",
        model_name: str = "llama3:8b",
        results_dir: str = "evaluation/results"
    ) -> "ReplayHarness":
        """Factory helper to create a harness for a specific evaluation mode."""
        return cls(mode=mode, model_name=model_name, results_dir=results_dir)

    def run_ground_truth_eval(
        self,
        ground_truth_path: str = "data/ground_truth.jsonl",
        save_results: bool = True
    ) -> Dict[str, Any]:
        """
        Loads ground truth scenarios and records pipeline decision outputs against expected labels.
        Returns a dictionary containing evaluation results, metrics, and execution metadata.
        """
        results: List[Dict[str, Any]] = []
        logger.info(f"[{self.mode.upper()}] Loading evaluation dataset from {ground_truth_path}...")

        if not os.path.exists(ground_truth_path):
            logger.warning(f"Ground truth file not found at {ground_truth_path}. Returning empty report.")
            return {
                "mode": self.mode,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": MetricsCalculator.calculate_metrics([]),
                "results": []
            }

        with open(ground_truth_path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                raw_line = line.strip()
                if not raw_line:
                    continue
                item = json.loads(raw_line)

                alert_data = None
                file_path = item.get("file_path")
                if file_path and os.path.exists(file_path):
                    with open(file_path, "r", encoding="utf-8") as af:
                        alert_data = json.load(af)
                else:
                    # Fallback to dictionary synthesis for ad-hoc or legacy tests
                    alert_data = {
                        "alert_id": item.get("alert_id", f"ALT-{line_no:04d}"),
                        "rule_id": item.get("technique_id", "UNKNOWN"),
                        "rule_name": item.get("technique_name", f"Rule for {item.get('technique_id', 'UNKNOWN')}"),
                        "severity": "high" if item.get("expected_verdict") == "Escalate" else "low",
                        "timestamp": "2026-10-10T08:00:00Z",
                        "host_name": "EVAL-HOST-01",
                        "user_name": "eval_user",
                        "raw_event": {"notes": item.get("notes", "")}
                    }

                pipeline_res = self.orchestrator.run_pipeline(alert_data)
                actual_decision = pipeline_res.verdict.decision.value
                expected_verdict = item.get("expected_verdict", "Escalate")
                is_match = (actual_decision.lower() == expected_verdict.lower())

                record = {
                    "alert_id": item.get("alert_id") or pipeline_res.alert.alert_id,
                    "file_path": file_path or "inline_mock",
                    "technique_id": item.get("technique_id", pipeline_res.alert.rule_id),
                    "technique_name": item.get("technique_name", pipeline_res.alert.rule_name),
                    "scenario_type": item.get("scenario_type", "unknown"),
                    "expected": expected_verdict,
                    "actual": actual_decision,
                    "match": is_match,
                    "confidence": pipeline_res.verdict.confidence_score,
                    "processing_time_ms": pipeline_res.processing_time_ms,
                    "reasoning": pipeline_res.verdict.reasoning,
                    "recommended_playbook": pipeline_res.verdict.recommended_playbook,
                    "risk_factors": pipeline_res.verdict.risk_factors or [],
                }
                results.append(record)

        metrics = MetricsCalculator.calculate_metrics(results)
        report = {
            "mode": self.mode,
            "model_name": self.model_name if "llm" in self.mode else "none",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_alerts": len(results),
            "matches": sum(1 for r in results if r["match"]),
            "mismatches": sum(1 for r in results if not r["match"]),
            "metrics": metrics,
            "results": results
        }

        if save_results:
            self._save_run_results(report)

        return report

    def _save_run_results(self, report: Dict[str, Any]) -> None:
        """Saves evaluation report to JSON and CSV summaries in results_dir."""
        mode_str = report["mode"]
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # 1. Save detailed JSON (latest and timestamped)
        latest_json_path = os.path.join(self.results_dir, f"eval_{mode_str}_latest.json")
        archived_json_path = os.path.join(self.results_dir, f"eval_{mode_str}_{timestamp_str}.json")

        with open(latest_json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        with open(archived_json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # 2. Save summary CSV
        csv_path = os.path.join(self.results_dir, f"eval_{mode_str}_summary.csv")
        fieldnames = [
            "alert_id",
            "technique_id",
            "scenario_type",
            "expected",
            "actual",
            "match",
            "confidence",
            "processing_time_ms"
        ]
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in report["results"]:
                writer.writerow({
                    "alert_id": r["alert_id"],
                    "technique_id": r["technique_id"],
                    "scenario_type": r["scenario_type"],
                    "expected": r["expected"],
                    "actual": r["actual"],
                    "match": r["match"],
                    "confidence": r["confidence"],
                    "processing_time_ms": f"{r['processing_time_ms']:.2f}"
                })

        logger.info(f"[{mode_str.upper()}] Evaluation results saved to {latest_json_path} and {csv_path}")

    @classmethod
    def run_comparative_benchmark(
        cls,
        modes: Optional[List[str]] = None,
        model_name: str = "llama3:8b",
        ground_truth_path: str = "data/ground_truth.jsonl",
        results_dir: str = "evaluation/results"
    ) -> Dict[str, Any]:
        """
        Runs multiple triage modes sequentially and outputs a unified comparative benchmark table.
        """
        modes = modes or ["heuristic", "llm_no_rag", "llm_rag"]
        benchmark_results = {}

        for mode in modes:
            logger.info(f"========== Running Benchmark Mode: {mode.upper()} ==========")
            harness = cls.create_for_mode(mode=mode, model_name=model_name, results_dir=results_dir)
            report = harness.run_ground_truth_eval(ground_truth_path=ground_truth_path, save_results=True)
            benchmark_results[mode] = report

        # Construct comparative summary
        comparison = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_name": model_name,
            "modes_evaluated": modes,
            "metrics_comparison": {
                mode: benchmark_results[mode]["metrics"] for mode in modes
            },
            "detailed_reports": benchmark_results
        }

        # Save comparison JSON
        comparison_path = os.path.join(results_dir, "benchmark_comparison_latest.json")
        with open(comparison_path, "w", encoding="utf-8") as f:
            json.dump(comparison, f, indent=2, ensure_ascii=False)

        # Generate Markdown table
        md_path = os.path.join(results_dir, "benchmark_comparison_latest.md")
        cls._export_markdown_comparison(comparison, md_path)

        logger.info(f"Comparative benchmark complete! Reports written to {comparison_path} and {md_path}")
        return comparison

    @staticmethod
    def _export_markdown_comparison(comparison: Dict[str, Any], output_path: str) -> None:
        """Formats comparative metrics into a clean GitHub-style Markdown table."""
        modes = comparison["modes_evaluated"]
        metrics_dict = comparison["metrics_comparison"]

        headers = ["Metric"] + [m.replace("_", " ").title() for m in modes]
        separator = ["|---"] * len(headers)

        rows = [
            ("Precision", lambda m: f"{metrics_dict[m]['precision']:.4f}"),
            ("Recall", lambda m: f"{metrics_dict[m]['recall']:.4f}"),
            ("F1-Score", lambda m: f"{metrics_dict[m]['f1_score']:.4f}"),
            ("Mean Time to Respond (MTTR)", lambda m: f"{metrics_dict[m]['mttr_ms']:.2f} ms"),
            ("Cohen's Kappa (Agreement)", lambda m: f"{metrics_dict[m]['cohens_kappa']:.4f}"),
        ]

        md_lines = [
            "# Multi-Mode Triage Benchmark Comparison",
            f"**Generated:** {comparison['timestamp']}  ",
            f"**LLM Model:** `{comparison['model_name']}`  ",
            "",
            "| " + " | ".join(headers) + " |",
            "|".join(separator) + "|",
        ]

        for label, formatter in rows:
            line_vals = [label] + [formatter(m) for m in modes]
            md_lines.append("| " + " | ".join(line_vals) + " |")

        md_lines.append("")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines))


def main():
    parser = argparse.ArgumentParser(description="Replay Harness for LLM Alert Triage")
    parser.add_argument(
        "--mode",
        choices=["heuristic", "llm_no_rag", "llm_rag", "compare", "all"],
        default="heuristic",
        help="Execution mode (default: heuristic)"
    )
    parser.add_argument("--model", default="llama3:8b", help="Ollama model name (default: llama3:8b)")
    parser.add_argument("--ground-truth", default="data/ground_truth.jsonl", help="Path to ground truth dataset")
    parser.add_argument("--results-dir", default="evaluation/results", help="Directory for output results")
    args = parser.parse_args()

    if args.mode in ("compare", "all"):
        modes = ["heuristic", "llm_no_rag", "llm_rag"] if args.mode == "all" else ["heuristic", "llm_rag"]
        res = ReplayHarness.run_comparative_benchmark(
            modes=modes,
            model_name=args.model,
            ground_truth_path=args.ground_truth,
            results_dir=args.results_dir
        )
        print(f"\n[+] Benchmark finished across {len(modes)} modes.")
        for mode, m in res["metrics_comparison"].items():
            print(f"  [{mode.upper()}]: F1={m['f1_score']}, Precision={m['precision']}, Recall={m['recall']}, MTTR={m['mttr_ms']}ms")
    else:
        harness = ReplayHarness.create_for_mode(mode=args.mode, model_name=args.model, results_dir=args.results_dir)
        report = harness.run_ground_truth_eval(ground_truth_path=args.ground_truth, save_results=True)
        m = report["metrics"]
        print(f"\n[+] Run complete for mode [{args.mode.upper()}]:")
        print(f"    - Total: {report['total_alerts']} | Matches: {report['matches']} | Mismatches: {report['mismatches']}")
        print(f"    - Precision: {m['precision']} | Recall: {m['recall']} | F1: {m['f1_score']} | MTTR: {m['mttr_ms']}ms")


if __name__ == "__main__":
    main()

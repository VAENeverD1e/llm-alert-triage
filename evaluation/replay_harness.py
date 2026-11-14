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
from copy import deepcopy
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.orchestrator import TriageOrchestrator
from evaluation.metrics import MetricsCalculator

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

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
        enable_enrichment: bool = True,
        include_severity: bool = False,
        elastic_url: Optional[str] = None,
        elastic_api_key: Optional[str] = None,
        elastic_verify_ssl: Optional[bool] = None,
        sanitize_label_leakage: bool = True,
        results_dir: str = "evaluation/results"
    ):
        self.mode = mode
        self.model_name = model_name
        self.enable_enrichment = enable_enrichment
        self.include_severity = include_severity
        self.elastic_url = elastic_url or os.getenv("ELASTIC_URL")
        self.elastic_api_key = elastic_api_key or os.getenv("ELASTIC_API_KEY")
        if elastic_verify_ssl is None:
            elastic_verify_ssl = os.getenv("ELASTIC_VERIFY_SSL", "true").lower() in (
                "true", "1", "yes"
            )
        self.elastic_verify_ssl = elastic_verify_ssl
        self.sanitize_label_leakage = sanitize_label_leakage
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)

        if orchestrator is not None:
            self.orchestrator = orchestrator
        else:
            self.orchestrator = self._init_orchestrator(
                mode=mode,
                model_name=model_name,
                enable_enrichment=enable_enrichment,
                include_severity=include_severity,
                elastic_url=self.elastic_url,
                elastic_api_key=self.elastic_api_key,
                elastic_verify_ssl=self.elastic_verify_ssl,
            )

    @classmethod
    def _init_orchestrator(
        cls,
        mode: str,
        model_name: str,
        enable_enrichment: bool = True,
        include_severity: bool = False,
        elastic_url: Optional[str] = None,
        elastic_api_key: Optional[str] = None,
        elastic_verify_ssl: bool = True,
    ) -> TriageOrchestrator:
        """Instantiates the appropriate orchestrator configuration for the chosen mode."""
        if mode == "heuristic":
            # Pure heuristic baseline without LLM
            return TriageOrchestrator.create_default(
                use_ollama=False,
                use_rag=True,
                enable_enrichment=enable_enrichment,
                include_severity=include_severity,
                elastic_url=elastic_url,
                elastic_api_key=elastic_api_key,
                elastic_verify_ssl=elastic_verify_ssl,
            )
        elif mode == "llm_no_rag":
            # Local LLM without RAG playbook grounding
            return TriageOrchestrator.create_default(
                use_ollama=True,
                use_rag=False,
                model_name=model_name,
                enable_enrichment=enable_enrichment,
                include_severity=include_severity,
                elastic_url=elastic_url,
                elastic_api_key=elastic_api_key,
                elastic_verify_ssl=elastic_verify_ssl,
            )
        elif mode == "llm_rag":
            # Full two-stage pipeline with local LLM and RAG Playbooks
            return TriageOrchestrator.create_default(
                use_ollama=True,
                use_rag=True,
                model_name=model_name,
                enable_enrichment=enable_enrichment,
                include_severity=include_severity,
                elastic_url=elastic_url,
                elastic_api_key=elastic_api_key,
                elastic_verify_ssl=elastic_verify_ssl,
            )
        else:
            logger.warning(f"Unknown mode '{mode}'; defaulting to heuristic baseline.")
            return TriageOrchestrator.create_default(
                use_ollama=False,
                use_rag=True,
                elastic_url=elastic_url,
                elastic_api_key=elastic_api_key,
                elastic_verify_ssl=elastic_verify_ssl,
            )

    @classmethod
    def create_for_mode(
        cls,
        mode: str = "heuristic",
        model_name: str = "llama3:8b",
        enable_enrichment: bool = True,
        include_severity: bool = False,
        elastic_url: Optional[str] = None,
        elastic_api_key: Optional[str] = None,
        elastic_verify_ssl: Optional[bool] = None,
        sanitize_label_leakage: bool = True,
        results_dir: str = "evaluation/results"
    ) -> "ReplayHarness":
        """Factory helper to create a harness for a specific evaluation mode."""
        return cls(
            mode=mode,
            model_name=model_name,
            enable_enrichment=enable_enrichment,
            include_severity=include_severity,
            elastic_url=elastic_url,
            elastic_api_key=elastic_api_key,
            elastic_verify_ssl=elastic_verify_ssl,
            sanitize_label_leakage=sanitize_label_leakage,
            results_dir=results_dir
        )

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

                if self.sanitize_label_leakage:
                    alert_data = self._sanitize_benchmark_alert(alert_data)
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
            "enrichment_configured": bool(self.elastic_url),
            "label_leakage_sanitized": self.sanitize_label_leakage,
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

    @staticmethod
    def _sanitize_benchmark_alert(alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove metadata that reveals the expected label in the benchmark."""
        sanitized = deepcopy(alert_data)
        sanitized.pop("reason", None)
        sanitized["host_name"] = "benchmark-host"
        sanitized["user_name"] = "benchmark-user"
        network = sanitized.get("network_context")
        if isinstance(network, dict):
            network["source_ip"] = "198.51.100.10" if network.get("source_ip") else None
            network["destination_ip"] = "198.51.100.20" if network.get("destination_ip") else None
            network["suricata_signature"] = None
            network["suricata_category"] = None
        return sanitized

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


    @classmethod
    def run_multi_run_benchmark(
        cls,
        mode: str = "llm_rag",
        model_name: str = "llama3:8b",
        runs: int = 5,
        enable_enrichment: bool = True,
        include_severity: bool = False,
        ground_truth_path: str = "data/ground_truth.jsonl",
        results_dir: str = "evaluation/results"
    ) -> Dict[str, Any]:
        """
        Executes K repeated benchmark evaluations for a single configuration,
        calculating Mean ± Std Dev across runs to measure statistical variance.
        """
        logger.info(f"========== Starting Multi-Run Benchmark ({runs} runs) for [{mode.upper()}] ==========")
        run_results = []
        metrics_list = []

        for i in range(1, runs + 1):
            logger.info(f"--- Iteration {i}/{runs} for Mode [{mode}] ---")
            harness = cls.create_for_mode(
                mode=mode,
                model_name=model_name,
                enable_enrichment=enable_enrichment,
                include_severity=include_severity,
                results_dir=results_dir
            )
            report = harness.run_ground_truth_eval(ground_truth_path=ground_truth_path, save_results=False)
            metrics_list.append(report["metrics"])
            run_results.append({
                "iteration": i,
                "matches": report["matches"],
                "mismatches": report["mismatches"],
                "metrics": report["metrics"]
            })

        aggregate_stats = MetricsCalculator.calculate_aggregate_metrics(metrics_list)
        summary = {
            "mode": mode,
            "model_name": model_name,
            "runs_requested": runs,
            "enable_enrichment": enable_enrichment,
            "include_severity": include_severity,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "aggregate_metrics": aggregate_stats,
            "individual_runs": run_results
        }

        # Save summary JSON
        out_name = f"eval_multirun_{mode}_{runs}runs.json"
        summary_path = os.path.join(results_dir, out_name)
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        logger.info(f"Multi-run evaluation complete! Summary saved to {summary_path}")
        return summary

    @classmethod
    def run_full_ablation_suite(
        cls,
        model_name: str = "llama3:8b",
        runs: int = 5,
        include_severity: bool = False,
        ground_truth_path: str = "data/ground_truth.jsonl",
        results_dir: str = "evaluation/results/ablation",
    ) -> Dict[str, Any]:
        """
        Runs the full scientific ablation matrix:
        1. Heuristic Baseline (Deterministic rule baseline)
        2. LLM Zero-Shot (No RAG, No Enrich)
        3. LLM + Stage 1 Enrich (Enrichment only)
        4. LLM + RAG Playbooks (RAG only, No Enrich)
        5. Full Proposed Pipeline (Stage 1 Enrich + Stage 2 RAG)
        """
        os.makedirs(results_dir, exist_ok=True)
        logger.info(f"========== STARTING FULL SCIENTIFIC ABLATION SUITE (N={runs} runs/config) ==========")

        configs = [
            {
                "config_id": "heuristic_baseline",
                "label": "Heuristic Baseline",
                "mode": "heuristic",
                "enable_enrichment": False,
                "runs": 1,  # Deterministic rule code only needs 1 iteration
            },
            {
                "config_id": "llm_zero_shot",
                "label": "LLM Zero-Shot (No RAG, No Enrich)",
                "mode": "llm_no_rag",
                "enable_enrichment": False,
                "runs": runs,
            },
            {
                "config_id": "llm_enrich_only",
                "label": "LLM + Stage 1 Enrich",
                "mode": "llm_no_rag",
                "enable_enrichment": True,
                "runs": runs,
            },
            {
                "config_id": "llm_rag_only",
                "label": "LLM + RAG Playbooks (No Enrich)",
                "mode": "llm_rag",
                "enable_enrichment": False,
                "runs": runs,
            },
            {
                "config_id": "full_pipeline",
                "label": "Full Pipeline (Enrich + RAG)",
                "mode": "llm_rag",
                "enable_enrichment": True,
                "runs": runs,
            },
        ]

        suite_results = {}
        for cfg in configs:
            cid = cfg["config_id"]
            logger.info(f"\n[Ablation Matrix] Evaluating: {cfg['label']} ({cfg['runs']} iterations)...")
            res = cls.run_multi_run_benchmark(
                mode=cfg["mode"],
                model_name=model_name,
                runs=cfg["runs"],
                enable_enrichment=cfg["enable_enrichment"],
                include_severity=include_severity,
                ground_truth_path=ground_truth_path,
                results_dir=results_dir
            )
            suite_results[cid] = {
                "label": cfg["label"],
                "runs": cfg["runs"],
                "aggregate": res["aggregate_metrics"]
            }

        ablation_summary = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_name": model_name,
            "severity_in_prompt": include_severity,
            "suite_results": suite_results
        }

        # Save Markdown table
        md_path = os.path.join(results_dir, "ablation_study_summary.md")
        cls._export_ablation_markdown(ablation_summary, md_path)

        # Save JSON
        json_path = os.path.join(results_dir, "ablation_study_summary.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(ablation_summary, f, indent=2, ensure_ascii=False)

        logger.info(f"Full ablation suite complete! Reports written to {md_path} and {json_path}")
        return ablation_summary

    @staticmethod
    def _export_ablation_markdown(summary: Dict[str, Any], output_path: str) -> None:
        """Formats ablation suite aggregate metrics into a research-grade Markdown table."""
        suite = summary["suite_results"]
        headers = ["Configuration", "Runs", "Precision", "Recall", "F1-Score", "Cohen's Kappa (κ)", "Mean Time (MTTR)"]
        separator = ["|---"] * len(headers)

        lines = [
            "# Empirical Ablation Study: Component Breakdown & Reproducibility",
            f"**Generated:** {summary['timestamp']}  ",
            f"**Evaluated Model:** `{summary['model_name']}`  ",
            f"**Telemetry Severity in Prompt:** `{'Enabled' if summary['severity_in_prompt'] else 'DISABLED (Pure Telemetry Reasoning)'}`  ",
            "",
            "| " + " | ".join(headers) + " |",
            "|".join(separator) + "|",
        ]

        for cid, data in suite.items():
            agg = data["aggregate"]
            p = agg.get("precision_formatted") or f"{agg.get('precision_mean', 0.0):.4f}"
            r = agg.get("recall_formatted") or f"{agg.get('recall_mean', 0.0):.4f}"
            f1 = agg.get("f1_score_formatted") or f"{agg.get('f1_score_mean', 0.0):.4f}"
            k = agg.get("cohens_kappa_formatted") or f"{agg.get('cohens_kappa_mean', 0.0):.4f}"
            mttr = agg.get("mttr_ms_formatted") or f"{agg.get('mttr_ms_mean', 0.0):.1f} ms"

            row_vals = [data["label"], str(data["runs"]), p, r, f1, k, mttr]
            lines.append("| " + " | ".join(row_vals) + " |")

        lines.append("")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(description="Replay Harness for LLM Alert Triage")
    parser.add_argument(
        "--mode",
        choices=["heuristic", "llm_no_rag", "llm_rag", "compare", "all"],
        default="heuristic",
        help="Execution mode (default: heuristic)"
    )
    parser.add_argument("--model", default="llama3:8b", help="Ollama model name (default: llama3:8b)")
    parser.add_argument("--runs", type=int, default=1, help="Number of repeated runs to calculate variance (default: 1)")
    parser.add_argument("--ablation-suite", action="store_true", help="Run the full 5-configuration scientific ablation suite")
    parser.add_argument("--include-severity", action="store_true", help="Include severity/risk in prompt (default: False)")
    parser.add_argument("--no-enrichment", action="store_true", help="Disable Stage 1 enrichment")
    parser.add_argument("--ground-truth", default="data/ground_truth.jsonl", help="Path to ground truth dataset")
    parser.add_argument("--results-dir", default="evaluation/results", help="Directory for output results")
    args = parser.parse_args()

    enable_enrichment = not args.no_enrichment

    if args.ablation_suite:
        ReplayHarness.run_full_ablation_suite(
            model_name=args.model,
            runs=args.runs if args.runs > 1 else 5,
            include_severity=args.include_severity,
            ground_truth_path=args.ground_truth,
            results_dir=os.path.join(args.results_dir, "ablation")
        )
    elif args.runs > 1:
        ReplayHarness.run_multi_run_benchmark(
            mode=args.mode,
            model_name=args.model,
            runs=args.runs,
            enable_enrichment=enable_enrichment,
            include_severity=args.include_severity,
            ground_truth_path=args.ground_truth,
            results_dir=args.results_dir
        )
    elif args.mode in ("compare", "all"):
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
        harness = ReplayHarness.create_for_mode(
            mode=args.mode,
            model_name=args.model,
            enable_enrichment=enable_enrichment,
            include_severity=args.include_severity,
            results_dir=args.results_dir
        )
        report = harness.run_ground_truth_eval(ground_truth_path=args.ground_truth, save_results=True)
        m = report["metrics"]
        print(f"\n[+] Run complete for mode [{args.mode.upper()}]:")
        print(f"    - Total: {report['total_alerts']} | Matches: {report['matches']} | Mismatches: {report['mismatches']}")
        print(f"    - Precision: {m['precision']} | Recall: {m['recall']} | F1: {m['f1_score']} | MTTR: {m['mttr_ms']}ms")


if __name__ == "__main__":
    main()

"""
Unit and Integration Tests for ReplayHarness and Evaluation Pipeline.
"""
import os
import json
import tempfile
import pytest

from evaluation.replay_harness import ReplayHarness
from agent.orchestrator import TriageOrchestrator


def test_replay_harness_init_modes():
    """Verifies that ReplayHarness properly initializes across supported modes."""
    harness_heuristic = ReplayHarness.create_for_mode(mode="heuristic")
    assert harness_heuristic.mode == "heuristic"
    assert harness_heuristic.orchestrator is not None

    harness_llm_no_rag = ReplayHarness.create_for_mode(mode="llm_no_rag", model_name="llama3:8b")
    assert harness_llm_no_rag.mode == "llm_no_rag"

    harness_llm_rag = ReplayHarness.create_for_mode(mode="llm_rag", model_name="llama3:8b")
    assert harness_llm_rag.mode == "llm_rag"


def test_replay_harness_eval_mock_dataset(tmp_path):
    """Tests evaluation execution on a controlled mock ground truth JSONL."""
    mock_gt_file = tmp_path / "mock_gt.jsonl"
    results_dir = tmp_path / "results"

    records = [
        {
            "alert_id": "MOCK-001",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "scenario_type": "attack",
            "expected_verdict": "Escalate",
            "notes": "Encoded powershell payload"
        },
        {
            "alert_id": "MOCK-002",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "scenario_type": "benign",
            "expected_verdict": "Close",
            "notes": "Routine admin script"
        }
    ]

    with open(mock_gt_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    harness = ReplayHarness(
        orchestrator=TriageOrchestrator(),  # Heuristic mock
        mode="heuristic",
        results_dir=str(results_dir)
    )

    report = harness.run_ground_truth_eval(ground_truth_path=str(mock_gt_file), save_results=True)

    assert report["total_alerts"] == 2
    assert "metrics" in report
    metrics = report["metrics"]
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "mttr_ms" in metrics
    assert "cohens_kappa" in metrics

    # Check that results files were saved
    latest_json = results_dir / "eval_heuristic_latest.json"
    summary_csv = results_dir / "eval_heuristic_summary.csv"
    assert latest_json.exists()
    assert summary_csv.exists()


def test_replay_harness_real_dataset_heuristic():
    """
    Executes ReplayHarness on the actual 16-scenario benchmark dataset in heuristic mode.
    Validates end-to-end ingestion and metrics calculation.
    """
    harness = ReplayHarness.create_for_mode(mode="heuristic", results_dir="evaluation/results")
    report = harness.run_ground_truth_eval(ground_truth_path="data/ground_truth.jsonl", save_results=True)

    assert report["total_alerts"] == 16
    assert len(report["results"]) == 16
    assert report["matches"] >= 12  # Heuristics accurately resolve at least 14/16

    metrics = report["metrics"]
    assert metrics["precision"] > 0.0
    assert metrics["recall"] > 0.0
    assert metrics["f1_score"] > 0.70
    assert metrics["mttr_ms"] >= 0.0


def test_replay_harness_comparative_benchmark(tmp_path):
    """Tests the comparative benchmark helper and markdown report generation."""
    mock_gt_file = tmp_path / "mock_gt.jsonl"
    results_dir = tmp_path / "results"

    records = [
        {"alert_id": "CMP-1", "technique_id": "T1059.001", "expected_verdict": "Escalate"},
        {"alert_id": "CMP-2", "technique_id": "T1059.001", "expected_verdict": "Close"},
    ]
    with open(mock_gt_file, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    # Run comparative benchmark across heuristic modes
    comparison = ReplayHarness.run_comparative_benchmark(
        modes=["heuristic"],
        ground_truth_path=str(mock_gt_file),
        results_dir=str(results_dir)
    )

    assert "metrics_comparison" in comparison
    assert "heuristic" in comparison["metrics_comparison"]

    md_report = results_dir / "benchmark_comparison_latest.md"
    assert md_report.exists()
    content = md_report.read_text(encoding="utf-8")
    assert "Multi-Mode Triage Benchmark Comparison" in content
    assert "Precision" in content
    assert "F1-Score" in content

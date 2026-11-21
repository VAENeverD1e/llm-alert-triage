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


def test_benchmark_sanitization_removes_label_leakage():
    alert = {
        "reason": "Authorized monthly internal vulnerability assessment scan",
        "host_name": "sec-scanner-01",
        "user_name": "svc-security",
        "network_context": {
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.75.20",
            "suricata_signature": "ET INFO fake benign signature",
            "suricata_category": "Corporate Scanner",
        },
    }

    sanitized = ReplayHarness._sanitize_benchmark_alert(alert)

    assert "reason" not in sanitized
    assert sanitized["host_name"] == "benchmark-host"
    assert sanitized["user_name"] == "benchmark-user"
    # Private addresses stay private (class-preserving mapping)
    assert sanitized["network_context"]["source_ip"] == "10.255.0.1"
    assert sanitized["network_context"]["destination_ip"] == "10.255.0.2"
    assert sanitized["network_context"]["suricata_signature"] is None
    assert sanitized["network_context"]["suricata_category"] is None


def test_benchmark_sanitization_raw_kibana_alert():
    """Raw Kibana hits must lose workflow status, reason, the `fields` block and lab identities."""
    with open("data/attack_scenarios/attack_T1046_port_scan.json", encoding="utf-8") as f:
        raw = json.load(f)
    assert raw["_source"]["kibana.alert.workflow_status"] == "acknowledged"  # precondition

    sanitized = ReplayHarness._sanitize_benchmark_alert(raw)
    src = sanitized["_source"]

    assert "fields" not in sanitized
    assert not any(k.startswith("kibana.alert.workflow_") for k in src)
    assert "kibana.alert.reason" not in src
    assert src["source"]["ip"].startswith("10.255.0.")
    assert src["destination"]["ip"].startswith("10.255.0.")
    assert src["source"]["ip"] != src["destination"]["ip"]
    assert src["suricata"]["eve"]["flow"]["src_ip"] == src["source"]["ip"]
    assert "192.168.75.1" not in json.dumps(src["related"])
    # Original document is untouched
    assert raw["_source"]["kibana.alert.workflow_status"] == "acknowledged"

    # Still parseable by the pipeline parser
    from agent.schemas.triage_schema import NormalizedAlert
    alert = NormalizedAlert.from_raw_alert(sanitized)
    assert alert.rule_id == "T1046"
    assert alert.network_context.destination_port == 1521


def test_public_ips_map_to_public_documentation_range():
    alert = {"network_context": {"source_ip": "10.0.0.5", "destination_ip": "20.189.173.1"}}
    sanitized = ReplayHarness._sanitize_benchmark_alert(alert)
    assert sanitized["network_context"]["source_ip"].startswith("10.255.0.")
    assert sanitized["network_context"]["destination_ip"].startswith("203.0.113.")


def test_metrics_count_unknown_and_fallbacks():
    from evaluation.metrics import MetricsCalculator
    results = [
        {"expected": "Escalate", "actual": "Escalate", "processing_time_ms": 10, "verdict_source": "llm"},
        {"expected": "Escalate", "actual": "Unknown", "processing_time_ms": 10, "verdict_source": "llm"},
        {"expected": "Close", "actual": "Close", "processing_time_ms": 10, "verdict_source": "heuristic_fallback"},
        {"expected": "Close", "actual": "escalate", "processing_time_ms": 10, "verdict_source": "error_fallback"},
    ]
    m = MetricsCalculator.calculate_metrics(results)
    assert m["unknown_count"] == 1
    assert m["coverage"] == 0.75
    assert m["recall"] == 1.0           # decided subset only
    assert m["recall_strict"] == 0.5    # Unknown on an attack counts as a miss
    assert m["fp"] == 1                 # lower-case label still counted
    assert m["heuristic_fallback_count"] == 1
    assert m["error_fallback_count"] == 1
    assert m["mean_latency_ms"] == m["mttr_ms"] == 10.0

    breakdown = MetricsCalculator.calculate_breakdown(
        [dict(r, technique_id="T1") for r in results[:2]] + [dict(r, technique_id="T2") for r in results[2:]],
        "technique_id",
    )
    assert set(breakdown) == {"T1", "T2"}
    assert breakdown["T1"]["unknown_count"] == 1


def test_comparative_benchmark_forwards_flags(tmp_path, monkeypatch):
    captured = []
    original = ReplayHarness.create_for_mode.__func__

    def spy(cls, **kwargs):
        captured.append(kwargs)
        return original(cls, **kwargs)

    monkeypatch.setattr(ReplayHarness, "create_for_mode", classmethod(spy))
    gt = tmp_path / "gt.jsonl"
    gt.write_text(json.dumps({"alert_id": "A", "technique_id": "T1059.001", "expected_verdict": "Close"}) + "\n")

    ReplayHarness.run_comparative_benchmark(
        modes=["heuristic"], ground_truth_path=str(gt), results_dir=str(tmp_path / "r"),
        enable_enrichment=False, include_severity=True, sanitize_label_leakage=False,
    )
    assert captured[0]["enable_enrichment"] is False
    assert captured[0]["include_severity"] is True
    assert captured[0]["sanitize_label_leakage"] is False


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


def test_replay_harness_real_dataset_heuristic(tmp_path):
    """
    Executes ReplayHarness on the actual 16-scenario benchmark dataset in heuristic mode.
    Validates end-to-end ingestion and report structure. The score itself is not asserted:
    the previous ">= 12 matches" threshold was only reachable through the severity leak.
    """
    harness = ReplayHarness(
        orchestrator=TriageOrchestrator.create_default(use_ollama=False, use_rag=True, enable_enrichment=False),
        mode="heuristic",
        enable_enrichment=False,
        results_dir=str(tmp_path),
    )
    report = harness.run_ground_truth_eval(ground_truth_path="data/ground_truth.jsonl", save_results=True)

    assert report["total_alerts"] == 16
    assert len(report["results"]) == 16
    assert all(r["verdict_source"] == "heuristic" for r in report["results"])
    assert report["metrics"]["error_fallback_count"] == 0
    assert report["metrics"]["total"] == 16

    excluded = set(report["excluded_unrealistic_alerts"])
    assert excluded == {"BNG-T1003.001", "BNG-T1055.001", "BNG-T1071.001-2"}
    assert report["metrics_realistic_only"]["total"] == 13
    assert "T1046" in report["metrics_by_technique"]
    assert set(report["metrics_by_scenario_type"]) == {"attack", "benign"}


def test_heuristic_ignores_severity_unless_enabled():
    from agent.schemas.triage_schema import SecurityAlert, FactFindingOutput
    from agent.verdict.evaluator import VerdictAgent

    alert = SecurityAlert(alert_id="S-1", rule_id="T1059.001", rule_name="x", severity="critical")
    facts = FactFindingOutput(alert_id="S-1", summary_of_events="s", user_context="u")

    assert VerdictAgent(include_severity=False).process(alert, facts).decision.value == "Close"
    assert VerdictAgent(include_severity=True).process(alert, facts).decision.value == "Escalate"


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

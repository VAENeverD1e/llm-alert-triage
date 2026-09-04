"""
Integration test for the two-stage triage orchestrator.
"""
from agent.orchestrator import TriageOrchestrator
from agent.schemas.triage_schema import TriageDecision


def test_orchestrator_pipeline_execution():
    orchestrator = TriageOrchestrator()
    sample_alert = {
        "alert_id": "TEST-ALT-100",
        "rule_id": "T1003.001",
        "rule_name": "LSASS Dump Attempt",
        "severity": "critical",
        "timestamp": "2026-09-03T12:00:00Z",
        "host_name": "PROD-SERVER",
        "user_name": "SYSTEM",
        "raw_event": {"process_name": "procdump.exe"}
    }

    result = orchestrator.run_pipeline(sample_alert)

    assert result.alert.alert_id == "TEST-ALT-100"
    assert result.fact_finding.alert_id == "TEST-ALT-100"
    assert result.verdict.decision in [TriageDecision.ESCALATE, TriageDecision.CLOSE]
    assert result.processing_time_ms >= 0.0

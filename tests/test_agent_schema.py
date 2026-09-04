"""
Unit test for validating agent schema inputs and outputs before output reaches notifications/Discord.
"""
import pytest
from agent.schemas.triage_schema import (
    SecurityAlert,
    FactFindingOutput,
    VerdictOutput,
    TriageDecision,
    TriagePipelineResult
)


def test_security_alert_validation():
    alert_dict = {
        "alert_id": "TEST-01",
        "rule_id": "T1059.001",
        "rule_name": "PowerShell Test",
        "severity": "high",
        "timestamp": "2026-09-03T12:00:00Z",
        "host_name": "HOST-01",
        "user_name": "user1"
    }
    alert = SecurityAlert(**alert_dict)
    assert alert.alert_id == "TEST-01"
    assert alert.severity == "high"


def test_verdict_schema_validation():
    verdict = VerdictOutput(
        alert_id="TEST-01",
        decision=TriageDecision.ESCALATE,
        confidence_score=0.95,
        reasoning="Suspicious encoded command execution."
    )
    assert verdict.decision == TriageDecision.ESCALATE
    assert verdict.confidence_score == 0.95


def test_invalid_confidence_score():
    with pytest.raises(Exception):
        VerdictOutput(
            alert_id="TEST-01",
            decision=TriageDecision.ESCALATE,
            confidence_score=1.5,  # Out of range [0, 1]
            reasoning="Invalid score test"
        )

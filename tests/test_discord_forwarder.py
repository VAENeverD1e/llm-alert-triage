"""
Unit and integration tests for notification/discord_forwarder.py.
"""
import pytest
from unittest.mock import MagicMock, patch
import requests

from notification.discord_forwarder import (
    DiscordForwarder,
    COLOR_ESCALATE,
    COLOR_CLOSE,
    COLOR_UNKNOWN,
    _truncate,
)
from agent.schemas.triage_schema import (
    NormalizedAlert,
    ProcessContext,
    ProcessInfo,
    NetworkContext,
    RegistryContext,
    FactFindingOutput,
    VerdictOutput,
    TriagePipelineResult,
    TriageDecision,
)
from agent.orchestrator import TriageOrchestrator


@pytest.fixture
def sample_pipeline_result():
    alert = NormalizedAlert(
        alert_id="TEST-ALT-001",
        rule_id="T1059.001",
        rule_name="PowerShell Script Execution",
        severity="high",
        risk_score=75,
        host_name="WORKSTATION-01",
        user_name="corp\\alice",
        telemetry_source="sysmon",
        event_code="1",
        process_context=ProcessContext(
            process=ProcessInfo(
                name="powershell.exe",
                pid=4321,
                command_line="powershell.exe -enc AAAAA...",
            ),
            parent_process=ProcessInfo(
                name="explorer.exe",
                pid=1234,
            ),
        ),
    )
    facts = FactFindingOutput(
        alert_id="TEST-ALT-001",
        summary_of_events="PowerShell launched encoded command line under explorer.exe.",
        associated_processes=["powershell.exe", "explorer.exe"],
        user_context="corp\\alice is standard business user.",
        has_anomalous_parent_process=False,
        evidence_extracted=["Encoded command flag detected"],
    )
    verdict = VerdictOutput(
        alert_id="TEST-ALT-001",
        decision=TriageDecision.ESCALATE,
        confidence_score=0.92,
        reasoning="Suspicious encoded command execution aligns with T1059.001 adversary behavior.",
        recommended_playbook="PB-T1059.001",
        risk_factors=["Obfuscated Base64 CLI", "Interactive Shell Spawn"],
    )
    return TriagePipelineResult(
        alert=alert,
        fact_finding=facts,
        verdict=verdict,
        processing_time_ms=145.2,
    )


def test_truncate_utility():
    assert _truncate("hello", 10) == "hello"
    assert _truncate(None, 10) == "N/A"
    long_str = "A" * 50
    truncated = _truncate(long_str, 10)
    assert len(truncated) == 10
    assert truncated.endswith("...")


def test_format_embed_escalate(sample_pipeline_result):
    forwarder = DiscordForwarder()
    payload = forwarder.format_embed(sample_pipeline_result)

    assert "embeds" in payload
    assert len(payload["embeds"]) == 1
    embed = payload["embeds"][0]

    assert embed["color"] == COLOR_ESCALATE
    assert "🚨 [ESCALATE]" in embed["title"]
    assert "PowerShell Script Execution" in embed["title"]
    assert "Suspicious encoded command" in embed["description"]

    field_names = [f["name"] for f in embed["fields"]]
    assert "Alert ID" in field_names
    assert "Verdict" in field_names
    assert "🖥️ Process Context" in field_names
    assert "🔍 Investigation Findings" in field_names
    assert "⚠️ Risk Factors" in field_names
    assert "📖 Playbook Guideline" in field_names


def test_format_embed_close(sample_pipeline_result):
    sample_pipeline_result.verdict.decision = TriageDecision.CLOSE
    sample_pipeline_result.verdict.confidence_score = 0.88
    sample_pipeline_result.verdict.reasoning = "Verified routine scheduled maintenance script."

    forwarder = DiscordForwarder()
    payload = forwarder.format_embed(sample_pipeline_result)
    embed = payload["embeds"][0]

    assert embed["color"] == COLOR_CLOSE
    assert "✅ [CLOSE]" in embed["title"]
    assert "Verified routine scheduled" in embed["description"]


def test_format_embed_network_and_registry(sample_pipeline_result):
    # Network alert
    sample_pipeline_result.alert.process_context = None
    sample_pipeline_result.alert.network_context = NetworkContext(
        source_ip="192.168.1.50",
        source_port=49152,
        destination_ip="203.0.113.5",
        destination_port=443,
        protocol="TCP",
        user_agent="Mozilla/5.0 MaliciousBot",
        suricata_signature="ET MALWARE C2 Channel",
    )
    # Registry alert
    sample_pipeline_result.alert.registry_context = RegistryContext(
        path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name="Updater",
        data="C:\\Temp\\backdoor.exe",
    )

    forwarder = DiscordForwarder()
    payload = forwarder.format_embed(sample_pipeline_result)
    embed = payload["embeds"][0]

    field_names = [f["name"] for f in embed["fields"]]
    assert "🌐 Network Context" in field_names
    assert "🔑 Registry Context" in field_names


def test_send_triage_result_dry_run(sample_pipeline_result):
    forwarder = DiscordForwarder(webhook_url="https://discord.com/api/webhooks/mock", dry_run=True)
    # When dry_run is True, it should not call requests.post
    with patch("requests.post") as mock_post:
        success = forwarder.send_triage_result(sample_pipeline_result)
        assert success is True
        mock_post.assert_not_called()


def test_send_triage_result_no_url(sample_pipeline_result):
    forwarder = DiscordForwarder(webhook_url="", dry_run=False)
    with patch("requests.post") as mock_post:
        success = forwarder.send_triage_result(sample_pipeline_result)
        assert success is True
        mock_post.assert_not_called()


def test_send_triage_result_http_204_success(sample_pipeline_result):
    forwarder = DiscordForwarder(webhook_url="https://discord.com/api/webhooks/valid/test", dry_run=False)
    mock_response = MagicMock()
    mock_response.status_code = 204

    with patch("requests.post", return_value=mock_response) as mock_post:
        success = forwarder.send_triage_result(sample_pipeline_result)
        assert success is True
        mock_post.assert_called_once()


def test_send_triage_result_rate_limited(sample_pipeline_result):
    forwarder = DiscordForwarder(webhook_url="https://discord.com/api/webhooks/rate/limited", retry_count=1)
    
    # 429 response then 204
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.json.return_value = {"retry_after": 0.01}

    resp_204 = MagicMock()
    resp_204.status_code = 204

    with patch("requests.post", side_effect=[resp_429, resp_204]):
        with patch("time.sleep") as mock_sleep:
            success = forwarder.send_triage_result(sample_pipeline_result)
            assert success is True
            mock_sleep.assert_called_once_with(0.01)


def test_send_triage_result_request_exception(sample_pipeline_result):
    forwarder = DiscordForwarder(webhook_url="https://discord.com/api/webhooks/fail", retry_count=1)

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Network down")):
        with patch("time.sleep"):
            success = forwarder.send_triage_result(sample_pipeline_result)
            assert success is False


def test_orchestrator_integration_with_discord():
    mock_forwarder = MagicMock()
    orchestrator = TriageOrchestrator.create_default(
        use_ollama=False,
        use_rag=False,
        discord_forwarder=mock_forwarder
    )

    sample_alert = {
        "alert_id": "ORCH-DISCORD-TEST",
        "rule_id": "T1059.001",
        "rule_name": "PowerShell Test",
        "severity": "medium",
        "timestamp": "2026-10-24T12:00:00Z",
        "host_name": "HOST-01",
        "user_name": "user01",
        "raw_event": {"command_line": "powershell.exe -NoProfile"}
    }

    result = orchestrator.run_pipeline(sample_alert)
    assert result.alert.alert_id == "ORCH-DISCORD-TEST"
    mock_forwarder.send_triage_result.assert_called_once_with(result)

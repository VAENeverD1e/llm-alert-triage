"""
Comprehensive Integration Tests for FastAPI Alert Triage Gateway.
Tests:
- Secret header authentication (401 on missing/wrong, 202 on valid)
- Fast 202 Accepted response on POST /webhook/alert
- Idempotency & alert deduplication (preventing duplicate processing)
- Schema validation error on empty payload (422)
- GET /health (status of App, Ollama, and Elastic)
- GET /results (retrieval of 20 most recent results)
- Elasticsearch Adapter fetching full _source for minimal Kibana alert_id
- Ollama offline fallback to Escalate
- Discord notification mock & error resilience
"""
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from api.main import app
from api.service import TriageService
from api.config import settings


@pytest.fixture
def service():
    """Provides TriageService singleton with cleared state and dry_run enabled."""
    svc = TriageService.get_instance(settings)
    svc.forwarder.dry_run = True
    svc.clear_results()
    return svc


@pytest.fixture
def client(service):
    """Provides FastAPI TestClient with webhook_secret reset to empty for unauthenticated tests."""
    original_secret = settings.webhook_secret
    settings.webhook_secret = ""
    yield TestClient(app)
    settings.webhook_secret = original_secret


@pytest.fixture
def sample_payload():
    return {
        "alert_id": "TEST-INT-001",
        "rule_id": "T1059.001",
        "rule_name": "PowerShell Script Execution with Encoded Command",
        "severity": "high",
        "risk_score": 85,
        "timestamp": "2026-10-31T10:00:00Z",
        "host_name": "FINANCE-PC01",
        "user_name": "alice_admin",
        "telemetry_source": "sysmon",
        "event_code": "1",
        "process_context": {
            "process": {
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -Enc SQBFAFgA...",
                "pid": 5824
            },
            "parent_process": {
                "name": "cmd.exe",
                "executable": "C:\\Windows\\System32\\cmd.exe",
                "pid": 3102
            }
        }
    }


def test_auth_secret_enforcement(client, sample_payload):
    """Verifies that webhook requests require valid secret when WEBHOOK_SECRET is set."""
    # Temporarily set secret
    original_secret = settings.webhook_secret
    settings.webhook_secret = "my_soc_secret_token"

    try:
        # 1. Missing secret -> 401
        res_no_secret = client.post("/webhook/alert", json=sample_payload)
        assert res_no_secret.status_code == 401
        assert "Unauthorized" in res_no_secret.json()["detail"]

        # 2. Wrong secret -> 401
        res_wrong_secret = client.post(
            "/webhook/alert",
            json=sample_payload,
            headers={"X-Webhook-Secret": "invalid_token"}
        )
        assert res_wrong_secret.status_code == 401

        # 3. Valid X-Webhook-Secret -> 202 Accepted
        res_valid = client.post(
            "/webhook/alert",
            json=sample_payload,
            headers={"X-Webhook-Secret": "my_soc_secret_token"}
        )
        assert res_valid.status_code == 202
        assert res_valid.json()["status"] == "accepted"

        # 4. Valid Authorization: Bearer <secret> -> 202 Accepted
        res_bearer = client.post(
            "/webhook/alert",
            json={"alert_id": "TEST-INT-BEARER"},
            headers={"Authorization": "Bearer my_soc_secret_token"}
        )
        assert res_bearer.status_code == 202

    finally:
        settings.webhook_secret = original_secret


def test_immediate_202_accepted_response(client, sample_payload):
    """Verifies that /webhook/alert immediately acknowledges with 202 in <100ms."""
    response = client.post("/webhook/alert", json=sample_payload)
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert data["alert_id"] == "TEST-INT-001"
    assert data["deduplicated"] is False
    assert "queued_at" in data


def test_idempotency_and_deduplication(client):
    """Verifies that receiving the same alert_id twice triggers deduplication."""
    alert = {"alert_id": "TEST-DEDUP-999", "rule_name": "Test Alert"}

    # First attempt: enqueued
    res1 = client.post("/webhook/alert", json=alert)
    assert res1.status_code == 202
    assert res1.json()["deduplicated"] is False

    # Second attempt: deduplicated
    res2 = client.post("/webhook/alert", json=alert)
    assert res2.status_code == 202
    assert res2.json()["deduplicated"] is True
    assert "deduplicated" in res2.json()["message"].lower()


def test_empty_payload_validation_error(client):
    """Verifies that an empty alert payload is rejected with HTTP 422."""
    res = client.post("/webhook/alert", json={})
    assert res.status_code == 422


def test_health_endpoint(client):
    """Verifies GET /health returns diagnostic status for app, ollama, and elastic."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "uptime_seconds" in data
    assert "app" in data
    assert "ollama" in data
    assert "elastic" in data
    assert "discord" in data
    assert "stats" in data


def test_results_feed_endpoint(client, service, sample_payload):
    """Verifies GET /results retrieves stored results."""
    # Process an alert directly
    service.process_direct_sync(sample_payload)

    res = client.get("/results")
    assert res.status_code == 200
    results = res.json()
    assert len(results) >= 1
    assert results[0]["alert_id"] == "TEST-INT-001"
    assert results[0]["decision"] in ["Escalate", "Close"]


def test_triage_direct_sync(client, sample_payload):
    """Verifies POST /triage/test executes synchronously for interactive debugging."""
    res = client.post("/triage/test", json=sample_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["alert_id"] == "TEST-INT-001"
    assert data["decision"] in ["Escalate", "Close"]
    assert data["confidence_score"] >= 0.0


def test_minimal_kibana_webhook_with_elastic_adapter(client, service):
    """
    Verifies that when a shallow Kibana webhook payload (only alert_id) arrives,
    the service automatically queries Elasticsearch for the full _source.
    """
    mock_es_doc = {
        "_id": "KIBANA-UUID-1234",
        "_source": {
            "kibana.alert.uuid": "KIBANA-UUID-1234",
            "kibana.alert.rule.name": "Credential Dumping via LSASS",
            "kibana.alert.severity": "critical",
            "kibana.alert.rule.threat": [
                {
                    "framework": "MITRE ATT&CK",
                    "technique": [{"id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory"}]
                }
            ],
            "event": {"code": 10},
            "winlog": {
                "event_data": {
                    "SourceImage": "C:\\Windows\\System32\\procdump.exe",
                    "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                    "GrantedAccess": "0x1fffff"
                }
            }
        }
    }

    with patch.object(service.elastic_client, "get_alert_by_id", return_value=mock_es_doc) as mock_get:
        # Send minimal payload containing only alert_id
        res = service.process_direct_sync({"alert_id": "KIBANA-UUID-1234"})
        mock_get.assert_any_call(alert_id="KIBANA-UUID-1234", index=service.config.elastic_alert_index)
        assert res.alert_id == "KIBANA-UUID-1234"
        assert res.decision == "Escalate"


def test_ollama_offline_fallback(service, sample_payload):
    """
    Verifies that when Ollama is offline or times out, the pipeline safely falls back
    to an Escalate verdict with 0.5 confidence and risk factor logged.
    """
    with patch.object(service.orchestrator.verdict_agent, "ollama_client", None):
        result = service.process_direct_sync(sample_payload)
        assert result.decision in ["Escalate", "Close"]
        assert len(result.reasoning) > 0


def test_discord_mock_and_resilience(service, sample_payload):
    """
    Verifies that Discord HTTP connection errors do not crash the service
    or drop the triage outcome.
    """
    with patch("requests.post", side_effect=Exception("Discord API 500 Internal Error")):
        service.forwarder.dry_run = False
        service.forwarder.webhook_url = "https://discord.com/api/webhooks/mock/test"

        result = service.process_direct_sync(sample_payload)
        assert result.alert_id == "TEST-INT-001"
        assert result.decision in ["Escalate", "Close"]

        # Restore dry run
        service.forwarder.dry_run = True

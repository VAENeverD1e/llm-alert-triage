"""
Pydantic API Schemas for Webhook Ingestion, Health, and Triage Results.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class WebhookAlertRequest(BaseModel):
    """
    Flexible envelope accepting either:
    1. Kibana action template payload (e.g. {"alert_id": "..."} or {"kibana.alert.uuid": "..."})
    2. Full raw Elasticsearch _source document
    3. NormalizedAlert dictionary
    """
    model_config = ConfigDict(extra="allow")

    alert_id: Optional[str] = Field(default=None, description="Alert ID or Kibana alert UUID")
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None


class WebhookAcceptedResponse(BaseModel):
    """Immediate HTTP 202 response returned to prevent Kibana webhook timeout."""
    status: str = Field(default="accepted")
    alert_id: str
    message: str
    queued_at: str
    deduplicated: bool = False


class TriageResultItem(BaseModel):
    """Structured result recorded after background triage processing."""
    model_config = ConfigDict(extra="ignore")

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    decision: str = Field(description="Escalate, Close, or Unknown")
    confidence_score: float
    processing_time_ms: float
    discord_forwarded: bool
    timestamp: str
    reasoning: str
    risk_factors: List[str] = Field(default_factory=list)
    recommended_playbook: Optional[str] = None
    investigation_summary: str = ""
    prompt_injection_detected: bool = False
    error_message: Optional[str] = None


class HealthResponse(BaseModel):
    """Diagnostic health status for API, Ollama LLM daemon, and Elasticsearch."""
    status: str
    version: str
    uptime_seconds: float
    app: Dict[str, Any]
    ollama: Dict[str, Any]
    elastic: Dict[str, Any]
    discord: Dict[str, Any]
    stats: Dict[str, Any]

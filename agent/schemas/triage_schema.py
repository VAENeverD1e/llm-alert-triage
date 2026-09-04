"""
Pydantic schemas enforcing output structure for Stage 1 (Fact-Finding) and Stage 2 (Verdict).
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class TriageDecision(str, Enum):
    ESCALATE = "Escalate"
    CLOSE = "Close"
    UNKNOWN = "Unknown"


class SecurityAlert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    timestamp: str
    host_name: str
    user_name: str
    raw_event: Dict[str, Any] = Field(default_factory=dict)


class FactFindingOutput(BaseModel):
    alert_id: str
    summary_of_events: str
    associated_processes: List[str] = Field(default_factory=list)
    network_connections: List[str] = Field(default_factory=list)
    user_context: str
    timeline: List[Dict[str, str]] = Field(default_factory=list)
    has_anomalous_parent_process: bool = False
    evidence_extracted: List[str] = Field(default_factory=list)


class VerdictOutput(BaseModel):
    alert_id: str
    decision: TriageDecision
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    recommended_playbook: Optional[str] = None
    mitre_attack_techniques: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)


class TriagePipelineResult(BaseModel):
    alert: SecurityAlert
    fact_finding: FactFindingOutput
    verdict: VerdictOutput
    processing_time_ms: float

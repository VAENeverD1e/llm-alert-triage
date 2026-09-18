"""
Pydantic schemas enforcing input and output structures for Stage 1 (Fact-Finding) and Stage 2 (Verdict).
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, ConfigDict


class TriageDecision(str, Enum):
    ESCALATE = "Escalate"
    CLOSE = "Close"
    UNKNOWN = "Unknown"


# ── Telemetry Context Sub-blocks ───────────────────────────────────────

class ProcessInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = None
    pid: Optional[int] = None
    args: List[str] = Field(default_factory=list)
    md5: Optional[str] = None
    sha256: Optional[str] = None


class ProcessContext(BaseModel):
    """Populated for host telemetry with event.code in {1, 3, 10, 13}."""
    model_config = ConfigDict(extra="ignore")
    process: Optional[ProcessInfo] = None
    parent_process: Optional[ProcessInfo] = None
    target_process_name: Optional[str] = None         # winlog.event_data.TargetImage (Event 10)
    granted_access: Optional[str] = None              # winlog.event_data.GrantedAccess (Event 10)
    call_trace: Optional[str] = None                  # winlog.event_data.CallTrace (Event 10)


class RegistryContext(BaseModel):
    """Populated for event.code == 13 (T1547.001)."""
    model_config = ConfigDict(extra="ignore")
    path: Optional[str] = None
    value_name: Optional[str] = None
    data: Optional[str] = None
    hive: Optional[str] = None


class NetworkContext(BaseModel):
    """
    Populated for:
      - Sysmon network connections (event.code 3)
      - Suricata IDS alerts (T1046, T1071.001)
    """
    model_config = ConfigDict(extra="ignore")
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    direction: Optional[str] = None
    user_agent: Optional[str] = None
    suricata_signature: Optional[str] = None
    suricata_category: Optional[str] = None


# ── Alert Envelope ─────────────────────────────────────────────────────

class NormalizedAlert(BaseModel):
    """
    Primary Alert Envelope unifying host (Sysmon) and network (Suricata) SIEM alerts.
    """
    model_config = ConfigDict(extra="ignore")

    alert_id: str
    rule_uuid: str = "UNKNOWN"
    rule_id: str = "UNKNOWN"
    rule_name: str = "UNKNOWN"
    severity: str = "medium"
    risk_score: Optional[int] = None
    timestamp: str = ""
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    reason: Optional[str] = None

    telemetry_source: Literal["sysmon", "suricata"] = "sysmon"
    event_code: Optional[str] = None

    process_context: Optional[ProcessContext] = None
    registry_context: Optional[RegistryContext] = None
    network_context: Optional[NetworkContext] = None

    # Retained for backwards compatibility with tests passing loose mock dicts
    raw_event: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_raw_alert(cls, raw: Dict[str, Any]) -> "NormalizedAlert":
        """Builds a NormalizedAlert from a raw Kibana signals _source document."""
        src = raw.get("_source", raw)

        module = src.get("event", {}).get("module") or src.get("event.module")
        telemetry_source = "suricata" if module == "suricata" else "sysmon"
        event_code = (
            src.get("event", {}).get("code")
            or src.get("event.code")
            or src.get("kibana.alert.original_event.code")
        )
        if event_code is not None:
            event_code = str(event_code)

        # MITRE technique id: prefer the subtechnique id if present
        rule_id = "UNKNOWN"
        threat = src.get("kibana.alert.rule.threat") or (src.get("kibana", {}).get("alert", {}).get("rule", {}).get("threat"))
        if threat:
            technique = threat[0].get("technique", [{}])[0]
            subtech = technique.get("subtechnique") or []
            rule_id = subtech[0]["id"] if subtech else technique.get("id", "UNKNOWN")

        rule_name = (
            src.get("kibana.alert.rule.name")
            or src.get("kibana", {}).get("alert", {}).get("rule", {}).get("name", "UNKNOWN")
        )
        rule_desc = (
            src.get("kibana.alert.rule.description")
            or src.get("kibana.alert.rule.parameters", {}).get("description")
            or src.get("kibana", {}).get("alert", {}).get("rule", {}).get("description", "")
        )
        if "." not in rule_id:
            subtech_match = re.search(r"(T\d{4}\.\d{3})", f"{rule_name} {rule_desc}")
            if subtech_match:
                rule_id = subtech_match.group(1)
            elif rule_id == "T1003" and "lsass" in f"{rule_name} {rule_desc}".lower():
                rule_id = "T1003.001"

        def get_process(block: Optional[Dict[str, Any]]) -> Optional[ProcessInfo]:
            if not block:
                return None
            hashes = block.get("hash", {})
            return ProcessInfo(
                name=block.get("name"),
                executable=block.get("executable"),
                command_line=block.get("command_line"),
                pid=block.get("pid"),
                args=block.get("args", []),
                md5=hashes.get("md5"),
                sha256=hashes.get("sha256"),
            )

        process_context = None
        if "process" in src:
            proc = src["process"]
            process_context = ProcessContext(
                process=get_process(proc),
                parent_process=get_process(proc.get("parent")),
                target_process_name=src.get("winlog", {}).get("event_data", {}).get("TargetImage") or src.get("winlog.event_data.TargetImage"),
                granted_access=src.get("winlog", {}).get("event_data", {}).get("GrantedAccess") or src.get("winlog.event_data.GrantedAccess"),
                call_trace=src.get("winlog", {}).get("event_data", {}).get("CallTrace") or src.get("winlog.event_data.CallTrace"),
            )

        registry_context = None
        if "registry" in src:
            reg = src["registry"]
            registry_context = RegistryContext(
                path=reg.get("path"),
                value_name=reg.get("value"),
                data=(reg.get("data", {}).get("strings") or [None])[0],
                hive=reg.get("hive"),
            )

        network_context = None
        if "source" in src or "destination" in src or telemetry_source == "suricata":
            source = src.get("source", {})
            destination = src.get("destination", {})
            network = src.get("network", {})
            rule_block = src.get("rule", {})
            network_context = NetworkContext(
                source_ip=source.get("ip") or source.get("address"),
                source_port=source.get("port"),
                destination_ip=destination.get("ip") or destination.get("address"),
                destination_port=destination.get("port"),
                protocol=network.get("protocol") or network.get("transport"),
                direction=network.get("direction"),
                user_agent=src.get("user_agent", {}).get("original"),
                suricata_signature=rule_block.get("name") if telemetry_source == "suricata" else None,
                suricata_category=rule_block.get("category") if telemetry_source == "suricata" else None,
            )

        user_name = (
            src.get("user", {}).get("name")
            or src.get("user.name")
            or src.get("winlog", {}).get("event_data", {}).get("SourceUser")
            or src.get("winlog.event_data.SourceUser")
        )

        return cls(
            alert_id=src.get("kibana.alert.uuid") or src.get("kibana", {}).get("alert", {}).get("uuid", "UNKNOWN"),
            rule_uuid=src.get("kibana.alert.rule.uuid") or src.get("kibana", {}).get("alert", {}).get("rule", {}).get("uuid", "UNKNOWN"),
            rule_id=rule_id,
            rule_name=rule_name,
            severity=src.get("kibana.alert.severity") or src.get("kibana", {}).get("alert", {}).get("severity", "unknown"),
            risk_score=src.get("kibana.alert.risk_score") or src.get("kibana", {}).get("alert", {}).get("risk_score"),
            timestamp=src.get("@timestamp", ""),
            host_name=src.get("host", {}).get("name") or src.get("host", {}).get("hostname") or src.get("host.name"),
            user_name=user_name,
            reason=src.get("kibana.alert.reason") or src.get("kibana", {}).get("alert", {}).get("reason"),
            telemetry_source=telemetry_source,
            event_code=event_code,
            process_context=process_context,
            registry_context=registry_context,
            network_context=network_context,
            raw_event=src,
        )


# Backwards compatibility alias
SecurityAlert = NormalizedAlert


# ── Agent Output Schemas ───────────────────────────────────────────────

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
    alert: NormalizedAlert
    fact_finding: FactFindingOutput
    verdict: VerdictOutput
    processing_time_ms: float

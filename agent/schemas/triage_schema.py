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
        """
        Builds a NormalizedAlert from a raw Kibana signals document.

        Accepts a search hit (``_source``), a bare ``_source`` dict, or a hit that
        only carries the flattened ``fields`` block (``{"a.b": [value]}``).
        """
        if "_source" in raw and isinstance(raw["_source"], dict):
            src = raw["_source"]
        elif "fields" in raw and isinstance(raw["fields"], dict) and "kibana.alert.uuid" not in raw:
            src = _unflatten_fields(raw["fields"])
        else:
            src = raw

        module = _dig(src, "event", "module")
        telemetry_source = "suricata" if module == "suricata" else "sysmon"
        event_code = _first_present(
            _dig(src, "event", "code"),
            src.get("kibana.alert.original_event.code"),
        )
        if event_code is not None:
            event_code = str(event_code)

        # MITRE technique id: prefer the subtechnique id if present
        rule_id = "UNKNOWN"
        threat = src.get("kibana.alert.rule.threat") or _dig(src, "kibana", "alert", "rule", "threat")
        if isinstance(threat, dict):
            threat = [threat]
        if threat and isinstance(threat[0], dict):
            techniques = threat[0].get("technique") or [{}]
            technique = techniques[0] if isinstance(techniques[0], dict) else {}
            subtech = technique.get("subtechnique") or []
            if subtech and isinstance(subtech[0], dict) and subtech[0].get("id"):
                rule_id = subtech[0]["id"]
            else:
                rule_id = technique.get("id") or "UNKNOWN"
        if rule_id == "UNKNOWN":
            # Flattened form, e.g. from a ``fields`` block
            flat_id = _first_present(
                src.get("kibana.alert.rule.threat.technique.subtechnique.id"),
                src.get("kibana.alert.rule.threat.technique.id"),
            )
            if isinstance(flat_id, list):
                flat_id = flat_id[0] if flat_id else None
            if flat_id:
                rule_id = str(flat_id)

        rule_name = _first_present(
            src.get("kibana.alert.rule.name"),
            _dig(src, "kibana", "alert", "rule", "name"),
        ) or "UNKNOWN"
        params = src.get("kibana.alert.rule.parameters")
        rule_desc = _first_present(
            src.get("kibana.alert.rule.description"),
            params.get("description") if isinstance(params, dict) else None,
            _dig(src, "kibana", "alert", "rule", "description"),
        ) or ""
        if "." not in rule_id:
            subtech_match = re.search(r"(T\d{4}\.\d{3})", f"{rule_name} {rule_desc}")
            if subtech_match:
                rule_id = subtech_match.group(1)
            elif rule_id == "T1003" and "lsass" in f"{rule_name} {rule_desc}".lower():
                rule_id = "T1003.001"

        def get_process(block: Any) -> Optional[ProcessInfo]:
            if not isinstance(block, dict) or not block:
                return None
            hashes = block.get("hash") if isinstance(block.get("hash"), dict) else {}
            args = block.get("args") or []
            if isinstance(args, str):
                args = [args]
            return ProcessInfo(
                name=block.get("name"),
                executable=block.get("executable"),
                command_line=block.get("command_line"),
                pid=block.get("pid"),
                args=[str(a) for a in args],
                md5=hashes.get("md5"),
                sha256=hashes.get("sha256"),
            )

        def event_data(field: str) -> Any:
            return _dig(src, "winlog", "event_data", field)

        process_context = None
        if isinstance(src.get("process"), dict):
            proc = src["process"]
            process_context = ProcessContext(
                process=get_process(proc),
                parent_process=get_process(proc.get("parent")),
                target_process_name=event_data("TargetImage"),
                granted_access=event_data("GrantedAccess"),
                call_trace=event_data("CallTrace"),
            )

        registry_context = None
        if isinstance(src.get("registry"), dict):
            reg = src["registry"]
            reg_data = reg.get("data")
            if isinstance(reg_data, dict):
                strings = reg_data.get("strings")
                if isinstance(strings, list):
                    data_value = strings[0] if strings else None
                else:
                    data_value = strings
            else:
                data_value = reg_data
            registry_context = RegistryContext(
                path=reg.get("path"),
                value_name=reg.get("value"),
                data=str(data_value) if data_value is not None else None,
                hive=reg.get("hive"),
            )

        network_context = None
        has_source = isinstance(src.get("source"), dict)
        has_destination = isinstance(src.get("destination"), dict)
        if has_source or has_destination or telemetry_source == "suricata":
            source = src.get("source") if has_source else {}
            destination = src.get("destination") if has_destination else {}
            network = src.get("network") if isinstance(src.get("network"), dict) else {}
            rule_block = src.get("rule") if isinstance(src.get("rule"), dict) else {}
            user_agent = src.get("user_agent") if isinstance(src.get("user_agent"), dict) else {}
            network_context = NetworkContext(
                source_ip=_first_present(source.get("ip"), source.get("address")),
                source_port=source.get("port"),
                destination_ip=_first_present(destination.get("ip"), destination.get("address")),
                destination_port=destination.get("port"),
                protocol=_first_present(network.get("protocol"), network.get("transport")),
                direction=_first_present(
                    network.get("direction"),
                    _dig(src, "suricata", "eve", "direction"),
                ),
                user_agent=user_agent.get("original"),
                suricata_signature=rule_block.get("name") if telemetry_source == "suricata" else None,
                suricata_category=rule_block.get("category") if telemetry_source == "suricata" else None,
            )

        user_name = _first_present(
            _dig(src, "user", "name"),
            event_data("SourceUser"),
        )

        severity = _first_present(
            src.get("kibana.alert.severity"),
            _dig(src, "kibana", "alert", "severity"),
        )
        risk_score = _first_present(
            src.get("kibana.alert.risk_score"),
            _dig(src, "kibana", "alert", "risk_score"),
        )

        return cls(
            alert_id=str(_first_present(
                src.get("kibana.alert.uuid"),
                _dig(src, "kibana", "alert", "uuid"),
                raw.get("_id"),
            ) or "UNKNOWN"),
            rule_uuid=str(_first_present(
                src.get("kibana.alert.rule.uuid"),
                _dig(src, "kibana", "alert", "rule", "uuid"),
            ) or "UNKNOWN"),
            rule_id=rule_id,
            rule_name=str(rule_name),
            severity=str(severity).lower() if severity is not None else "unknown",
            risk_score=int(risk_score) if risk_score is not None else None,
            timestamp=src.get("@timestamp", "") or "",
            host_name=_first_present(_dig(src, "host", "name"), _dig(src, "host", "hostname")),
            user_name=user_name,
            reason=_first_present(
                src.get("kibana.alert.reason"),
                _dig(src, "kibana", "alert", "reason"),
            ),
            telemetry_source=telemetry_source,
            event_code=event_code,
            process_context=process_context,
            registry_context=registry_context,
            network_context=network_context,
            raw_event=src,
        )


def _first_present(*values: Any) -> Any:
    """Returns the first value that is not None or an empty string (0 and False are kept)."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value == "":
            continue
        return value
    return None


def _dig(src: Dict[str, Any], *path: str) -> Any:
    """Looks up a value by nested path, falling back to the flattened dotted key."""
    node: Any = src
    for key in path:
        if isinstance(node, dict) and key in node:
            node = node[key]
        else:
            node = None
            break
    if node is not None:
        return node
    return src.get(".".join(path)) if isinstance(src, dict) else None


def _unflatten_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    """
    Converts a Kibana ``fields`` block (``{"a.b.c": [v]}``) into a nested dict.
    Single-element lists are unwrapped; ``kibana.*`` keys stay flattened because
    the parser reads them in that form.
    """
    nested: Dict[str, Any] = {}
    for dotted, value in fields.items():
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if dotted.startswith("kibana.") or dotted.startswith("signal."):
            nested[dotted] = value
            continue
        parts = dotted.split(".")
        node = nested
        for part in parts[:-1]:
            existing = node.get(part)
            if not isinstance(existing, dict):
                existing = {}
                node[part] = existing
            node = existing
        node[parts[-1]] = value
    return nested


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


VerdictSource = Literal["llm", "heuristic", "heuristic_fallback", "error_fallback"]


class VerdictOutput(BaseModel):
    alert_id: str
    decision: TriageDecision
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    recommended_playbook: Optional[str] = None
    mitre_attack_techniques: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    # Which path produced this verdict. "heuristic_fallback" = LLM was requested but
    # failed/returned unusable output; "error_fallback" = pipeline exception.
    verdict_source: VerdictSource = "heuristic"


class TriagePipelineResult(BaseModel):
    alert: NormalizedAlert
    fact_finding: FactFindingOutput
    verdict: VerdictOutput
    processing_time_ms: float

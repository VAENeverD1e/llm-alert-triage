"""
Fact-Finding Agent implementation.
Aggregates contextual event logs around an alert without diagnostic bias or
subjective judgment. Where the alert document itself is missing context
(no parent process on Event ID 3/10/13 alerts, no host.name on Suricata
alerts), it enriches via real Elastic queries -- never by guessing.
"""
import logging
from typing import Any, Dict, List, Optional, Tuple

from agent.schemas.triage_schema import SecurityAlert, FactFindingOutput

logger = logging.getLogger(__name__)

# Parents that make an alert's context worth flagging as anomalous --
# a scripting/shell interpreter directly ancestoring the flagged process.
ANOMALOUS_PARENTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


class FactFindingAgent:
    """
    Stage 1 Agent: Gathers and structures raw facts surrounding a security
    alert. Strictly forbidden from rendering verdicts or calculating risk
    scores -- enrichment failures and missing fields are reported as facts
    ("not available"), never silently upgraded into a judgment call.
    """

    def __init__(self, elastic_client=None, ollama_client=None):
        self.elastic_client = elastic_client
        self.ollama_client = ollama_client

    def process(self, alert: SecurityAlert) -> FactFindingOutput:
        logger.info(f"[Fact-Finding Stage] Gathering facts for alert: {alert.alert_id}")

        host_name = alert.host_name
        parent_process: Optional[Dict[str, Any]] = None
        evidence: List[str] = [f"Rule: {alert.rule_id}", f"Severity: {alert.severity}"]

        if alert.telemetry_source == "sysmon" and alert.process_context:
            parent_process, note = self._resolve_parent_process(alert)
            evidence.append(note)

        if alert.telemetry_source == "suricata" and not host_name:
            host_name, note = self._resolve_host(alert)
            evidence.append(note)

        processes = self._collect_process_names(alert, parent_process)
        network_calls = self._collect_network_connections(alert)

        summary = (
            f"Alert '{alert.rule_name}' ({alert.rule_id}) triggered on host "
            f"'{host_name or 'UNKNOWN'}'. "
            f"User: {alert.user_name or 'not captured in this telemetry'}."
        )

        return FactFindingOutput(
            alert_id=alert.alert_id,
            summary_of_events=summary,
            associated_processes=processes,
            network_connections=network_calls,
            user_context=f"User: {alert.user_name or 'None'} on Host: {host_name or 'None'}",
            timeline=[
                {"timestamp": alert.timestamp, "event": f"Triggered rule {alert.rule_id} ({alert.rule_name})"}
            ],
            has_anomalous_parent_process=bool(
                parent_process and parent_process.get("name") in ANOMALOUS_PARENTS
            ),
            evidence_extracted=evidence,
        )

    # ── Enrichment helpers ──────────────────────────────────────────────

    def _resolve_parent_process(self, alert: SecurityAlert) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Returns (parent_process_dict_or_None, evidence_note). Prefers the
        parent process already inline on the alert (Event ID 1 alerts
        carry it); otherwise correlates via Elastic to the process's own
        Event ID 1 record (Event ID 3/10/13 alerts never carry parent
        info inline -- see docs/alert-schema-audit.md, Bug 5).
        """
        pc = alert.process_context
        if pc.parent_process and pc.parent_process.name:
            return (
                {
                    "name": pc.parent_process.name,
                    "executable": pc.parent_process.executable,
                    "command_line": pc.parent_process.command_line,
                    "pid": pc.parent_process.pid,
                },
                "Parent process present inline on the alert (Event ID 1).",
            )

        if not self.elastic_client:
            return None, "No parent process inline and no Elastic client configured for enrichment."

        entity_id = (alert.raw_event.get("process") or {}).get("entity_id") if isinstance(alert.raw_event, dict) else None
        pid = pc.process.pid if pc.process else None

        parent = self.elastic_client.get_process_creation_context(
            entity_id=entity_id,
            pid=pid,
            host_name=alert.host_name,
            timestamp=alert.timestamp,
        )
        if parent:
            return parent, "Parent process resolved via Elastic Event ID 1 correlation."
        return None, "Parent process not found via Elastic correlation (no exception raised)."

    def _resolve_host(self, alert: SecurityAlert) -> Tuple[Optional[str], str]:
        """
        Returns (host_name_or_None, evidence_note). Suricata alerts carry
        only IPs, no host.name -- resolve it from any endpoint telemetry
        that has seen the same IP (docs/alert-schema-audit.md, Bug 4).
        """
        if not self.elastic_client:
            return None, "No host.name on alert and no Elastic client configured for resolution."

        net = alert.network_context
        candidate_ip = (net.source_ip or net.destination_ip) if net else None
        if not candidate_ip:
            return None, "No source/destination IP available to resolve a host from."

        host_name = self.elastic_client.resolve_host_from_ip(candidate_ip)
        if host_name:
            return host_name, f"Host resolved from IP {candidate_ip} via Elastic."
        return None, f"Host could not be resolved from IP {candidate_ip} (no exception raised)."

    # ── Plain aggregation helpers ────────────────────────────────────────

    @staticmethod
    def _collect_process_names(alert: SecurityAlert, parent_process: Optional[Dict[str, Any]]) -> List[str]:
        names: List[str] = []
        pc = alert.process_context
        if pc and pc.process and pc.process.name:
            names.append(pc.process.name)
        if parent_process and parent_process.get("name"):
            names.append(parent_process["name"])
        # Backwards compatibility fallback for legacy test mocks using raw_event["process_name"]
        if not names and isinstance(alert.raw_event, dict) and "process_name" in alert.raw_event:
            names.append(alert.raw_event["process_name"])
        return list(dict.fromkeys(names))  # de-dupe, keep order

    @staticmethod
    def _collect_network_connections(alert: SecurityAlert) -> List[str]:
        net = alert.network_context
        if not net or not net.destination_ip:
            return []
        return [f"{net.destination_ip}:{net.destination_port}"]

"""
Fact-Finding Agent implementation.
Aggregates contextual event logs around an alert without diagnostic bias or subjective judgment.
"""
import logging
from typing import Dict, Any, List
from agent.schemas.triage_schema import SecurityAlert, FactFindingOutput

logger = logging.getLogger(__name__)


class FactFindingAgent:
    """
    Stage 1 Agent: Gathers and structures raw facts surrounding a security alert.
    Strictly forbidden from rendering verdicts or calculating risk scores.
    """

    def __init__(self, elastic_client=None, ollama_client=None):
        self.elastic_client = elastic_client
        self.ollama_client = ollama_client

    def process(self, alert: SecurityAlert) -> FactFindingOutput:
        """
        Ingests alert telemetry and queries related host/network events.
        """
        logger.info(f"[Fact-Finding Stage] Gathering facts for alert: {alert.alert_id}")

        # Fetch related events if elastic client is available
        related_events: List[Dict[str, Any]] = []
        if self.elastic_client:
            related_events = self.elastic_client.query_context_events(
                host_name=alert.host_name,
                timestamp=alert.timestamp,
                window_minutes=5
            )

        # Extract process trees, network calls, and timeline
        processes = [
            event.get("process", {}).get("name", "unknown")
            for event in related_events
            if "process" in event
        ] or [alert.raw_event.get("process_name", "powershell.exe")]

        network_calls = [
            f"{event.get('destination', {}).get('ip', '0.0.0.0')}:{event.get('destination', {}).get('port', 80)}"
            for event in related_events
            if "destination" in event
        ]

        summary = (
            f"Alert '{alert.rule_name}' triggered on host '{alert.host_name}' by user '{alert.user_name}'. "
            f"Observed {len(processes)} process activity events and {len(network_calls)} network connection attempts."
        )

        return FactFindingOutput(
            alert_id=alert.alert_id,
            summary_of_events=summary,
            associated_processes=list(set(processes)),
            network_connections=list(set(network_calls)),
            user_context=f"User: {alert.user_name} on Host: {alert.host_name}",
            timeline=[
                {"timestamp": alert.timestamp, "event": f"Triggered rule {alert.rule_id} ({alert.rule_name})"}
            ],
            has_anomalous_parent_process=True if "powershell.exe" in processes else False,
            evidence_extracted=[
                f"Rule: {alert.rule_id}",
                f"Host: {alert.host_name}",
                f"User: {alert.user_name}"
            ]
        )

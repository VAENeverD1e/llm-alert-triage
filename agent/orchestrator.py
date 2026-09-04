"""
Orchestrator Module.
Coordinates the two-stage triage pipeline:
Stage 1: Fact-Finding (Event Aggregation) -> Stage 2: Verdict (Escalate/Close)
"""
import time
import logging
from typing import Optional, Dict, Any

from agent.schemas.triage_schema import (
    SecurityAlert,
    FactFindingOutput,
    VerdictOutput,
    TriagePipelineResult,
    TriageDecision
)
from agent.fact_finding.collector import FactFindingAgent
from agent.verdict.evaluator import VerdictAgent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("TriageOrchestrator")


class TriageOrchestrator:
    """
    Two-Stage Pipeline Orchestrator for Security Alert Triage.
    """

    def __init__(
        self,
        elastic_client: Optional[Any] = None,
        playbook_retriever: Optional[Any] = None,
        ollama_client: Optional[Any] = None,
        discord_forwarder: Optional[Any] = None
    ):
        self.fact_finder = FactFindingAgent(elastic_client=elastic_client, ollama_client=ollama_client)
        self.verdict_agent = VerdictAgent(playbook_retriever=playbook_retriever, ollama_client=ollama_client)
        self.discord_forwarder = discord_forwarder

    def run_pipeline(self, alert_data: Dict[str, Any]) -> TriagePipelineResult:
        """
        Executes end-to-end triage pipeline for an incoming alert dict.
        """
        start_time = time.time()
        logger.info(f"--- Starting Triage Pipeline for Alert {alert_data.get('alert_id')} ---")

        # Parse alert
        alert = SecurityAlert(**alert_data)

        try:
            # Stage 1: Fact-Finding
            facts: FactFindingOutput = self.fact_finder.process(alert)

            # Stage 2: Verdict
            verdict: VerdictOutput = self.verdict_agent.process(alert, facts)

        except Exception as e:
            logger.error(f"Error executing triage pipeline: {e}. Falling back to default Escalate.")
            facts = FactFindingOutput(
                alert_id=alert.alert_id,
                summary_of_events=f"Pipeline error encountered: {str(e)}",
                user_context=f"User: {alert.user_name}"
            )
            verdict = VerdictOutput(
                alert_id=alert.alert_id,
                decision=TriageDecision.ESCALATE,
                confidence_score=0.5,
                reasoning=f"Pipeline error fallback trigger: {str(e)}",
                risk_factors=["Pipeline Execution Failure"]
            )

        elapsed_ms = (time.time() - start_time) * 1000.0

        result = TriagePipelineResult(
            alert=alert,
            fact_finding=facts,
            verdict=verdict,
            processing_time_ms=elapsed_ms
        )

        # Notify via Discord if configured
        if self.discord_forwarder:
            try:
                self.discord_forwarder.send_triage_result(result)
            except Exception as notify_err:
                logger.warning(f"Failed to forward alert to Discord: {notify_err}")

        logger.info(
            f"--- Pipeline Finished ({elapsed_ms:.1f}ms) | Decision: {verdict.decision.value} "
            f"(Confidence: {verdict.confidence_score:.2f}) ---"
        )
        return result


if __name__ == "__main__":
    # Test script execution
    sample_alert = {
        "alert_id": "ALT-9999",
        "rule_id": "T1059.001",
        "rule_name": "PowerShell Script Execution with Encoded Command",
        "severity": "high",
        "timestamp": "2026-09-03T12:00:00Z",
        "host_name": "WORKSTATION-01",
        "user_name": "jdoe",
        "raw_event": {"process_name": "powershell.exe", "command_line": "powershell -Enc ..."}
    }

    orchestrator = TriageOrchestrator()
    res = orchestrator.run_pipeline(sample_alert)
    print(res.model_dump_json(indent=2))

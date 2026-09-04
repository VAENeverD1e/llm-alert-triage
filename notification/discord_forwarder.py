"""
Discord Notification Forwarder.
Extends ELK Discord Alerter capabilities by attaching LLM triage results (Verdict + Confidence + Reasoning).
"""
import logging
from typing import Dict, Any
from agent.schemas.triage_schema import TriagePipelineResult, TriageDecision

logger = logging.getLogger(__name__)


class DiscordForwarder:
    """
    Formats and forwards enriched triage results to Discord webhooks.
    """

    def __init__(self, webhook_url: str = ""):
        self.webhook_url = webhook_url

    def format_embed(self, result: TriagePipelineResult) -> Dict[str, Any]:
        """
        Formats a Discord embed payload with color-coded triage status.
        """
        color = 0xFF0000 if result.verdict.decision == TriageDecision.ESCALATE else 0x00FF00
        
        embed = {
            "title": f"🚨 [Triage Verdict: {result.verdict.decision.value}] {result.alert.rule_name}",
            "description": result.verdict.reasoning,
            "color": color,
            "fields": [
                {
                    "name": "Alert ID",
                    "value": result.alert.alert_id,
                    "inline": True
                },
                {
                    "name": "Confidence",
                    "value": f"{result.verdict.confidence_score * 100:.1f}%",
                    "inline": True
                },
                {
                    "name": "Host / User",
                    "value": f"`{result.alert.host_name}` / `{result.alert.user_name}`",
                    "inline": True
                },
                {
                    "name": "Stage 1 Summary",
                    "value": result.fact_finding.summary_of_events,
                    "inline": False
                },
                {
                    "name": "Risk Factors",
                    "value": ", ".join(result.verdict.risk_factors) if result.verdict.risk_factors else "None",
                    "inline": False
                }
            ],
            "footer": {
                "text": f"LLM Alert Triage Engine • Executed in {result.processing_time_ms:.1f}ms"
            }
        }
        return {"embeds": [embed]}

    def send_triage_result(self, result: TriagePipelineResult) -> bool:
        """
        Posts payload to configured Discord webhook URL.
        """
        payload = self.format_embed(result)
        logger.info(f"Sending Discord notification for alert {result.alert.alert_id} (Verdict: {result.verdict.decision.value})...")
        if not self.webhook_url:
            logger.info("No webhook URL configured; skipping actual HTTP POST.")
            return True
        # In production: requests.post(self.webhook_url, json=payload)
        return True

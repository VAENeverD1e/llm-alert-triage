"""
Discord Notification Forwarder.
Extends SOC alerting capabilities by formatting and forwarding rich, color-coded LLM triage results
(verdict, confidence score, investigation facts, and forensic context) to Discord channels via webhooks.
"""
import os
import time
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

import requests

from agent.schemas.triage_schema import (
    TriagePipelineResult,
    TriageDecision,
    NormalizedAlert,
)

logger = logging.getLogger(__name__)

# Discord embed color constants
COLOR_ESCALATE = 0xED4245  # Discord Red
COLOR_CLOSE = 0x57F287     # Discord Green
COLOR_UNKNOWN = 0xFEE75C   # Discord Yellow / Amber

DISCORD_FIELD_MAX_LEN = 1024
DISCORD_DESC_MAX_LEN = 2048


def _truncate(text: Optional[str], max_len: int = 1024, suffix: str = "...") -> str:
    """Safely truncates text to fit within Discord length constraints."""
    if not text:
        return "N/A"
    text_str = str(text).strip()
    if len(text_str) <= max_len:
        return text_str
    return text_str[: max_len - len(suffix)] + suffix


class DiscordForwarder:
    """
    Formats and forwards enriched triage results to Discord webhooks.
    Includes retry logic, rate limit handling, and defensive fallback.
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        timeout: float = 5.0,
        retry_count: int = 2,
        dry_run: bool = False,
    ):
        """
        Initializes the DiscordForwarder.
        
        Args:
            webhook_url: Target Discord incoming webhook URL. Defaults to DISCORD_WEBHOOK_URL env var.
            timeout: HTTP request timeout in seconds.
            retry_count: Number of retries on transient connection or 5xx server errors.
            dry_run: If True, builds payload and logs without executing actual HTTP request.
        """
        self.webhook_url = webhook_url or os.environ.get("DISCORD_WEBHOOK_URL", "")
        self.timeout = timeout
        self.retry_count = retry_count
        self.dry_run = dry_run

    def format_embed(self, result: TriagePipelineResult) -> Dict[str, Any]:
        """
        Formats a structured Discord embed payload with color-coded triage status,
        investigation summary, and forensic telemetry indicators.
        """
        decision = result.verdict.decision
        if decision == TriageDecision.ESCALATE:
            color = COLOR_ESCALATE
            title_prefix = "🚨 [ESCALATE]"
        elif decision == TriageDecision.CLOSE:
            color = COLOR_CLOSE
            title_prefix = "✅ [CLOSE]"
        else:
            color = COLOR_UNKNOWN
            title_prefix = "⚠️ [UNKNOWN]"

        alert: NormalizedAlert = result.alert
        confidence_pct = result.verdict.confidence_score * 100.0

        embed_fields: List[Dict[str, Any]] = [
            {
                "name": "Alert ID",
                "value": f"`{alert.alert_id}`",
                "inline": True,
            },
            {
                "name": "Technique",
                "value": f"`{alert.rule_id}`",
                "inline": True,
            },
            {
                "name": "Verdict",
                "value": f"**{decision.value}** ({confidence_pct:.1f}%)",
                "inline": True,
            },
            {
                "name": "Severity / Risk",
                "value": f"{alert.severity.upper()} (Score: {alert.risk_score or 'N/A'})",
                "inline": True,
            },
            {
                "name": "Host / User",
                "value": f"`{alert.host_name or 'N/A'}` / `{alert.user_name or 'N/A'}`",
                "inline": True,
            },
            {
                "name": "Telemetry Source",
                "value": f"{alert.telemetry_source} (Code {alert.event_code or 'N/A'})",
                "inline": True,
            },
        ]

        # Add Telemetry Specific Context Indicators
        if alert.process_context and alert.process_context.process:
            proc = alert.process_context.process
            parent = alert.process_context.parent_process
            p_val = f"**Proc:** `{proc.name or 'N/A'}` (PID: {proc.pid or 'N/A'})\n"
            if proc.command_line:
                p_val += f"**CLI:** `{_truncate(proc.command_line, 250)}`\n"
            if parent and parent.name:
                p_val += f"**Parent:** `{parent.name}`"
            embed_fields.append({
                "name": "🖥️ Process Context",
                "value": _truncate(p_val, DISCORD_FIELD_MAX_LEN),
                "inline": False,
            })

        if alert.network_context:
            net = alert.network_context
            net_val = f"**Connection:** `{net.source_ip}:{net.source_port}` ➔ `{net.destination_ip}:{net.destination_port}` ({net.protocol or 'TCP'})\n"
            if net.user_agent:
                net_val += f"**User-Agent:** `{_truncate(net.user_agent, 200)}`\n"
            if net.suricata_signature:
                net_val += f"**Suricata Sig:** `{_truncate(net.suricata_signature, 200)}`"
            embed_fields.append({
                "name": "🌐 Network Context",
                "value": _truncate(net_val, DISCORD_FIELD_MAX_LEN),
                "inline": False,
            })

        if alert.registry_context:
            reg = alert.registry_context
            reg_val = f"**Path:** `{reg.path or 'N/A'}`\n**Value:** `{reg.value_name or 'N/A'}`\n**Data:** `{_truncate(reg.data, 200)}`"
            embed_fields.append({
                "name": "🔑 Registry Context",
                "value": _truncate(reg_val, DISCORD_FIELD_MAX_LEN),
                "inline": False,
            })

        # Stage 1 Summary
        embed_fields.append({
            "name": "🔍 Investigation Findings",
            "value": _truncate(result.fact_finding.summary_of_events, DISCORD_FIELD_MAX_LEN),
            "inline": False,
        })

        # Risk Factors
        risk_factors_str = (
            "\n".join([f"• {rf}" for rf in result.verdict.risk_factors])
            if result.verdict.risk_factors
            else "None identified"
        )
        embed_fields.append({
            "name": "⚠️ Risk Factors",
            "value": _truncate(risk_factors_str, DISCORD_FIELD_MAX_LEN),
            "inline": False,
        })

        # Recommended Playbook (if present)
        if result.verdict.recommended_playbook:
            embed_fields.append({
                "name": "📖 Playbook Guideline",
                "value": f"`{result.verdict.recommended_playbook}`",
                "inline": True,
            })

        embed = {
            "title": _truncate(f"{title_prefix} {alert.rule_name}", 256),
            "description": _truncate(result.verdict.reasoning, DISCORD_DESC_MAX_LEN),
            "color": color,
            "fields": embed_fields,
            "footer": {
                "text": f"LLM Alert Triage Engine • Processing: {result.processing_time_ms:.1f}ms",
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return {"embeds": [embed]}

    def send_triage_result(
        self,
        result: TriagePipelineResult,
        webhook_url: Optional[str] = None,
    ) -> bool:
        """
        Posts payload to configured Discord webhook URL.
        
        Args:
            result: TriagePipelineResult object containing alert, facts, and verdict.
            webhook_url: Optional override URL for Discord webhook.
            
        Returns:
            bool: True if delivery was successful or dry-run was executed, False on failure.
        """
        url = webhook_url or self.webhook_url
        payload = self.format_embed(result)

        if self.dry_run or not url:
            logger.info(
                f"[DiscordForwarder] Dry-run/No webhook URL configured. "
                f"Alert {result.alert.alert_id} ({result.verdict.decision.value}) formatted successfully."
            )
            return True

        headers = {"Content-Type": "application/json"}
        for attempt in range(1, self.retry_count + 2):
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=self.timeout)

                # Discord webhook success is typically HTTP 204 No Content (or 200 OK)
                if response.status_code in (200, 204):
                    logger.info(
                        f"[DiscordForwarder] Successfully forwarded alert {result.alert.alert_id} to Discord "
                        f"(Status: {response.status_code})."
                    )
                    return True

                if response.status_code == 429:
                    retry_after = 1.0
                    try:
                        retry_after = float(response.json().get("retry_after", 1.0))
                    except Exception:
                        pass
                    logger.warning(
                        f"[DiscordForwarder] Rate limited (HTTP 429). Retry-After: {retry_after}s. "
                        f"Attempt {attempt}/{self.retry_count + 1}."
                    )
                    if attempt <= self.retry_count:
                        time.sleep(retry_after)
                        continue
                    return False

                # Handle other client or server errors
                logger.error(
                    f"[DiscordForwarder] Failed to post to Discord (HTTP {response.status_code}): {response.text[:200]}"
                )
                if response.status_code >= 500 and attempt <= self.retry_count:
                    time.sleep(1.0 * attempt)
                    continue
                return False

            except requests.exceptions.RequestException as err:
                logger.warning(
                    f"[DiscordForwarder] Connection error on attempt {attempt}/{self.retry_count + 1}: {err}"
                )
                if attempt <= self.retry_count:
                    time.sleep(1.0 * attempt)
                    continue
                return False
            except Exception as e:
                logger.error(f"[DiscordForwarder] Unexpected error forwarding alert to Discord: {e}")
                return False

        return False

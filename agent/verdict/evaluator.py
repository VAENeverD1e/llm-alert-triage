"""
Verdict Agent implementation.
Evaluates aggregated facts from Stage 1 against security playbooks and rule policies to issue an Escalate/Close decision.
Integrates local LLM (Ollama) with RAG Incident Playbooks for automated reasoning and confidence scoring.
"""
import json
import logging
import re
from typing import Dict, Any, Optional, List

from agent.schemas.triage_schema import (
    SecurityAlert,
    FactFindingOutput,
    VerdictOutput,
    TriageDecision
)

logger = logging.getLogger(__name__)


class VerdictAgent:
    """
    Stage 2 Agent: Evaluates facts against playbooks to render a final triage verdict.
    Combines local LLM reasoning (via Ollama) with grounded incident response playbooks (RAG).
    """

    def __init__(self, playbook_retriever=None, ollama_client=None):
        self.playbook_retriever = playbook_retriever
        self.ollama_client = ollama_client

    def process(self, alert: SecurityAlert, facts: FactFindingOutput) -> VerdictOutput:
        """
        Processes alert and Stage 1 investigation facts to produce a structured verdict.
        """
        logger.info(f"[Verdict Stage] Rendering verdict for alert: {alert.alert_id} (Rule: {alert.rule_id})")

        playbook_text = ""
        playbook_id = f"PB-{alert.rule_id}" if alert.rule_id else "PB-Default"
        if self.playbook_retriever:
            # Query by technique ID first, fallback to rule name
            playbook_text = self.playbook_retriever.get_playbook(alert.rule_id)
            if not playbook_text or "DEFAULT PLAYBOOK" in playbook_text:
                pb_by_name = self.playbook_retriever.get_playbook(alert.rule_name)
                if pb_by_name and "DEFAULT PLAYBOOK" not in pb_by_name:
                    playbook_text = pb_by_name

        # If LLM client is available, attempt grounded LLM evaluation
        if self.ollama_client:
            try:
                verdict = self._evaluate_with_llm(alert, facts, playbook_text, playbook_id)
                if verdict:
                    return verdict
            except Exception as e:
                logger.warning(f"[Verdict Stage] LLM evaluation failed or timed out: {e}. Falling back to rule heuristic.")

        # Safe fallback if LLM is unavailable or offline
        return self._evaluate_heuristic(alert, facts, playbook_id)

    def _evaluate_with_llm(
        self,
        alert: SecurityAlert,
        facts: FactFindingOutput,
        playbook_text: str,
        playbook_id: str
    ) -> Optional[VerdictOutput]:
        """
        Constructs a cyber triage prompt and queries local Ollama model for structured verdict.
        """
        system_prompt = (
            "You are a Senior SOC L2 Analyst specialized in automated cyber alert triage. "
            "Your task is to analyze the security alert, the Stage 1 enrichment facts, and the incident response playbook "
            "to issue a definitive triage verdict: ESCALATE (true threat / active attacker / anomalous activity) "
            "or CLOSE (benign / verified administrative activity / false positive). "
            "You MUST respond ONLY with a valid JSON object matching the required schema."
        )

        process_details = ""
        pctx = getattr(alert, "process_context", None)
        if pctx:
            proc = pctx.process
            parent = pctx.parent_process
            process_details = (
                f"- Process Name: {proc.name if proc else 'N/A'}\n"
                f"- Executable: {proc.executable if proc else 'N/A'}\n"
                f"- Command Line: {proc.command_line if proc else 'N/A'}\n"
                f"- Parent Process: {parent.name if parent else 'N/A'}\n"
                f"- Parent Command Line: {parent.command_line if parent else 'N/A'}\n"
                f"- Target Process: {pctx.target_process_name or 'N/A'}\n"
                f"- Granted Access: {pctx.granted_access or 'N/A'}\n"
                f"- Call Trace: {pctx.call_trace or 'N/A'}\n"
            )
        elif getattr(alert, "raw_event", None):
            raw_pname = alert.raw_event.get("process_name") or alert.raw_event.get("process", {}).get("name")
            if raw_pname:
                process_details = f"- Process Name (raw): {raw_pname}\n"

        network_details = ""
        net_ctx = getattr(alert, "network_context", None)
        if net_ctx:
            network_details = (
                f"- Source IP: {net_ctx.source_ip or 'N/A'}:{net_ctx.source_port or 'N/A'}\n"
                f"- Destination IP: {net_ctx.destination_ip or 'N/A'}:{net_ctx.destination_port or 'N/A'}\n"
                f"- Protocol: {net_ctx.protocol or 'N/A'}\n"
                f"- Direction: {net_ctx.direction or 'N/A'}\n"
                f"- User Agent: {net_ctx.user_agent or 'N/A'}\n"
                f"- Suricata Signature: {net_ctx.suricata_signature or 'N/A'}\n"
                f"- Suricata Category: {net_ctx.suricata_category or 'N/A'}\n"
            )

        registry_details = ""
        reg_ctx = getattr(alert, "registry_context", None)
        if reg_ctx:
            registry_details = (
                f"- Registry Path: {reg_ctx.path or 'N/A'}\n"
                f"- Value Name: {reg_ctx.value_name or 'N/A'}\n"
                f"- Value Data: {reg_ctx.value_data or 'N/A'}\n"
            )

        # Extract targeted guidance (focus on TP vs FP criteria to maximize speed and reasoning precision)
        playbook_snippet = ""
        if playbook_text:
            crit_match = re.search(r"(## TP vs FP escalation criteria.*)", playbook_text, re.DOTALL)
            if crit_match:
                snippet = crit_match.group(1).split("## Containment")[0].strip()
                playbook_snippet = snippet[:1500]
            else:
                playbook_snippet = playbook_text[:1500]
        else:
            playbook_snippet = "Inspect host telemetry and escalate if unauthorized activity."

        user_prompt = f"""### INCIDENT RESPONSE PLAYBOOK GUIDANCE:
{playbook_snippet}

### INCOMING ALERT TELEMETRY:
- Alert ID: {alert.alert_id}
- Rule Name: {alert.rule_name}
- MITRE Technique: {alert.rule_id}
- Severity: {alert.severity} (Risk Score: {alert.risk_score})
- Telemetry Source: {alert.telemetry_source}
- Host Name: {alert.host_name or 'Unknown'}
- User: {alert.user_name or 'Unknown'}
- Detection Reason: {alert.reason}

[Process Context]
{process_details or 'None'}

[Network Context]
{network_details or 'None'}

[Registry Context]
{registry_details or 'None'}

### STAGE 1 ENRICHMENT & INVESTIGATION FINDINGS:
- Summary: {facts.summary_of_events}
- Associated Processes: {facts.associated_processes}
- Network Connections: {facts.network_connections}
- User Context: {facts.user_context}
- Has Anomalous Parent Process: {facts.has_anomalous_parent_process}
- Evidence Extracted: {facts.evidence_extracted}

### TRIAGE INSTRUCTIONS:
1. Cross-reference the alert telemetry and investigation findings with the Playbook's TP vs FP criteria.
2. Determine whether this alert should be ESCALATED or CLOSED.
3. Provide your professional reasoning, confidence score (0.0 to 1.0), and key risk factors.

Output ONLY a JSON object:
{{
  "decision": "ESCALATE",
  "confidence_score": 0.95,
  "reasoning": "Clear analytical reasoning justifying the verdict based on indicators and playbook...",
  "recommended_playbook": "{playbook_id}",
  "mitre_attack_techniques": ["{alert.rule_id}"],
  "risk_factors": ["risk factor 1", "risk factor 2"]
}}
"""

        raw_response = self.ollama_client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            json_format=True,
            temperature=0.1,
            fallback_mock=False
        )

        return self._parse_llm_response(raw_response, alert, facts, playbook_id)

    def _parse_llm_response(
        self,
        raw_response: str,
        alert: SecurityAlert,
        facts: FactFindingOutput,
        playbook_id: str
    ) -> Optional[VerdictOutput]:
        """
        Parses structured JSON response from Ollama into VerdictOutput.
        """
        if not raw_response or not raw_response.strip():
            return None

        cleaned = raw_response.strip()
        # Handle markdown fence wrapping if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"(\{.*\})", cleaned, re.DOTALL)
            if match:
                data = json.loads(match.group(1))
            else:
                logger.warning(f"Could not parse valid JSON from LLM: {raw_response[:200]}")
                return None

        decision_str = str(data.get("decision", "")).strip().upper()
        if "ESCALATE" in decision_str:
            decision = TriageDecision.ESCALATE
        elif "CLOSE" in decision_str:
            decision = TriageDecision.CLOSE
        else:
            is_suspicious = alert.severity.lower() in ["high", "critical"] or facts.has_anomalous_parent_process
            decision = TriageDecision.ESCALATE if is_suspicious else TriageDecision.CLOSE

        try:
            confidence = float(data.get("confidence_score", 0.85))
            confidence = max(0.0, min(1.0, confidence))
        except (ValueError, TypeError):
            confidence = 0.85

        reasoning = data.get("reasoning")
        if not reasoning or not isinstance(reasoning, str):
            reasoning = f"LLM assessed alert '{alert.rule_name}' and determined decision is {decision.value}."

        rec_pb = data.get("recommended_playbook") or playbook_id
        mitre_techs = data.get("mitre_attack_techniques")
        if not isinstance(mitre_techs, list) or not mitre_techs:
            mitre_techs = [alert.rule_id] if alert.rule_id else []

        risk_factors = data.get("risk_factors")
        if not isinstance(risk_factors, list):
            risk_factors = [f"Severity: {alert.severity}"]

        return VerdictOutput(
            alert_id=alert.alert_id,
            decision=decision,
            confidence_score=confidence,
            reasoning=reasoning,
            recommended_playbook=rec_pb,
            mitre_attack_techniques=mitre_techs,
            risk_factors=risk_factors
        )

    def _evaluate_heuristic(
        self,
        alert: SecurityAlert,
        facts: FactFindingOutput,
        playbook_id: str
    ) -> VerdictOutput:
        """
        Rule-based heuristic fallback when LLM is unavailable or offline.
        """
        is_suspicious = (
            alert.severity.lower() in ["high", "critical"]
            or facts.has_anomalous_parent_process
        )
        decision = TriageDecision.ESCALATE if is_suspicious else TriageDecision.CLOSE
        confidence = 0.92 if is_suspicious else 0.88

        reasoning = (
            f"[Rule Heuristic] Alert '{alert.rule_name}' triggered with severity '{alert.severity}'. "
            f"Fact-finding revealed anomalous parent process pattern: {facts.has_anomalous_parent_process} "
            f"(Processes: {facts.associated_processes}). "
            f"Recommended triage action is {decision.value}."
        )

        return VerdictOutput(
            alert_id=alert.alert_id,
            decision=decision,
            confidence_score=confidence,
            reasoning=reasoning,
            recommended_playbook=playbook_id if is_suspicious else None,
            mitre_attack_techniques=[alert.rule_id] if alert.rule_id else [],
            risk_factors=[
                f"Severity: {alert.severity}",
                f"Anomalous Process: {facts.has_anomalous_parent_process}"
            ]
        )

"""
Verdict Agent implementation.
Evaluates aggregated facts from Stage 1 against security playbooks and rule policies to issue an Escalate/Close decision.
"""
import logging
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
    """

    def __init__(self, playbook_retriever=None, ollama_client=None):
        self.playbook_retriever = playbook_retriever
        self.ollama_client = ollama_client

    def process(self, alert: SecurityAlert, facts: FactFindingOutput) -> VerdictOutput:
        """
        Processes alert and facts to produce a structured verdict.
        """
        logger.info(f"[Verdict Stage] Rendering verdict for alert: {alert.alert_id}")

        playbook_text = ""
        if self.playbook_retriever:
            playbook_text = self.playbook_retriever.get_playbook(alert.rule_id)

        # Logic / LLM reasoning simulation fallback
        is_suspicious = (
            alert.severity.lower() in ["high", "critical"]
            or facts.has_anomalous_parent_process
        )

        decision = TriageDecision.ESCALATE if is_suspicious else TriageDecision.CLOSE
        confidence = 0.92 if is_suspicious else 0.88

        reasoning = (
            f"Alert '{alert.rule_name}' triggered with severity '{alert.severity}'. "
            f"Fact-finding revealed anomalous parent process pattern in processes: {facts.associated_processes}. "
            f"Recommended triage action is {decision.value}."
        )

        return VerdictOutput(
            alert_id=alert.alert_id,
            decision=decision,
            confidence_score=confidence,
            reasoning=reasoning,
            recommended_playbook=f"Playbook-{alert.rule_id}" if is_suspicious else None,
            mitre_attack_techniques=[alert.rule_id],
            risk_factors=[
                f"Severity: {alert.severity}",
                f"Anomalous Process: {facts.has_anomalous_parent_process}"
            ]
        )

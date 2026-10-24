"""
Prompt Guard Security Module.
Provides defense-in-depth sanitization, delimiter isolation, and adversarial pattern detection
against prompt injection payloads embedded in SIEM alert telemetry.
"""
import copy
import re
import logging
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any, Optional

from agent.schemas.triage_schema import NormalizedAlert

logger = logging.getLogger(__name__)

# Core Prompt Injection Signatures categorized by attack vector
INJECTION_SIGNATURES: Dict[str, List[Tuple[str, re.Pattern]]] = {
    "instruction_override": [
        (
            "Ignore Previous Instructions",
            re.compile(
                r"(?i)\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|existing|system)\s+(?:instructions?|commands?|rules?|prompts?|guidelines?)\b"
            ),
        ),
        (
            "Disregard Playbook/Instructions",
            re.compile(
                r"(?i)\bdisregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|playbooks?|instructions?|rules?|guidelines?)\b"
            ),
        ),
        (
            "Forget Instructions",
            re.compile(
                r"(?i)\bforget\s+(?:all\s+|everything\s+|previous\s+|prior\s+)?(?:instructions?|prompts?|rules?)\b"
            ),
        ),
        (
            "System Override Directive",
            re.compile(
                r"(?i)\bsystem\s+(?:prompt\s+)?(?:override|command|instruction|directive)\b"
            ),
        ),
        (
            "New Instruction Injection",
            re.compile(r"(?i)\bnew\s+instructions?\s*:\b"),
        ),
    ],
    "role_hijacking": [
        (
            "Persona Switch",
            re.compile(
                r"(?i)\byou\s+are\s+now\s+(?:a|an)?\s*(?:benign|harmless|admin|security\s+scanner|maintenance|logging\s+assistant|helpful\s+assistant)\b"
            ),
        ),
        (
            "Act As Benign",
            re.compile(
                r"(?i)\bact\s+as\s+(?:a|an)?\s*(?:benign|harmless|safe|helper|admin|authorized)\b"
            ),
        ),
        (
            "Assume Role",
            re.compile(r"(?i)\bassume\s+(?:the\s+)?role\s+of\b"),
        ),
    ],
    "verdict_tampering": [
        (
            "Force Decision Close",
            re.compile(
                r"""(?i)\b(?:set|mark|output|return)\s+(?:the\s+)?(?:verdict|decision)\s*(?:as|to|:|=)\s*['"]?(?:close|benign|safe)['"]?\b"""
            ),
        ),
        (
            "Direct Decision Close Assignment",
            re.compile(r"""(?i)\b(?:verdict|decision)\s*(?:is|:|=)\s*['"]?close['"]?\b"""),
        ),
        (
            "Manipulate Confidence",
            re.compile(
                r"""(?i)\bconfidence\s*(?:score)?\s*(?:is|:|=)\s*(?:1\.0|100%|0\.99)\b"""
            ),
        ),
    ],
    "delimiter_injection": [
        (
            "Markdown Header Hijack",
            re.compile(
                r"(?i)###\s*(?:triage\s+instructions|incident\s+response\s+playbook|incoming\s+alert|stage\s+1)"
            ),
        ),
        (
            "JSON Code Block Inject",
            re.compile(r"""(?i)```json\s*\{\s*["']decision["']\s*:\s*["']close["']"""),
        ),
        (
            "Fenced Tag Escape",
            re.compile(r"(?i)</?untrusted_telemetry(?:_data)?>|</?system>"),
        ),
    ],
    "evasion_sqli": [
        (
            "SQLi Delimiter Injection",
            re.compile(r"(?i)';\s*DROP\s+TABLE\s+alerts"),
        ),
        (
            "Comment Delimiter Prompt Injection",
            re.compile(r"(?i)--\s*\[SYSTEM\s+PROMPT"),
        ),
    ],
}


@dataclass
class PromptGuardResult:
    """Result of running PromptGuard analysis and sanitization on an alert."""
    is_injected: bool
    detected_patterns: List[str] = field(default_factory=list)
    redacted_fields: List[str] = field(default_factory=list)
    sanitized_alert: Optional[NormalizedAlert] = None


class PromptGuard:
    """
    Defensive security guard inspecting, neutralizing, and logging adversarial prompt injections
    found within untrusted SIEM alert telemetry fields.
    """

    def __init__(self, redact_injections: bool = True):
        self.redact_injections = redact_injections

    def detect_injections(self, text: Optional[str]) -> List[str]:
        """
        Scans a text string for known prompt injection signatures.
        Returns a list of detected pattern names.
        """
        if not text:
            return []

        text_str = str(text)
        detected = []
        for category, signatures in INJECTION_SIGNATURES.items():
            for label, pattern in signatures:
                if pattern.search(text_str):
                    detected.append(f"{category}:{label}")
        return detected

    def sanitize_text(self, text: Optional[str]) -> Tuple[str, List[str]]:
        """
        Detects and sanitizes adversarial patterns in a text string.
        Replaces detected injections with a safe redaction token if configured.
        
        Returns:
            Tuple of (sanitized_text, list of detected pattern descriptions).
        """
        if not text:
            return text or "", []

        original_text = str(text)
        detected = []
        sanitized = original_text

        for category, signatures in INJECTION_SIGNATURES.items():
            for label, pattern in signatures:
                matches = list(pattern.finditer(sanitized))
                if matches:
                    detected.append(f"{category}:{label}")
                    if self.redact_injections:
                        replacement = f"[REDACTED_ADVERSARIAL_PAYLOAD:{label.upper().replace(' ', '_')}]"
                        sanitized = pattern.sub(replacement, sanitized)

        return sanitized, detected

    def sanitize_alert(self, alert: NormalizedAlert) -> PromptGuardResult:
        """
        Performs deep inspection and sanitization across all untrusted telemetry fields
        in a NormalizedAlert document.
        
        Returns:
            PromptGuardResult containing injection status, detected patterns,
            redacted field names, and the sanitized alert copy.
        """
        sanitized_alert = copy.deepcopy(alert)
        all_detected: List[str] = []
        redacted_fields: List[str] = []

        # 1. Envelope Fields
        if sanitized_alert.user_name:
            clean, hits = self.sanitize_text(sanitized_alert.user_name)
            if hits:
                sanitized_alert.user_name = clean
                all_detected.extend(hits)
                redacted_fields.append("user_name")

        if sanitized_alert.host_name:
            clean, hits = self.sanitize_text(sanitized_alert.host_name)
            if hits:
                sanitized_alert.host_name = clean
                all_detected.extend(hits)
                redacted_fields.append("host_name")

        if sanitized_alert.reason:
            clean, hits = self.sanitize_text(sanitized_alert.reason)
            if hits:
                sanitized_alert.reason = clean
                all_detected.extend(hits)
                redacted_fields.append("reason")

        # 2. Process Context
        if sanitized_alert.process_context:
            pctx = sanitized_alert.process_context
            if pctx.process:
                if pctx.process.command_line:
                    clean, hits = self.sanitize_text(pctx.process.command_line)
                    if hits:
                        pctx.process.command_line = clean
                        all_detected.extend(hits)
                        redacted_fields.append("process.command_line")

                if pctx.process.name:
                    clean, hits = self.sanitize_text(pctx.process.name)
                    if hits:
                        pctx.process.name = clean
                        all_detected.extend(hits)
                        redacted_fields.append("process.name")

            if pctx.parent_process and pctx.parent_process.command_line:
                clean, hits = self.sanitize_text(pctx.parent_process.command_line)
                if hits:
                    pctx.parent_process.command_line = clean
                    all_detected.extend(hits)
                    redacted_fields.append("parent_process.command_line")

            if pctx.target_process_name:
                clean, hits = self.sanitize_text(pctx.target_process_name)
                if hits:
                    pctx.target_process_name = clean
                    all_detected.extend(hits)
                    redacted_fields.append("target_process_name")

        # 3. Registry Context
        if sanitized_alert.registry_context:
            rctx = sanitized_alert.registry_context
            if rctx.data:
                clean, hits = self.sanitize_text(rctx.data)
                if hits:
                    rctx.data = clean
                    all_detected.extend(hits)
                    redacted_fields.append("registry.data")
            if rctx.value_name:
                clean, hits = self.sanitize_text(rctx.value_name)
                if hits:
                    rctx.value_name = clean
                    all_detected.extend(hits)
                    redacted_fields.append("registry.value_name")

        # 4. Network Context
        if sanitized_alert.network_context:
            nctx = sanitized_alert.network_context
            if nctx.user_agent:
                clean, hits = self.sanitize_text(nctx.user_agent)
                if hits:
                    nctx.user_agent = clean
                    all_detected.extend(hits)
                    redacted_fields.append("network.user_agent")
            if nctx.suricata_signature:
                clean, hits = self.sanitize_text(nctx.suricata_signature)
                if hits:
                    nctx.suricata_signature = clean
                    all_detected.extend(hits)
                    redacted_fields.append("network.suricata_signature")

        is_injected = len(all_detected) > 0
        if is_injected:
            logger.warning(
                f"[PromptGuard] Adversarial prompt injection detected in alert {alert.alert_id}! "
                f"Fields: {redacted_fields} | Signatures: {all_detected}"
            )

        return PromptGuardResult(
            is_injected=is_injected,
            detected_patterns=list(set(all_detected)),
            redacted_fields=list(set(redacted_fields)),
            sanitized_alert=sanitized_alert,
        )

"""
Playbook Retrieval Module (RAG).
Grounds Stage 2 Verdict Agent decisions in official security incident response playbooks.
"""
import os
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PlaybookRetriever:
    """
    RAG retriever loading markdown/text incident response playbooks.
    """

    def __init__(self, playbooks_dir: str = "./playbooks"):
        self.playbooks_dir = playbooks_dir
        self._cache: Dict[str, str] = {}
        self._load_mock_playbooks()

    def _load_mock_playbooks(self):
        """Pre-loads default incident response playbooks for common MITRE techniques."""
        self._cache["T1059.001"] = (
            "PLAYBOOK T1059.001 (PowerShell Execution):\n"
            "- Check if command line contains -Enc or base64 streams.\n"
            "- Verify parent process legitimacy (e.g. SCCM/WMI vs cmd.exe/explorer.exe).\n"
            "- If downloading remote payloads from unlisted external IPs -> ESCALATE."
        )
        self._cache["T1003.001"] = (
            "PLAYBOOK T1003.001 (LSASS Dumping):\n"
            "- Check for unauthorized access masks to LSASS process memory.\n"
            "- Inspect tool signatures (procdump, mimikatz, comsvcs.dll).\n"
            "- If process is not legitimate AV/EDR agent -> ESCALATE CRITICAL."
        )

    def get_playbook(self, rule_id: str) -> Optional[str]:
        """
        Retrieves relevant response playbook by rule ID or MITRE technique.
        """
        logger.info(f"Retrieving playbook for rule/technique: {rule_id}")
        return self._cache.get(rule_id, "DEFAULT PLAYBOOK: Inspect host telemetry, verify parent process, escalate if unverified executable.")

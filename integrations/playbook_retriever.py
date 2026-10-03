"""
Playbook Retrieval Module (RAG).
Grounds Stage 2 Verdict Agent decisions in official security incident response playbooks.
"""
import os
import re
import glob
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class PlaybookRetriever:
    """
    RAG retriever loading markdown/text incident response playbooks from directory.
    Matches queries by MITRE technique ID (e.g. T1003.001) or rule name.
    """

    def __init__(self, playbooks_dir: str = "./playbooks"):
        self.playbooks_dir = playbooks_dir
        self._cache: Dict[str, str] = {}
        self._load_playbooks_from_dir()
        if not self._cache:
            self._load_fallback_playbooks()

    def _load_playbooks_from_dir(self):
        """Loads and indexes markdown playbooks from playbooks_dir."""
        if not os.path.exists(self.playbooks_dir):
            logger.warning(f"Playbooks directory not found at: {self.playbooks_dir}")
            return

        md_files = glob.glob(os.path.join(self.playbooks_dir, "*.md"))
        for filepath in md_files:
            filename = os.path.basename(filepath)
            if filename.lower() == "readme.md":
                continue

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                # Extract MITRE technique ID from filename (e.g. PB-T1003.001-...) or content
                match = re.search(r"(T\d{4}(?:\.\d{3})?)", filename)
                if match:
                    technique_id = match.group(1)
                    self._cache[technique_id] = content
                    logger.debug(f"Loaded playbook for technique {technique_id} from {filename}")

                # Also search inside header table for detection rule name or technique
                # e.g. | Technique | T1003.001 ... |
                # e.g. | Detection rule | `LSASS Memory Access` |
                rule_match = re.search(r"\|\s*Detection rule\s*\|\s*`?([^`|\n]+)`?\s*\|", content, re.IGNORECASE)
                if rule_match:
                    rule_name = rule_match.group(1).strip()
                    self._cache[rule_name.lower()] = content
            except Exception as e:
                logger.error(f"Error reading playbook {filepath}: {e}")

        logger.info(f"Loaded {len(self._cache)} playbook mappings from {self.playbooks_dir}")

    def _load_fallback_playbooks(self):
        """Pre-loads default incident response playbooks if folder is missing."""
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

    def get_playbook(self, rule_or_technique: str) -> Optional[str]:
        """
        Retrieves relevant response playbook by MITRE technique ID (e.g., T1003.001) or rule name.
        """
        if not rule_or_technique:
            return None

        # Direct match (e.g., "T1003.001")
        if rule_or_technique in self._cache:
            logger.info(f"Retrieved playbook for exact key: {rule_or_technique}")
            return self._cache[rule_or_technique]

        # Case-insensitive match
        lower_key = rule_or_technique.lower()
        if lower_key in self._cache:
            logger.info(f"Retrieved playbook for rule name: {rule_or_technique}")
            return self._cache[lower_key]

        # Regex search for technique ID in string
        match = re.search(r"(T\d{4}(?:\.\d{3})?)", rule_or_technique)
        if match and match.group(1) in self._cache:
            logger.info(f"Retrieved playbook by extracted technique {match.group(1)} for {rule_or_technique}")
            return self._cache[match.group(1)]

        logger.warning(f"No specific playbook found for {rule_or_technique}. Returning default guidance.")
        return "DEFAULT PLAYBOOK: Inspect host telemetry, verify parent process legitimacy, escalate if unverified executable or anomalous network activity."

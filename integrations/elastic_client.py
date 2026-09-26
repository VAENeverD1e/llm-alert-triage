"""
Elasticsearch / SIEM Integration Client.

Provides two things:
1. The original alert-fetching mock methods (kept for the orchestrator demo).
2. Real enrichment queries used by the Fact-Finding Agent to fill gaps the
   alert document itself does not carry:
   - get_process_creation_context(): resolves a process's own parent
     (name/executable/command_line/pid) by finding its Event ID 1
     (process creation) record, for Sysmon events that don't carry
     parent info inline (Event ID 3 NetworkConnect, 10 ProcessAccess,
     13 RegistryEvent). See docs/alert-schema-audit.md, Bug 5.
   - resolve_host_from_ip(): resolves a host.name from an IP address,
     for Suricata alerts which carry only source/destination IPs.
     See docs/alert-schema-audit.md, Bug 4.

Both enrichment methods return None (not an exception) when nothing is
found or the query fails, so a missing datapoint never crashes the
Fact-Finding Agent.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

DEFAULT_INDEX = "logs-*"


def _parse_timestamp(timestamp: str) -> Optional[datetime]:
    if not timestamp:
        return None
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        logger.warning(f"Could not parse timestamp for enrichment window: {timestamp!r}")
        return None


def _time_window(timestamp: str, window_minutes: int) -> Optional[Tuple[str, str]]:
    ts = _parse_timestamp(timestamp)
    if ts is None:
        return None
    delta = timedelta(minutes=window_minutes)
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    start = (ts - delta).astimezone(timezone.utc).strftime(fmt)
    end = (ts + delta).astimezone(timezone.utc).strftime(fmt)
    return start, end


class ElasticClient:
    """
    Interfaces with Elasticsearch to ingest alerts and to enrich them
    with context the alert document doesn't already contain.
    """

    def __init__(self, host: str = "http://localhost:9200", api_key: str = ""):
        self.host = host.rstrip("/")
        self.api_key = api_key
        logger.info(f"Initialized ElasticClient targeting host: {self.host}")

    # ── Low-level search helper ─────────────────────────────────────────

    def _search(self, query: Dict[str, Any], index: str = DEFAULT_INDEX) -> List[Dict[str, Any]]:
        """
        Runs a raw ES query and returns the hit list. Never raises: on any
        transport/HTTP error it logs a warning and returns [] so callers
        can treat "query failed" and "query found nothing" the same way
        (both resolve to None for the enrichment field).
        """
        url = f"{self.host}/{index}/_search"
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        try:
            resp = requests.post(url, headers=headers, json=query, timeout=10)
            resp.raise_for_status()
            return resp.json().get("hits", {}).get("hits", [])
        except requests.exceptions.RequestException as e:
            logger.warning(f"Elastic enrichment query failed against {url}: {e}")
            return []

    # ── Enrichment: parent process via Event ID 1 correlation ──────────

    def get_process_creation_context(
        self,
        entity_id: Optional[str] = None,
        pid: Optional[int] = None,
        host_name: Optional[str] = None,
        timestamp: Optional[str] = None,
        window_minutes: int = 5,
    ) -> Optional[Dict[str, Any]]:
        """
        Finds the Event ID 1 (process creation) record for the process
        that raised the alert, and returns THAT record's parent process
        fields. This is what supplies "parent process" for Event ID 3,
        10 and 13 alerts, which never carry process.parent.* themselves
        -- only the process's own Event ID 1 record does.

        Correlates on process.entity_id (Sysmon ProcessGuid) when
        available, since that's a stable 1:1 key; falls back to
        pid + host_name + a time window around the alert timestamp.

        Returns None (never raises) if nothing matches, if the matched
        record has no parent recorded, or if the query itself fails.
        """
        must: List[Dict[str, Any]] = [{"term": {"event.code": "1"}}]

        if entity_id:
            must.append({"term": {"process.entity_id": entity_id}})
        else:
            if pid is None and not host_name:
                logger.warning(
                    "get_process_creation_context called with no entity_id, "
                    "pid, or host_name -- refusing to run an unscoped query."
                )
                return None
            if pid is not None:
                must.append({"term": {"process.pid": pid}})
            if host_name:
                must.append({"term": {"host.name": host_name}})
            window = _time_window(timestamp, window_minutes) if timestamp else None
            if window:
                start, end = window
                must.append({"range": {"@timestamp": {"gte": start, "lte": end}}})

        query = {
            "query": {"bool": {"must": must}},
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        hits = self._search(query)
        if not hits:
            return None

        process = hits[0].get("_source", {}).get("process", {})
        parent = process.get("parent") or {}
        if not parent.get("name"):
            return None

        return {
            "name": parent.get("name"),
            "executable": parent.get("executable"),
            "command_line": parent.get("command_line"),
            "pid": parent.get("pid"),
        }

    # ── Enrichment: host resolution from IP (Suricata alerts) ──────────

    def resolve_host_from_ip(self, ip: str, window_minutes: int = 1440) -> Optional[str]:
        """
        Suricata alerts carry only source/destination IPs, no host.name
        (see docs/alert-schema-audit.md, Bug 4). This looks for any
        recent endpoint (Sysmon/Winlogbeat) document whose host.ip
        includes the given address, and returns that host's name.

        Returns None (never raises) if no match is found or the query
        fails.
        """
        if not ip:
            return None

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"host.ip": ip}},
                        {"exists": {"field": "host.name"}},
                    ]
                }
            },
            "size": 1,
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        hits = self._search(query)
        if not hits:
            return None
        return hits[0].get("_source", {}).get("host", {}).get("name")

    # ── Original mock methods (kept for orchestrator demo / backwards compat) ──

    def fetch_open_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Pulls recent unprocessed alerts from SIEM index.
        """
        logger.info(f"Fetching up to {limit} open alerts from Elasticsearch...")
        return [
            {
                "alert_id": "ALT-2001",
                "rule_id": "T1003.001",
                "rule_name": "LSASS Memory Dump Attempt",
                "severity": "critical",
                "timestamp": "2026-09-03T13:45:00Z",
                "host_name": "DB-SERVER-02",
                "user_name": "SYSTEM",
                "raw_event": {"process_name": "procdump64.exe", "target_process": "lsass.exe"},
            }
        ]

    def query_context_events(self, host_name: str, timestamp: str, window_minutes: int = 5) -> List[Dict[str, Any]]:
        """
        Queries surrounding process, network, and file system event logs
        for a host within timestamp +/- window. Retained as a mock for
        the orchestrator's demo/replay path; the Fact-Finding Agent's
        real enrichment now goes through get_process_creation_context()
        and resolve_host_from_ip() above.
        """
        logger.info(f"Querying context events for host={host_name} around {timestamp} (+/- {window_minutes}m)")
        return [
            {
                "timestamp": timestamp,
                "process": {"name": "procdump64.exe", "pid": 4812, "parent": "cmd.exe"},
                "user": {"name": "admin_user"},
            },
            {
                "timestamp": timestamp,
                "destination": {"ip": "192.168.1.50", "port": 445},
                "network": {"protocol": "smb"},
            },
        ]

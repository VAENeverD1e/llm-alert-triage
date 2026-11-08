"""
Triage Service Core.
Implements:
1. Sequential Background Queue Worker protecting local Ollama daemon.
2. Idempotency & Alert Deduplication preventing repeated Discord alerts.
3. Elasticsearch Adapter fetching full _source for minimal Kibana webhook payloads.
4. Thread-safe in-memory results ring buffer (last 20 results).
5. ElasticClient and DiscordForwarder integration.
"""
import os
import json
import time
import queue
import logging
import threading
from collections import deque
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone

from agent.orchestrator import TriageOrchestrator
from agent.schemas.triage_schema import TriagePipelineResult, TriageDecision
from integrations.elastic_client import ElasticClient
from notification.discord_forwarder import DiscordForwarder
from api.config import APISettings, settings
from api.schemas import TriageResultItem, HealthResponse

logger = logging.getLogger("TriageService")


def _mask_url(url: Optional[str]) -> str:
    """Masks secret tokens in URLs for secure health/config reporting."""
    if not url:
        return "Not configured"
    parts = url.split("/")
    if len(parts) >= 2:
        masked_token = "********" + parts[-1][-4:] if len(parts[-1]) > 4 else "********"
        parts[-1] = masked_token
        return "/".join(parts)
    return "********"


def _extract_alert_id(payload: Dict[str, Any]) -> str:
    """Safely extracts or generates a deterministic alert identifier."""
    # Check top-level keys
    for key in ("alert_id", "kibana.alert.uuid", "_id", "id", "uuid"):
        if payload.get(key):
            return str(payload[key]).strip()

    # Check nested Kibana structures
    if isinstance(payload.get("alert"), dict) and payload["alert"].get("id"):
        return str(payload["alert"]["id"]).strip()

    if isinstance(payload.get("kibana"), dict):
        k_alert = payload["kibana"].get("alert", {})
        if k_alert.get("uuid"):
            return str(k_alert["uuid"]).strip()

    # Check _source
    if isinstance(payload.get("_source"), dict):
        src = payload["_source"]
        if src.get("kibana.alert.uuid"):
            return str(src["kibana.alert.uuid"]).strip()

    # Fallback deterministic pseudo-ID
    import hashlib
    raw_str = json.dumps(payload, sort_keys=True)
    digest = hashlib.md5(raw_str.encode("utf-8")).hexdigest()[:10]
    return f"ALT-FALLBACK-{digest}"


class TriageService:
    """
    Central service orchestrating sequential triage, deduplication,
    Elastic document retrieval, and outbound Discord notifications.
    """

    _instance: Optional["TriageService"] = None
    _init_lock = threading.Lock()

    def __init__(self, cfg: Optional[APISettings] = None):
        self.config = cfg or settings
        self.start_time = time.time()

        # Idempotency Tracking
        self._dedup_lock = threading.Lock()
        self.processed_alert_ids: Set[str] = set()
        self.in_progress_alert_ids: Set[str] = set()

        # Results buffer (latest 20 results for /results endpoint and dashboard)
        self._results_lock = threading.Lock()
        self.recent_results: deque = deque(maxlen=20)

        # Operational Statistics
        self.stats: Dict[str, Any] = {
            "total_received": 0,
            "total_processed": 0,
            "total_deduplicated": 0,
            "escalated_count": 0,
            "closed_count": 0,
            "unknown_count": 0,
            "prompt_injections_blocked": 0,
            "queue_pending": 0,
        }

        # Initialize Real Integrations
        self.elastic_client = ElasticClient(
            host=self.config.elastic_url,
            api_key=self.config.elastic_api_key
        )

        self.forwarder = DiscordForwarder(
            webhook_url=self.config.discord_webhook_url,
            timeout=self.config.discord_timeout,
            retry_count=self.config.discord_retry_count,
            dry_run=self.config.discord_dry_run
        )

        # Pass real ElasticClient into Orchestrator so Stage 1 Enrichment actually executes
        self.orchestrator = TriageOrchestrator.create_default(
            use_ollama=self.config.use_ollama,
            use_rag=self.config.use_rag,
            model_name=self.config.ollama_model,
            playbooks_dir=self.config.playbooks_dir,
            elastic_client=self.elastic_client,
            discord_forwarder=self.forwarder,
            confidence_threshold_escalate=self.config.confidence_threshold_escalate,
            confidence_threshold_close=self.config.confidence_threshold_close,
        )

        # Sequential Background Queue & Single Worker Thread
        self.task_queue: queue.Queue = queue.Queue()
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="SequentialTriageWorker"
        )
        self._worker_thread.start()
        logger.info("Initialized Sequential Background Worker for LLM Triage.")

    @classmethod
    def get_instance(cls, cfg: Optional[APISettings] = None) -> "TriageService":
        """Thread-safe singleton accessor."""
        with cls._init_lock:
            if cls._instance is None:
                cls._instance = cls(cfg)
            return cls._instance

    def enqueue_alert(self, payload: Dict[str, Any]) -> Tuple[str, bool, str]:
        """
        Receives an alert payload, performs deduplication, and queues for sequential processing.
        Returns: (alert_id, is_deduplicated, status_message)
        """
        alert_id = _extract_alert_id(payload)

        with self._dedup_lock:
            self.stats["total_received"] += 1

            # Idempotency Check: if alert was already triaged or is currently queued
            if alert_id in self.processed_alert_ids or alert_id in self.in_progress_alert_ids:
                self.stats["total_deduplicated"] += 1
                logger.info(f"[Dedup] Alert {alert_id} already received/processed. Skipping duplicate.")
                return alert_id, True, "Alert already processed (deduplicated)."

            # Mark in-progress and push to queue
            self.in_progress_alert_ids.add(alert_id)
            self.task_queue.put((alert_id, payload))
            self.stats["queue_pending"] = self.task_queue.qsize()

        logger.info(f"[Queue] Alert {alert_id} enqueued. Queue depth: {self.task_queue.qsize()}")
        return alert_id, False, "Alert accepted and queued for triage."

    def _worker_loop(self) -> None:
        """Sequential worker pulling alerts one-by-one to avoid overloading local Ollama."""
        while True:
            try:
                alert_id, raw_payload = self.task_queue.get()
                self._process_single_alert(alert_id, raw_payload)
            except Exception as e:
                logger.error(f"[Worker Error] Unhandled exception in triage worker loop: {e}", exc_info=True)
            finally:
                with self._dedup_lock:
                    self.stats["queue_pending"] = self.task_queue.qsize()
                self.task_queue.task_done()

    def _process_single_alert(self, alert_id: str, raw_payload: Dict[str, Any]) -> TriageResultItem:
        """
        Executes pipeline on an alert:
        1. If payload is minimal, fetches full _source from Elasticsearch index.
        2. Executes Orchestrator run_pipeline (which dispatches to Discord once).
        3. Updates deduplication set and stores in results buffer.
        """
        start_time = time.time()
        logger.info(f"==> [Worker] Processing alert {alert_id}")

        # Check if payload needs enrichment from Elasticsearch (Kibana minimal webhook)
        has_rich_context = (
            "_source" in raw_payload
            or "process_context" in raw_payload
            or "network_context" in raw_payload
            or "raw_event" in raw_payload
        )

        effective_payload = raw_payload
        if not has_rich_context and self.elastic_client:
            logger.info(f"Minimal webhook payload detected for {alert_id}. Querying Elasticsearch index...")
            es_doc = self.elastic_client.get_alert_by_id(
                alert_id=alert_id,
                index=self.config.elastic_alert_index
            )
            if es_doc:
                logger.info(f"Retrieved full Elasticsearch document for alert {alert_id}.")
                effective_payload = es_doc
            else:
                logger.warning(f"Could not locate alert {alert_id} in Elasticsearch. Continuing with webhook payload.")

        # Execute two-stage pipeline
        # Note: orchestrator.run_pipeline automatically calls self.forwarder.send_triage_result(result)
        pipeline_result: TriagePipelineResult = self.orchestrator.run_pipeline(effective_payload)
        
        # Check prompt injection
        is_injection = False
        evidence_list = pipeline_result.fact_finding.evidence_extracted or []
        risk_list = pipeline_result.verdict.risk_factors or []
        for item in evidence_list + risk_list:
            if "prompt injection" in str(item).lower() or "[redacted_adversarial_payload" in str(item).lower():
                is_injection = True
                break

        # Check Discord forwarder status (was it sent?)
        discord_sent = bool(self.forwarder.webhook_url)

        # Build Result Item
        result_item = TriageResultItem(
            alert_id=pipeline_result.alert.alert_id,
            rule_id=pipeline_result.alert.rule_id,
            rule_name=pipeline_result.alert.rule_name,
            severity=pipeline_result.alert.severity,
            decision=pipeline_result.verdict.decision.value,
            confidence_score=round(pipeline_result.verdict.confidence_score, 4),
            processing_time_ms=round(pipeline_result.processing_time_ms, 2),
            discord_forwarded=discord_sent,
            timestamp=pipeline_result.alert.timestamp or datetime.now(timezone.utc).isoformat(),
            reasoning=pipeline_result.verdict.reasoning,
            risk_factors=pipeline_result.verdict.risk_factors,
            recommended_playbook=pipeline_result.verdict.recommended_playbook,
            investigation_summary=pipeline_result.fact_finding.summary_of_events,
            prompt_injection_detected=is_injection,
            error_message=None
        )

        # Update stats, dedup sets, and results buffer
        with self._dedup_lock:
            self.in_progress_alert_ids.discard(alert_id)
            self.processed_alert_ids.add(alert_id)
            self.stats["total_processed"] += 1
            if pipeline_result.verdict.decision == TriageDecision.ESCALATE:
                self.stats["escalated_count"] += 1
            elif pipeline_result.verdict.decision == TriageDecision.CLOSE:
                self.stats["closed_count"] += 1
            else:
                self.stats["unknown_count"] += 1

            if is_injection:
                self.stats["prompt_injections_blocked"] += 1

        with self._results_lock:
            self.recent_results.appendleft(result_item)

        elapsed = (time.time() - start_time) * 1000.0
        logger.info(
            f"<== [Worker] Finished {alert_id} in {elapsed:.1f}ms | Verdict: {result_item.decision} "
            f"({result_item.confidence_score * 100:.0f}%)"
        )
        return result_item

    def process_direct_sync(self, raw_payload: Dict[str, Any]) -> TriageResultItem:
        """
        Synchronous direct processing method for interactive test endpoints or unit tests.
        """
        alert_id = _extract_alert_id(raw_payload)
        return self._process_single_alert(alert_id, raw_payload)

    def get_recent_results(self, limit: int = 20) -> List[TriageResultItem]:
        """Returns the most recent 20 triaged alert results."""
        with self._results_lock:
            return list(self.recent_results)[:limit]

    def clear_results(self) -> None:
        """Clears results and idempotency sets (useful for test resets)."""
        with self._results_lock:
            self.recent_results.clear()
        with self._dedup_lock:
            self.processed_alert_ids.clear()
            self.in_progress_alert_ids.clear()

    def get_health(self) -> HealthResponse:
        """Gathers connectivity status for API, Ollama daemon, and Elasticsearch instance."""
        uptime = round(time.time() - self.start_time, 1)

        # Check Ollama daemon connectivity
        ollama_reachable = False
        try:
            import requests
            r = requests.get(f"{self.config.ollama_host}/api/tags", timeout=1.5)
            ollama_reachable = (r.status_code == 200)
        except Exception:
            ollama_reachable = False

        # Check Elasticsearch connectivity
        es_reachable = self.elastic_client.ping() if self.elastic_client else False

        overall_status = "healthy"
        if self.config.use_ollama and not ollama_reachable:
            overall_status = "degraded (Ollama offline - heuristic fallback active)"
        elif not es_reachable:
            overall_status = "degraded (Elasticsearch unreachable)"

        return HealthResponse(
            status=overall_status,
            version=self.config.api_version,
            uptime_seconds=uptime,
            app={
                "environment": "production",
                "queue_pending": self.task_queue.qsize(),
                "processed_cache_size": len(self.processed_alert_ids),
                "auth_enabled": bool(self.config.webhook_secret)
            },
            ollama={
                "enabled": self.config.use_ollama,
                "model": self.config.ollama_model,
                "endpoint": self.config.ollama_host,
                "reachable": ollama_reachable
            },
            elastic={
                "endpoint": self.config.elastic_url,
                "alert_index": self.config.elastic_alert_index,
                "reachable": es_reachable
            },
            discord={
                "configured": bool(self.forwarder.webhook_url),
                "masked_webhook": _mask_url(self.forwarder.webhook_url),
                "dry_run": self.forwarder.dry_run
            },
            stats=dict(self.stats)
        )

"""
FastAPI Route Handlers.
Exposes REST endpoints for Elasticsearch SIEM webhooks, health inspection,
preset benchmark samples, triage history, and Discord forwarder management.
"""
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, Body, status

from api.schemas import (
    TriageWebhookResponse,
    DiscordConfigUpdateRequest,
    DiscordConfigResponse,
    HealthResponse,
    AlertSampleItem,
    HistorySummaryItem,
)
from api.service import TriageService, _mask_discord_url

logger = logging.getLogger("APIRoutes")

router = APIRouter(prefix="/api/v1", tags=["Alert Triage & Webhooks"])


@router.post(
    "/webhook/elastic",
    response_model=TriageWebhookResponse,
    summary="Elasticsearch / Kibana Alert Webhook Ingestion",
    description=(
        "Primary webhook receiver endpoint accepting raw Elasticsearch/Kibana SIEM alerts. "
        "Executes Stage 1 Fact-Finding, Prompt Injection Defense, Stage 2 RAG Playbook Verdict, "
        "and automatically broadcasts results to Discord."
    ),
    status_code=status.HTTP_200_OK
)
async def ingest_elastic_webhook(
    payload: Dict[str, Any] = Body(
        ...,
        description="Raw Elasticsearch / Kibana alert JSON or NormalizedAlert dictionary"
    ),
    forward_discord: Optional[bool] = Query(
        default=None,
        description="Override Discord forwarding behavior (True to force, False to suppress, None for default)"
    )
) -> TriageWebhookResponse:
    """
    Handles incoming alert webhook from Elasticsearch/Kibana.
    """
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alert payload cannot be empty."
        )

    service = TriageService.get_instance()
    try:
        response = service.process_alert(
            alert_payload=payload,
            override_forward_discord=forward_discord
        )
        return response
    except Exception as e:
        logger.error(f"Error handling elastic webhook: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Triage pipeline processing failed: {str(e)}"
        )


@router.post(
    "/triage",
    response_model=TriageWebhookResponse,
    summary="Direct Security Alert Triage",
    description="Direct endpoint for executing the full triage pipeline on custom or synthetic alerts.",
    status_code=status.HTTP_200_OK
)
async def direct_triage(
    payload: Dict[str, Any] = Body(..., description="Alert payload dictionary"),
    forward_discord: Optional[bool] = Query(default=None)
) -> TriageWebhookResponse:
    """Convenience alias for direct API triage clients."""
    return await ingest_elastic_webhook(payload=payload, forward_discord=forward_discord)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="System Health & Connectivity Status",
    description="Returns live status of the triage engine, LLM inference backend, RAG playbooks, and Discord forwarder."
)
async def get_system_health() -> HealthResponse:
    """Returns operational health diagnostics."""
    service = TriageService.get_instance()
    return service.get_health()


@router.get(
    "/samples",
    response_model=List[AlertSampleItem],
    summary="Preset Evaluation Benchmark Scenarios",
    description="Returns standardized ground-truth benchmark scenarios (attack and benign) for 1-click dashboard testing."
)
async def list_alert_samples() -> List[AlertSampleItem]:
    """Retrieves pre-loaded benchmark scenarios."""
    service = TriageService.get_instance()
    return service.get_samples()


@router.get(
    "/history",
    response_model=List[HistorySummaryItem],
    summary="Recent Triage History Feed",
    description="Returns recent alerts triaged by the engine with verdicts and execution times."
)
async def get_triage_history(
    limit: int = Query(default=50, ge=1, le=100, description="Max history items to return")
) -> List[HistorySummaryItem]:
    """Retrieves in-memory alert history."""
    service = TriageService.get_instance()
    return service.get_history(limit=limit)


@router.delete(
    "/history",
    summary="Clear Alert History",
    description="Clears in-memory history buffer (useful when restarting live demonstrations)."
)
async def clear_triage_history() -> Dict[str, str]:
    """Clears history queue."""
    service = TriageService.get_instance()
    service.clear_history()
    return {"message": "Alert history cleared successfully."}


@router.get(
    "/config/discord",
    response_model=DiscordConfigResponse,
    summary="Inspect Discord Forwarder Configuration",
    description="Returns current Discord webhook target status and masked URL."
)
async def get_discord_config() -> DiscordConfigResponse:
    """Checks current Discord webhook configuration."""
    service = TriageService.get_instance()
    url = service.forwarder.webhook_url
    return DiscordConfigResponse(
        webhook_url_masked=_mask_discord_url(url),
        is_configured=bool(url),
        dry_run=service.forwarder.dry_run,
        test_sent=None,
        message="Discord configuration loaded."
    )


@router.post(
    "/config/discord",
    response_model=DiscordConfigResponse,
    summary="Update Discord Webhook URL",
    description="Dynamically updates the Discord incoming webhook destination and optionally triggers an immediate test ping."
)
async def update_discord_config(
    req: DiscordConfigUpdateRequest
) -> DiscordConfigResponse:
    """Updates Discord webhook settings at runtime."""
    service = TriageService.get_instance()
    return service.update_discord_config(
        webhook_url=req.webhook_url,
        send_test=req.send_test
    )


@router.post(
    "/test/discord",
    summary="Send Test Notification to Discord",
    description="Dispatches a verification ping message to the active Discord webhook channel."
)
async def test_discord_ping(
    message: Optional[str] = Query(default=None, description="Optional custom test message text")
) -> Dict[str, Any]:
    """Sends test message to Discord."""
    service = TriageService.get_instance()
    success = service.test_discord_ping(custom_message=message)
    if not success:
        return {
            "success": False,
            "message": "Discord ping failed. Please verify that a valid DISCORD_WEBHOOK_URL is configured."
        }
    return {
        "success": True,
        "message": "Test ping successfully delivered to Discord webhook channel."
    }

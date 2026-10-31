"""
FastAPI Server Application Entrypoint.
Exposes:
- POST /webhook/alert (Secret authentication, 202 Accepted immediate return, sequential queue execution)
- GET /health (App uptime, Ollama inference status, Elasticsearch reachability)
- GET /results (20 most recent triage verdicts, confidence scores, and latencies)
- POST /triage/test (Synchronous manual triage testing endpoint)
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Query, Body, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from api.config import settings
from api.schemas import (
    WebhookAlertRequest,
    WebhookAcceptedResponse,
    TriageResultItem,
    HealthResponse
)
from api.service import TriageService

logger = logging.getLogger("API")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)


def _verify_webhook_secret(
    x_webhook_secret: Optional[str] = Header(None, alias="X-Webhook-Secret"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> None:
    """
    Enforces secret token verification for incoming webhook requests.
    Accepts token via either X-Webhook-Secret header or Authorization: Bearer <secret>.
    If settings.webhook_secret is empty, authentication is bypassed (open mode).
    """
    expected_secret = settings.webhook_secret.strip()
    if not expected_secret:
        return  # No authentication configured

    # Check X-Webhook-Secret
    if x_webhook_secret and x_webhook_secret.strip() == expected_secret:
        return

    # Check Authorization: Bearer <secret>
    if authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer" and parts[1] == expected_secret:
            return

    logger.warning("Unauthorized webhook request rejected (invalid or missing secret header).")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Invalid or missing webhook secret header."
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager pre-warming TriageService and logging operational parameters."""
    logger.info("=================================================================")
    logger.info(" Starting LLM Security Alert Triage Gateway & Webhook Service")
    logger.info(f" Host: {settings.host}:{settings.port} | Auth Secret: {'Configured' if settings.webhook_secret else 'Disabled (Open)'}")
    logger.info(f" Model: {settings.ollama_model} | Ollama URL: {settings.ollama_host}")
    logger.info(f" Elastic URL: {settings.elastic_url} | Alert Index: {settings.elastic_alert_index}")
    logger.info(f" Discord Webhook: {'Configured' if settings.discord_webhook_url else 'Dry-Run/Disabled'}")
    logger.info("=================================================================")
    
    # Pre-warm singleton
    service = TriageService.get_instance(settings)
    yield
    logger.info("Shutting down LLM Alert Triage Service.")


app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=settings.api_description,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Enable CORS for external tools and browser test panels
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post(
    "/webhook/alert",
    response_model=WebhookAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Kibana Alert Webhook Ingestion (Async 202)",
    description=(
        "Primary webhook endpoint accepting Kibana / Elasticsearch alerts. "
        "Validates secret header, performs deduplication, immediately returns HTTP 202 Accepted (<50ms), "
        "and processes the alert sequentially in a background worker queue to avoid Ollama concurrency bottlenecks."
    )
)
@app.post("/api/v1/webhook/alert", response_model=WebhookAcceptedResponse, status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
@app.post("/api/v1/webhook/elastic", response_model=WebhookAcceptedResponse, status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
async def receive_webhook_alert(
    payload: Dict[str, Any] = Body(
        ...,
        description="Kibana webhook connector payload or full Elasticsearch alert document"
    ),
    x_webhook_secret: Optional[str] = Header(None, alias="X-Webhook-Secret"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> WebhookAcceptedResponse:
    """
    Ingests alert webhook, verifies authentication, deduplicates, and delegates to background queue.
    """
    # 1. Enforce Authentication
    _verify_webhook_secret(x_webhook_secret, authorization)

    # 2. Validate payload is non-empty
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Alert payload cannot be empty."
        )

    # 3. Enqueue alert for sequential processing
    service = TriageService.get_instance()
    alert_id, is_dedup, msg = service.enqueue_alert(payload)

    return WebhookAcceptedResponse(
        status="accepted",
        alert_id=alert_id,
        message=msg,
        queued_at=datetime.now(timezone.utc).isoformat(),
        deduplicated=is_dedup
    )


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Subsystem Health & Connectivity Check",
    description="Inspects real-time operational status for API uptime, Ollama inference, and Elasticsearch connectivity."
)
@app.get("/api/v1/health", response_model=HealthResponse, include_in_schema=False)
async def check_health() -> HealthResponse:
    """Returns diagnostic health metrics."""
    service = TriageService.get_instance()
    return service.get_health()


@app.get(
    "/results",
    response_model=List[TriageResultItem],
    summary="Retrieve 20 Most Recent Triage Results",
    description="Returns the last 20 processed security alerts with decisions, confidence scores, reasoning, and latencies."
)
@app.get("/api/v1/results", response_model=List[TriageResultItem], include_in_schema=False)
async def get_recent_results(
    limit: int = Query(default=20, ge=1, le=50, description="Number of results to retrieve")
) -> List[TriageResultItem]:
    """Retrieves recent triage results from memory."""
    service = TriageService.get_instance()
    return service.get_recent_results(limit=limit)


@app.post(
    "/triage/test",
    response_model=TriageResultItem,
    summary="Synchronous Interactive Triage Test",
    description="Directly executes triage on the provided alert JSON and returns the full verdict synchronously."
)
@app.post("/api/v1/triage/test", response_model=TriageResultItem, include_in_schema=False)
async def test_triage_direct(
    payload: Dict[str, Any] = Body(..., description="Alert payload dictionary")
) -> TriageResultItem:
    """Synchronous test endpoint."""
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Alert payload cannot be empty."
        )
    service = TriageService.get_instance()
    return service.process_direct_sync(payload)


@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirects base path to Swagger OpenAPI documentation."""
    return RedirectResponse(url="/docs")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host=settings.host,
        port=settings.port,
        reload=True
    )

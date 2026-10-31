"""
FastAPI Server Entrypoint.
Initializes application, CORS middleware, API router, static assets, and lifecycle hooks.
"""
import os
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.config import settings
from api.routes import router
from api.service import TriageService

logger = logging.getLogger("APIServer")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Lifecycle manager warming up the TriageService singleton,
    pre-loading playbooks and ground-truth benchmark scenarios.
    """
    logger.info("=============================================================")
    logger.info(" Starting LLM Security Alert Triage API & Webhook Service")
    logger.info(f" Model: {settings.ollama_model} | Ollama Enabled: {settings.use_ollama}")
    logger.info(f" Playbooks Dir: {settings.playbooks_dir} | RAG Enabled: {settings.use_rag}")
    logger.info("=============================================================")
    
    # Pre-warm service singleton
    service = TriageService.get_instance(settings)
    samples = service.get_samples()
    logger.info(f"Loaded {len(samples)} benchmark alert scenarios into cache.")
    
    yield

    logger.info("Shutting down LLM Security Alert Triage API service.")


def create_app() -> FastAPI:
    """Application factory for FastAPI server."""
    app = FastAPI(
        title=settings.api_title,
        version=settings.api_version,
        description=settings.api_description,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Enable Cross-Origin Resource Sharing (CORS) for local and web dashboards
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routes
    app.include_router(router)

    # Mount static assets for Webhook Test Dashboard if directory exists
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    if os.path.exists(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

        @app.get("/dashboard", include_in_schema=False)
        async def dashboard_view():
            from fastapi.responses import FileResponse
            index_path = os.path.join(static_dir, "index.html")
            if os.path.exists(index_path):
                return FileResponse(index_path)
            return RedirectResponse(url="/docs")

    @app.get("/", include_in_schema=False)
    async def root_redirect():
        static_dir = os.path.join(os.path.dirname(__file__), "static")
        index_path = os.path.join(static_dir, "index.html")
        if os.path.exists(index_path):
            return RedirectResponse(url="/dashboard")
        return RedirectResponse(url="/docs")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.server:app",
        host=settings.host,
        port=settings.port,
        reload=True
    )

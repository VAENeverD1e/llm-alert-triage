"""
FastAPI Server Entrypoint.
Re-exports canonical application from api.main.
"""
from api.main import app

__all__ = ["app"]

if __name__ == "__main__":
    import uvicorn
    from api.config import settings

    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False
    )

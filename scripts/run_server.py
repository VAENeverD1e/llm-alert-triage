"""
Launcher script for the LLM Alert Triage REST API & Webhook Service.
Usage:
    python scripts/run_server.py [--host 0.0.0.0] [--port 8000] [--reload]
"""
import os
import sys
import argparse
import uvicorn

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass

from api.config import settings


def main():
    parser = argparse.ArgumentParser(description="Start LLM Alert Triage API Server")
    parser.add_argument("--host", default=settings.host, help=f"Host interface to bind (default: {settings.host})")
    parser.add_argument("--port", type=int, default=settings.port, help=f"Port number to listen on (default: {settings.port})")
    parser.add_argument("--reload", action="store_true", default=False, help="Enable automatic code reload")
    args = parser.parse_args()

    print("=" * 65)
    print("🚀 Starting LLM Alert Triage API Server")
    print(f"📡 Webhook URL: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/webhook/alert")
    print(f"📊 Results Feed: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/results")
    print(f"📚 OpenAPI Docs: http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}/docs")
    print("=" * 65)

    uvicorn.run(
        "api.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload
    )


if __name__ == "__main__":
    main()

"""FastAPI application factory. Run with: uvicorn exposureguard.api.main:create_app --factory"""

from __future__ import annotations

from fastapi import FastAPI

from exposureguard import __version__
from exposureguard.api.ratelimit import RateLimiter
from exposureguard.api.routes import audit, health, scans
from exposureguard.config import Settings
from exposureguard.storage.repository import Repository


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(
        title="ExposureDetect",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    app.state.repo = Repository(settings.database_url)
    app.state.limiter = RateLimiter(settings.scan_rate_limit_per_minute)
    app.include_router(health.router)
    app.include_router(scans.router)
    app.include_router(audit.router)
    return app

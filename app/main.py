"""
Main FastAPI application for Scambot Honeypot.
"""
import asyncio
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.api import router
from app.core.config import settings
from app.core.limiter import limiter
from app.core.logging import logger

# Background housekeeping handle, set during startup
_sweeper_task: asyncio.Task | None = None

# How often to evict expired in-memory sessions (seconds)
_SWEEP_INTERVAL = 300


async def _session_sweeper():
    """
    Evict expired in-memory sessions on an interval.

    Without this, ``SessionManager._sessions`` grows for the process lifetime --
    one entry per distinct sessionId ever seen -- because cleanup was only
    reachable through the manual admin endpoint.
    """
    from app.storage.session_manager import session_manager

    while True:
        try:
            await asyncio.sleep(_SWEEP_INTERVAL)
            removed = session_manager.cleanup_expired_sessions()
            if removed:
                logger.info(
                    f"Session sweeper evicted {removed} expired sessions "
                    f"({session_manager.get_session_count()} active)"
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(f"Session sweeper iteration failed: {exc}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    global _sweeper_task

    # Startup - Validate configuration
    from app.core.config import validate_configuration

    logger.info("="*70)
    logger.info("Starting Scambot Honeypot API")
    logger.info("="*70)

    validate_configuration()

    # Load ML scam detection model off the event loop -- load_model() does
    # hundreds of MB of blocking disk I/O and would otherwise stall the health
    # check during a cold start.
    try:
        from app.services.ml_detector import load_model
        loaded = await asyncio.to_thread(load_model)
        if loaded:
            logger.info("ML scam detection model loaded successfully")
        else:
            logger.error(
                "ML model NOT loaded - detection is running on rules only. "
                "Expected model files under ml/models/."
            )
    except Exception as ml_exc:
        logger.error(f"ML model loading failed: {ml_exc}")

    # Ensure the retention TTL index exists (best effort, never blocks startup)
    try:
        from app.storage.mongodb import ensure_retention_index
        await ensure_retention_index()
    except Exception as ttl_exc:
        logger.warning(f"Retention index setup skipped: {ttl_exc}")

    _sweeper_task = asyncio.create_task(_session_sweeper())

    logger.info(f"Debug mode: {settings.debug}")
    logger.info(f"OpenAI model: {settings.openai_model}")
    logger.info("[TARGET] Honeypot is LIVE and ready to engage!")
    logger.info("="*70)

    yield

    # Shutdown
    logger.info("="*70)
    logger.info("Shutting down Scambot Honeypot API")

    if _sweeper_task is not None:
        _sweeper_task.cancel()
        try:
            await _sweeper_task
        except asyncio.CancelledError:
            pass
        except Exception as sweeper_exc:
            logger.debug(f"Sweeper task raised during shutdown: {sweeper_exc}")

    # Give in-flight background work (PDF write, Mongo persist, callback) a
    # bounded chance to finish instead of dropping it on SIGTERM.
    pending = [
        t for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]
    if pending:
        logger.info(f"Draining {len(pending)} in-flight background task(s)...")
        done, still_running = await asyncio.wait(pending, timeout=10.0)
        if still_running:
            logger.warning(
                f"{len(still_running)} background task(s) did not finish within "
                "10s and were abandoned"
            )

    logger.info("Shutdown complete")
    logger.info("="*70)


# Create FastAPI application
app = FastAPI(
    title="Scambot Honeypot API",
    description="AI-powered honeypot system for scam detection and intelligence extraction",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None
)

# Attach rate limiter state and handler. The limiter is defined in
# app.core.limiter so routes and the exception handler share ONE instance --
# two separate Limiter objects meant config could diverge silently.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.middleware("http")
async def request_context(request: Request, call_next):
    """
    Assign a request ID, reject oversized bodies, and convert unhandled
    exceptions into a consistent JSON shape without leaking internals.
    """
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    request.state.request_id = request_id

    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > settings.max_request_bytes:
        logger.warning(
            f"Rejected oversized request body: {declared} bytes "
            f"(limit {settings.max_request_bytes}) path={request.url.path} rid={request_id}"
        )
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "status": "error",
                "detail": f"Request body exceeds {settings.max_request_bytes} bytes",
                "requestId": request_id,
            },
        )

    try:
        response = await call_next(request)
    except Exception as exc:
        # Log the detail server-side; return an opaque body to the caller.
        logger.exception(
            f"Unhandled {type(exc).__name__} on {request.method} {request.url.path} "
            f"rid={request_id}: {exc}"
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "detail": "Internal server error",
                "requestId": request_id,
            },
        )

    response.headers["x-request-id"] = request_id
    return response


# CORS -- deny-by-default. ALLOWED_ORIGINS is an explicit allowlist and never
# "*", because "*" combined with allow_credentials is both rejected by browsers
# and would expose the authenticated admin surface to any origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "x-api-key", "x-admin-key", "x-request-id"],
)

# Include API router
app.include_router(router, prefix="/api/v1", tags=["conversation"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "Scambot Honeypot API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health", include_in_schema=False)
@app.head("/health", include_in_schema=False)
async def health_check():
    """
    Deep health check -- this is the endpoint the platform probes.

    Returns 503 when a dependency the service needs is unavailable, so a
    degraded instance is actually detected instead of reporting 200 forever.
    """
    from app.api.routes import build_health_report

    report = await build_health_report()
    # 503 only when the service genuinely cannot do its job (configured database
    # unreachable => every collected session is being lost). A missing ML model
    # is reported as "degraded" with a 200: detection falls back to rules, which
    # is worse but still functional, and killing the instance would be worse.
    code = (
        status.HTTP_200_OK if report["serving"]
        else status.HTTP_503_SERVICE_UNAVAILABLE
    )
    return JSONResponse(status_code=code, content=report)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower()
    )

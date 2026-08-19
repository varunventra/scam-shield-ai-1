"""
Security utilities: API key validation and admin session handling.

Admin authentication is deliberately two-step:

  1. ``POST /api/v1/admin/login`` with the admin key in the ``x-admin-key``
     header, exactly once, from a trusted context.
  2. The server returns an opaque, signed, httpOnly session cookie. Every
     subsequent admin request authenticates with that cookie.

The reason is that the dashboard is a browser app. A key the browser must
present on every request has to be present *in the browser*, and with Vite any
``VITE_*`` value is inlined into the shipped bundle as a string literal -- so
the admin key was readable from devtools by anyone who loaded the page. A
cookie the JavaScript cannot read is the fix; the raw key never reaches the
client.
"""
import hashlib
import hmac
import secrets
import time

from fastapi import HTTPException, Request, Response, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import settings
from app.core.logging import logger

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)
admin_key_header = APIKeyHeader(name="x-admin-key", auto_error=False)

ADMIN_COOKIE_NAME = "scamshield_admin"

# Admin sessions expire after this many seconds; the dashboard re-logs in.
ADMIN_SESSION_TTL = 8 * 60 * 60


def _session_secret() -> bytes:
    """
    Key used to sign admin session cookies.

    Derived from the admin key so no extra secret needs managing, and domain
    separated so the cookie value is never the admin key itself.
    """
    return hashlib.sha256(
        b"scamshield-admin-session|" + settings.admin_api_key.encode("utf-8")
    ).digest()


def _sign(payload: str) -> str:
    return hmac.new(_session_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def mint_admin_session() -> str:
    """Create a signed, expiring session token."""
    expires_at = int(time.time()) + ADMIN_SESSION_TTL
    nonce = secrets.token_urlsafe(16)
    payload = f"{expires_at}.{nonce}"
    return f"{payload}.{_sign(payload)}"


def _valid_admin_session(token: str) -> bool:
    """Constant-time verification of a session cookie."""
    if not token:
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    expires_raw, nonce, signature = parts
    payload = f"{expires_raw}.{nonce}"
    if not hmac.compare_digest(signature, _sign(payload)):
        return False
    try:
        return int(expires_raw) > int(time.time())
    except ValueError:
        return False


def issue_admin_session(response: Response) -> None:
    """Attach a fresh admin session cookie to a response."""
    response.set_cookie(
        key=ADMIN_COOKIE_NAME,
        value=mint_admin_session(),
        max_age=ADMIN_SESSION_TTL,
        httponly=True,
        # Must be "none" for cross-site use (Vercel frontend → Render backend).
        # "strict"/"lax" silently block the cookie on cross-origin requests.
        # Browsers require Secure=True whenever SameSite=None, so we enforce
        # that unconditionally here — regardless of the DEBUG flag.
        samesite="none",
        secure=True,
        path="/",
    )


def clear_admin_session(response: Response) -> None:
    """Remove the admin session cookie."""
    response.delete_cookie(key=ADMIN_COOKIE_NAME, path="/")


async def verify_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Verify the API key from request headers.

    Args:
        api_key: API key from header

    Returns:
        Validated API key

    Raises:
        HTTPException: If API key is invalid or missing
    """
    if not api_key:
        logger.warning("Request received without API key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key"
        )

    if not settings.api_key or not secrets.compare_digest(api_key, settings.api_key):
        logger.warning("Invalid API key attempted")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )

    return api_key


async def verify_admin_login(admin_key: str = Security(admin_key_header)) -> str:
    """
    Verify the raw admin key. Used ONLY by the login endpoint.

    Fails closed when ADMIN_API_KEY is unset, so a misconfigured deploy denies
    admin access rather than opening it.
    """
    if not admin_key:
        logger.warning("Admin login attempted without admin key")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing admin API key"
        )

    if not settings.admin_api_key or not secrets.compare_digest(
        admin_key, settings.admin_api_key
    ):
        logger.warning("Invalid admin API key attempted")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin API key"
        )

    return admin_key


async def verify_admin_key(
    request: Request,
    admin_key: str = Security(admin_key_header),
) -> str:
    """
    Authorize an admin request via session cookie, or a server-to-server key.

    Accepted, in order:
      1. A valid ``scamshield_admin`` session cookie (how the dashboard works).
      2. The raw admin key in ``x-admin-key`` -- retained for CLI/server callers
         and existing integrations. Browsers must never use this path.

    Raises:
        HTTPException: 401 when neither is valid.
    """
    # Public dashboard mode: reads are open so evaluators can browse the
    # dashboard without the key. Restricted to GET so mutating endpoints
    # (cleanup, future deletes) still require real admin credentials.
    if settings.public_dashboard and request.method == "GET":
        return "public"

    if not settings.admin_api_key:
        logger.error(
            "Admin request rejected: ADMIN_API_KEY is not configured, so no "
            "admin credential can ever be valid"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin access is not configured"
        )

    cookie = request.cookies.get(ADMIN_COOKIE_NAME, "")
    if _valid_admin_session(cookie):
        return "session"

    if admin_key and secrets.compare_digest(admin_key, settings.admin_api_key):
        return admin_key

    logger.warning(
        f"Unauthorized admin request to {request.url.path} "
        f"(cookie_present={bool(cookie)}, header_present={bool(admin_key)})"
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Admin authentication required"
    )

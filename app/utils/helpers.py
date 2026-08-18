"""
Utility helper functions.
"""
from typing import Any

from app.models.requests import Message

# Rough estimate of a scammer's productive minute, used to translate engagement
# time into "cost imposed on the scammer". Conservative placeholder, not a claim.
SCAMMER_COST_PER_MINUTE = 5.0  # arbitrary units for the time-waste meter


def transcript_duration_seconds(transcript: list[dict[str, Any]] | None) -> int:
    """
    Compute engagement duration from a conversation transcript.

    Uses the span between the first and last message timestamps (epoch ms).
    Returns 0 when the transcript is missing, too short, or malformed.
    """
    if not transcript or len(transcript) < 2:
        return 0
    try:
        stamps = [m.get("timestamp") for m in transcript if m.get("timestamp")]
        if len(stamps) < 2:
            return 0
        span_ms = max(stamps) - min(stamps)
        return max(0, int(span_ms / 1000))
    except (TypeError, ValueError):
        return 0


def format_duration(seconds: int) -> str:
    """Human-readable duration, e.g. 95 -> '1m 35s'."""
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_conversation_for_display(messages: list[Message]) -> str:
    """
    Format conversation messages for display.

    Args:
        messages: List of messages

    Returns:
        Formatted conversation string
    """
    if not messages:
        return "No messages"

    lines = []
    for msg in messages:
        sender_label = "Scammer" if msg.sender == "scammer" else "User"
        lines.append(f"{sender_label}: {msg.text}")

    return "\n".join(lines)


def sanitize_intelligence_data(data: dict) -> dict:
    """
    Sanitize intelligence data for logging.

    Args:
        data: Intelligence data dictionary

    Returns:
        Sanitized data
    """
    sanitized = data.copy()

    # Mask sensitive information for logs
    if 'bankAccounts' in sanitized:
        sanitized['bankAccounts'] = [
            f"****{acc[-4:]}" if len(acc) > 4 else "****"
            for acc in sanitized['bankAccounts']
        ]

    if 'phoneNumbers' in sanitized:
        sanitized['phoneNumbers'] = [
            f"****{phone[-4:]}" if len(phone) > 4 else "****"
            for phone in sanitized['phoneNumbers']
        ]

    return sanitized


def validate_session_id(session_id: str) -> bool:
    """
    Validate session ID format.

    Args:
        session_id: Session identifier

    Returns:
        True if valid
    """
    if not session_id or not isinstance(session_id, str):
        return False

    stripped = session_id.strip()
    if not stripped or len(stripped) > 256:
        return False

    # Allow alphanumeric, hyphens, underscores, dots (UUID-compatible)
    import re
    return bool(re.match(r'^[a-zA-Z0-9_.\-]+$', stripped))

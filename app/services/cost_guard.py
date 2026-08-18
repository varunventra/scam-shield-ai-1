"""
Global spend circuit breaker for paid LLM calls.

The honeypot engages automatically, fails open on detector errors, and exposes
an LLM-backed generator endpoint -- so without a ceiling there is no input that
cannot cost money and no bound on how much. This module is that ceiling.

Design notes:
  * Counts tokens actually reported by the provider (``response.usage``), not
    estimates, so the number is auditable against the provider's own billing.
  * Resets on UTC date change. No scheduler required.
  * In-process. With multiple workers each gets its own budget, so divide
    DAILY_TOKEN_BUDGET by the worker count, or move this to Redis/Mongo.
  * Fails CLOSED for spend: once tripped, callers must fall back to a canned
    reply rather than calling the provider.
"""
import re
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from app.core.config import settings
from app.core.logging import logger

# API-key shapes we hold: OpenAI (sk-...), Featherless (rc_...), plus any
# long bearer-ish token. Matched against provider error text before storage.
_SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_-]{8,}|rc_[A-Za-z0-9]{8,}|Bearer\s+\S{8,})")


@dataclass
class _DailyUsage:
    day: date
    prompt_tokens: int = 0
    completion_tokens: int = 0
    calls: int = 0
    blocked_calls: int = 0
    by_purpose: dict[str, int] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class CostGuard:
    """Tracks LLM token spend and refuses calls past the daily budget."""

    def __init__(self) -> None:
        self._usage = _DailyUsage(day=datetime.now(UTC).date())
        self._tripped_logged = False

    def _roll_day(self) -> None:
        today = datetime.now(UTC).date()
        if self._usage.day != today:
            logger.info(
                f"Cost guard day rollover: {self._usage.day} used "
                f"{self._usage.total_tokens:,} tokens over {self._usage.calls} calls"
            )
            self._usage = _DailyUsage(day=today)
            self._tripped_logged = False

    @property
    def budget(self) -> int:
        return settings.daily_token_budget

    def tokens_used(self) -> int:
        self._roll_day()
        return self._usage.total_tokens

    def remaining(self) -> int:
        return max(0, self.budget - self.tokens_used())

    def is_tripped(self) -> bool:
        """True when the daily budget is exhausted and calls must be refused."""
        self._roll_day()
        if self.budget <= 0:
            return False  # 0 or negative disables the breaker entirely
        tripped = self._usage.total_tokens >= self.budget
        if tripped and not self._tripped_logged:
            logger.critical(
                f"COST GUARD TRIPPED: {self._usage.total_tokens:,} tokens used today "
                f"(budget {self.budget:,}). Refusing further paid LLM calls until "
                "00:00 UTC. Raise DAILY_TOKEN_BUDGET to lift."
            )
            self._tripped_logged = True
        return tripped

    def check(self, purpose: str) -> bool:
        """
        Ask permission to make a paid call.

        Returns False when the breaker is tripped; the caller must then use a
        non-LLM fallback path.
        """
        if self.is_tripped():
            self._usage.blocked_calls += 1
            logger.warning(f"Cost guard blocked an LLM call (purpose={purpose})")
            return False
        return True

    def record(self, response: Any, purpose: str = "unknown") -> None:
        """
        Record real token usage from a provider response.

        Accepts any object exposing ``.usage.prompt_tokens`` /
        ``.usage.completion_tokens``; silently ignores anything else so a
        provider shape change can never break the request path.
        """
        self._roll_day()
        prompt = completion = 0
        try:
            usage = getattr(response, "usage", None)
            if usage is not None:
                prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
                completion = int(getattr(usage, "completion_tokens", 0) or 0)
        except (TypeError, ValueError):
            prompt = completion = 0

        self._usage.prompt_tokens += prompt
        self._usage.completion_tokens += completion
        self._usage.calls += 1
        self._usage.by_purpose[purpose] = (
            self._usage.by_purpose.get(purpose, 0) + prompt + completion
        )

        # Structured-ish cost line so "what did this session cost" is answerable
        # from logs alone.
        logger.info(
            f"llm_usage purpose={purpose} prompt_tokens={prompt} "
            f"completion_tokens={completion} day_total={self._usage.total_tokens} "
            f"budget={self.budget}"
        )

    def snapshot(self) -> dict[str, Any]:
        """Current-day usage, for the health and stats endpoints."""
        self._roll_day()
        return {
            "day": self._usage.day.isoformat(),
            "promptTokens": self._usage.prompt_tokens,
            "completionTokens": self._usage.completion_tokens,
            "totalTokens": self._usage.total_tokens,
            "calls": self._usage.calls,
            "blockedCalls": self._usage.blocked_calls,
            "budget": self.budget,
            "remaining": self.remaining(),
            "tripped": self.is_tripped(),
            "byPurpose": dict(self._usage.by_purpose),
        }

    def reset(self) -> None:
        """Test hook: clear all recorded usage."""
        self._usage = _DailyUsage(day=datetime.now(UTC).date())
        self._tripped_logged = False


# Process-wide singleton
cost_guard = CostGuard()


# ---------------------------------------------------------------------------
# Provider-error signal, so a revoked key surfaces as an alert not a user report
# ---------------------------------------------------------------------------

class ProviderHealth:
    """Tracks consecutive LLM auth/availability failures for /health."""

    def __init__(self) -> None:
        self.consecutive_auth_failures = 0
        self.last_error: str | None = None
        self.last_error_at: str | None = None

    def record_success(self) -> None:
        self.consecutive_auth_failures = 0
        self.last_error = None

    def record_failure(self, error_type: str, message: str) -> None:
        lowered = message.lower()
        if "authentication" in lowered or "api_key" in lowered or "401" in lowered:
            self.consecutive_auth_failures += 1
        # Provider 401 bodies echo fragments of the offending key back
        # (e.g. "Incorrect API key provided: sk-proj-***"); scrub before storing.
        sanitized = _SECRET_RE.sub("[REDACTED]", message[:200])
        self.last_error = f"{error_type}: {sanitized}"
        self.last_error_at = datetime.now(UTC).isoformat()

    @property
    def key_probably_revoked(self) -> bool:
        return self.consecutive_auth_failures >= 3

    def snapshot(self) -> dict[str, Any]:
        return {
            "consecutiveAuthFailures": self.consecutive_auth_failures,
            "keyProbablyRevoked": self.key_probably_revoked,
            "lastError": self.last_error,
            "lastErrorAt": self.last_error_at,
        }


provider_health = ProviderHealth()

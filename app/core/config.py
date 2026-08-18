"""
Core configuration module for the Scambot Honeypot system.
"""
import logging

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings

# Config is imported before app.core.logging is set up, so validators use a
# plain module logger rather than print() -- keeps startup output in one stream.
_boot_logger = logging.getLogger("scambot_honeypot.config")


class ConfigurationError(RuntimeError):
    """Raised when the environment is not fit to serve traffic."""


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # API Configuration
    api_key: str = Field(..., env="API_KEY")
    port: int = Field(default=8000, env="PORT")
    host: str = Field(default="0.0.0.0", env="HOST")  # noqa: S104 — must bind all interfaces inside the Render/Docker container

    # OpenAI Configuration
    openai_api_key: str = Field(..., env="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o", env="OPENAI_MODEL")
    openai_temperature: float = Field(default=0.7, env="OPENAI_TEMPERATURE")
    max_tokens: int = Field(default=1000, env="MAX_TOKENS")

    # Featherless.ai Configuration (OpenAI-compatible serverless inference for
    # open-weight models) — powers the /ai-scammer demo generator
    featherless_api_key: str = Field(default="", env="FEATHERLESS_API_KEY")
    featherless_base_url: str = Field(
        default="https://api.featherless.ai/v1", env="FEATHERLESS_BASE_URL"
    )
    # Qwen2.5-7B-Instruct: ungated on Featherless and returns clean text
    # (Qwen3 emits <think> blocks; Llama 3.1 requires HuggingFace OAuth)
    featherless_model: str = Field(
        default="Qwen/Qwen2.5-7B-Instruct", env="FEATHERLESS_MODEL"
    )

    # MongoDB Configuration
    mongodb_uri: str = Field(default="", env="MONGODB_URI")

    # Admin API Key
    admin_api_key: str = Field(default="", env="ADMIN_API_KEY")

    # Public dashboard mode: when true, read-only (GET) admin endpoints are
    # served without authentication so evaluators can open the dashboard
    # without being handed the admin key. Mutating admin endpoints (e.g.
    # /admin/cleanup) still require the key. Flip back to false after the event:
    # everything these endpoints serve (intel exports, PDFs, transcripts) is
    # scammer PII that should not stay world-readable.
    public_dashboard: bool = Field(default=False, env="PUBLIC_DASHBOARD")

    # Callback URL (optional -- leave empty for local/log-only mode)
    callback_url: str = Field(
        default="",
        env="CALLBACK_URL"
    )

    # Base URL for generating clickable links (auto-detected on Render).
    # Used ONLY for building PDF download links -- never for CORS.
    base_url: str = Field(default="", env="BASE_URL")

    # Comma-separated list of browser origins allowed to call the API.
    # Deny-by-default: an empty value allows no cross-origin browser traffic.
    allowed_origins: str = Field(default="", env="ALLOWED_ORIGINS")

    # Spend circuit breaker: hard ceiling on LLM tokens per UTC day across the
    # whole process. Once tripped, no further paid calls are made until reset.
    daily_token_budget: int = Field(default=2_000_000, env="DAILY_TOKEN_BUDGET")

    # Per-request hard limits on attacker-controlled input
    max_message_chars: int = Field(default=4000, env="MAX_MESSAGE_CHARS")
    max_request_bytes: int = Field(default=262_144, env="MAX_REQUEST_BYTES")

    # Outbound LLM call timeout (seconds) and retry count
    llm_timeout_seconds: float = Field(default=20.0, env="LLM_TIMEOUT_SECONDS")
    llm_max_retries: int = Field(default=1, env="LLM_MAX_RETRIES")

    # Retention window for stored scammer PII (days). Enforced by a TTL index.
    data_retention_days: int = Field(default=180, env="DATA_RETENTION_DAYS")

    # Application Settings
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    max_conversation_turns: int = Field(default=20, env="MAX_CONVERSATION_TURNS")
    session_timeout: int = Field(default=3600, env="SESSION_TIMEOUT")

    # Scam Detection
    scam_confidence_threshold: float = Field(default=0.7, env="SCAM_CONFIDENCE_THRESHOLD")

    # Agent Persona
    agent_name: str = Field(default="Rahul", env="AGENT_NAME")
    agent_age: int = Field(default=28, env="AGENT_AGE")
    agent_occupation: str = Field(default="Software Engineer", env="AGENT_OCCUPATION")

    @field_validator("openai_api_key")
    def validate_openai_key(cls, v):
        """Validate OpenAI API key format."""
        if not v or len(v) < 20:
            raise ValueError("OpenAI API key appears invalid (too short or empty)")
        if not v.startswith("sk-"):
            print("[WARN] WARNING: OpenAI API key doesn't start with 'sk-' - this may be incorrect!")
        return v

    @field_validator("api_key")
    def validate_api_key(cls, v):
        """Validate API key is set."""
        if not v or len(v) < 8:
            raise ValueError("API_KEY must be at least 8 characters long")
        return v

    @field_validator("openai_model")
    def validate_model(cls, v):
        """Validate OpenAI model name."""
        valid_models = ["gpt-4o", "gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"]
        if v not in valid_models:
            _boot_logger.warning(
                f"Model '{v}' not in the known list {valid_models} - "
                "ensure the API key has access to it"
            )
        return v

    @model_validator(mode="after")
    def validate_production_config(self):
        """
        Fail-fast on configurations that silently lose data or leak.

        Only enforced when DEBUG is false, so local development stays easy.
        """
        if self.debug:
            return self

        missing = []
        if not self.mongodb_uri:
            missing.append("MONGODB_URI (without it every session is lost on restart)")
        if not self.admin_api_key:
            missing.append("ADMIN_API_KEY (admin surface would be permanently 401)")
        if len(self.admin_api_key) < 32 and self.admin_api_key:
            missing.append("ADMIN_API_KEY must be at least 32 characters")
        if missing:
            raise ValueError(
                "Refusing to start with DEBUG=false and incomplete configuration:\n  - "
                + "\n  - ".join(missing)
            )
        return self

    @property
    def cors_origins(self) -> list:
        """
        Browser origins allowed to call the API.

        Deny-by-default: never returns ``["*"]``. Wildcard plus credentials is
        rejected by browsers anyway, and would expose the admin surface.
        """
        raw = [o.strip() for o in self.allowed_origins.split(",") if o.strip()]
        return [o for o in raw if o != "*"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


def validate_configuration():
    """
    Log the effective configuration at startup.

    Deliberately makes NO outbound API call: the previous implementation issued
    a billable chat completion on every boot, which on a plan that spins down
    when idle meant paying per cold start. Key validity now surfaces through the
    first real request and through the health endpoint.
    """
    logger = logging.getLogger("scambot_honeypot")

    logger.info("=" * 70)
    logger.info("CONFIGURATION")
    logger.info(f"  API key:          set (...{settings.api_key[-4:]})")
    logger.info(f"  Admin key:        {'set' if settings.admin_api_key else 'NOT SET'}")
    logger.info(f"  OpenAI model:     {settings.openai_model}")
    logger.info(f"  OpenAI key:       set (...{settings.openai_api_key[-4:]})")
    logger.info(f"  MongoDB:          {'configured' if settings.mongodb_uri else 'NOT CONFIGURED'}")
    logger.info(f"  Debug:            {settings.debug}")
    logger.info(f"  Scam threshold:   {settings.scam_confidence_threshold}")
    logger.info(f"  Daily token cap:  {settings.daily_token_budget:,}")
    logger.info(f"  CORS origins:     {settings.cors_origins or 'none (same-origin only)'}")
    logger.info(f"  Retention:        {settings.data_retention_days} days")
    logger.info("=" * 70)

    if not settings.mongodb_uri:
        logger.error(
            "MONGODB_URI is empty - sessions will NOT persist and PDF storage is "
            "disabled. This is only acceptable for local development."
        )


# Global settings instance.
# Raises ConfigurationError rather than calling sys.exit() so that importing
# this module never kills the interpreter (breaks pytest collection and tooling).
try:
    settings = Settings()
except Exception as exc:
    raise ConfigurationError(
        f"Failed to load configuration: {exc}\n"
        "Create a .env file in the project root with at least API_KEY and "
        "OPENAI_API_KEY set. See .env.example for the full list."
    ) from exc

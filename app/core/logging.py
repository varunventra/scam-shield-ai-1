"""
Logging configuration for the application.
"""
import logging
import sys

from app.core.config import settings


class _SafeStreamHandler(logging.StreamHandler):
    """StreamHandler that survives UnicodeEncodeError on Windows CP1252 terminals.
    Any character that can't be encoded is replaced with '?' instead of crashing."""
    def emit(self, record: logging.LogRecord) -> None:
        try:
            super().emit(record)
        except UnicodeEncodeError:
            try:
                # Re-encode the formatted message as ASCII, replacing unencodable chars
                record.msg = str(record.msg).encode('ascii', errors='replace').decode('ascii')
                record.args = None
                super().emit(record)
            except Exception:
                self.handleError(record)


def setup_logging(log_level: str | None = None) -> logging.Logger:
    """
    Configure and return a logger instance.

    Args:
        log_level: Optional log level override

    Returns:
        Configured logger instance
    """
    level = log_level or settings.log_level

    # Create logger
    logger = logging.getLogger("scambot_honeypot")
    logger.setLevel(getattr(logging, level.upper()))

    # Safe handler -- won't crash on emoji/non-ASCII on Windows CP1252
    handler = _SafeStreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, level.upper()))

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)

    # Add handler to logger
    if not logger.handlers:
        logger.addHandler(handler)

    return logger


# Global logger instance
logger = setup_logging()

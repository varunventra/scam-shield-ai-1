"""
Session management for tracking conversation state.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.core.config import settings
from app.core.logging import logger
from app.models.requests import Message
from app.models.responses import ExtractedIntelligence


@dataclass
class DetectedIdentity:
    """
    Identity inferred from the scammer's messages.
    Separate from persona category (grandmother/professional/etc).
    Once locked, never changes for the rest of the session.
    """
    name: str | None = None          # e.g. "Hansika", "Rahul"
    gender: str | None = None        # "male", "female", or None
    age_group: str | None = None     # "elderly", "middle_aged", "young"
    locked: bool = False


@dataclass
class SessionData:
    """Data structure for session information."""
    session_id: str
    scam_detected: bool = False
    scam_confidence: float = 0.0
    agent_activated: bool = False
    messages: list[Message] = field(default_factory=list)
    intelligence: ExtractedIntelligence | None = None
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    callback_sent: bool = False
    # Multi-persona + multilingual fields
    detected_language: str = "english"
    response_language: str = "english"
    persona_selected: str | None = None
    persona_switch_history: list[str] = field(default_factory=list)
    # Dynamic identity detection
    detected_identity: DetectedIdentity = field(default_factory=DetectedIdentity)
    # Hybrid detection fields
    rule_score: float = 0.0
    ml_score: float | None = None
    scam_type: str = "UNKNOWN"
    detection_method: str = "none"
    detected_indicators: list[str] = field(default_factory=list)
    # Strategic conversation state (initialized lazily to avoid circular import)
    conversation_strategy: object | None = None

    def add_message(self, message: Message) -> None:
        """Add a message to the session."""
        self.messages.append(message)
        self.last_updated = datetime.now()

    def get_message_count(self) -> int:
        """Get total message count."""
        return len(self.messages)

    def is_expired(self) -> bool:
        """Check if session has expired."""
        timeout = timedelta(seconds=settings.session_timeout)
        return datetime.now() - self.last_updated > timeout


class SessionManager:
    """Manages conversation sessions in memory."""

    def __init__(self):
        """Initialize session manager."""
        self._sessions: dict[str, SessionData] = {}
        logger.info("SessionManager initialized")

    def create_session(self, session_id: str) -> SessionData:
        """
        Create a new session.

        Args:
            session_id: Unique session identifier

        Returns:
            New session data
        """
        if session_id in self._sessions:
            logger.warning(f"Session already exists: {session_id}")
            return self._sessions[session_id]

        session = SessionData(session_id=session_id)
        self._sessions[session_id] = session
        logger.info(f"Created new session: {session_id}")
        return session

    def get_session(self, session_id: str) -> SessionData | None:
        """
        Get existing session.

        Args:
            session_id: Session identifier

        Returns:
            Session data if exists, None otherwise
        """
        return self._sessions.get(session_id)

    def get_or_create_session(self, session_id: str) -> SessionData:
        """
        Get existing session or create new one.

        Args:
            session_id: Session identifier

        Returns:
            Session data
        """
        session = self.get_session(session_id)
        if session is None:
            session = self.create_session(session_id)
        return session

    # Sentinel for distinguishing "not passed" from "passed as None"
    _UNSET = object()

    def update_session(
        self,
        session_id: str,
        scam_detected: bool | None = None,
        scam_confidence: float | None = None,
        agent_activated: bool | None = None,
        intelligence: ExtractedIntelligence | None = None,
        callback_sent: bool | None = None,
        detected_language: str | None = None,
        response_language: str | None = None,
        persona_selected: str | None = None,
        rule_score: float | None = None,
        ml_score: object = _UNSET,  # sentinel: None means "ML not used"
        scam_type: str | None = None,
        detection_method: str | None = None,
        detected_indicators: list[str] | None = None,
        detected_identity: DetectedIdentity | None = None,
    ) -> SessionData | None:
        """
        Update session data.

        Returns:
            Updated session data if exists
        """
        session = self.get_session(session_id)
        if session is None:
            logger.warning(f"Cannot update non-existent session: {session_id}")
            return None

        if scam_detected is not None:
            session.scam_detected = scam_detected
        if scam_confidence is not None:
            session.scam_confidence = scam_confidence
        if agent_activated is not None:
            session.agent_activated = agent_activated
        if intelligence is not None:
            session.intelligence = intelligence
        if callback_sent is not None:
            session.callback_sent = callback_sent
        if detected_language is not None:
            session.detected_language = detected_language
        if response_language is not None:
            session.response_language = response_language
        if persona_selected is not None:
            # Track persona switches
            if session.persona_selected and session.persona_selected != persona_selected:
                session.persona_switch_history.append(session.persona_selected)
            session.persona_selected = persona_selected
        if rule_score is not None:
            session.rule_score = rule_score
        if ml_score is not self._UNSET:
            session.ml_score = ml_score  # Can be None (ML not used) or float
        if scam_type is not None:
            session.scam_type = scam_type
        if detection_method is not None:
            session.detection_method = detection_method
        if detected_indicators is not None:
            session.detected_indicators = detected_indicators
        if detected_identity is not None:
            session.detected_identity = detected_identity

        session.last_updated = datetime.now()
        logger.debug(f"Updated session: {session_id}")
        return session

    def add_message_to_session(self, session_id: str, message: Message) -> bool:
        """
        Add a message to session.

        Args:
            session_id: Session identifier
            message: Message to add

        Returns:
            True if successful
        """
        session = self.get_session(session_id)
        if session is None:
            logger.warning(f"Cannot add message to non-existent session: {session_id}")
            return False

        session.add_message(message)
        logger.debug(f"Added message to session: {session_id}")
        return True

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.

        Returns:
            Number of sessions removed
        """
        expired_sessions = [
            sid for sid, session in self._sessions.items()
            if session.is_expired()
        ]

        for session_id in expired_sessions:
            del self._sessions[session_id]
            logger.info(f"Removed expired session: {session_id}")

        return len(expired_sessions)

    def get_session_count(self) -> int:
        """Get total number of active sessions."""
        return len(self._sessions)

    def get_all_sessions(self) -> dict[str, SessionData]:
        """Get all active sessions."""
        return self._sessions.copy()


# Global session manager instance
session_manager = SessionManager()

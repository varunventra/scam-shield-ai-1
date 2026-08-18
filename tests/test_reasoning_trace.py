"""
Tests for the per-turn agent reasoning trace.

Covers:
- _build_reasoning unit behaviour (new-intel diffing, persona reason, phase mapping)
- _describe_phase_trigger explanations mirror select_phase logic
- /conversation response includes a well-formed reasoning block
"""
import time

from fastapi.testclient import TestClient

from app.api.routes import _PHASE_NAMES, _build_reasoning, _describe_phase_trigger
from app.core.config import settings
from app.main import app
from app.services.conversation_strategy import ConversationStrategy, select_phase
from app.storage.session_manager import SessionData

client = TestClient(app)
VALID_API_KEY = settings.api_key


def _make_session(**overrides) -> SessionData:
    session = SessionData(session_id="reasoning-test-session")
    session.scam_detected = True
    session.scam_confidence = 0.92
    session.rule_score = 0.8
    session.ml_score = 0.95
    session.scam_type = "bank_fraud"
    session.detection_method = "ml"
    session.detected_indicators = ["urgency", "account_threat"]
    session.persona_selected = "grandmother"
    session.detected_language = "english"
    session.response_language = "english"
    for key, value in overrides.items():
        setattr(session, key, value)
    return session


class TestBuildReasoning:
    def test_new_intel_diffing(self):
        """Only items absent from previous turn appear in newIntelThisTurn."""
        strategy = ConversationStrategy()
        strategy.turn_count = 2
        prev = {"phoneNumbers": ["9876543210"], "upiIds": []}
        curr = {"phoneNumbers": ["9876543210"], "upiIds": ["scammer@paytm"]}

        reasoning = _build_reasoning(
            session=_make_session(),
            strategy=strategy,
            prev_intel=prev,
            curr_intel=curr,
            persona_kept=True,
        )

        assert reasoning.newIntelThisTurn == ["upiIds: scammer@paytm"]

    def test_persona_kept_reason(self):
        reasoning = _build_reasoning(
            session=_make_session(),
            strategy=ConversationStrategy(),
            prev_intel={},
            curr_intel={},
            persona_kept=True,
        )
        assert reasoning.personaReason == "kept for session consistency"

    def test_persona_new_reason_mentions_scam_type(self):
        reasoning = _build_reasoning(
            session=_make_session(),
            strategy=ConversationStrategy(),
            prev_intel={},
            curr_intel={},
            persona_kept=False,
        )
        assert "bank_fraud" in reasoning.personaReason

    def test_detection_fields_copied_from_session(self):
        reasoning = _build_reasoning(
            session=_make_session(),
            strategy=ConversationStrategy(),
            prev_intel={},
            curr_intel={},
            persona_kept=True,
        )
        assert reasoning.detectionMethod == "ml"
        assert reasoning.detectionConfidence == 0.92
        assert reasoning.mlScore == 0.95
        assert reasoning.scamType == "bank_fraud"
        assert reasoning.indicators == ["urgency", "account_threat"]

    def test_phase_name_matches_selected_phase(self):
        strategy = ConversationStrategy()
        strategy.turn_count = 6
        reasoning = _build_reasoning(
            session=_make_session(),
            strategy=strategy,
            prev_intel={},
            curr_intel={},
            persona_kept=True,
        )
        expected_phase = select_phase(strategy)
        assert reasoning.phase == expected_phase
        assert reasoning.phaseName == _PHASE_NAMES[expected_phase]

    def test_works_without_strategy(self):
        """Reasoning degrades gracefully when no strategy exists yet."""
        reasoning = _build_reasoning(
            session=_make_session(),
            strategy=None,
            prev_intel={},
            curr_intel={"phoneNumbers": ["9123456789"]},
            persona_kept=False,
        )
        assert reasoning.detectionMethod == "ml"
        assert reasoning.newIntelThisTurn == ["phoneNumbers: 9123456789"]


class TestPhaseTrigger:
    def test_early_jump_explanation(self):
        strategy = ConversationStrategy()
        strategy.turn_count = 3
        strategy.info_collected["phone_numbers"] = ["9876543210"]
        strategy.info_collected["upi_ids"] = ["a@upi"]
        strategy.info_collected["bank_accounts"] = ["12345678901"]
        phase = select_phase(strategy)
        assert phase == 3
        assert "early jump" in _describe_phase_trigger(strategy, phase)

    def test_first_contact_explanation(self):
        strategy = ConversationStrategy()
        strategy.turn_count = 1
        phase = select_phase(strategy)
        assert phase == 1
        assert "first contact" in _describe_phase_trigger(strategy, phase)

    def test_phone_collected_gap_explanation(self):
        strategy = ConversationStrategy()
        strategy.turn_count = 2
        strategy.info_collected["phone_numbers"] = ["9876543210"]
        phase = select_phase(strategy)
        assert phase == 2
        assert "phone collected" in _describe_phase_trigger(strategy, phase)


class TestReasoningInResponse:
    def test_conversation_response_includes_reasoning(self):
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": f"reasoning-e2e-{int(time.time())}",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Your SBI account is blocked. Call 9876543210 now to verify KYC.",
                    "timestamp": int(time.time() * 1000),
                },
                "conversationHistory": [],
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data.get("reasoning") is not None
        reasoning = data["reasoning"]
        assert reasoning["turn"] >= 1
        assert reasoning["phase"] in (1, 2, 3)
        assert reasoning["phaseName"] in _PHASE_NAMES.values()
        assert isinstance(reasoning["missingTargets"], list)
        assert isinstance(reasoning["newIntelThisTurn"], list)
        # First message contained a phone number — must show up as new intel
        assert any("9876543210" in item for item in reasoning["newIntelThisTurn"])

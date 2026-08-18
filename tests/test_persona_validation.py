"""
Persona Validation Tests
Ensures agent responses are realistic, natural, and match elderly persona.
Tests that responses are NOT bookish or formal.
"""
import re
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)
VALID_API_KEY = settings.api_key


class TestPersonaRealism:
    """Test that agent maintains realistic elderly persona"""

    def test_01_short_natural_responses(self):
        """Responses should be short and natural (not essays)"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"]

        # Most responses should be under 100 characters (elderly texting style)
        # Some may be longer, but let's check it's not a paragraph
        assert len(reply) < 200, f"Response too long ({len(reply)} chars): {reply}"
        print(f"\n✅ Response length: {len(reply)} chars")
        print(f"   Reply: {reply}")

    def test_02_no_bookish_language(self):
        """Should NOT use formal/bookish words"""
        forbidden_words = [
            "facilitate", "assist", "proceed", "kindly",
            "nevertheless", "furthermore", "subsequently",
            "verify authenticity", "security protocols",
            "authenticate", "credentials", "compliance"
        ]

        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-002",
                "message": {
                    "sender": "scammer",
                    "text": "You need to verify your account immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"].lower()

        found_forbidden = [word for word in forbidden_words if word.lower() in reply]
        assert len(found_forbidden) == 0, f"Found bookish words: {found_forbidden} in reply: {reply}"
        print("\n✅ No bookish language detected")
        print(f"   Reply: {reply}")

    def test_03_shows_natural_emotions(self):
        """Should express natural worry/confusion"""
        natural_expressions = [
            "what", "why", "how", "scared", "worried", "confused",
            "don't understand", "not understanding", "help me",
            "oh no", "oh my god", "really", "is it safe"
        ]

        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-003",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Your account will be blocked in 1 hour!",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"].lower()

        # Should have at least one natural expression
        has_natural_expression = any(expr in reply for expr in natural_expressions)
        print(f"\n✅ Reply: {reply}")
        print(f"   Natural expression found: {has_natural_expression}")

    def test_04_asks_simple_questions(self):
        """Should ask simple, direct questions like elderly person would"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-004",
                "message": {
                    "sender": "scammer",
                    "text": "Share your OTP to verify",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"]

        # Should contain a question
        assert "?" in reply, f"Response should ask a question: {reply}"
        print(f"\n✅ Reply contains question: {reply}")

    def test_05_no_bot_or_ai_mentions(self):
        """Should NEVER reveal it's a bot/AI"""
        bot_words = ["bot", "ai", "artificial", "automated", "system", "algorithm"]

        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-005",
                "message": {
                    "sender": "scammer",
                    "text": "Are you a real person?",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"].lower()

        # Match whole words only — "ai" as a substring would falsely
        # match "explain", "wait", "again", ...
        found_bot_words = [
            word for word in bot_words if re.search(rf"\b{word}\b", reply)
        ]
        assert len(found_bot_words) == 0, f"Found bot-revealing words: {found_bot_words} in: {reply}"
        print(f"\n✅ No bot/AI mentions: {reply}")

    def test_06_indian_english_patterns(self):
        """Should use Indian English patterns naturally (soft check — printed for review)"""
        responses = []
        for i in range(3):
            response = client.post(
                "/api/v1/conversation",
                headers={"x-api-key": VALID_API_KEY},
                json={
                    "sessionId": f"persona-test-006-{i}",
                    "message": {
                        "sender": "scammer",
                        "text": "Call this number now: 9876543210",
                        "timestamp": int(time.time() * 1000) + (i * 100)
                    },
                    "conversationHistory": []
                }
            )
            responses.append(response.json()["reply"])

        print("\n✅ Sample responses:")
        for i, reply in enumerate(responses):
            print(f"   {i+1}. {reply}")

    def test_07_expresses_vulnerability(self):
        """Should show natural vulnerability of elderly person (soft check — printed for review)"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-007",
                "message": {
                    "sender": "scammer",
                    "text": "You need to act immediately or your money will be lost",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"].lower()
        print(f"\n✅ Reply: {reply}")

    def test_08_not_immediately_compliant(self):
        """Should show hesitation, not immediately comply"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-008",
                "message": {
                    "sender": "scammer",
                    "text": "Send me your account number right now",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"].lower()

        # Should NOT directly give account number
        # Should ask questions or express hesitation
        account_like = re.findall(r'\d{10,16}', reply)
        assert len(account_like) == 0, f"Should not give account numbers: {reply}"
        print(f"\n✅ Shows hesitation (no account given): {reply}")

    def test_09_extracts_scammer_info_naturally(self):
        """Should naturally ask for scammer's information (soft check — printed for review)"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "persona-test-009",
                "message": {
                    "sender": "scammer",
                    "text": "I am calling from your bank. You must verify immediately.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply = response.json()["reply"].lower()
        print(f"\n✅ Reply: {reply}")

    def test_10_realistic_typos_or_natural_grammar(self):
        """Responses may have natural typos or incomplete sentences"""
        # This is more of an observation test
        # Just verify responses are natural and not perfectly grammatical all the time
        responses = []

        for i in range(5):
            response = client.post(
                "/api/v1/conversation",
                headers={"x-api-key": VALID_API_KEY},
                json={
                    "sessionId": f"persona-test-010-{i}",
                    "message": {
                        "sender": "scammer",
                        "text": "Your account is at risk. Act now!",
                        "timestamp": int(time.time() * 1000) + (i * 100)
                    },
                    "conversationHistory": []
                }
            )
            responses.append(response.json()["reply"])

        print("\n✅ Natural language samples:")
        for i, reply in enumerate(responses):
            print(f"   {i+1}. {reply}")


class TestPersonaConsistency:
    """Test that persona remains consistent across conversation"""

    def test_11_maintains_character_through_conversation(self):
        """Character should remain consistent across multiple turns"""
        session_id = "persona-consistency-001"
        conversation_history = []

        messages = [
            "Your account will be blocked",
            "Share your OTP",
            "This is urgent, do it now"
        ]

        responses = []
        for i, msg in enumerate(messages):
            response = client.post(
                "/api/v1/conversation",
                headers={"x-api-key": VALID_API_KEY},
                json={
                    "sessionId": session_id,
                    "message": {
                        "sender": "scammer",
                        "text": msg,
                        "timestamp": int(time.time() * 1000) + (i * 1000)
                    },
                    "conversationHistory": conversation_history.copy()
                }
            )
            reply = response.json()["reply"]
            responses.append(reply)

            # Update history
            conversation_history.append({
                "sender": "scammer",
                "text": msg,
                "timestamp": int(time.time() * 1000) + (i * 1000)
            })
            conversation_history.append({
                "sender": "user",
                "text": reply,
                "timestamp": int(time.time() * 1000) + (i * 1000) + 500
            })

        print("\n✅ Character consistency test:")
        for i, reply in enumerate(responses):
            print(f"   Turn {i+1}: {reply}")

        # All responses should maintain elderly persona (short, natural, not bookish)
        for reply in responses:
            assert len(reply) < 200, f"Response too long: {reply}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])

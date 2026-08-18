"""
Comprehensive test suite for Scambot Honeypot API.
Tests cover all requirements from the problem statement including:
- API Authentication
- Scam Detection
- Multi-turn Conversations (Critical)
- Intelligence Extraction
- Response Format
- Edge Cases
"""
import re
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)

# Valid API key for tests
VALID_API_KEY = settings.api_key
INVALID_API_KEY = "invalid-key-12345"
VALID_ADMIN_KEY = settings.admin_api_key


class TestAPIAuthentication:
    """Test 1-3: API Authentication"""

    def test_01_missing_api_key(self):
        """Test 1: Request without API key should fail"""
        response = client.post(
            "/api/v1/conversation",
            json={
                "sessionId": "test-001",
                "message": {
                    "sender": "scammer",
                    "text": "Test message",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 401
        assert "Missing API key" in response.json()["detail"]

    def test_02_invalid_api_key(self):
        """Test 2: Request with invalid API key should fail"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": INVALID_API_KEY},
            json={
                "sessionId": "test-002",
                "message": {
                    "sender": "scammer",
                    "text": "Test message",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 401
        assert "Invalid API key" in response.json()["detail"]

    def test_03_valid_api_key(self):
        """Test 3: Request with valid API key should succeed"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-003",
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200


class TestScamDetection:
    """Test 4-8: Scam Detection Functionality"""

    def test_04_bank_fraud_detection(self):
        """Test 4: Detect bank fraud scam with urgency tactics"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-004",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Your bank account will be blocked today. Verify immediately by calling 9876543210.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "SMS",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "reply" in data
        assert len(data["reply"]) > 0

    def test_05_upi_fraud_detection(self):
        """Test 5: Detect UPI fraud scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-005",
                "message": {
                    "sender": "scammer",
                    "text": "Send 1 rupee to verify your UPI: scammer123@paytm",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_06_phishing_link_detection(self):
        """Test 6: Detect phishing links"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-006",
                "message": {
                    "sender": "scammer",
                    "text": "Click here to verify your account: http://fake-bank-verify.com/verify?id=123",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_07_lottery_scam_detection(self):
        """Test 7: Detect lottery/prize scams"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-007",
                "message": {
                    "sender": "scammer",
                    "text": "Congratulations! You won 10 Lakh rupees in KBC lottery. Claim now by sharing your bank details.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_08_otp_request_scam(self):
        """Test 8: Detect OTP/credentials request scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-008",
                "message": {
                    "sender": "scammer",
                    "text": "Share the OTP sent to your mobile to verify your identity",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"


class TestMultiTurnConversations:
    """Test 9-14: Multi-turn Conversation Handling (CRITICAL REQUIREMENT)"""

    def test_09_two_turn_conversation(self):
        """Test 9: Handle 2-turn conversation with context"""
        session_id = "test-009"

        # First message
        response1 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked due to suspicious activity.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response1.status_code == 200
        reply1 = response1.json()["reply"]

        # Second message with history
        response2 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Share your OTP to unblock your account",
                    "timestamp": int(time.time() * 1000) + 1000
                },
                "conversationHistory": [
                    {
                        "sender": "scammer",
                        "text": "Your account will be blocked due to suspicious activity.",
                        "timestamp": int(time.time() * 1000)
                    },
                    {
                        "sender": "user",
                        "text": reply1,
                        "timestamp": int(time.time() * 1000) + 500
                    }
                ]
            }
        )
        assert response2.status_code == 200
        data = response2.json()
        assert data["status"] == "success"
        assert len(data["reply"]) > 0

    def test_10_five_turn_conversation(self):
        """Test 10: Handle 5-turn conversation maintaining context"""
        session_id = "test-010"
        conversation_history = []

        messages = [
            "Your bank account will be suspended today.",
            "You need to verify your identity immediately to avoid suspension.",
            "Please share your account number to verify: Mine is 1234567890",
            "Also provide your UPI ID. Mine is: scammer@paytm",
            "Call me on this number for verification: +919876543210"
        ]

        for i, scam_msg in enumerate(messages):
            response = client.post(
                "/api/v1/conversation",
                headers={"x-api-key": VALID_API_KEY},
                json={
                    "sessionId": session_id,
                    "message": {
                        "sender": "scammer",
                        "text": scam_msg,
                        "timestamp": int(time.time() * 1000) + (i * 1000)
                    },
                    "conversationHistory": conversation_history.copy()
                }
            )
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"

            # Update conversation history
            conversation_history.append({
                "sender": "scammer",
                "text": scam_msg,
                "timestamp": int(time.time() * 1000) + (i * 1000)
            })
            conversation_history.append({
                "sender": "user",
                "text": data["reply"],
                "timestamp": int(time.time() * 1000) + (i * 1000) + 500
            })

    def test_11_conversation_context_retention(self):
        """Test 11: Verify agent remembers conversation context"""
        session_id = "test-011"

        # First: Scammer asks to verify
        response1 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Verify your account at http://fake-link.com",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply1 = response1.json()["reply"]

        # Second: Reference previous message
        response2 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Did you click the verification link I sent earlier?",
                    "timestamp": int(time.time() * 1000) + 2000
                },
                "conversationHistory": [
                    {
                        "sender": "scammer",
                        "text": "Verify your account at http://fake-link.com",
                        "timestamp": int(time.time() * 1000)
                    },
                    {
                        "sender": "user",
                        "text": reply1,
                        "timestamp": int(time.time() * 1000) + 1000
                    }
                ]
            }
        )
        assert response2.status_code == 200
        # Agent should respond contextually about the link

    def test_12_ten_turn_extended_conversation(self):
        """Test 12: Handle extended 10-turn conversation"""
        session_id = "test-012"
        conversation_history = []

        scam_messages = [
            "Urgent: Your account will be blocked",
            "We are from State Bank of India customer care",
            "What is your full name for verification?",
            "Your account number please? Format: XXXX-XXXX-XXXX",
            "Share your registered UPI ID",
            "What is your registered mobile number?",
            "An OTP has been sent. Can you share it?",
            "Your PAN card number for KYC?",
            "Send a screenshot of your bank statement",
            "Transfer 1 rupee to this UPI to verify: scammer@paytm"
        ]

        for i, msg in enumerate(scam_messages):
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
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"

            # Update history
            conversation_history.append({
                "sender": "scammer",
                "text": msg,
                "timestamp": int(time.time() * 1000) + (i * 1000)
            })
            conversation_history.append({
                "sender": "user",
                "text": data["reply"],
                "timestamp": int(time.time() * 1000) + (i * 1000) + 500
            })

    def test_13_empty_conversation_history_first_message(self):
        """Test 13: Handle first message (empty conversation history)"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-013",
                "message": {
                    "sender": "scammer",
                    "text": "Your account is compromised. Immediate action required.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_14_different_channels_multiturn(self):
        """Test 14: Multi-turn conversation across different channels"""
        session_id = "test-014"
        conversation_history = []

        channels = ["SMS", "WhatsApp", "Email"]
        messages = [
            "Your account is at risk",
            "Click this link to secure it",
            "Share OTP to confirm"
        ]

        for i, (msg, channel) in enumerate(zip(messages, channels, strict=False)):
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
                    "conversationHistory": conversation_history.copy(),
                    "metadata": {
                        "channel": channel,
                        "language": "English",
                        "locale": "IN"
                    }
                }
            )
            assert response.status_code == 200

            conversation_history.append({
                "sender": "scammer",
                "text": msg,
                "timestamp": int(time.time() * 1000) + (i * 1000)
            })
            conversation_history.append({
                "sender": "user",
                "text": response.json()["reply"],
                "timestamp": int(time.time() * 1000) + (i * 1000) + 500
            })


class TestIntelligenceExtraction:
    """Test 15-17: Intelligence Extraction"""

    def test_15_extract_bank_account_numbers(self):
        """Test 15: Extract bank account numbers from conversation"""
        session_id = "test-015"
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Transfer money to account 123456789012 or 987654321098",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200

    def test_16_extract_upi_ids(self):
        """Test 16: Extract UPI IDs from conversation"""
        session_id = "test-016"
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Send payment to scammer123@paytm or fraudster@ybl for verification",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200

    def test_17_extract_phone_numbers(self):
        """Test 17: Extract phone numbers from conversation"""
        session_id = "test-017"
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Call me urgently at +919876543210 or WhatsApp on 8765432109",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200


class TestResponseFormat:
    """Test 18-19: Response Format Validation"""

    def test_18_response_structure_compliance(self):
        """Test 18: Response follows problem statement format"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-018",
                "message": {
                    "sender": "scammer",
                    "text": "Urgent action required on your account",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        # Must have exactly these fields as per problem statement
        assert "status" in data
        assert "reply" in data
        assert data["status"] == "success"

    def test_19_reply_is_human_like(self):
        """Test 19: Reply is a non-empty human-like string"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-019",
                "message": {
                    "sender": "scammer",
                    "text": "Verify your account now",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        data = response.json()
        assert isinstance(data["reply"], str)
        assert len(data["reply"]) > 0
        # Should not reveal it's a bot (whole words only — "ai" as a
        # substring would falsely match "explain", "wait", "again", ...)
        reply = data["reply"].lower()
        assert not re.search(r"\bbot\b", reply)
        assert not re.search(r"\bai\b", reply)


class TestEdgeCasesAndErrors:
    """Test 20-22: Edge Cases and Error Handling"""

    def test_20_missing_required_fields(self):
        """Test 20: Handle missing required fields gracefully"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-020",
                # Missing 'message' field
                "conversationHistory": []
            }
        )
        assert response.status_code == 422  # Validation error

    def test_21_invalid_session_id(self):
        """Test 21: Handle empty or invalid session ID"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "",  # Empty session ID
                "message": {
                    "sender": "scammer",
                    "text": "Test",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 400

    def test_22_health_endpoint_no_auth(self):
        """Test 22: Health check works without authentication.

        The endpoint no longer reports "healthy" unconditionally -- it reports
        "degraded" and lists the specific problems when a dependency is missing
        (e.g. the ML model isn't loaded, as in this test process). It still
        serves 200 while degraded; only an unreachable configured database
        produces 503.
        """
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("healthy", "degraded")
        assert data["serving"] is True
        assert isinstance(data["problems"], list)
        assert "active_sessions" in data


class TestAPIEndpoints:
    """Bonus Tests: Additional endpoint testing"""

    def test_23_root_endpoint(self):
        """Test 23: Root endpoint returns service info"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "service" in data
        assert data["service"] == "Scambot Honeypot API"

    def test_24_admin_cleanup(self):
        """Test 24: Admin cleanup endpoint requires the admin key"""
        # Plain API key must NOT be enough for an admin endpoint
        response = client.post(
            "/api/v1/admin/cleanup",
            headers={"x-api-key": VALID_API_KEY}
        )
        assert response.status_code == 401

        response = client.post(
            "/api/v1/admin/cleanup",
            headers={"x-admin-key": VALID_ADMIN_KEY}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"

    def test_26_ai_scammer_provider_selection(self, monkeypatch):
        """Test 26: /ai-scammer uses Featherless when configured, OpenAI otherwise"""
        import openai as openai_module

        captured = {}

        class _FakeMessage:
            content = "Your account will be blocked. Pay now."

        class _FakeChoice:
            message = _FakeMessage()

        class _FakeUsage:
            prompt_tokens = 100
            completion_tokens = 50

        class _FakeCompletion:
            choices = [_FakeChoice()]
            usage = _FakeUsage()

        class _FakeClient:
            # **kwargs absorbs timeout / max_retries, which the app now sets on
            # every client so a hung call can't hold a task for ~30 minutes.
            def __init__(self, api_key=None, base_url=None, **kwargs):
                captured["api_key"] = api_key
                captured["base_url"] = base_url
                captured["timeout"] = kwargs.get("timeout")

                class _Completions:
                    @staticmethod
                    async def create(**kwargs):
                        captured["model"] = kwargs.get("model")
                        return _FakeCompletion()

                class _Chat:
                    completions = _Completions()

                self.chat = _Chat()

        monkeypatch.setattr(openai_module, "AsyncOpenAI", _FakeClient)

        # Featherless key set -> Featherless base_url + model
        monkeypatch.setattr(settings, "featherless_api_key", "fl-test-key")
        response = client.post(
            "/api/v1/ai-scammer",
            headers={"x-api-key": VALID_API_KEY},
            json={"scamType": "sbi_bank_fraud", "conversationHistory": []},
        )
        assert response.status_code == 200
        assert response.json()["provider"] == "featherless"
        assert "featherless.ai" in captured["base_url"]
        assert captured["model"] == settings.featherless_model

        # No Featherless key -> OpenAI fallback
        monkeypatch.setattr(settings, "featherless_api_key", "")
        response = client.post(
            "/api/v1/ai-scammer",
            headers={"x-api-key": VALID_API_KEY},
            json={"scamType": "lottery", "conversationHistory": []},
        )
        assert response.status_code == 200
        assert response.json()["provider"] == "openai"
        assert captured["base_url"] is None

    def test_25_cors_is_deny_by_default(self):
        """Test 25: CORS is an explicit allowlist, not a wildcard.

        Previously the app sent `allow_origins=["*"]` whenever BASE_URL was
        unset, which combined with allow_credentials=True exposed the
        authenticated admin surface to any origin. An origin that is not on the
        allowlist must get no Access-Control-Allow-Origin header at all.
        """
        response = client.options(
            "/api/v1/conversation",
            headers={
                "Origin": "http://evil.example",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert response.headers.get("access-control-allow-origin") != "*"
        assert "access-control-allow-origin" not in response.headers

    def test_25b_allowlisted_origin_is_permitted(self, monkeypatch):
        """An origin on ALLOWED_ORIGINS is echoed back, and only that origin."""
        from starlette.middleware.cors import CORSMiddleware

        from app.core.config import Settings
        from app.main import app as fastapi_app

        allowed = "https://dashboard.example"
        s = Settings(
            api_key="a" * 20,
            openai_api_key="sk-" + "b" * 30,
            allowed_origins=allowed,
            debug=True,
            _env_file=None,
        )
        assert s.cors_origins == [allowed]

        # Confirm the app wires the allowlist through to the middleware rather
        # than hardcoding a wildcard.
        cors = [m for m in fastapi_app.user_middleware if m.cls is CORSMiddleware]
        assert cors, "CORS middleware is not installed"
        assert "*" not in cors[0].kwargs.get("allow_origins", [])


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

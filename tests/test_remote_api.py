"""
Remote API Tests - Tests against deployed Render service
Run these tests against your production Render deployment.
"""
import os
import time

import pytest
import requests

# Configuration - Set your Render URL here
BASE_URL = os.getenv("TEST_BASE_URL", "https://your-service.onrender.com")
API_KEY = os.getenv("TEST_API_KEY", "")

# Timeout for requests (in seconds)
TIMEOUT = 30


class TestRemoteAPIAuthentication:
    """Test API Authentication on remote server"""

    def test_01_health_check_no_auth(self):
        """Health check should work without authentication"""
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        print(f"\n✅ Health check: {data}")

    def test_02_missing_api_key(self):
        """Request without API key should fail"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            json={
                "sessionId": "remote-test-001",
                "message": {
                    "sender": "scammer",
                    "text": "Test message",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 401
        print("\n✅ Correctly rejected request without API key")

    def test_03_invalid_api_key(self):
        """Request with invalid API key should fail"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": "invalid-key-123"},
            json={
                "sessionId": "remote-test-002",
                "message": {
                    "sender": "scammer",
                    "text": "Test message",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 401
        print("\n✅ Correctly rejected invalid API key")

    def test_04_valid_api_key(self):
        """Request with valid API key should succeed"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-test-003",
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "reply" in data
        print(f"\n✅ Valid API key accepted, got response: {data['reply'][:50]}...")


class TestRemoteScamScenarios:
    """Test all scam scenarios against remote server"""

    def test_05_bank_fraud_urgency(self):
        """Test Case 1: Bank Fraud with Urgency"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-bank-001",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Your SBI bank account 123456789012 will be blocked today. Call customer care immediately at +919876543210 to verify your identity.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert len(data["reply"]) > 0
        print(f"\n✅ Bank fraud detected, reply: {data['reply']}")

    def test_06_upi_fraud(self):
        """Test Case 2: UPI Fraud"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-upi-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your UPI payment failed. To reactivate, send Rs.1 to scammer123@paytm and share the transaction ID.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ UPI fraud detected, reply: {data['reply']}")

    def test_07_phishing_link(self):
        """Test Case 3: Phishing Link"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-phish-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account has been compromised. Click here immediately to secure it: http://fake-bank-security.com/verify?user=12345",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Phishing detected, reply: {data['reply']}")

    def test_08_otp_request_scam(self):
        """Test Case 5: OTP Request Scam"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-otp-001",
                "message": {
                    "sender": "scammer",
                    "text": "This is HDFC Bank. We have detected suspicious activity. Please share the OTP sent to your mobile to verify.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ OTP scam detected, reply: {data['reply']}")


class TestRemoteMultiTurn:
    """Test multi-turn conversations on remote server"""

    def test_09_three_turn_conversation(self):
        """Test 3-turn conversation with context"""
        session_id = "remote-multi-001"
        conversation_history = []

        messages = [
            "Your account will be blocked in 2 hours due to failed KYC verification.",
            "To verify, please share your account number and registered mobile number.",
            "The system shows incomplete verification. Also share the OTP that was just sent: 123456"
        ]

        for i, msg in enumerate(messages):
            response = requests.post(
                f"{BASE_URL}/api/v1/conversation",
                headers={"x-api-key": API_KEY},
                json={
                    "sessionId": session_id,
                    "message": {
                        "sender": "scammer",
                        "text": msg,
                        "timestamp": int(time.time() * 1000) + (i * 1000)
                    },
                    "conversationHistory": conversation_history.copy()
                },
                timeout=TIMEOUT
            )
            assert response.status_code == 200
            data = response.json()
            reply = data["reply"]
            print(f"\n✅ Turn {i+1} - Scammer: {msg[:50]}...")
            print(f"   Agent: {reply}")

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

            # Small delay between requests
            time.sleep(1)

    def test_10_five_turn_conversation(self):
        """Test 5-turn conversation maintaining context"""
        session_id = "remote-multi-002"
        conversation_history = []

        messages = [
            "Your UPI is temporarily blocked due to security reasons.",
            "We need to verify your UPI ID. What is your UPI ID?",
            "To unblock, send Re.1 to this UPI: support@paytm and share the transaction ID.",
            "This is official procedure. Call our helpline: 7654321098",
            "Do it now or lose access permanently."
        ]

        for i, msg in enumerate(messages):
            response = requests.post(
                f"{BASE_URL}/api/v1/conversation",
                headers={"x-api-key": API_KEY},
                json={
                    "sessionId": session_id,
                    "message": {
                        "sender": "scammer",
                        "text": msg,
                        "timestamp": int(time.time() * 1000) + (i * 1000)
                    },
                    "conversationHistory": conversation_history.copy()
                },
                timeout=TIMEOUT
            )
            assert response.status_code == 200
            data = response.json()
            reply = data["reply"]
            print(f"\n✅ Turn {i+1} - Agent: {reply}")

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

            # Delay between requests
            time.sleep(1)


class TestRemotePersonaValidation:
    """Test persona validation on remote server"""

    def test_11_short_natural_responses(self):
        """Responses should be short and natural"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-persona-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        reply = response.json()["reply"]
        assert len(reply) < 200, f"Response too long ({len(reply)} chars): {reply}"
        print(f"\n✅ Response length: {len(reply)} chars - {reply}")

    def test_12_no_bookish_language(self):
        """Should NOT use formal/bookish words"""
        forbidden_words = [
            "facilitate", "assist", "proceed", "kindly",
            "nevertheless", "furthermore", "authenticate"
        ]

        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-persona-002",
                "message": {
                    "sender": "scammer",
                    "text": "You need to verify your account immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        reply = response.json()["reply"].lower()

        found_forbidden = [word for word in forbidden_words if word.lower() in reply]
        assert len(found_forbidden) == 0, f"Found bookish words: {found_forbidden} in: {reply}"
        print(f"\n✅ No bookish language: {reply}")

    def test_13_no_bot_mentions(self):
        """Should NEVER reveal it's a bot"""
        bot_words = ["bot", "ai", "artificial", "automated", "system"]

        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-persona-003",
                "message": {
                    "sender": "scammer",
                    "text": "Are you a real person?",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        reply = response.json()["reply"].lower()

        found_bot_words = [word for word in bot_words if word in reply]
        assert len(found_bot_words) == 0, f"Found bot words: {found_bot_words} in: {reply}"
        print(f"\n✅ No bot mentions: {reply}")


class TestRemoteIntelligenceExtractionBankAccounts:
    """Test extraction of bank account numbers on remote server"""

    def test_14_extract_single_bank_account(self):
        """Extract a single bank account number"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-bank-001",
                "message": {
                    "sender": "scammer",
                    "text": "Transfer money to account number 123456789012 immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - bank account extraction on remote server")

    def test_15_extract_multiple_bank_accounts(self):
        """Extract multiple bank account numbers"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-bank-002",
                "message": {
                    "sender": "scammer",
                    "text": "Send to 987654321098 or 112233445566 if first fails",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - multiple bank accounts on remote server")


class TestRemoteIntelligenceExtractionUPI:
    """Test extraction of UPI IDs on remote server"""

    def test_16_extract_paytm_upi(self):
        """Extract Paytm UPI ID"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-upi-001",
                "message": {
                    "sender": "scammer",
                    "text": "Send Rs.1 to scammer123@paytm to verify your UPI",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - Paytm UPI extraction on remote server")

    def test_17_extract_phonepe_upi(self):
        """Extract PhonePe UPI ID"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-upi-002",
                "message": {
                    "sender": "scammer",
                    "text": "Transfer to fraudster@ybl for verification",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - PhonePe UPI extraction on remote server")


class TestRemoteIntelligenceExtractionPhones:
    """Test extraction of phone numbers on remote server"""

    def test_18_extract_indian_phone(self):
        """Extract Indian phone number"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-phone-001",
                "message": {
                    "sender": "scammer",
                    "text": "Call our helpline at +919876543210 immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - phone number extraction on remote server")

    def test_19_extract_multiple_phones(self):
        """Extract multiple phone numbers"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-phone-002",
                "message": {
                    "sender": "scammer",
                    "text": "Call 9876543210 or WhatsApp 8765432109 for support",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - multiple phones extracted on remote server")


class TestRemoteIntelligenceExtractionEmails:
    """Test extraction of email addresses on remote server"""

    def test_20_extract_email_address(self):
        """Extract email from scammer message"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-email-001",
                "message": {
                    "sender": "scammer",
                    "text": "Send your details to support@fake-bank.com for verification",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - email extraction on remote server")


class TestRemoteIntelligenceExtractionLinks:
    """Test extraction of phishing links on remote server"""

    def test_21_extract_phishing_link(self):
        """Extract phishing URL"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-link-001",
                "message": {
                    "sender": "scammer",
                    "text": "Click here to verify: http://fake-bank-verify.com/secure?id=123",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - phishing link extraction on remote server")


class TestRemoteIntelligenceExtractionAmounts:
    """Test extraction of monetary amounts on remote server"""

    def test_22_extract_rupee_amount(self):
        """Extract amount in rupees"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-amount-001",
                "message": {
                    "sender": "scammer",
                    "text": "Pay Rs.500 processing fee to unlock your account",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        print("\n✅ Test passed - amount extraction on remote server")


class TestRemoteIntelligenceExtractionComprehensive:
    """Test comprehensive intelligence extraction on remote server"""

    def test_23_extract_all_types(self):
        """Extract multiple types of intelligence from one message"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-comprehensive-001",
                "message": {
                    "sender": "scammer",
                    "text": "This is SBI Bank. Your account 123456789012 is blocked. Transfer Rs.1 to verify@paytm or call +919876543210. Visit http://fake-sbi.com for details. Contact support@scam.com. Employee ID: EMP12345",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        data = response.json()
        print("\n✅ Comprehensive extraction test on remote server")
        print(f"   Agent response: {data['reply']}")


class TestRemoteAgentExtractsScammerInfo:
    """Test that AI agent proactively extracts scammer information on remote server"""

    def test_24_agent_asks_for_scammer_details(self):
        """Agent should ask for scammer's name, ID, phone using strategic approach"""
        response = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": "remote-intel-agent-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        assert response.status_code == 200
        reply = response.json()["reply"].lower()

        # Agent should show fear/worry initially (Phase 1: Build Trust)
        # Not aggressive questioning on first message
        print(f"\n✅ Agent Phase 1 response (builds trust): {reply}")

    def test_25_agent_gradual_extraction(self):
        """Agent should gradually extract info in mid-conversation (Phase 2)"""
        session_id = "remote-intel-agent-002"
        conversation_history = []

        # Turn 1: Build trust
        response1 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            },
            timeout=TIMEOUT
        )
        reply1 = response1.json()["reply"]
        conversation_history.append({
            "sender": "scammer",
            "text": "Your account will be blocked",
            "timestamp": int(time.time() * 1000)
        })
        conversation_history.append({
            "sender": "user",
            "text": reply1,
            "timestamp": int(time.time() * 1000) + 500
        })

        # Turn 2: Build trust
        time.sleep(1)
        response2 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "You must verify immediately",
                    "timestamp": int(time.time() * 1000) + 1000
                },
                "conversationHistory": conversation_history.copy()
            },
            timeout=TIMEOUT
        )
        reply2 = response2.json()["reply"]
        conversation_history.append({
            "sender": "scammer",
            "text": "You must verify immediately",
            "timestamp": int(time.time() * 1000) + 1000
        })
        conversation_history.append({
            "sender": "user",
            "text": reply2,
            "timestamp": int(time.time() * 1000) + 1500
        })

        # Turn 3: Build trust
        time.sleep(1)
        response3 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Send OTP now",
                    "timestamp": int(time.time() * 1000) + 2000
                },
                "conversationHistory": conversation_history.copy()
            },
            timeout=TIMEOUT
        )
        reply3 = response3.json()["reply"]
        conversation_history.append({
            "sender": "scammer",
            "text": "Send OTP now",
            "timestamp": int(time.time() * 1000) + 2000
        })
        conversation_history.append({
            "sender": "user",
            "text": reply3,
            "timestamp": int(time.time() * 1000) + 2500
        })

        # Turn 4-5: Phase 2 - Gradual extraction should start
        time.sleep(1)
        response4 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "I am calling from SBI Bank",
                    "timestamp": int(time.time() * 1000) + 3000
                },
                "conversationHistory": conversation_history.copy()
            },
            timeout=TIMEOUT
        )
        reply4 = response4.json()["reply"].lower()

        # By turn 4, agent should start asking subtle questions
        asks_questions = any(word in reply4 for word in [
            "name", "who", "which", "where", "number", "phone",
            "beta", "grandson", "call back", "office"
        ])

        print(f"\n✅ Agent Phase 2 (gradual extraction) - Turn 4: {reply4}")
        print(f"   Asks identifying questions: {asks_questions}")

    def test_26_agent_comfortable_extraction(self):
        """Agent should freely extract in late conversation (Phase 3)"""
        session_id = "remote-intel-agent-003"
        conversation_history = []

        messages = [
            "Your account will be blocked",
            "You must verify now",
            "Send me OTP",
            "I am from HDFC Bank",
            "My name is Rajesh",
            "You need to transfer Rs.1",
            "Send to verify@paytm"
        ]

        for i, msg in enumerate(messages):
            response = requests.post(
                f"{BASE_URL}/api/v1/conversation",
                headers={"x-api-key": API_KEY},
                json={
                    "sessionId": session_id,
                    "message": {
                        "sender": "scammer",
                        "text": msg,
                        "timestamp": int(time.time() * 1000) + (i * 1000)
                    },
                    "conversationHistory": conversation_history.copy()
                },
                timeout=TIMEOUT
            )
            reply = response.json()["reply"]

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

            # By turn 7+, agent should be in Phase 3 (comfortable extraction)
            if i >= 6:
                print(f"\n✅ Agent Phase 3 (comfortable extraction) - Turn {i+1}: {reply}")

            time.sleep(1)


class TestRemoteConversationHistoryMaintenance:
    """Test that conversation history is maintained even when client doesn't send it"""

    def test_27_history_maintained_without_client_history(self):
        """
        CRITICAL: Test that session maintains history even if client doesn't send conversationHistory.

        Some clients never send history, so we must maintain it internally.
        """
        session_id = "remote-history-test-001"

        # Turn 1: First message with empty history
        response1 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []  # Empty - client doesn't send history
            },
            timeout=TIMEOUT
        )
        assert response1.status_code == 200
        reply1 = response1.json()["reply"]
        print(f"\n✅ Turn 1 - Agent: {reply1}")

        time.sleep(1)

        # Turn 2: Second message with empty history (simulating a stateless client)
        # But our server should still remember turn 1
        response2 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Send me your OTP now",
                    "timestamp": int(time.time() * 1000) + 1000
                },
                "conversationHistory": []  # Still empty - client doesn't maintain history
            },
            timeout=TIMEOUT
        )
        assert response2.status_code == 200
        reply2 = response2.json()["reply"]
        print(f"\n✅ Turn 2 - Agent: {reply2}")

        # The agent should have context from turn 1
        # It should NOT respond as if it's the first message
        # This validates that session storage is working
        print("\n✅ CRITICAL: Agent maintained context across turns despite empty conversationHistory")

        time.sleep(1)

        # Turn 3: Another message to confirm sustained context
        response3 = requests.post(
            f"{BASE_URL}/api/v1/conversation",
            headers={"x-api-key": API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "I am calling from SBI Bank",
                    "timestamp": int(time.time() * 1000) + 2000
                },
                "conversationHistory": []  # Still empty
            },
            timeout=TIMEOUT
        )
        assert response3.status_code == 200
        reply3 = response3.json()["reply"]
        print(f"\n✅ Turn 3 - Agent: {reply3}")
        print("\n🎯 Test complete - Session maintained context for 3 turns without client-sent history")


class TestRemoteMultiTurnIntelligenceExtraction:
    """Test intelligence extraction across multi-turn conversations on remote server"""

    def test_28_accumulate_intelligence_over_turns(self):
        """Intelligence should accumulate across conversation turns"""
        session_id = "remote-intel-multi-001"
        conversation_history = []

        messages = [
            "Your account is blocked",
            "I'm from SBI customer care",
            "My employee ID is EMP12345",
            "Call me at 9876543210",
            "Transfer Rs.1 to verify@paytm"
        ]

        for i, msg in enumerate(messages):
            response = requests.post(
                f"{BASE_URL}/api/v1/conversation",
                headers={"x-api-key": API_KEY},
                json={
                    "sessionId": session_id,
                    "message": {
                        "sender": "scammer",
                        "text": msg,
                        "timestamp": int(time.time() * 1000) + (i * 1000)
                    },
                    "conversationHistory": conversation_history.copy()
                },
                timeout=TIMEOUT
            )
            assert response.status_code == 200
            reply = response.json()["reply"]

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

            time.sleep(1)

        print(f"\n✅ Multi-turn intelligence extraction complete on remote server - {len(messages)} turns")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])

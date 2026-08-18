"""
Comprehensive tests for intelligence extraction.
Tests that the system extracts scammer information effectively.
"""
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)
VALID_API_KEY = settings.api_key


class TestIntelligenceExtractionBankAccounts:
    """Test extraction of bank account numbers"""

    def test_extract_single_bank_account(self):
        """Extract a single bank account number"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-bank-001",
                "message": {
                    "sender": "scammer",
                    "text": "Transfer money to account number 123456789012 immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - bank account extraction")

    def test_extract_multiple_bank_accounts(self):
        """Extract multiple bank account numbers"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-bank-002",
                "message": {
                    "sender": "scammer",
                    "text": "Send to 987654321098 or 112233445566 if first fails",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - multiple bank accounts")


class TestIntelligenceExtractionUPI:
    """Test extraction of UPI IDs"""

    def test_extract_paytm_upi(self):
        """Extract Paytm UPI ID"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-upi-001",
                "message": {
                    "sender": "scammer",
                    "text": "Send Rs.1 to scammer123@paytm to verify your UPI",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - Paytm UPI extraction")

    def test_extract_phonepe_upi(self):
        """Extract PhonePe UPI ID"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-upi-002",
                "message": {
                    "sender": "scammer",
                    "text": "Transfer to fraudster@ybl for verification",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - PhonePe UPI extraction")


class TestIntelligenceExtractionPhones:
    """Test extraction of phone numbers"""

    def test_extract_indian_phone(self):
        """Extract Indian phone number"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-phone-001",
                "message": {
                    "sender": "scammer",
                    "text": "Call our helpline at +919876543210 immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - phone number extraction")

    def test_extract_multiple_phones(self):
        """Extract multiple phone numbers"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-phone-002",
                "message": {
                    "sender": "scammer",
                    "text": "Call 9876543210 or WhatsApp 8765432109 for support",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - multiple phones extracted")


class TestIntelligenceExtractionEmails:
    """Test extraction of email addresses"""

    def test_extract_email_address(self):
        """Extract email from scammer message"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-email-001",
                "message": {
                    "sender": "scammer",
                    "text": "Send your details to support@fake-bank.com for verification",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - email extraction")


class TestIntelligenceExtractionLinks:
    """Test extraction of phishing links"""

    def test_extract_phishing_link(self):
        """Extract phishing URL"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-link-001",
                "message": {
                    "sender": "scammer",
                    "text": "Click here to verify: http://fake-bank-verify.com/secure?id=123",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - phishing link extraction")

    def test_extract_schemeless_links(self):
        """Scam SMS rarely includes http:// — bare domains must still be caught"""
        from app.services.intelligence_extractor import IntelligenceExtractor

        extractor = IntelligenceExtractor()

        found = {
            "Click [sbi-kyc-verify.in/update] now":  "sbi-kyc-verify.in/update",
            "short link bit.ly/3xYz9 here":          "bit.ly/3xYz9",
            "go to www.fake-bank.in":                "www.fake-bank.in",
            "visit https://evil.com/pay please":     "https://evil.com/pay",
        }
        for text, expected in found.items():
            assert expected in extractor._extract_urls(text), f"missed link in: {text}"

        # Must not fire on emails, UPI handles, amounts, or account numbers
        for text in [
            "mail me at sbi.helpdesk.official@gmail.com",
            "Send to upi id helpdesk.sbi@ybl now",
            "Please pay Rs. 25,000 today. Thanks.",
            "My account is 40291837650 and IFSC SBIN0001234",
        ]:
            assert extractor._extract_urls(text) == [], f"false positive in: {text}"


class TestIntelligenceExtractionAmounts:
    """Test extraction of monetary amounts"""

    def test_extract_rupee_amount(self):
        """Extract amount in rupees"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-amount-001",
                "message": {
                    "sender": "scammer",
                    "text": "Pay Rs.500 processing fee to unlock your account",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        print("\n✅ Test passed - amount extraction")


class TestIntelligenceExtractionComprehensive:
    """Test comprehensive intelligence extraction from complex scenarios"""

    def test_extract_all_types(self):
        """Extract multiple types of intelligence from one message"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-comprehensive-001",
                "message": {
                    "sender": "scammer",
                    "text": "This is SBI Bank. Your account 123456789012 is blocked. Transfer Rs.1 to verify@paytm or call +919876543210. Visit http://fake-sbi.com for details. Contact support@scam.com. Employee ID: EMP12345",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        data = response.json()
        print("\n✅ Comprehensive extraction test")
        print(f"   Agent response: {data['reply']}")


class TestAgentExtractsScammerInfo:
    """Test that AI agent proactively extracts scammer information"""

    def test_agent_asks_for_scammer_details(self):
        """Agent should ask for scammer's name, ID, phone"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-agent-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked immediately",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        reply = response.json()["reply"].lower()

        # Agent should ask identifying questions
        asks_questions = any(word in reply for word in [
            "name", "who", "employee", "id", "number", "phone",
            "which", "where", "bank", "company"
        ])

        assert asks_questions, f"Agent should ask for scammer details, but replied: {reply}"
        print(f"\n✅ Agent asks for scammer info: {reply}")

    def test_agent_requests_callback_number(self):
        """Agent should request scammer's callback number"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "intel-agent-002",
                "message": {
                    "sender": "scammer",
                    "text": "This is urgent. You must act now",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response.status_code == 200
        reply = response.json()["reply"].lower()
        print(f"\n✅ Agent reply: {reply}")

    def test_agent_repeats_scammer_info(self):
        """Agent should repeat back scammer's information to confirm"""
        session_id = "intel-agent-003"

        # First message
        response1 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "I am calling from HDFC Bank",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        reply1 = response1.json()["reply"]

        # Second message with phone number
        response2 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "My number is 9876543210",
                    "timestamp": int(time.time() * 1000) + 1000
                },
                "conversationHistory": [
                    {
                        "sender": "scammer",
                        "text": "I am calling from HDFC Bank",
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
        reply2 = response2.json()["reply"]
        print(f"\n✅ Agent response to phone: {reply2}")


class TestMultiTurnIntelligenceExtraction:
    """Test intelligence extraction across multi-turn conversations"""

    def test_accumulate_intelligence_over_turns(self):
        """Intelligence should accumulate across conversation turns"""
        session_id = "intel-multi-001"
        conversation_history = []

        messages = [
            "Your account is blocked",
            "I'm from SBI customer care",
            "My employee ID is EMP12345",
            "Call me at 9876543210",
            "Transfer Rs.1 to verify@paytm"
        ]

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

        print(f"\n✅ Multi-turn extraction complete - {len(messages)} turns")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])

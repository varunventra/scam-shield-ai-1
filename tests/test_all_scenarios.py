"""
Automated test suite covering ALL scenarios from TEST_EXAMPLES.md
This runs all test cases automatically without Postman.
"""
import time

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)
VALID_API_KEY = settings.api_key


class TestAllScenarios:
    """Tests for all scam scenarios from TEST_EXAMPLES.md"""

    def test_scenario_01_bank_fraud_urgency(self):
        """Test Case 1: Bank Fraud with Urgency"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-bank-fraud-001",
                "message": {
                    "sender": "scammer",
                    "text": "URGENT: Your SBI bank account 123456789012 will be blocked today. Call customer care immediately at +919876543210 to verify your identity.",
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
        assert len(data["reply"]) > 0
        # Agent should respond with concern/questions
        print(f"\n✅ Test 1 - Agent response: {data['reply']}")

    def test_scenario_02_upi_fraud(self):
        """Test Case 2: UPI Fraud"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-upi-fraud-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your UPI payment failed. To reactivate, send Rs.1 to scammer123@paytm and share the transaction ID.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "WhatsApp",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Test 2 - Agent response: {data['reply']}")

    def test_scenario_03_phishing_link(self):
        """Test Case 3: Phishing Link"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-phishing-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your account has been compromised. Click here immediately to secure it: http://fake-bank-security.com/verify?user=12345&session=abc",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "Email",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Test 3 - Agent response: {data['reply']}")

    def test_scenario_04_lottery_prize_scam(self):
        """Test Case 4: Lottery/Prize Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-lottery-001",
                "message": {
                    "sender": "scammer",
                    "text": "Congratulations Rahul! You have won 50 Lakh rupees in the KBC Lucky Draw 2024. To claim your prize, share your bank account details and PAN card number. Contact: winner@kbc-prize.com or call 8765432109.",
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
        print(f"\n✅ Test 4 - Agent response: {data['reply']}")

    def test_scenario_05_otp_request_scam(self):
        """Test Case 5: OTP Request Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-otp-001",
                "message": {
                    "sender": "scammer",
                    "text": "This is HDFC Bank. We have detected suspicious activity on your account. An OTP has been sent to your mobile. Please share it to verify your identity and prevent account suspension.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "Call",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Test 5 - Agent response: {data['reply']}")

    def test_scenario_06_kyc_update_scam(self):
        """Test Case 6: KYC Update Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-kyc-001",
                "message": {
                    "sender": "scammer",
                    "text": "Dear customer, your KYC will expire today. Update immediately at http://bank-kyc-update.in or your account will be blocked. Provide: PAN card, Aadhaar number, and bank account details.",
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
        print(f"\n✅ Test 6 - Agent response: {data['reply']}")

    def test_scenario_07_investment_scam(self):
        """Test Case 7: Investment Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-investment-001",
                "message": {
                    "sender": "scammer",
                    "text": "Limited time offer! Invest Rs.10,000 today and get Rs.50,000 in 30 days. Guaranteed returns. Transfer to account: 998877665544 or UPI: invest@guaranteed.com. WhatsApp: +918888777766",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "WhatsApp",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Test 7 - Agent response: {data['reply']}")

    def test_scenario_08_fake_delivery_scam(self):
        """Test Case 8: Fake Delivery Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-delivery-001",
                "message": {
                    "sender": "scammer",
                    "text": "Your courier package is held at customs. Pay Rs.500 clearance fee to: delivery@courier-india.com or account 556677889900. Track at: http://fake-courier-track.com/track?id=ABC123",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "Email",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Test 8 - Agent response: {data['reply']}")

    def test_scenario_09_job_offer_scam(self):
        """Test Case 9: Job Offer Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-job-001",
                "message": {
                    "sender": "scammer",
                    "text": "Congratulations! You are selected for Google Software Engineer position with 25 LPA salary. Pay Rs.5000 registration fee to: hr@google-recruitment.co.in or UPI: googlehr@paytm. Contact HR: +917777888899",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": [],
                "metadata": {
                    "channel": "Email",
                    "language": "English",
                    "locale": "IN"
                }
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        print(f"\n✅ Test 9 - Agent response: {data['reply']}")

    def test_scenario_10_tax_refund_scam(self):
        """Test Case 10: Tax Refund Scam"""
        response = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": "test-tax-001",
                "message": {
                    "sender": "scammer",
                    "text": "Income Tax Department: You are eligible for Rs.35,000 tax refund. Click to claim: http://incometax-refund-india.com/claim?pan=ABCD1234E. Provide your bank details, PAN, and Aadhaar to process refund.",
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
        print(f"\n✅ Test 10 - Agent response: {data['reply']}")


class TestMultiTurnScenarios:
    """Multi-turn conversation tests from TEST_EXAMPLES.md"""

    def test_scenario_11_three_turn_bank_fraud(self):
        """Example A: 3-Turn Bank Fraud Conversation"""
        session_id = "multi-turn-bank-001"
        conversation_history = []

        # Turn 1
        response1 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "Your account will be blocked in 2 hours due to failed KYC verification.",
                    "timestamp": int(time.time() * 1000)
                },
                "conversationHistory": []
            }
        )
        assert response1.status_code == 200
        reply1 = response1.json()["reply"]
        print(f"\n✅ Turn 1 - Agent: {reply1}")

        # Update history
        conversation_history.append({
            "sender": "scammer",
            "text": "Your account will be blocked in 2 hours due to failed KYC verification.",
            "timestamp": int(time.time() * 1000)
        })
        conversation_history.append({
            "sender": "user",
            "text": reply1,
            "timestamp": int(time.time() * 1000) + 500
        })

        # Turn 2
        response2 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "To verify, please share your account number and registered mobile number.",
                    "timestamp": int(time.time() * 1000) + 1000
                },
                "conversationHistory": conversation_history.copy()
            }
        )
        assert response2.status_code == 200
        reply2 = response2.json()["reply"]
        print(f"✅ Turn 2 - Agent: {reply2}")

        # Update history
        conversation_history.append({
            "sender": "scammer",
            "text": "To verify, please share your account number and registered mobile number.",
            "timestamp": int(time.time() * 1000) + 1000
        })
        conversation_history.append({
            "sender": "user",
            "text": reply2,
            "timestamp": int(time.time() * 1000) + 1500
        })

        # Turn 3
        response3 = client.post(
            "/api/v1/conversation",
            headers={"x-api-key": VALID_API_KEY},
            json={
                "sessionId": session_id,
                "message": {
                    "sender": "scammer",
                    "text": "The system shows incomplete verification. Also share the OTP that was just sent to your mobile: 123456",
                    "timestamp": int(time.time() * 1000) + 2000
                },
                "conversationHistory": conversation_history.copy()
            }
        )
        assert response3.status_code == 200
        reply3 = response3.json()["reply"]
        print(f"✅ Turn 3 - Agent: {reply3}")

    def test_scenario_12_five_turn_upi_scam(self):
        """Example B: 5-Turn UPI Scam Conversation"""
        session_id = "multi-turn-upi-001"
        conversation_history = []

        messages = [
            "Your UPI is temporarily blocked due to security reasons.",
            "We need to verify your UPI ID. What is your UPI ID?",
            "To unblock, send Re.1 to this UPI: support@paytm and share the transaction ID.",
            "This is official procedure. Your account will remain blocked if you do not comply. Call our helpline: 7654321098",
            "It is just for verification. You will get your money back instantly. Do it now or lose access permanently."
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

    def test_scenario_13_ten_turn_extended_conversation(self):
        """10-Turn Extended Conversation - Maximum Limit Test"""
        session_id = "multi-turn-max-001"
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
            print(f"\n✅ Turn {i+1}/10 - Agent responded")

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


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])

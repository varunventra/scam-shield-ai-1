"""
ScamShield Live Demo - Automated Conversation Script
=====================================================
Sends the demo scam scenario to the API and displays responses.

Usage:
    python demo_conversation.py
    python demo_conversation.py --local          # Use localhost instead of Render
    python demo_conversation.py --fast            # No pauses between messages
    python demo_conversation.py --session myid    # Custom session ID
"""

import argparse
import os
import sys
import time
import uuid

import requests
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration — reads from .env (never hardcoded)
# ---------------------------------------------------------------------------

RENDER_URL = "https://scambot-honeypot.onrender.com/api/v1/conversation"
LOCAL_URL = "http://localhost:8000/api/v1/conversation"
API_KEY = os.getenv("API_KEY", "")
ADMIN_KEY = os.getenv("ADMIN_API_KEY", "")

# ---------------------------------------------------------------------------
# Demo Scam Messages (SBI Bank Impersonation)
# ---------------------------------------------------------------------------

SCAM_MESSAGES = [
    {
        "label": "1 - Ambiguous Opening",
        "text": (
            "Hello, this is regarding your bank account. We noticed some "
            "activity that needs your attention. Can you please confirm your name?"
        ),
    },
    {
        "label": "2 - Authority Claim + Pressure",
        "text": (
            "Madam, I am Vikram Sharma, Senior Manager from SBI Main Branch, "
            "Hyderabad. Your account ending in 4532 has been flagged for "
            "suspicious transaction of Rs.48,000. We need to verify your "
            "identity immediately or your account will be frozen within 2 hours."
        ),
    },
    {
        "label": "3 - Phone Number + OTP Request",
        "text": (
            "For verification, I am sending an OTP to your registered mobile "
            "number. Please share the 6-digit code when you receive it. My "
            "direct number is 9876543210 if the call drops. This is urgent madam."
        ),
    },
    {
        "label": "4 - Language Switch to Hindi",
        "text": (
            "Madam jaldi kijiye, aapka account block ho jayega. OTP batayiye "
            "turant. Yeh bahut zaroori hai."
        ),
    },
    {
        "label": "5 - UPI Payment Request",
        "text": (
            "Madam OTP nahi aa raha toh koi baat nahi. Account verify karne "
            "ke liye Rs.10 ka test payment kijiye is UPI pe: vikram.sbi@ybl "
            "-- yeh official SBI verification process hai."
        ),
    },
    {
        "label": "6 - Bank Account + Phishing Link",
        "text": (
            "Haan madam bilkul safe hai. Mera employee ID hai SBI-VK-4821. "
            "Agar UPI se nahi hota toh yeh account mein transfer karein: "
            "34927581046, IFSC: SBIN0001234. Ya phir is link pe verify "
            "karein: https://sbi-secure-verify.com/auth"
        ),
    },
    {
        "label": "7 - Pressure Escalation",
        "text": "Jaldi kijiye madam, time khatam ho raha hai.",
    },
    {
        "label": "8 - Threat",
        "text": (
            "Madam aap sun rahi hain? Account freeze ho jayega 30 minutes mein."
        ),
    },
    {
        "label": "9 - Final Warning",
        "text": (
            "Last warning madam, iske baad main kuch nahi kar paunga aapke liye."
        ),
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ts():
    """Current epoch in milliseconds."""
    return int(time.time() * 1000)


def separator(char="-", width=70):
    print(char * width)


def send_message(url, session_id, text, history):
    """Send a single scammer message and return the AI reply."""
    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": text,
            "timestamp": ts(),
        },
        "conversationHistory": history,
        "metadata": {
            "channel": "WhatsApp",
            "language": "English",
            "locale": "IN",
        },
    }

    headers = {
        "Content-Type": "application/json",
        "x-api-key": API_KEY,
    }

    resp = requests.post(url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_demo(url, session_id, fast=False, count=None):
    print()
    separator("=")
    print("  SCAMSHIELD LIVE DEMO")
    print(f"  Session : {session_id}")
    print(f"  Endpoint: {url}")
    separator("=")
    print()

    # Warm-up ping
    print("[*] Warming up API...")
    try:
        requests.get(url.replace("/conversation", "/../health"), timeout=10)
    except Exception:
        pass
    print("[*] Ready.\n")

    history = []
    messages = SCAM_MESSAGES[:count] if count else SCAM_MESSAGES

    for i, msg in enumerate(messages):
        # --- Scammer message ---
        separator()
        print(f"\n  SCAMMER  [{msg['label']}]")
        separator()
        print(f"\n  {msg['text']}\n")

        if not fast:
            # Brief pause so the audience can read
            time.sleep(1.5)

        try:
            result = send_message(url, session_id, msg["text"], history)
        except requests.exceptions.HTTPError as e:
            print(f"\n  [ERROR] HTTP {e.response.status_code}: {e.response.text}")
            sys.exit(1)
        except requests.exceptions.ConnectionError:
            print("\n  [ERROR] Cannot connect to API. Is the server running?")
            sys.exit(1)
        except requests.exceptions.Timeout:
            print("\n  [ERROR] Request timed out.")
            sys.exit(1)

        reply = result.get("reply", "(no reply)")

        # --- AI response ---
        print(f"  AI AGENT:")
        separator()
        print(f"\n  {reply}\n")

        # --- Update history for next request ---
        history.append({
            "sender": "scammer",
            "text": msg["text"],
            "timestamp": ts(),
        })
        history.append({
            "sender": "user",
            "text": reply,
            "timestamp": ts(),
        })

        if not fast:
            time.sleep(1)

    # --- Summary ---
    print()
    separator("=")
    print("  DEMO COMPLETE")
    separator("=")
    print(f"\n  Session ID : {session_id}")
    print(f"  Messages   : {len(messages)}")
    print(f"\n  Check MongoDB Atlas for live session data.")
    print(f"\n  PDF Report URL (send x-admin-key header):")
    base = url.replace("/conversation", "")
    print(f"  {base}/admin/report/{session_id}")
    separator("=")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ScamShield Live Demo")
    parser.add_argument(
        "--local", action="store_true",
        help="Use localhost:8000 instead of Render",
    )
    parser.add_argument(
        "--fast", action="store_true",
        help="No pauses between messages",
    )
    parser.add_argument(
        "--session", type=str, default=None,
        help="Custom session ID (default: auto-generated)",
    )
    parser.add_argument(
        "--count", type=int, default=None,
        help="Number of messages to send (default: all 9)",
    )
    args = parser.parse_args()

    if not API_KEY:
        print("\n[ERROR] API_KEY not found. Make sure your .env file exists with API_KEY set.")
        sys.exit(1)
    if not ADMIN_KEY:
        print("\n[WARNING] ADMIN_API_KEY not found in .env. PDF URL will be incomplete.")

    api_url = LOCAL_URL if args.local else RENDER_URL
    sid = args.session or f"demo-{uuid.uuid4().hex[:8]}"

    run_demo(api_url, sid, fast=args.fast, count=args.count)

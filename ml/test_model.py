"""
CYBER-FORENSIC AGENT: ML Scam Detection — Live Demo & Test Suite

Usage:
    python -m ml.test_model                         # Run full test suite
    python -m ml.test_model --text "your message"   # Test a single message
"""
import argparse
import joblib
import os
import sys

MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "scam_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "vectorizer.pkl")


def load_model():
    """Load trained model and vectorizer from disk."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(VECTORIZER_PATH):
        print("ERROR: Model files not found in ml/models/")
        print("Run:  python -m ml.train_model --data data/scam_dataset.csv")
        sys.exit(1)
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return model, vectorizer


def predict(text, model, vectorizer):
    """Predict scam probability for a single message."""
    features = vectorizer.transform([text])
    probs = model.predict_proba(features)[0]
    safe_prob = probs[0]
    scam_prob = probs[1]
    is_scam = model.predict(features)[0] == 1
    return is_scam, scam_prob, safe_prob


def print_result(text, is_scam, scam_prob, safe_prob):
    """Pretty-print a single prediction result."""
    label = "SCAM" if is_scam else "SAFE"
    bar_len = int(scam_prob * 30)
    bar = "#" * bar_len + "-" * (30 - bar_len)
    print(f"  [{label:4s}] Scam: {scam_prob:.1%}  Safe: {safe_prob:.1%}  [{bar}]")
    print(f"         {text[:90]}")
    print()


# ---------------------------------------------------------------------------
# Test Suite — covers real-world Indian scam patterns + safe messages
# ---------------------------------------------------------------------------

TEST_CASES = [
    # --- SCAM: OTP / Bank Fraud ---
    ("Your SBI account is blocked. Call 9876543210 to verify your KYC immediately.", True),
    ("RBI Alert: Your account will be suspended. Share OTP to reactivate: 4521", True),
    ("Dear customer, your debit card is blocked. Click http://sbi-verify.com to unlock.", True),

    # --- SCAM: UPI Fraud ---
    ("Send 1 rupee to verify your UPI: verifyme@paytm", True),
    ("You won cashback of Rs 500! Claim now by sending Rs 10 to reward@ybl", True),
    ("Receive your OLX payment of Rs 2000. Scan QR and enter UPI PIN.", True),

    # --- SCAM: Job Scam ---
    ("Hi, I'm the Senior HR. You are shortlisted for an AI role. Pay Rs 299 for docs: hcl.recruit@okaxis", True),
    ("Congratulations! You are hired by Google. Send Rs 1000 for laptop delivery to: google.hr@okicici", True),
    ("Work from home job! Earn 5000 daily. No experience needed. WhatsApp 9988776655", True),

    # --- SCAM: Lottery / Prize ---
    ("You have won Rs 50 lakh in KBC lottery! Call 8877665544 to claim your prize.", True),
    ("Amazon lucky draw! You won an iPhone 15. Pay Rs 500 shipping: http://bit.ly/amazon-win", True),

    # --- SCAM: Digital Arrest / Authority ---
    ("This is CBI. A case has been filed against your Aadhaar. Pay fine of Rs 25000 or face arrest.", True),
    ("Your electricity connection will be cut in 2 hours. Pay pending bill now: http://v.ht/pay-bill", True),

    # --- SCAM: Emotional / Social Engineering ---
    ("Bhai urgent accident ho gaya hai, help chahiye. Is UPI pe bhej do: help@ybl", True),
    ("Mummy phone chori ho gaya hai, naye number pe 2000 bhej do: naya@ybl", True),

    # --- SAFE: Normal Messages ---
    ("Hey, are we still meeting for dinner at 8 PM tonight?", False),
    ("Mom says the food is ready, come home soon.", False),
    ("Please send the project report by Monday morning. Thanks!", False),
    ("I'll be late for the meeting, stuck in traffic.", False),
    ("Did you see the new update on the company portal about holidays?", False),
    ("Your order has been shipped and will arrive by tomorrow.", False),
    ("Happy birthday! Hope you have a great year ahead.", False),
    ("The meeting has been rescheduled to 3 PM. Please confirm.", False),
    ("Mom: I paid the electricity bill online. Receipt is on your WhatsApp.", False),
    ("Let's catch up this weekend. Are you free on Saturday?", False),
]


def run_test_suite(model, vectorizer):
    """Run all test cases and print results with accuracy stats."""
    print("=" * 65)
    print("   CYBER-FORENSIC AGENT: ML SCAM DETECTION — LIVE TEST SUITE")
    print("=" * 65)
    print()

    correct = 0
    total = len(TEST_CASES)
    false_positives = []
    false_negatives = []

    for text, expected_scam in TEST_CASES:
        is_scam, scam_prob, safe_prob = predict(text, model, vectorizer)
        print_result(text, is_scam, scam_prob, safe_prob)

        if is_scam == expected_scam:
            correct += 1
        elif is_scam and not expected_scam:
            false_positives.append((text, scam_prob))
        else:
            false_negatives.append((text, scam_prob))

    # Summary
    print("=" * 65)
    print(f"   RESULTS: {correct}/{total} correct ({correct/total:.0%} accuracy)")
    print("=" * 65)

    if false_positives:
        print(f"\n   FALSE POSITIVES ({len(false_positives)}) — safe messages flagged as scam:")
        for text, prob in false_positives:
            print(f"     [{prob:.1%}] {text[:80]}")

    if false_negatives:
        print(f"\n   FALSE NEGATIVES ({len(false_negatives)}) — scam messages missed:")
        for text, prob in false_negatives:
            print(f"     [{prob:.1%}] {text[:80]}")

    if not false_positives and not false_negatives:
        print("\n   All test cases passed!")

    print()


def test_single(text, model, vectorizer):
    """Test a single user-provided message."""
    print()
    is_scam, scam_prob, safe_prob = predict(text, model, vectorizer)
    print_result(text, is_scam, scam_prob, safe_prob)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test ML scam detection model")
    parser.add_argument("--text", type=str, help="Test a single message")
    args = parser.parse_args()

    model, vectorizer = load_model()

    if args.text:
        test_single(args.text, model, vectorizer)
    else:
        run_test_suite(model, vectorizer)

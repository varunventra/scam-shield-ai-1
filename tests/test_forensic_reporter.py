"""
Automated tests for the Forensic PDF Report Generator.
Runs without requiring a live server or API keys.

Usage:
    pytest tests/test_forensic_reporter.py -v
    python tests/test_forensic_reporter.py          # standalone mode
"""
import importlib.util
import os
import sys
import time
import types
import unittest
from datetime import datetime
from unittest.mock import MagicMock

# Ensure project root is on path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

# ── Stub out app.core.logging BEFORE any app imports so config is never loaded ──
# We must insert stub modules with __path__ so Python treats them as packages.
_app_dir = os.path.join(PROJECT_ROOT, "app")

for mod_name, mod_path in [
    ("app", _app_dir),
    ("app.core", os.path.join(_app_dir, "core")),
]:
    if mod_name not in sys.modules:
        m = types.ModuleType(mod_name)
        m.__path__ = [mod_path]
        sys.modules[mod_name] = m

_logger_stub = MagicMock()
_core_logging_mod = types.ModuleType("app.core.logging")
_core_logging_mod.logger = _logger_stub
sys.modules["app.core.logging"] = _core_logging_mod

# Now import models (pydantic only, safe)
from app.models.requests import Message
from app.models.responses import ExtractedIntelligence

# Load forensic_reporter.py directly from file to skip app.services.__init__
_fr_path = os.path.join(PROJECT_ROOT, "app", "services", "forensic_reporter.py")
_fr_spec = importlib.util.spec_from_file_location("app.services.forensic_reporter", _fr_path)
_fr_module = importlib.util.module_from_spec(_fr_spec)
sys.modules["app.services.forensic_reporter"] = _fr_module
_fr_spec.loader.exec_module(_fr_module)
ForensicReporter = _fr_module.ForensicReporter


# ────────────────────────────────────────────
# Helpers to build realistic test data
# ────────────────────────────────────────────

def _ts(offset_seconds: int = 0) -> int:
    """Return a millisecond timestamp with an optional offset."""
    return int((time.time() + offset_seconds) * 1000)


def build_sbi_scam_conversation() -> list[Message]:
    """20-turn SBI bank fraud scam conversation."""
    exchanges = [
        ("scammer", "Dear customer, this is SBI Security Division. Your account has been flagged for suspicious activity. Immediate verification required or your account will be blocked within 24 hours."),
        ("user", "oh no what happened? is my money safe beta?"),
        ("scammer", "Ma'am your pension account ending 4521 has unauthorized transactions. We need to verify your identity immediately. Please share your registered mobile number."),
        ("user", "oh god my pension! ok my number is 9876543210. please help"),
        ("scammer", "Thank you. For security verification, we are sending an OTP to your number. Please share it immediately when received."),
        ("user", "ok beta i will share. what is your name? my grandson will ask who helped"),
        ("scammer", "I am Rajesh Kumar, Employee ID SBI2847. Now please share the OTP quickly before your account gets permanently blocked."),
        ("user", "ok Rajesh beta. wait my phone is slow today. which branch are you from?"),
        ("scammer", "Ma'am I am from SBI Head Office Cyber Cell. The OTP is urgent. Your Rs.50000 pension deposit is at risk. Share OTP now."),
        ("user", "50000 rupees! oh no. ok let me check. my grandson says official work has portal. can you send bank link?"),
        ("scammer", "Yes ma'am, you can also verify through our secure portal: http://sbi-secure-verify.fake/auth. Click and enter your details there."),
        ("user", "ok opening it beta. but its asking for account number. which one to put?"),
        ("scammer", "Put your account number 12345678901234. And also transfer Rs.500 as security deposit to verify your identity."),
        ("user", "500 rupees ok. where to send? my phonepe is easier for me"),
        ("scammer", "Send to our verification UPI ID: sbi.security@fakebank. This is official SBI verification account."),
        ("user", "ok beta doing it now. sbi.security@fakebank right? let me open phonepe"),
        ("scammer", "Yes correct. Do it immediately. Also share the OTP that was sent to complete verification."),
        ("user", "beta my phone acting up and i cannot see the OTP. is there another way?"),
        ("scammer", "Ma'am this is very urgent. Your account will be blocked in 10 minutes. Please try again and share OTP."),
        ("user", "ok ok dont block please. i am trying beta. my hands shaking"),
    ]
    messages = []
    for i, (sender, text) in enumerate(exchanges):
        messages.append(Message(sender=sender, text=text, timestamp=_ts(i * 30)))
    return messages


def build_sbi_intelligence() -> ExtractedIntelligence:
    """Intelligence extracted from the SBI scam scenario."""
    intel = ExtractedIntelligence(
        bankAccounts=["12345678901234"],
        upiIds=["sbi.security@fakebank"],
        phishingLinks=["http://sbi-secure-verify.fake/auth"],
        phoneNumbers=["9876543210"],
        suspiciousKeywords=[
            "urgent", "immediately", "verify", "blocked", "suspicious",
            "otp", "security", "transaction", "pension", "transfer"
        ],
        emails=[],
        amounts=["Rs.50000", "Rs.500"],
        employeeIds=["SBI2847"],
        impersonationTargets=["SBI"]
    )
    return intel


def build_empty_intelligence() -> ExtractedIntelligence:
    """Intelligence with no extracted data (edge case)."""
    return ExtractedIntelligence()


def build_partial_intelligence() -> ExtractedIntelligence:
    """Intelligence with only a phone number extracted."""
    return ExtractedIntelligence(
        phoneNumbers=["8899001122"],
        suspiciousKeywords=["urgent", "blocked"]
    )


def build_short_conversation() -> list[Message]:
    """A very short 4-message exchange."""
    return [
        Message(sender="scammer", text="Your KYC is expired. Update now or face account closure.", timestamp=_ts(0)),
        Message(sender="user", text="what is kyc beta? is my account ok?", timestamp=_ts(30)),
        Message(sender="scammer", text="Send your Aadhaar number and OTP to verify.", timestamp=_ts(60)),
        Message(sender="user", text="ok let me find my aadhaar card", timestamp=_ts(90)),
    ]


# ────────────────────────────────────────────
# Test Cases
# ────────────────────────────────────────────

class TestForensicReporter(unittest.TestCase):
    """Test suite for ForensicReporter PDF generation."""

    reporter: ForensicReporter
    test_output_dir: str

    @classmethod
    def setUpClass(cls):
        cls.test_output_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "forensics", "_test_outputs"
        )
        os.makedirs(cls.test_output_dir, exist_ok=True)
        cls.reporter = ForensicReporter()
        # Point reporter output to test subfolder
        cls.reporter.FORENSICS_DIR = cls.test_output_dir

    @classmethod
    def tearDownClass(cls):
        # Optionally clean up test outputs
        # shutil.rmtree(cls.test_output_dir, ignore_errors=True)
        print(f"\n{'='*60}")
        print(f"Test PDFs saved in: {cls.test_output_dir}")
        print(f"{'='*60}")

    # ── Core generation tests ──

    def test_full_sbi_scam_report(self):
        """Full 20-turn SBI scam generates a valid PDF with all sections."""
        convo = build_sbi_scam_conversation()
        intel = build_sbi_intelligence()
        agent_notes = (
            "Successfully extracted: target bank account, normalized phone number, "
            "baited payment credentials. Tactics: urgency, threats, credential requests, "
            "payment redirection. Impersonating: SBI. Payment intelligence: 1 bank account(s), "
            "1 UPI ID(s), 1 phishing link(s). Contact: 1 phone number(s). 20 messages exchanged"
        )

        path = self.reporter.generate_forensic_report(
            session_id="SBI-SCAM-2026-TEST",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes=agent_notes,
            scam_detected=True,
            total_messages=20
        )

        self.assertIsNotNone(path, "Report path should not be None")
        self.assertTrue(os.path.exists(path), f"PDF file should exist at {path}")
        self.assertTrue(path.endswith(".pdf"), "Output should be a .pdf file")
        self.assertGreater(os.path.getsize(path), 1000, "PDF should not be trivially small")
        print(f"  [PASS] Full SBI scam report: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")

    def test_empty_intelligence_report(self):
        """Report generates without crashing when no intelligence is extracted."""
        convo = build_short_conversation()
        intel = build_empty_intelligence()

        path = self.reporter.generate_forensic_report(
            session_id="EMPTY-INTEL-TEST",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes="Scam conversation detected. No intelligence extracted.",
            scam_detected=False,
            total_messages=4
        )

        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))
        print(f"  [PASS] Empty intelligence report: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")

    def test_partial_intelligence_report(self):
        """Report handles partial data gracefully (phone only, no UPI/links)."""
        convo = build_short_conversation()
        intel = build_partial_intelligence()

        path = self.reporter.generate_forensic_report(
            session_id="PARTIAL-INTEL-TEST",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes="Contact: 1 phone number(s). 4 messages exchanged",
            scam_detected=True,
            total_messages=4
        )

        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))
        print(f"  [PASS] Partial intelligence report: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")

    def test_empty_conversation_report(self):
        """Report generates even with zero conversation messages."""
        intel = build_sbi_intelligence()

        path = self.reporter.generate_forensic_report(
            session_id="NO-CONVO-TEST",
            extracted_intelligence=intel,
            conversation_history=[],
            agent_notes="No conversation available.",
            scam_detected=True,
            total_messages=0
        )

        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))
        print(f"  [PASS] Empty conversation report: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")

    # ── Naming and case ID tests ──

    def test_filename_convention(self):
        """PDF filename follows CyberCrime_Report_[CaseID].pdf convention."""
        intel = build_partial_intelligence()
        path = self.reporter.generate_forensic_report(
            session_id="abc123-test-session",
            extracted_intelligence=intel,
            conversation_history=build_short_conversation(),
            agent_notes="Test",
            scam_detected=True,
            total_messages=4
        )
        filename = os.path.basename(path)
        self.assertTrue(filename.startswith("CyberCrime_Report_CFA-"), f"Bad filename: {filename}")
        self.assertTrue(filename.endswith(".pdf"), f"Bad extension: {filename}")
        print(f"  [PASS] Filename convention: {filename}")

    def test_case_id_generation(self):
        """Case IDs are deterministic based on session ID."""
        cid1 = self.reporter._generate_case_id("session-abc-123")
        cid2 = self.reporter._generate_case_id("session-abc-123")
        self.assertEqual(cid1, cid2, "Same session should produce same case ID")
        self.assertTrue(cid1.startswith("CFA-"), f"Case ID should start with CFA-: {cid1}")
        year = str(datetime.now().year)
        self.assertIn(year, cid1, f"Case ID should contain current year: {cid1}")
        print(f"  [PASS] Case ID: {cid1}")

    # ── Unicode and special character tests ──

    def test_unicode_in_messages(self):
        """Report handles Unicode characters (rupee symbol, smart quotes, etc.)."""
        convo = [
            Message(sender="scammer", text="Transfer \u20b950,000 to account \u2018verify\u2019 immediately\u2026", timestamp=_ts(0)),
            Message(sender="user", text="ok beta\u2014let me try", timestamp=_ts(30)),
        ]
        intel = build_partial_intelligence()

        path = self.reporter.generate_forensic_report(
            session_id="UNICODE-TEST",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes="Unicode test \u20b9 \u2018 \u201c",
            scam_detected=True,
            total_messages=2
        )

        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))
        print(f"  [PASS] Unicode handling: {os.path.basename(path)}")

    def test_very_long_messages(self):
        """Report handles extremely long scammer messages without breaking."""
        long_text = "Please verify your account. " * 100  # ~2800 chars
        convo = [
            Message(sender="scammer", text=long_text, timestamp=_ts(0)),
            Message(sender="user", text="what is this beta?", timestamp=_ts(30)),
        ]
        intel = build_empty_intelligence()

        path = self.reporter.generate_forensic_report(
            session_id="LONGMSG-TEST",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes="Long message test",
            scam_detected=True,
            total_messages=2
        )

        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))
        print(f"  [PASS] Long message handling: {os.path.basename(path)} ({os.path.getsize(path)} bytes)")

    # ── Threat level tests ──

    def test_critical_threat_level(self):
        """8+ keywords produce CRITICAL threat level."""
        intel = ExtractedIntelligence(
            suspiciousKeywords=[
                "urgent", "immediately", "blocked", "verify", "otp",
                "security", "transaction", "transfer", "confirm"
            ]
        )
        convo = build_short_conversation()
        path = self.reporter.generate_forensic_report(
            session_id="CRITICAL-THREAT",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes="Critical threat level test",
            scam_detected=True,
            total_messages=4
        )
        self.assertIsNotNone(path)
        print(f"  [PASS] Critical threat level report: {os.path.basename(path)}")

    def test_moderate_threat_level(self):
        """Fewer than 4 keywords produce MODERATE threat level."""
        intel = ExtractedIntelligence(
            suspiciousKeywords=["urgent", "blocked"]
        )
        convo = build_short_conversation()
        path = self.reporter.generate_forensic_report(
            session_id="MODERATE-THREAT",
            extracted_intelligence=intel,
            conversation_history=convo,
            agent_notes="Moderate threat level test",
            scam_detected=True,
            total_messages=4
        )
        self.assertIsNotNone(path)
        print(f"  [PASS] Moderate threat level report: {os.path.basename(path)}")

    # ── Multiple report generation ──

    def test_multiple_sessions(self):
        """Multiple reports for different sessions don't collide."""
        paths = []
        for i in range(3):
            path = self.reporter.generate_forensic_report(
                session_id=f"MULTI-{i:03d}",
                extracted_intelligence=build_partial_intelligence(),
                conversation_history=build_short_conversation(),
                agent_notes=f"Multi-session test #{i}",
                scam_detected=True,
                total_messages=4
            )
            self.assertIsNotNone(path)
            paths.append(path)

        # All paths should be unique
        self.assertEqual(len(set(paths)), 3, "Each session should produce a unique file")
        print(f"  [PASS] Multiple sessions: {len(paths)} unique reports")


# ────────────────────────────────────────────
# Standalone runner
# ────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("FORENSIC PDF REPORTER - AUTOMATED TEST SUITE")
    print("=" * 60)
    print()
    unittest.main(verbosity=2)

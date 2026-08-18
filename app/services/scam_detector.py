"""
Scam detection service with hybrid detection:
  Rule-based → ML model → OpenAI fallback.
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum

from openai import OpenAI

from app.core.config import settings
from app.core.logging import logger
from app.models.requests import ConversationRequest
from app.services.ml_detector import predict_scam_probability

# ---------------------------------------------------------------------------
# ScamType enum
# ---------------------------------------------------------------------------

class ScamType(str, Enum):
    OTP_FRAUD = "OTP_FRAUD"
    UPI_FRAUD = "UPI_FRAUD"
    PHISHING = "PHISHING"
    BANK_IMPERSONATION = "BANK_IMPERSONATION"
    JOB_SCAM = "JOB_SCAM"
    INVESTMENT_SCAM = "INVESTMENT_SCAM"
    LOTTERY_SCAM = "LOTTERY_SCAM"
    DELIVERY_SCAM = "DELIVERY_SCAM"
    DIGITAL_ARREST = "DIGITAL_ARREST"
    UTILITY_SCAM = "UTILITY_SCAM"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# DetectionResult dataclass
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    is_scam: bool = False
    final_confidence: float = 0.0
    reasoning: str = ""
    rule_score: float = 0.0
    ml_score: float | None = None
    scam_type: str = "UNKNOWN"
    detected_indicators: list[str] = field(default_factory=list)
    detection_method: str = "none"  # "rule_based", "ml", "hybrid", "openai", "fail_open"


# ---------------------------------------------------------------------------
# Keyword category sets for ScamType classification
# ---------------------------------------------------------------------------

_CATEGORY_KEYWORDS = {
    ScamType.OTP_FRAUD: {
        "otp", "pin", "password", "cvv",
        "ओटीपी", "पासवर्ड", "पिन", "आधार",
        "ఓటీపీ", "పాస్‌వర్డ్", "పిన్", "ఆధార్",
    },
    ScamType.UPI_FRAUD: {
        "upi", "paytm", "phonepe", "gpay", "transfer",
        "send", "rupees", "donate", "donation", "charity", "foundation", "₹",
        "भेजो", "ट्रांसफर", "जमा", "रुपये", "दान",
        "పంపండి", "చెల్లింపులు", "ట్రాన్స్‌ఫర్", "రూపాయలు",
    },
    ScamType.PHISHING: {
        "click here", "link", "http", "https", "bit.ly",
    },
    ScamType.BANK_IMPERSONATION: {
        "bank", "account", "kyc", "debit", "credit", "sbi", "rbi",
        "बैंक", "खाता", "खाता बंद", "सस्पेंड", "केवाईसी",
        "బ్యాంక్", "ఖాతా", "ఖాతా బంద్", "కేవైసీ",
    },
    ScamType.JOB_SCAM: {
        "job", "salary", "hiring", "work from home", "vacancy",
        "earn", "registration fee", "part time",
    },
    ScamType.INVESTMENT_SCAM: {
        "invest", "trading", "profit", "returns", "stock", "crypto",
        "bitcoin", "guaranteed",
    },
    ScamType.LOTTERY_SCAM: {
        "won", "lottery", "prize", "reward", "cashback",
        "इनाम", "लॉटरी", "जीत",
        "బహుమతి", "లాటరీ", "గెలవడం",
    },
    ScamType.DELIVERY_SCAM: {
        "delivery", "package", "shipment", "courier", "tracking",
        "parcel",
    },
    ScamType.DIGITAL_ARREST: {
        "digital arrest", "cyber cell", "cyber crime", "money laundering",
        "narcotics", "cbi", "police", "arrest", "giraftar",
        "पुलिस", "गिरफ्तार",
        "పోలీసు", "అరెస్ట్",
    },
    ScamType.UTILITY_SCAM: {
        "electricity", "disconnected", "power cut", "bijli",
    },
}


class ScamDetector:
    """Detects scam intent using a 3-tier hybrid pipeline."""

    # Full scam keywords list (English + Hindi + Telugu)
    SCAM_KEYWORDS = [
        # Urgency (English)
        "urgent", "immediately", "now", "today", "suspended", "blocked", "expire",
        # Verification/Authentication
        "verify", "confirm", "authenticate", "validate", "update", "kYC", "kyc",
        # Account/Banking
        "account", "bank", "upi", "paytm", "phonepe", "gpay", "debit", "credit",
        # Threats
        "legal action", "police", "arrest", "fine", "penalty", "court",
        # Requests for sensitive info
        "otp", "pin", "password", "cvv", "card", "aadhaar", "aadhar", "pan",
        # Common scam phrases
        "won", "lottery", "prize", "reward", "refund", "cashback",
        "click here", "link", "http", "https", "bit.ly",
        # Impersonation
        "customer care", "customer support", "helpline", "helpdesk",
        # Job scams
        "earn", "work from home", "registration fee", "part time",
        "hiring", "vacancy",
        # Investment scams
        "invest", "crypto", "bitcoin", "trading", "guaranteed",
        # Delivery / courier scams
        "parcel", "courier", "shipment", "tracking",
        # Digital-arrest scams
        "digital arrest", "cyber cell", "cyber crime", "money laundering",
        "narcotics", "cbi",
        # Utility-disconnection scams
        "electricity", "disconnected", "power cut", "bijli",
        # Social engineering / charity / emotional manipulation
        "send", "rupees", "donate", "donation", "charity", "foundation",
        "support women", "help us", "beti", "welfare", "ngo", "trust fund",
        "transfer money", "send money", "pay now", "amount", "₹",
        # --- Hindi / Hinglish scam keywords (transliterated) ---
        "turant", "abhi", "fauran", "jaldi",                # urgency
        "khata", "paisa", "rupaye", "rashi",                 # money/account
        "band", "block", "suspend",                           # threats
        "kanooni karwai", "police", "giraftar",              # legal threats
        "jama", "bhejo", "transfer",                          # transfer requests
        "sathyapan", "jaanch",                                # verification
        "inam", "lottery", "jeet",                            # prize/lottery
        # --- Hindi (Devanagari script) ---
        "तुरंत", "अभी", "फौरन", "जल्दी",                      # urgency
        "खाता", "पैसा", "रुपये", "राशि",                       # money/account
        "बंद", "ब्लॉक", "निलंबित",                              # blocked/suspended
        "कानूनी कार्रवाई", "पुलिस", "गिरफ्तार",                  # legal threats
        "भेजो", "ट्रांसफर", "जमा",                              # transfer
        "सत्यापन", "जाँच", "केवाईसी",                           # verification
        "इनाम", "लॉटरी", "जीत",                                # prize/lottery
        "ओटीपी", "पासवर्ड", "पिन", "आधार",                     # sensitive info
        "बैंक", "खाता बंद", "सस्पेंड",                          # banking threats
        # --- Telugu (transliterated) ---
        "urgentuga", "ventane", "ippudu",                     # urgency
        "khata", "dabbu", "mottam",                           # money/account
        "nilipi", "block",                                    # blocked/suspended
        "chattapara charya", "arrest",                        # legal threats
        "pampandi", "chellimpulu",                            # send/transfer
        "dhruvikarana",                                       # verification
        "bahumathi", "lottery", "gelavadam",                  # prize/lottery
        # --- Telugu (Telugu script) ---
        "తురంతుగా", "వెంటనే", "ఇప్పుడు",                        # urgency
        "ఖాతా", "డబ్బు", "మొత్తం", "రూపాయలు",                   # money/account
        "నిలిపి", "బ్లాక్", "సస్పెండ్",                          # blocked/suspended
        "చట్టపర చర్య", "పోలీసు", "అరెస్ట్",                     # legal threats
        "పంపండి", "చెల్లింపులు", "ట్రాన్స్‌ఫర్",                  # transfer
        "ధృవీకరణ", "కేవైసీ",                                    # verification
        "బహుమతి", "లాటరీ", "గెలవడం",                            # prize/lottery
        "ఓటీపీ", "పాస్‌వర్డ్", "పిన్", "ఆధార్",                  # sensitive info
        "బ్యాంక్", "ఖాతా బంద్",                                 # banking threats
    ]

    def __init__(self):
        """Initialize the scam detector with OpenAI client."""
        self.client = OpenAI(
            api_key=settings.openai_api_key,
            timeout=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,
        )
        self.model = settings.openai_model
        logger.info(f"ScamDetector initialized with model: {self.model}")

    # ------------------------------------------------------------------
    # Rule-based detection (tier 1)
    # ------------------------------------------------------------------

    # Compiled word-boundary matchers, cached per keyword. Multi-word keywords
    # ("limited time") are matched as a phrase with boundaries at both ends.
    _KEYWORD_RE_CACHE: dict = {}

    # Call-to-action signals: a URL, a dialable number, or a money amount.
    # A scam needs at least one of these to monetise; a message with none is
    # informational and an ML-positive on it is very likely a false positive
    # (e.g. "your order has been delivered").
    _URL_RE = re.compile(r"(https?://|www\.|\b\w[\w-]*\.[a-z]{2,6}/\S)", re.IGNORECASE)
    _PHONE_RE = re.compile(r"\d{7,}")
    _MONEY_RE = re.compile(r"(₹|\brs\.?\s*\d|rupees|lakh|crore)", re.IGNORECASE)

    @classmethod
    def _has_call_to_action(cls, text: str) -> bool:
        return bool(
            cls._URL_RE.search(text)
            or cls._PHONE_RE.search(text)
            or cls._MONEY_RE.search(text)
        )

    @classmethod
    def _keyword_matcher(cls, keyword: str):
        """Return a cached compiled word-boundary regex for one keyword."""
        key = keyword.lower()
        matcher = cls._KEYWORD_RE_CACHE.get(key)
        if matcher is None:
            matcher = re.compile(rf"(?<!\w){re.escape(key)}(?!\w)")
            cls._KEYWORD_RE_CACHE[key] = matcher
        return matcher

    def _rule_based_detection(
        self, message_text: str,
    ) -> tuple[bool, float, str, list[str], str]:
        """
        Rule-based scam detection with keyword matching.

        Returns:
            (is_scam, confidence, reasoning, detected_indicators, scam_type)
        """
        message_lower = message_text.lower()

        # Word-boundary matching. Plain substring matching fired on "now" inside
        # "know", "card" inside "discard", "account" inside "accountant" -- so
        # ordinary text reached 2 matches and scored 0.75, which short-circuits
        # ML and activates the paid agent.
        matches = [
            keyword for keyword in self.SCAM_KEYWORDS
            if self._keyword_matcher(keyword).search(message_lower)
        ]

        match_count = len(matches)

        # Determine scam type from keyword categories
        scam_type = self._classify_scam_type(matches)

        if match_count >= 3:
            confidence = 0.9
            is_scam = True
            reasoning = f"Rule-based: High match ({match_count} keywords: {', '.join(matches[:5])})"
        elif match_count >= 2:
            confidence = 0.75
            is_scam = True
            reasoning = f"Rule-based: Medium match ({match_count} keywords: {', '.join(matches)})"
        elif match_count >= 1:
            confidence = 0.6
            is_scam = True
            reasoning = f"Rule-based: Low match ({match_count} keyword: {matches[0]})"
        else:
            confidence = 0.3
            is_scam = False
            reasoning = "Rule-based: No scam keywords detected"

        logger.info(
            f"Rule-based detection: is_scam={is_scam}, confidence={confidence:.2f}, "
            f"matches={match_count}, scam_type={scam_type}"
        )
        return is_scam, confidence, reasoning, matches, scam_type

    def _classify_scam_type(self, matched_keywords: list[str]) -> str:
        """Determine scam type from matched keywords by category counts."""
        if not matched_keywords:
            return ScamType.UNKNOWN.value

        category_counts = {}
        matched_lower = {kw.lower() for kw in matched_keywords}

        for scam_type, keywords in _CATEGORY_KEYWORDS.items():
            count = len(matched_lower & {kw.lower() for kw in keywords})
            if count > 0:
                category_counts[scam_type] = count

        if not category_counts:
            return ScamType.UNKNOWN.value

        # Return category with the highest match count
        best = max(category_counts, key=category_counts.get)
        return best.value

    # ------------------------------------------------------------------
    # OpenAI-based detection (tier 3 / legacy)
    # ------------------------------------------------------------------

    async def _openai_detection(
        self, request: ConversationRequest,
    ) -> tuple[bool, float, str]:
        """
        Detect scam using OpenAI API.

        Returns:
            (is_scam, confidence, reasoning)
        """
        context = self._build_context(request)
        prompt = self._create_detection_prompt(context, request.message.text)

        logger.info(f"OpenAI detection - Session: {request.sessionId}")

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": """You are an expert fraud detection system. Analyze messages for scam intent including:
- Bank fraud attempts
- UPI fraud
- Phishing attempts
- Fake offers and lottery scams
- Account verification scams
- Urgency-based manipulation
- Request for sensitive information (OTP, PIN, passwords, account details)

Respond in JSON format with:
{
    "is_scam": true,
    "confidence": 0.9,
    "reasoning": "brief explanation"
}

Use true/false (lowercase) for boolean values."""
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3,
            max_tokens=200,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content
        logger.debug(f"OpenAI raw response: {content}")

        result = json.loads(content)

        is_scam = result.get("is_scam", False)
        if isinstance(is_scam, str):
            is_scam = is_scam.lower() in ['true', '1', 'yes']

        confidence = float(result.get("confidence", 0.0))
        reasoning = result.get("reasoning", "No reasoning provided")

        logger.info(
            f"OpenAI detection - Session: {request.sessionId}, "
            f"Scam: {is_scam}, Confidence: {confidence:.2f}, Reason: {reasoning}"
        )
        return is_scam, confidence, reasoning

    # ------------------------------------------------------------------
    # Hybrid detection (main entry point)
    # ------------------------------------------------------------------

    async def detect_scam_hybrid(
        self, request: ConversationRequest,
    ) -> DetectionResult:
        """
        Hybrid 3-tier scam detection:
          1. Rule-based keywords  (fast, free)
          2. ML model             (fast, local)
          3. OpenAI API           (slow, costly -- only for ambiguous cases)

        Flow:
          rule_score >= 0.75 → SCAM (skip ML)
          else → ML → ml_score >= 0.65 → SCAM
          ML unavailable → rule_score alone
          All fail → FAIL-OPEN

        Returns:
            DetectionResult with all metadata.
        """
        dr = DetectionResult()

        # --- Tier 1: Rule-based ---
        try:
            is_scam_rule, rule_score, reasoning, indicators, scam_type = \
                self._rule_based_detection(request.message.text)
            dr.rule_score = rule_score
            dr.detected_indicators = indicators
            dr.scam_type = scam_type
        except Exception as exc:
            logger.error(f"Rule-based detection error: {exc}")
            is_scam_rule = False
            rule_score = 0.0
            reasoning = "Rule-based detection failed"
            indicators = []
            scam_type = ScamType.UNKNOWN.value
            dr.rule_score = 0.0

        # High confidence from rules alone -- skip ML
        if rule_score >= 0.75:
            dr.is_scam = True
            dr.final_confidence = rule_score
            dr.reasoning = reasoning
            dr.detection_method = "rule_based"
            logger.info(
                f"Hybrid: rule_score={rule_score:.2f} >= 0.75 → SCAM "
                f"(skip ML) - Session: {request.sessionId}"
            )
            return dr

        # --- Tier 2: ML model ---
        # Offloaded: tokenization plus a DistilBERT forward pass is 50-200ms of
        # pure CPU, which would block the event loop for every concurrent
        # request (including the health check) if run inline.
        ml_score = await asyncio.to_thread(
            predict_scam_probability, request.message.text
        )
        dr.ml_score = ml_score

        if ml_score is not None:
            if ml_score >= 0.65:
                # ML-positive with ZERO corroboration (no keyword hit, no URL,
                # no phone number, no money amount) is overwhelmingly a false
                # positive -- transactional notifications ("your order has
                # been delivered") score high on the classifier but carry no
                # way for a scammer to monetise. Downgrade to uncertain.
                if rule_score <= 0.3 and not self._has_call_to_action(
                    request.message.text
                ):
                    dr.is_scam = False
                    dr.final_confidence = 0.5
                    dr.reasoning = (
                        f"ML positive (score={ml_score:.4f}) but no corroboration: "
                        f"zero keyword matches and no URL/phone/amount in message. "
                        f"Downgraded to uncertain."
                    )
                    dr.detection_method = "hybrid"
                    logger.info(
                        f"Hybrid: ml_score={ml_score:.4f} DAMPENED (no call-to-action, "
                        f"rule_score={rule_score:.2f}) → NOT SCAM - "
                        f"Session: {request.sessionId}"
                    )
                    return dr

                dr.is_scam = True
                dr.final_confidence = max(rule_score, ml_score)
                dr.reasoning = (
                    f"ML detection: score={ml_score:.4f} >= 0.65. "
                    f"Rule score={rule_score:.2f}. {reasoning}"
                )
                dr.detection_method = "ml" if rule_score < 0.6 else "hybrid"
                logger.info(
                    f"Hybrid: ml_score={ml_score:.4f} >= 0.65 → SCAM - "
                    f"Session: {request.sessionId}"
                )
                return dr
            else:
                # ML says not scam. Report the ML score as the confidence rather
                # than max(rule, ml): with max(), a model that actively
                # disagreed could never lower the reported confidence, so
                # final_confidence meant "strongest signal seen" while every
                # caller reads it as "confidence this is a scam".
                # Rules override an ML "not scam" only at 2+ keyword matches
                # (0.75): a single generic keyword ("jaldi", "bill") against an
                # active ML disagreement produced false scam labels on plain
                # family texts.
                dr.is_scam = is_scam_rule and rule_score >= 0.75
                dr.final_confidence = rule_score if dr.is_scam else ml_score
                dr.reasoning = (
                    f"ML detection: score={ml_score:.4f} < 0.65. "
                    f"Rule score={rule_score:.2f}. {reasoning}"
                )
                dr.detection_method = "hybrid"
                logger.info(
                    f"Hybrid: ml_score={ml_score:.4f} < 0.65, "
                    f"rule_score={rule_score:.2f} → "
                    f"{'SCAM' if dr.is_scam else 'NOT SCAM'} - "
                    f"Session: {request.sessionId}"
                )
                return dr

        # --- ML unavailable: use rule score alone ---
        # Warning, not info: half of a "hybrid" detector being absent is a
        # material degradation, and at LOG_LEVEL=INFO an info line is
        # indistinguishable from routine chatter.
        logger.warning(
            "ML model unavailable - detection degraded to rule-based scoring only"
        )
        dr.is_scam = is_scam_rule
        dr.final_confidence = rule_score
        dr.reasoning = f"{reasoning} (ML unavailable)"
        dr.detection_method = "rule_based"
        return dr

    # ------------------------------------------------------------------
    # Legacy OpenAI-based detect_scam (kept as internal helper)
    # ------------------------------------------------------------------

    async def detect_scam(
        self, request: ConversationRequest,
    ) -> tuple[bool, float, str]:
        """
        Legacy: Analyse message via OpenAI with rule-based fallback.

        FAIL-OPEN: If OpenAI fails, use rules. If both fail, assume suspicious.
        """
        try:
            return await self._openai_detection(request)
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error: {e}")
            logger.warning("Falling back to rule-based detection (JSON error)")
            is_scam, conf, reasoning, _, _ = self._rule_based_detection(request.message.text)
            return is_scam, conf, reasoning
        except Exception as e:
            logger.error(
                f"OPENAI API ERROR - Session: {request.sessionId}, "
                f"Type: {type(e).__name__}, Message: {e}"
            )
            logger.warning("Falling back to rule-based detection (OpenAI error)")
            is_scam, conf, reasoning, _, _ = self._rule_based_detection(request.message.text)
            reasoning = f"{reasoning} (OpenAI failed: {type(e).__name__})"
            return is_scam, conf, reasoning

    # ------------------------------------------------------------------
    # Activation decision
    # ------------------------------------------------------------------

    async def should_activate_agent(
        self, request: ConversationRequest,
    ) -> tuple[bool, DetectionResult]:
        """
        Determine if the AI agent should be activated.

        FAIL-OPEN: If in doubt, engage! This is a honeypot.

        Returns:
            (should_activate, DetectionResult)
        """
        try:
            dr = await self.detect_scam_hybrid(request)

            # The configured threshold is the ONLY gate. A previous version
            # OR-ed in `>= 0.5`, which subsumed the threshold entirely and made
            # SCAM_CONFIDENCE_THRESHOLD dead configuration -- every single
            # keyword match bought a paid LLM turn.
            should_activate = (
                dr.is_scam
                and dr.final_confidence >= settings.scam_confidence_threshold
            )

            if should_activate:
                logger.info(
                    f"ACTIVATING AGENT - Session: {request.sessionId}, "
                    f"Scam: {dr.is_scam}, Confidence: {dr.final_confidence:.2f}, "
                    f"Method: {dr.detection_method}, Type: {dr.scam_type}"
                )
            else:
                logger.info(
                    f"Not activating agent - Session: {request.sessionId}, "
                    f"Scam: {dr.is_scam}, Confidence: {dr.final_confidence:.2f}, "
                    f"Method: {dr.detection_method}"
                )

            return should_activate, dr

        except Exception as exc:
            logger.error(
                f"Entire detection pipeline failed - Session: {request.sessionId}: {exc}"
            )
            # FAIL-OPEN: return a fail-open DetectionResult
            fail_dr = DetectionResult(
                is_scam=True,
                final_confidence=0.5,
                reasoning=f"Detection pipeline failed: {type(exc).__name__}. FAIL-OPEN engaged.",
                detection_method="fail_open",
            )
            return True, fail_dr

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_context(self, request: ConversationRequest) -> str:
        """Build conversation context from history."""
        if not request.conversationHistory:
            return "This is the first message in the conversation."

        context_parts = ["Previous conversation:"]
        for msg in request.conversationHistory:
            sender_label = "Scammer" if msg.sender == "scammer" else "User"
            context_parts.append(f"{sender_label}: {msg.text}")

        return "\n".join(context_parts)

    def _create_detection_prompt(self, context: str, current_message: str) -> str:
        """Create detection prompt with context."""
        return f"""{context}

Current message to analyze: "{current_message}"

Analyze if this message is a scam attempt. Consider the full conversation context."""

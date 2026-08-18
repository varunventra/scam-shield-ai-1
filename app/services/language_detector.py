"""
Language detection service.

Detects whether incoming scammer messages are in English, Hindi, or Telugu
and determines what language the agent should reply in.
"""
import re

from app.core.logging import logger

# Unicode ranges for script detection (fast, no external dep needed)
_DEVANAGARI_RE = re.compile(r"[\u0900-\u097F]")  # Hindi
_TELUGU_RE = re.compile(r"[\u0C00-\u0C7F]")       # Telugu

# Common Hindi words in Latin script (transliterated)
_HINDI_LATIN_MARKERS = [
    "kya", "hai", "nahi", "haan", "aap", "mera", "tera", "karo",
    "bhejo", "paisa", "bhai", "beta", "yaar", "abhi", "turant",
    "khata", "kholein", "rupaye", "didi", "amma", "sahab",
    "batao", "dijiye", "karein", "bhejiye", "kaise", "kyun",
]

SUPPORTED_LANGUAGES = {"english", "hindi", "telugu", "hinglish"}


def _word_hindi_ratio(text: str) -> float:
    """
    Compute ratio of purely-Devanagari words to (Devanagari + Latin) words.
    Mixed-script words (e.g. 'SBI' inside a Hindi sentence) are excluded from
    both counts so they don't skew the ratio.
    """
    words = text.split()
    hindi_words = sum(
        1 for w in words if _DEVANAGARI_RE.search(w) and not re.search(r"[a-zA-Z]", w)
    )
    english_words = sum(
        1 for w in words if re.search(r"[a-zA-Z]", w) and not _DEVANAGARI_RE.search(w)
    )
    total = hindi_words + english_words
    if total == 0:
        return 0.0
    return hindi_words / total


def detect_language(
    message_text: str,
    metadata_language: str | None = None,
) -> str:
    """
    Detect language from metadata or message text.

    Priority:
    1. metadata.language (if present and supported)
    2. Telugu script detection
    3. Pure Devanagari (>80% Devanagari chars among script chars) -> Hindi
    4. Mixed-script messages: word-level dominance ratio
       - word_hindi_ratio > 0.50 -> hindi
       - word_hindi_ratio < 0.35 -> english
       - else                    -> hinglish
    5. Transliterated Hindi marker words -> hindi/hinglish
    6. Default -> English

    Returns one of: "english", "hindi", "telugu", "hinglish"
    """
    # 1. Metadata hint
    if metadata_language:
        normalized = metadata_language.strip().lower()
        if normalized in SUPPORTED_LANGUAGES:
            logger.debug(f"Language from metadata: {normalized}")
            return normalized
        mapping = {
            "en": "english", "eng": "english", "hi": "hindi",
            "hin": "hindi", "te": "telugu", "tel": "telugu",
        }
        if normalized in mapping:
            return mapping[normalized]

    text = message_text.strip()
    if not text:
        return "english"

    # Count script characters
    telugu_chars = len(_TELUGU_RE.findall(text))
    devanagari_chars = len(_DEVANAGARI_RE.findall(text))
    latin_chars = len(re.findall(r"[a-zA-Z]", text))
    script_total = max(telugu_chars + devanagari_chars + latin_chars, 1)

    # 2. Telugu detection (takes priority)
    if telugu_chars / script_total > 0.15:
        logger.debug(f"Telugu detected via script ({telugu_chars} chars)")
        return "telugu"

    # 3. Pure Devanagari — hard rule: >80% of script chars are Devanagari
    if devanagari_chars > 0:
        deva_ratio = devanagari_chars / max(devanagari_chars + latin_chars, 1)
        if deva_ratio > 0.80:
            logger.debug(
                f"Hindi detected (pure Devanagari, ratio={deva_ratio:.2f}, "
                f"devanagari={devanagari_chars}, latin={latin_chars})"
            )
            return "hindi"

        # 4. Mixed script: use word-level dominance
        word_ratio = _word_hindi_ratio(text)
        logger.debug(
            f"Mixed script: word_hindi_ratio={word_ratio:.2f}, "
            f"deva_char_ratio={deva_ratio:.2f}"
        )
        if word_ratio > 0.50:
            return "hindi"
        elif word_ratio < 0.45:
            return "english"
        else:
            return "hinglish"

    # 5. Transliterated Hindi / Hinglish (Latin script only, no Devanagari)
    text_lower = text.lower()
    hindi_marker_hits = sum(1 for w in _HINDI_LATIN_MARKERS if w in text_lower)

    if hindi_marker_hits >= 2:
        if latin_chars / script_total > 0.4:
            logger.debug(f"Hinglish detected (markers={hindi_marker_hits})")
            return "hinglish"
        logger.debug(f"Hindi transliterated detected (markers={hindi_marker_hits})")
        return "hindi"

    # 6. Default to English
    logger.debug("Defaulting to English")
    return "english"


def detect_response_language(
    detected_language: str,
    message_text: str,
) -> str:
    """
    Determine response language.

    If scammer mixes languages (e.g. Hindi + English), we respond in the
    same mix style - which effectively means replying in detected_language.
    """
    return detected_language

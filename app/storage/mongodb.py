"""
MongoDB storage for persistent session data, repeat scammer detection,
and threat intelligence.
"""
import asyncio
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from app.core.config import settings
from app.core.logging import logger

# Motor (async MongoDB driver) - imported lazily so the app still starts
# even if MongoDB is unavailable.
_client = None
_db = None
_collection = None

# In-memory fallback store used when MongoDB is unavailable
_memory_store: dict[str, Any] = {}
_using_memory_fallback = False


async def get_collection():
    """
    Lazily initialise and return the ``scam_sessions`` collection.

    Retries up to 3 times with exponential backoff before falling back to
    in-memory storage. Returns ``None`` when no ``MONGODB_URI`` is configured.
    """
    global _client, _db, _collection, _using_memory_fallback

    if _collection is not None:
        return _collection

    uri = settings.mongodb_uri
    if not uri:
        logger.warning("MONGODB_URI not set - running without persistent storage")
        return None

    max_attempts = 3
    for attempt in range(1, max_attempts + 1):
        try:
            from motor.motor_asyncio import AsyncIOMotorClient

            _client = AsyncIOMotorClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                socketTimeoutMS=10000,
                maxPoolSize=20,
                minPoolSize=2,
                maxIdleTimeMS=30_000,
            )
            await _client.admin.command("ping")
            _db = _client["scamshield_v2"]
            _collection = _db["scam_sessions"]

            # Ensure indexes for fast lookups
            await _collection.create_index("sessionId", unique=True)
            await _collection.create_index("extractedIntelligence.phoneNumbers")
            await _collection.create_index("extractedIntelligence.upiIds")
            await _collection.create_index("extractedIntelligence.bankAccounts")
            await _collection.create_index("extractedIntelligence.phishingLinks")
            await _collection.create_index("repeatScammer")
            await _collection.create_index("riskLevel")
            await _collection.create_index("scamType")
            await _collection.create_index("detectionMethod")

            _using_memory_fallback = False
            logger.info(f"MongoDB connected - scam_sessions collection ready (attempt {attempt})")
            return _collection

        except Exception as exc:
            logger.warning(f"MongoDB connection attempt {attempt}/{max_attempts} failed: {exc}")
            if attempt < max_attempts:
                await asyncio.sleep(2 ** attempt)  # 2s, 4s backoff
            else:
                logger.error(
                    "MongoDB unavailable after 3 attempts - "
                    "falling back to in-memory storage (data will not persist)"
                )
                _client = _db = _collection = None
                _using_memory_fallback = True
                return None


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def normalize_phone(phone: str) -> str:
    """Strip spaces/dashes, ensure +91 prefix for 10-digit Indian numbers."""
    cleaned = re.sub(r"[\s\-\.\(\)]+", "", phone)
    digits = re.sub(r"\D", "", cleaned)
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    if len(digits) == 10:
        return f"+91{digits}"
    return cleaned


def normalize_upi(upi: str) -> str:
    return upi.strip().lower()


def normalize_link(link: str) -> str:
    return link.strip().rstrip("/").lower()


def extract_domain(link: str) -> str:
    """
    Return the domain from a URL for domain-level matching.

    Uses an anchored substitution rather than ``lstrip("www.")``: lstrip strips
    any leading character in the SET {'w', '.'}, so "wallet-scam.in" became
    "allet-scam.in" and "wwf.org" became "f.org", silently corrupting both
    stored domains and repeat-scammer matching.
    """
    try:
        parsed = urlparse(link if "://" in link else f"https://{link}")
        return re.sub(r"^www\.", "", parsed.netloc.lower())
    except Exception:
        return link.strip().lower()


def deduplicate_intelligence(intel: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate and normalise all extractedIntelligence arrays."""
    if not intel:
        return intel

    if "phoneNumbers" in intel:
        intel["phoneNumbers"] = list({normalize_phone(p) for p in intel["phoneNumbers"]})
    if "upiIds" in intel:
        intel["upiIds"] = list({normalize_upi(u) for u in intel["upiIds"]})
    if "phishingLinks" in intel:
        intel["phishingLinks"] = list({normalize_link(link) for link in intel["phishingLinks"]})
    if "bankAccounts" in intel:
        intel["bankAccounts"] = list(set(intel["bankAccounts"]))
    if "suspiciousKeywords" in intel:
        intel["suspiciousKeywords"] = list({k.lower().strip() for k in intel["suspiciousKeywords"]})
    return intel


# ---------------------------------------------------------------------------
# Repeat-scammer detection
# ---------------------------------------------------------------------------

async def find_repeat_matches(
    session_id: str,
    intelligence: dict[str, Any],
) -> dict[str, Any]:
    """
    Search ALL other sessions for overlapping entities.

    Returns a dict with:
      - repeatScammer: bool
      - repeatMatches: {phoneNumbers: [...], upiIds: [...], ...}
      - repeatSessionIds: [...]
    """
    result = {
        "repeatScammer": False,
        "repeatMatches": {
            "phoneNumbers": [],
            "upiIds": [],
            "bankAccounts": [],
            "phishingLinks": [],
        },
        "repeatSessionIds": [],
    }

    col = await get_collection()
    if col is None:
        return result

    phones = intelligence.get("phoneNumbers", [])
    upis = intelligence.get("upiIds", [])
    accounts = intelligence.get("bankAccounts", [])
    links = intelligence.get("phishingLinks", [])
    # Also build domain list for domain-level matching
    domains = [extract_domain(link) for link in links if link]

    or_clauses: list[dict] = []
    if phones:
        or_clauses.append({"extractedIntelligence.phoneNumbers": {"$in": phones}})
    if upis:
        or_clauses.append({"extractedIntelligence.upiIds": {"$in": upis}})
    if accounts:
        or_clauses.append({"extractedIntelligence.bankAccounts": {"$in": accounts}})
    if links:
        or_clauses.append({"extractedIntelligence.phishingLinks": {"$in": links}})
    if domains:
        or_clauses.append({"extractedIntelligence.phishingDomains": {"$in": domains}})

    if not or_clauses:
        return result

    query = {
        "sessionId": {"$ne": session_id},
        "$or": or_clauses,
    }

    try:
        matched_session_ids = set()
        async for doc in col.find(query, {"sessionId": 1, "extractedIntelligence": 1}):
            other_id = doc["sessionId"]
            other_intel = doc.get("extractedIntelligence", {})

            matched_session_ids.add(other_id)

            # Find which entities matched
            for p in phones:
                if p in other_intel.get("phoneNumbers", []):
                    result["repeatMatches"]["phoneNumbers"].append(p)
            for u in upis:
                if u in other_intel.get("upiIds", []):
                    result["repeatMatches"]["upiIds"].append(u)
            for a in accounts:
                if a in other_intel.get("bankAccounts", []):
                    result["repeatMatches"]["bankAccounts"].append(a)
            for l_link in links:
                if l_link in other_intel.get("phishingLinks", []):
                    result["repeatMatches"]["phishingLinks"].append(l_link)
            # Domain-level
            for d in domains:
                if d in other_intel.get("phishingDomains", []):
                    # Add the original link that matched by domain
                    for orig in links:
                        if extract_domain(orig) == d:
                            result["repeatMatches"]["phishingLinks"].append(orig)

        # Deduplicate matches
        for key in result["repeatMatches"]:
            result["repeatMatches"][key] = list(set(result["repeatMatches"][key]))

        result["repeatSessionIds"] = list(matched_session_ids)
        result["repeatScammer"] = len(matched_session_ids) > 0
    except Exception as exc:
        logger.error(f"Repeat-scammer detection query failed: {exc}")

    return result


async def check_repeat_scammer(intel_dict: dict[str, Any]) -> dict[str, Any]:
    """
    High-level repeat scammer check with scoring.

    Reuses find_repeat_matches internally and adds:
      - match_count: total matching sessions
      - first_seen: earliest createdAt among matched sessions
      - session_ids: list of matched session IDs
      - repeat_scammer_score: 0-100 composite score (25 per matched session, capped at 100)
    """
    result = {
        "match_count": 0,
        "first_seen": None,
        "session_ids": [],
        "repeat_scammer_score": 0,
    }

    col = await get_collection()
    if col is None:
        return result

    phones   = [normalize_phone(p) for p in intel_dict.get("phoneNumbers", []) if p]
    upis     = [normalize_upi(u) for u in intel_dict.get("upiIds", []) if u]
    accounts = intel_dict.get("bankAccounts", [])

    or_clauses: list[dict] = []
    if phones:
        or_clauses.append({"extractedIntelligence.phoneNumbers": {"$in": phones}})
    if upis:
        or_clauses.append({"extractedIntelligence.upiIds": {"$in": upis}})
    if accounts:
        or_clauses.append({"extractedIntelligence.bankAccounts": {"$in": accounts}})

    if not or_clauses:
        return result

    try:
        query = {"$or": or_clauses}
        matched_ids = []
        earliest: datetime | None = None
        async for doc in col.find(query, {"sessionId": 1, "createdAt": 1}):
            matched_ids.append(doc["sessionId"])
            created = doc.get("createdAt")
            if created and (earliest is None or created < earliest):
                earliest = created

        match_count = len(matched_ids)
        result["match_count"] = match_count
        result["session_ids"] = matched_ids
        result["first_seen"] = earliest
        result["repeat_scammer_score"] = min(100, match_count * 25)
        if match_count:
            logger.info(
                f"[REPEAT] Repeat scammer detected: {match_count} prior sessions, "
                f"score={result['repeat_scammer_score']}, first_seen={earliest}"
            )
    except Exception as exc:
        logger.error(f"check_repeat_scammer query failed: {exc}")

    return result


# ---------------------------------------------------------------------------
# Risk level
# ---------------------------------------------------------------------------

def compute_risk_level(
    repeat_scammer: bool,
    scam_detected: bool,
    rule_score: float = 0.0,
    ml_score: float | None = None,
) -> str:
    if repeat_scammer:
        return "HIGH"
    if scam_detected and (rule_score >= 0.75 or (ml_score is not None and ml_score >= 0.8)):
        return "HIGH"
    if scam_detected:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Upsert session document
# ---------------------------------------------------------------------------

async def upsert_session(
    session_id: str,
    scam_detected: bool,
    total_messages: int,
    extracted_intelligence: dict[str, Any],
    agent_notes: str,
    metadata: dict[str, Any] | None,
    conversation_transcript: list[dict[str, Any]],
    final_callback_payload: dict[str, Any] | None = None,
    callback_sent: bool = False,
    callback_sent_at: datetime | None = None,
    repeat_info: dict[str, Any] | None = None,
    detected_language: str = "english",
    response_language: str = "english",
    persona_selected: str | None = None,
    persona_switch_history: list[str] | None = None,
    rule_score: float = 0.0,
    ml_score: float | None = None,
    scam_type: str = "UNKNOWN",
    detection_method: str = "none",
    detected_indicators: list[str] | None = None,
    detected_identity_dict: dict[str, Any] | None = None,
    pdf_report_generated: bool = False,
    pdf_report_file_id: str | None = None,
    pdf_report_generated_at: datetime | None = None,
    pdf_report_case_id: str | None = None,
) -> bool:
    """
    Upsert the full session record into MongoDB.

    Returns True on success, False on failure (never raises).
    """
    col = await get_collection()
    if col is None:
        return False

    now = datetime.now(UTC)

    # Normalise + deduplicate intelligence before storage
    intel = deduplicate_intelligence(dict(extracted_intelligence))

    # Build domain array for domain-level repeat matching
    intel["phishingDomains"] = list({
        extract_domain(link) for link in intel.get("phishingLinks", []) if link
    })

    # Repeat scammer info
    repeat_scammer = (repeat_info or {}).get("repeatScammer", False)
    risk_level = compute_risk_level(repeat_scammer, scam_detected, rule_score, ml_score)

    # Cross-session deduplication score
    repeat_score_info = await check_repeat_scammer(intel)

    update_doc: dict[str, Any] = {
        "$set": {
            "scamDetected": scam_detected,
            "totalMessagesExchanged": total_messages,
            "extractedIntelligence": intel,
            "agentNotes": agent_notes,
            "metadata": metadata or {},
            "conversationTranscript": conversation_transcript,
            "updatedAt": now,
            "repeatScammer": repeat_scammer,
            "repeatMatches": (repeat_info or {}).get("repeatMatches", {}),
            "repeatSessionIds": (repeat_info or {}).get("repeatSessionIds", []),
            "riskLevel": risk_level,
            "detectedLanguage": detected_language,
            "responseLanguage": response_language,
            "personaSelected": persona_selected,
            "personaSwitchHistory": persona_switch_history or [],
            "ruleScore": rule_score,
            "mlScore": ml_score,
            "scamType": scam_type,
            "detectionMethod": detection_method,
            "detectedIndicators": detected_indicators or [],
            "detectedIdentity": detected_identity_dict or {},
            "repeatScammerScore": repeat_score_info["repeat_scammer_score"],
            "repeatScammerSessionIds": repeat_score_info["session_ids"],
            "repeatScammerFirstSeen": repeat_score_info["first_seen"],
        },
        "$setOnInsert": {
            "sessionId": session_id,
        },
    }

    if final_callback_payload is not None:
        update_doc["$set"]["finalCallbackPayload"] = final_callback_payload
    if callback_sent:
        update_doc["$set"]["callbackSent"] = True
        update_doc["$set"]["callbackSentAt"] = callback_sent_at or now
    else:
        # Don't overwrite an existing True with False
        update_doc["$set"].setdefault("callbackSent", False)

    # Add PDF report fields if provided
    if pdf_report_generated:
        update_doc["$set"]["pdfReportGenerated"] = True
        update_doc["$set"]["pdfReportFileId"] = pdf_report_file_id
        update_doc["$set"]["pdfReportGeneratedAt"] = pdf_report_generated_at or now
        if pdf_report_case_id:
            update_doc["$set"]["pdfReportCaseId"] = pdf_report_case_id

        # Build PDF download URL (requires x-admin-key header to fetch;
        # never embed the admin key itself in stored documents)
        import os
        base = (
            settings.base_url
            or os.environ.get("RENDER_EXTERNAL_URL", "")
            or f"http://localhost:{settings.port}"
        )
        base = base.rstrip("/")
        pdf_url = f"{base}/api/v1/admin/report/{session_id}"
        update_doc["$set"]["pdfReportUrl"] = pdf_url

    # Ensure createdAt is set on insert AND backfilled for old documents that
    # may be missing it (use $min so the earliest timestamp always wins).
    update_doc.setdefault("$min", {})["createdAt"] = now

    try:
        await col.update_one(
            {"sessionId": session_id},
            update_doc,
            upsert=True,
        )
        logger.info(f"MongoDB upsert OK - session {session_id}")
        return True
    except Exception as exc:
        logger.error(f"MongoDB upsert failed - session {session_id}: {exc}")
        # Fallback to memory on write failure
        existing = _memory_store.get(session_id, {"sessionId": session_id, "createdAt": now})
        existing.update(update_doc.get("$set", {}))
        if "createdAt" not in existing:
            existing["createdAt"] = now
        _memory_store[session_id] = existing
        return False


def _iso_utc(dt: datetime) -> str:
    """Serialize a datetime as ISO-8601 with an explicit UTC offset.

    PyMongo returns naive datetimes that are actually UTC; without the
    offset suffix, JS `new Date()` parses them as local time and every
    timestamp in the dashboard shifts by the viewer's UTC offset.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# Admin query helpers
# ---------------------------------------------------------------------------

async def get_session_doc(session_id: str) -> dict[str, Any] | None:
    col = await get_collection()
    if col is None:
        return None
    doc = await col.find_one({"sessionId": session_id}, {"_id": 0})
    return doc


async def get_repeat_analysis(session_id: str) -> dict[str, Any] | None:
    col = await get_collection()
    if col is None:
        return None
    doc = await col.find_one(
        {"sessionId": session_id},
        {
            "_id": 0,
            "sessionId": 1,
            "repeatScammer": 1,
            "repeatMatches": 1,
            "repeatSessionIds": 1,
            "riskLevel": 1,
            "extractedIntelligence": 1,
        },
    )
    return doc


async def get_all_sessions(limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent sessions ordered by updatedAt descending."""
    col = await get_collection()
    if col is None:
        return list(_memory_store.values())[:limit]

    results = []
    seen_ids: set = set()
    try:
        async for doc in col.find({}, {"_id": 0}).sort("updatedAt", -1).limit(limit):
            # Serialize ALL datetime fields to ISO strings for JSON transport
            for key, val in list(doc.items()):
                if isinstance(val, datetime):
                    doc[key] = _iso_utc(val)
            # Ensure createdAt falls back to updatedAt if somehow missing
            if not doc.get("createdAt"):
                doc["createdAt"] = doc.get("updatedAt")
            results.append(doc)
            seen_ids.add(doc.get("sessionId"))
    except Exception as exc:
        logger.error(f"MongoDB get_all_sessions failed: {exc}")

    # Also include any in-memory fallback entries that aren't in MongoDB
    # (these accumulate when MongoDB upserts fail transiently)
    if _memory_store:
        for sid, doc in _memory_store.items():
            if sid not in seen_ids:
                doc_copy = dict(doc)
                for key in ("createdAt", "updatedAt"):
                    if isinstance(doc_copy.get(key), datetime):
                        doc_copy[key] = _iso_utc(doc_copy[key])
                results.append(doc_copy)

    # Re-sort combined results
    def _sort_key(d):
        ts = d.get("updatedAt") or d.get("createdAt") or ""
        return ts

    results.sort(key=_sort_key, reverse=True)
    return results[:limit]


_INTEL_CATEGORIES = [
    "phoneNumbers", "upiIds", "bankAccounts",
    "phishingLinks", "emailAddresses", "suspiciousKeywords",
]


def _empty_stats() -> dict[str, Any]:
    """Zeroed stats payload, shape-identical to a real aggregation result."""
    from app.utils.helpers import format_duration

    return {
        "totalSessions": 0,
        "intelTotal": 0,
        "intelByCategory": {k: 0 for k in _INTEL_CATEGORIES},
        "scamTypeCounts": {},
        "repeatScammers": 0,
        "avgTurns": 0.0,
        "scammerTimeWastedSeconds": 0,
        "scammerTimeWastedHuman": format_duration(0),
        "avgEngagementSeconds": 0,
        "avgEngagementHuman": format_duration(0),
        "estimatedScammerCost": 0.0,
    }


def _aggregate_stats_from_memory() -> dict[str, Any]:
    """
    Fallback aggregation over the in-memory store.

    Only reachable when MongoDB is unavailable, where the store is small by
    definition (it exists because writes are failing), so a Python loop is fine.
    """
    from app.utils.helpers import (
        SCAMMER_COST_PER_MINUTE,
        format_duration,
        transcript_duration_seconds,
    )

    sessions = list(_memory_store.values())
    if not sessions:
        return _empty_stats()

    scam_type_counts: dict[str, int] = {}
    intel_counts: dict[str, int] = {k: 0 for k in _INTEL_CATEGORIES}
    repeat_scammers = total_turns = total_seconds = 0

    for s in sessions:
        key = s.get("scamType") or "unknown"
        scam_type_counts[key] = scam_type_counts.get(key, 0) + 1
        intel = s.get("extractedIntelligence") or {}
        for cat in _INTEL_CATEGORIES:
            vals = intel.get(cat)
            if isinstance(vals, list):
                intel_counts[cat] += len(vals)
        if s.get("repeatScammer"):
            repeat_scammers += 1
        total_turns += s.get("totalMessagesExchanged") or 0
        total_seconds += transcript_duration_seconds(s.get("conversationTranscript"))

    total_sessions = len(sessions)
    return {
        "totalSessions": total_sessions,
        "intelTotal": sum(intel_counts.values()),
        "intelByCategory": intel_counts,
        "scamTypeCounts": scam_type_counts,
        "repeatScammers": repeat_scammers,
        "avgTurns": round(total_turns / total_sessions, 1),
        "scammerTimeWastedSeconds": total_seconds,
        "scammerTimeWastedHuman": format_duration(total_seconds),
        "avgEngagementSeconds": int(total_seconds / total_sessions),
        "avgEngagementHuman": format_duration(int(total_seconds / total_sessions)),
        "estimatedScammerCost": round(
            (total_seconds / 60.0) * SCAMMER_COST_PER_MINUTE, 2
        ),
    }


async def ensure_retention_index() -> bool:
    """
    Create the TTL index that enforces the data retention window.

    The stored documents contain third-party personal data by design (phone
    numbers, bank accounts, IFSC codes, extracted Aadhaar/PAN). Keeping them
    forever is a compliance problem under India's DPDP Act; this expires them
    automatically DATA_RETENTION_DAYS after creation.
    """
    col = await get_collection()
    if col is None:
        return False

    seconds = max(1, int(settings.data_retention_days)) * 86400
    try:
        await col.create_index(
            "createdAt",
            name="retention_ttl",
            expireAfterSeconds=seconds,
        )
        logger.info(
            f"Retention TTL index active: sessions expire "
            f"{settings.data_retention_days} days after createdAt"
        )
        return True
    except Exception as exc:
        # An existing index with different options must be dropped by hand;
        # surface it loudly rather than pretending retention is enforced.
        logger.error(
            f"Could not create retention TTL index ({exc}). "
            "Scammer PII will be retained indefinitely until this is fixed."
        )
        return False


async def get_aggregate_stats() -> dict[str, Any]:
    """
    Compute dashboard aggregate stats across all sessions.

    Runs as a MongoDB aggregation pipeline. The previous implementation pulled
    up to 10,000 FULL documents -- including every conversation transcript --
    into Python and looped over them, which on a 512MB instance was ~100MB of
    allocation per dashboard poll plus an event-loop stall.

    Duration is derived server-side from the first/last transcript timestamps
    via $reduce, so no transcript bodies cross the wire.
    """
    from app.utils.helpers import SCAMMER_COST_PER_MINUTE, format_duration

    col = await get_collection()
    if col is None:
        return _aggregate_stats_from_memory()

    intel_size_stage = {
        f"{cat}Count": {
            "$size": {"$ifNull": [f"$extractedIntelligence.{cat}", []]}
        }
        for cat in _INTEL_CATEGORIES
    }

    # Span between the smallest and largest timestamp in the transcript.
    duration_expr = {
        "$let": {
            "vars": {
                "stamps": {
                    "$filter": {
                        "input": {
                            "$map": {
                                "input": {"$ifNull": ["$conversationTranscript", []]},
                                "as": "m",
                                "in": "$$m.timestamp",
                            }
                        },
                        "as": "t",
                        "cond": {"$isNumber": "$$t"},
                    }
                }
            },
            "in": {
                "$cond": [
                    {"$gt": [{"$size": "$$stamps"}, 1]},
                    {
                        "$max": [
                            0,
                            {
                                "$floor": {
                                    "$divide": [
                                        {
                                            "$subtract": [
                                                {"$max": "$$stamps"},
                                                {"$min": "$$stamps"},
                                            ]
                                        },
                                        1000,
                                    ]
                                }
                            },
                        ]
                    },
                    0,
                ]
            },
        }
    }

    pipeline = [
        {
            "$project": {
                "_id": 0,
                "scamType": {"$ifNull": ["$scamType", "unknown"]},
                "repeatScammer": {"$ifNull": ["$repeatScammer", False]},
                "turns": {"$ifNull": ["$totalMessagesExchanged", 0]},
                "durationSeconds": duration_expr,
                **intel_size_stage,
            }
        },
        {
            "$group": {
                "_id": None,
                "totalSessions": {"$sum": 1},
                "totalTurns": {"$sum": "$turns"},
                "totalSeconds": {"$sum": "$durationSeconds"},
                "repeatScammers": {
                    "$sum": {"$cond": ["$repeatScammer", 1, 0]}
                },
                "scamTypes": {"$push": "$scamType"},
                **{
                    f"{cat}Total": {"$sum": f"${cat}Count"}
                    for cat in _INTEL_CATEGORIES
                },
            }
        },
    ]

    try:
        docs = await col.aggregate(pipeline).to_list(length=1)
    except Exception as exc:
        logger.error(f"Aggregate stats pipeline failed: {exc}")
        return _aggregate_stats_from_memory()

    if not docs:
        return _empty_stats()

    agg = docs[0]
    total_sessions = agg.get("totalSessions", 0)
    total_turns = agg.get("totalTurns", 0) or 0
    total_seconds = agg.get("totalSeconds", 0) or 0
    repeat_scammers = agg.get("repeatScammers", 0) or 0
    intel_counts = {
        cat: int(agg.get(f"{cat}Total", 0) or 0) for cat in _INTEL_CATEGORIES
    }

    scam_type_counts: dict[str, int] = {}
    for scam_type in agg.get("scamTypes", []):
        key = scam_type or "unknown"
        scam_type_counts[key] = scam_type_counts.get(key, 0) + 1

    intel_total = sum(intel_counts.values())
    avg_turns = round(total_turns / total_sessions, 1) if total_sessions else 0.0
    avg_seconds = int(total_seconds / total_sessions) if total_sessions else 0
    estimated_cost = round((total_seconds / 60.0) * SCAMMER_COST_PER_MINUTE, 2)

    return {
        "totalSessions": total_sessions,
        "intelTotal": intel_total,
        "intelByCategory": intel_counts,
        "scamTypeCounts": scam_type_counts,
        "repeatScammers": repeat_scammers,
        "avgTurns": avg_turns,
        "scammerTimeWastedSeconds": total_seconds,
        "scammerTimeWastedHuman": format_duration(total_seconds),
        "avgEngagementSeconds": avg_seconds,
        "avgEngagementHuman": format_duration(avg_seconds),
        "estimatedScammerCost": estimated_cost,
    }


async def search_sessions(
    phone: str | None = None,
    upi: str | None = None,
    account: str | None = None,
    link: str | None = None,
    keyword: str | None = None,
) -> list[dict[str, Any]]:
    """Search sessions by extracted intelligence fields."""
    col = await get_collection()
    if col is None:
        return []

    or_clauses: list[dict] = []
    if phone:
        normalized = normalize_phone(phone)
        or_clauses.append({"extractedIntelligence.phoneNumbers": normalized})
    if upi:
        or_clauses.append({"extractedIntelligence.upiIds": normalize_upi(upi)})
    if account:
        or_clauses.append({"extractedIntelligence.bankAccounts": account.strip()})
    if link:
        or_clauses.append({"extractedIntelligence.phishingLinks": normalize_link(link)})
        domain = extract_domain(link)
        if domain:
            or_clauses.append({"extractedIntelligence.phishingDomains": domain})
    if keyword:
        or_clauses.append({"extractedIntelligence.suspiciousKeywords": keyword.lower().strip()})

    if not or_clauses:
        return []

    query = {"$or": or_clauses}
    results = []
    try:
        async for doc in col.find(query, {
            "_id": 0,
            "sessionId": 1,
            "scamDetected": 1,
            "totalMessagesExchanged": 1,
            "riskLevel": 1,
            "repeatScammer": 1,
            "extractedIntelligence": 1,
            "createdAt": 1,
            "updatedAt": 1,
        }).limit(50):
            results.append(doc)
    except Exception as exc:
        logger.error(f"MongoDB search failed: {exc}")

    return results

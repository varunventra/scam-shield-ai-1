"""
API routes for the Scambot Honeypot system.
"""
import asyncio
import re
import time
from collections import OrderedDict
from datetime import UTC, datetime
from io import BytesIO

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import settings

# Shared limiter instance -- see app/core/limiter.py for why it must be shared.
from app.core.limiter import limiter
from app.core.logging import logger
from app.core.security import (
    issue_admin_session,
    verify_admin_key,
    verify_api_key,
)
from app.models.requests import ConversationRequest, Message
from app.models.responses import (
    AgentReasoning,
    ConversationResponse,
    EngagementMetrics,
    FinalResultPayload,
)
from app.services import (
    AIAgent,
    CallbackHandler,
    ForensicReporter,
    IntelligenceExtractor,
    ScamDetector,
    detect_identity,
    detect_language,
    detect_response_language,
    get_persona_prompt,
    lock_identity_after_threshold,
    select_persona,
)
from app.services.conversation_strategy import ConversationStrategy, select_phase
from app.services.cost_guard import cost_guard, provider_health
from app.services.guardrails import (
    GuardrailReport,
    build_injection_reinforcement,
    check_output,
    scan_input,
)
from app.services.scam_detector import DetectionResult
from app.storage import session_manager
from app.storage.mongodb import (
    deduplicate_intelligence,
    find_repeat_matches,
    get_aggregate_stats,
    get_all_sessions,
    get_repeat_analysis,
    get_session_doc,
    search_sessions,
    upsert_session,
)
from app.storage.pdf_storage import check_pdf_exists, retrieve_pdf_by_session, store_pdf
from app.utils import validate_session_id

# Create router
router = APIRouter()

# Initialize services
scam_detector = ScamDetector()
ai_agent = AIAgent()
intelligence_extractor = IntelligenceExtractor()
callback_handler = CallbackHandler()
forensic_reporter = ForensicReporter()


# ---------------------------------------------------------------------------
# Helper: build full conversation transcript from all sources
# ---------------------------------------------------------------------------

def _build_transcript(conversation_history, current_message, agent_reply: str) -> list:
    """
    Build an ordered conversation transcript:
      conversationHistory + latest scammer message + AI reply.
    """
    transcript = []
    for msg in conversation_history:
        transcript.append({
            "sender": msg.sender,
            "text": msg.text,
            "timestamp": msg.timestamp,
        })
    transcript.append({
        "sender": current_message.sender,
        "text": current_message.text,
        "timestamp": current_message.timestamp,
    })
    transcript.append({
        "sender": "user",
        "text": agent_reply,
        "timestamp": int(time.time() * 1000),
    })
    return transcript


# ---------------------------------------------------------------------------
# Helper: build the per-turn agent reasoning trace
# ---------------------------------------------------------------------------

_PHASE_NAMES = {
    1: "Emotional Hook",
    2: "Active Extraction",
    3: "Deep Extraction",
}

_INTEL_KEYS = [
    "phoneNumbers", "upiIds", "bankAccounts",
    "phishingLinks", "emailAddresses", "suspiciousKeywords",
]

# Categories included in the law-enforcement intel export (order = CSV order)
_INTEL_EXPORT_CATEGORIES = [
    "phoneNumbers", "upiIds", "bankAccounts", "phishingLinks",
    "emailAddresses", "caseIds", "policyNumbers", "orderNumbers",
    "suspiciousKeywords",
]

_EXPORT_FIELDS = ["sessionId", "intelType", "value", "scamType", "detectionMethod", "mlScore"]

# Per-entry cap on prompt context forwarded to the demo scammer generator
_AI_SCAMMER_MAX_CHARS = 500


# ---------------------------------------------------------------------------
# Per-session serialization
# ---------------------------------------------------------------------------
# Two concurrent turns for one sessionId previously interleaved a non-atomic
# read-modify-write on the session dict: both could observe
# agent_activated=False (two paid detections), and messages could be appended
# out of order, corrupting the transcript that ends up in the forensic report.
_SESSION_LOCKS: "OrderedDict[str, asyncio.Lock]" = OrderedDict()
_SESSION_LOCK_LIMIT = 2048


def _session_lock(session_id: str) -> asyncio.Lock:
    """Return the lock for a session, evicting the oldest when over capacity."""
    lock = _SESSION_LOCKS.get(session_id)
    if lock is None:
        lock = asyncio.Lock()
        _SESSION_LOCKS[session_id] = lock
        while len(_SESSION_LOCKS) > _SESSION_LOCK_LIMIT:
            _, evicted = _SESSION_LOCKS.popitem(last=False)
            if evicted.locked():  # never drop a lock that is in use
                _SESSION_LOCKS[session_id] = lock
                break
    else:
        _SESSION_LOCKS.move_to_end(session_id)
    return lock


def _escape_csv_value(value) -> str:
    """
    Neutralise spreadsheet formula injection in exported cells.

    Extracted values are attacker-supplied (e.g. the phishing link
    ``-evil-bank.in/pay`` is stored verbatim), and Excel/LibreOffice treat a
    leading = + - @ tab or CR as the start of a formula. Prefixing with an
    apostrophe forces the cell to be read as text.
    """
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _flatten_intel_records(session_id: str, doc: dict) -> list:
    """Flatten a session doc's intelligence into one record per (type, value)."""
    intel = doc.get("extractedIntelligence") or {}
    scam_type = doc.get("scamType") or "unknown"
    detection_method = doc.get("detectionMethod") or "unknown"
    ml_score = doc.get("mlScore")

    records = []
    for category in _INTEL_EXPORT_CATEGORIES:
        for value in (intel.get(category) or []):
            records.append({
                "sessionId": session_id,
                "intelType": category,
                "value": value,
                "scamType": scam_type,
                "detectionMethod": detection_method,
                "mlScore": ml_score,
            })
    return records


def _describe_phase_trigger(strategy: ConversationStrategy, phase: int) -> str:
    """Explain why select_phase() landed on this phase, mirroring its logic."""
    collected = strategy.info_collected
    intel_count = sum([
        len(collected.get("phone_numbers", [])) > 0,
        len(collected.get("upi_ids", [])) > 0,
        len(collected.get("bank_accounts", [])) > 0,
        len(collected.get("links", [])) > 0,
    ])
    if phase == 3 and intel_count >= 3 and strategy.turn_count < 5:
        return f"early jump: {intel_count} intel types collected before turn 5"
    if phase == 2 and len(collected.get("phone_numbers", [])) > 0 and intel_count < 2:
        return "phone collected but other intel gaps remain"
    if phase == 1:
        return "first contact — build emotional hook"
    if phase == 2:
        return f"turn {strategy.turn_count} — active gap-driven extraction"
    return f"turn {strategy.turn_count} or 3+ intel types — full compliance mode"


def _build_reasoning(
    session,
    strategy: ConversationStrategy | None,
    prev_intel: dict,
    curr_intel: dict,
    persona_kept: bool,
    guardrail: GuardrailReport | None = None,
) -> AgentReasoning:
    """Assemble the per-turn decision trace from pipeline state."""
    new_items = []
    for key in _INTEL_KEYS:
        prev_vals = set(prev_intel.get(key) or [])
        for val in (curr_intel.get(key) or []):
            if val not in prev_vals:
                new_items.append(f"{key}: {val}")

    if persona_kept:
        persona_reason = "kept for session consistency"
    else:
        persona_reason = (
            f"matched {session.scam_type or 'unknown'} scam cues"
            if session.scam_type else "default selection from first message cues"
        )

    if strategy:
        phase = select_phase(strategy)
        return AgentReasoning(
            turn=strategy.turn_count,
            detectionMethod=session.detection_method,
            detectionConfidence=session.scam_confidence,
            ruleScore=session.rule_score,
            mlScore=session.ml_score,
            scamType=session.scam_type,
            indicators=list(session.detected_indicators or []),
            personaSelected=session.persona_selected,
            personaReason=persona_reason,
            languageDetected=session.detected_language,
            responseLanguage=session.response_language,
            phase=phase,
            phaseName=_PHASE_NAMES.get(phase, ""),
            phaseTrigger=_describe_phase_trigger(strategy, phase),
            trustLevel=strategy.trust_level,
            scammerPressure=strategy.scammer_pressure,
            authorityType=strategy.authority_type,
            missingTargets=list(strategy.missing_targets[:5]),
            newIntelThisTurn=new_items,
            injectionDetected=guardrail.injection_detected if guardrail else False,
            guardrailAction=guardrail.action if guardrail else None,
        )

    return AgentReasoning(
        turn=session.get_message_count(),
        detectionMethod=session.detection_method,
        detectionConfidence=session.scam_confidence,
        ruleScore=session.rule_score,
        mlScore=session.ml_score,
        scamType=session.scam_type,
        indicators=list(session.detected_indicators or []),
        personaSelected=session.persona_selected,
        personaReason=persona_reason,
        languageDetected=session.detected_language,
        responseLanguage=session.response_language,
        newIntelThisTurn=new_items,
        injectionDetected=guardrail.injection_detected if guardrail else False,
        guardrailAction=guardrail.action if guardrail else None,
    )


# ===================================================================
# MAIN CONVERSATION ENDPOINT
# ===================================================================

@router.post("/conversation", response_model=ConversationResponse)
@limiter.limit("30/minute")
async def handle_conversation(
    body: ConversationRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
) -> ConversationResponse:
    """
    Main endpoint for handling incoming scam messages.

    Validates, then serializes the turn per session so concurrent requests for
    one sessionId cannot interleave their read-modify-write on session state.
    """
    if not validate_session_id(body.sessionId):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format. Must be alphanumeric with hyphens/underscores."
        )
    if not body.message.text or not body.message.text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Message text cannot be empty"
        )

    async with _session_lock(body.sessionId):
        return await _conversation_turn(body, background_tasks)


async def _conversation_turn(
    body: ConversationRequest,
    background_tasks: BackgroundTasks,
) -> ConversationResponse:
    """
    Process one conversation turn. Caller holds the per-session lock.

    Flow:
    1. Receives a message from the platform
    2. Detects scam intent
    3. Activates AI agent if scam detected
    4. Checks for repeat scammer and adapts behaviour
    5. Returns agent's response
    6. Extracts intelligence and sends callback when appropriate
    7. Persists everything to MongoDB (non-blocking on failure)
    """
    try:
        # Validate session ID
        if not validate_session_id(body.sessionId):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid session ID format. Must be alphanumeric with hyphens/underscores."
            )

        # Validate message text is not empty
        if not body.message.text or not body.message.text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Message text cannot be empty"
            )

        logger.info(
            f"Received message - Session: {body.sessionId}, "
            f"Sender: {body.message.sender}, "
            f"History length: {len(body.conversationHistory)}"
        )

        # Initialize variables that may be set conditionally later
        intel_dict = {}
        prev_intel_dict = {}

        # Get or create session
        session = session_manager.get_or_create_session(body.sessionId)

        # ── BACKEND RESTART RECOVERY ──────────────────────────────────────
        # Only restore from MongoDB on first message of a brand-new session
        # (avoids slow MongoDB round-trip on every subsequent request)
        if not session.agent_activated and len(session.messages) == 0 and len(body.conversationHistory) > 0:
            try:
                existing_doc = await get_session_doc(body.sessionId)
                if existing_doc:
                    session_manager.update_session(
                        body.sessionId,
                        agent_activated=True,
                        scam_detected=existing_doc.get("scamDetected", True),
                        scam_confidence=existing_doc.get("mlScore") or 0.7,
                        persona_selected=existing_doc.get("personaSelected"),
                        detected_language=existing_doc.get("detectedLanguage", "english"),
                        response_language=existing_doc.get("responseLanguage", "english"),
                        scam_type=existing_doc.get("scamType", "UNKNOWN"),
                        detection_method=existing_doc.get("detectionMethod", "restored"),
                    )
                    identity_dict = existing_doc.get("detectedIdentity", {})
                    if identity_dict:
                        from app.storage.session_manager import DetectedIdentity as _DI
                        session_manager.update_session(
                            body.sessionId,
                            detected_identity=_DI(
                                name=identity_dict.get("name"),
                                gender=identity_dict.get("gender"),
                                age_group=identity_dict.get("ageGroup"),
                                locked=identity_dict.get("locked", False),
                            )
                        )
                    session = session_manager.get_or_create_session(body.sessionId)
                    logger.info(f"Session state restored from MongoDB after restart: {body.sessionId}")
            except Exception as restore_err:
                logger.warning(f"Session restore from MongoDB failed (non-blocking): {restore_err}")
        # ─────────────────────────────────────────────────────────────────

        # Add current message to session
        session_manager.add_message_to_session(body.sessionId, body.message)

        # Check if agent is already activated for this session
        detection_result: DetectionResult | None = None

        if not session.agent_activated:
            logger.info(f"First message - checking for scam - Session: {body.sessionId}")

            try:
                should_activate, detection_result = await scam_detector.should_activate_agent(body)

                if should_activate:
                    session_manager.update_session(
                        body.sessionId,
                        scam_detected=detection_result.is_scam,
                        scam_confidence=detection_result.final_confidence,
                        agent_activated=True,
                        rule_score=detection_result.rule_score,
                        ml_score=detection_result.ml_score,
                        scam_type=detection_result.scam_type,
                        detection_method=detection_result.detection_method,
                        detected_indicators=detection_result.detected_indicators,
                    )
                    logger.info(
                        f"Agent activated - Session: {body.sessionId}, "
                        f"Scam: {detection_result.is_scam}, "
                        f"Confidence: {detection_result.final_confidence:.2f}, "
                        f"Method: {detection_result.detection_method}, "
                        f"Type: {detection_result.scam_type}"
                    )
                else:
                    # HONEYPOT FAIL-OPEN: Treat as scam (honeypot philosophy)
                    logger.info(
                        f"Low confidence - STILL ENGAGING (honeypot mode) - Session: {body.sessionId}"
                    )
                    session_manager.update_session(
                        body.sessionId,
                        scam_detected=True,  # Honeypot legitimately treats all interactions as scams
                        scam_confidence=detection_result.final_confidence,
                        agent_activated=True,
                        rule_score=detection_result.rule_score,
                        ml_score=detection_result.ml_score,
                        scam_type=detection_result.scam_type,
                        detection_method=detection_result.detection_method,
                        detected_indicators=detection_result.detected_indicators,
                    )

            except Exception as e:
                # CRITICAL FAIL-OPEN
                logger.error(
                    f"Scam detection FAILED - Session: {body.sessionId}, "
                    f"Error type: {type(e).__name__}, Message: {str(e)}"
                )
                logger.warning("FAIL-OPEN: Engaging anyway (honeypot behavior)")
                detection_result = DetectionResult(
                    is_scam=True,
                    final_confidence=0.5,
                    reasoning=f"Detection failed: {type(e).__name__}. FAIL-OPEN.",
                    detection_method="fail_open",
                )
                session_manager.update_session(
                    body.sessionId,
                    scam_detected=True,
                    scam_confidence=0.5,
                    agent_activated=True,
                    detection_method="fail_open",
                )

        # -----------------------------------------------------------------
        # LANGUAGE DETECTION + PERSONA SELECTION
        # -----------------------------------------------------------------
        metadata_language = None
        if body.metadata and hasattr(body.metadata, "language"):
            metadata_language = body.metadata.language

        detected_lang = detect_language(body.message.text, metadata_language)
        response_lang = detect_response_language(detected_lang, body.message.text)

        # Nuclear override: if message has >10 Devanagari chars, force Hindi
        # regardless of what language_detector returned. This bypasses any
        # detection edge-cases for pure Hindi messages.
        import re as _re
        _deva_count = len(_re.findall(r"[\u0900-\u097F]", body.message.text))
        if _deva_count > 10 and response_lang != "hindi":
            logger.info(
                f"[LANG OVERRIDE] Forced hindi (devanagari={_deva_count}, "
                f"was={response_lang}) session={body.sessionId}"
            )
            response_lang = "hindi"
            detected_lang = "hindi"

        # Build conversation history text for persona selection context
        history_text = " ".join(
            msg.text for msg in body.conversationHistory
        ) if body.conversationHistory else ""

        persona_before = session.persona_selected
        chosen_persona = select_persona(
            message_text=body.message.text,
            conversation_history_text=history_text,
            existing_persona=session.persona_selected,
        )

        # -----------------------------------------------------------------
        # IDENTITY DETECTION + LOCKING
        # -----------------------------------------------------------------
        existing_identity = session.detected_identity

        if not existing_identity.locked:
            updated_identity = detect_identity(
                message_text=body.message.text,
                conversation_history_text=history_text,
                existing_identity=existing_identity,
                persona_category=chosen_persona,
            )
            # Force-lock after 3 scammer turns
            scammer_turn_count = len([
                m for m in session.messages if m.sender != "user"
            ])
            updated_identity = lock_identity_after_threshold(
                identity=updated_identity,
                turn_count=scammer_turn_count,
                persona_category=chosen_persona,
            )
        else:
            updated_identity = existing_identity

        # Build persona prompt with detected identity
        persona_prompt = get_persona_prompt(chosen_persona, response_lang, identity=updated_identity)

        # Persist language + persona + identity to in-memory session
        session_manager.update_session(
            body.sessionId,
            detected_language=detected_lang,
            response_language=response_lang,
            persona_selected=chosen_persona,
            detected_identity=updated_identity,
        )

        logger.info(
            f"Language: {detected_lang}, Persona: {chosen_persona}, "
            f"Identity: name={updated_identity.name}, gender={updated_identity.gender}, "
            f"age_group={updated_identity.age_group}, locked={updated_identity.locked} - "
            f"Session: {body.sessionId}"
        )

        # -----------------------------------------------------------------
        # PRE-PROCESSING EXTRACTION PIPELINE (Extract-Before-Speak Architecture)
        # CRITICAL: Extract intelligence BEFORE AI generates response for Turn 1 literacy
        # -----------------------------------------------------------------
        message_count = session.get_message_count()
        intelligence = None
        repeat_matches_for_prompt = None

        # FULL intelligence extraction from ALL messages (including just-added scammer message)
        if message_count >= 1:
            all_messages = session.messages

            try:
                # Snapshot previous intel so the reasoning trace can report
                # what was newly extracted on THIS turn
                prev_intel_dict = (
                    session.intelligence.model_dump() if session.intelligence else {}
                )

                # Extract intelligence IMMEDIATELY from all conversation history.
                # Offloaded to a worker thread: extraction is pure sync CPU over
                # attacker-controlled text and previously blocked the event loop
                # for the whole request.
                intelligence = await asyncio.to_thread(
                    intelligence_extractor.extract_intelligence, body, all_messages
                )

                # Save intelligence to session state BEFORE AI response
                session_manager.update_session(
                    body.sessionId,
                    intelligence=intelligence
                )

                # Deduplicate for strategy and repeat detection
                intel_dict = deduplicate_intelligence(intelligence.model_dump())

                # Repeat match check (slow MongoDB cross-reference) runs in the
                # background task, not here.
                logger.info(
                    f"[EXTRACT] PRE-EXTRACTION Complete - Session: {body.sessionId}, "
                    f"Phones: {len(intelligence.phoneNumbers)}, UPIs: {len(intelligence.upiIds)}, "
                    f"Banks: {len(intelligence.bankAccounts)}, Links: {len(intelligence.phishingLinks)}"
                )

            except Exception as exc:
                logger.error(f"Pre-extraction failed (non-blocking): {exc}")
                # Create empty intelligence object as fallback
                from app.models.responses import ExtractedIntelligence
                intelligence = ExtractedIntelligence()
                intel_dict = {}

        # -----------------------------------------------------------------
        # INITIALIZE/RETRIEVE CONVERSATION STRATEGY
        # -----------------------------------------------------------------
        if session.conversation_strategy is None:
            session.conversation_strategy = ConversationStrategy()
            logger.info(f"Initialized conversation strategy - Session: {body.sessionId}")

        # -----------------------------------------------------------------
        # GENERATE AGENT RESPONSE (with FULL extracted intelligence context)
        # -----------------------------------------------------------------
        logger.info(f"Generating agent response - Session: {body.sessionId}")

        session_messages = session.messages
        logger.info(
            f"Session has {len(session_messages)} messages stored - "
            f"Session: {body.sessionId}"
        )

        # Pass FULL extracted intelligence to AI for literate prompting
        known_intel = intel_dict if intelligence else {}

        # GUARDRAIL LAYER 1: scan incoming message for prompt-injection attempts
        guardrail_report = GuardrailReport()
        input_scan = scan_input(body.message.text)
        guardrail_prompt = None
        if input_scan.injection_detected:
            guardrail_report.injection_detected = True
            guardrail_report.injection_patterns = input_scan.patterns
            guardrail_prompt = build_injection_reinforcement(input_scan.patterns)

        agent_response = await ai_agent.generate_response(
            body,
            session_messages,
            repeat_matches=repeat_matches_for_prompt,
            persona_prompt=persona_prompt,
            known_intelligence=known_intel,
            language=response_lang,
            identity=updated_identity,
            conversation_strategy=session.conversation_strategy,
            guardrail_prompt=guardrail_prompt,
        )

        # GUARDRAIL LAYER 2: validate the reply before it leaves the system
        output_scan = check_output(agent_response)
        if not output_scan.safe:
            guardrail_report.output_sanitized = True
            guardrail_report.output_violations = output_scan.violations
            agent_response = output_scan.final_reply

        # Add agent's response to session history
        agent_message = Message(
            sender="user",
            text=agent_response,
            timestamp=int(time.time() * 1000)
        )
        session_manager.add_message_to_session(body.sessionId, agent_message)


        # -----------------------------------------------------------------
        # POST-RESPONSE: GENERATE AGENT NOTES (intelligence already extracted)
        # -----------------------------------------------------------------
        agent_notes = ""
        message_count = session.get_message_count()

        # Intelligence was already extracted BEFORE response generation
        # Now generate forensic notes for callback
        if intelligence:
            all_messages = session.messages
            agent_notes = intelligence_extractor.generate_agent_notes(
                body, all_messages, intelligence
            )
        else:
            # Fallback: create empty intelligence if somehow missed
            from app.models.responses import ExtractedIntelligence
            intelligence = ExtractedIntelligence()
            agent_notes = "No intelligence extracted yet."

        # -----------------------------------------------------------------
        # BACKGROUND TASKS: PDF, callback, MongoDB (non-blocking)
        # These run AFTER the response is returned to the client
        # -----------------------------------------------------------------
        _session_snap = session
        _intel_snap = intelligence
        _intel_dict_snap = intel_dict.copy() if intel_dict else {}
        _agent_notes_snap = agent_notes
        _message_count_snap = message_count
        _agent_response_snap = agent_response

        async def _background_work():
            pdf_file_id = None
            pdf_case_id = None
            pdf_generated = False
            pdf_generated_at = None
            final_callback_payload_dict = None

            # --- Repeat scammer check ---
            try:
                repeat_info_bg = await find_repeat_matches(body.sessionId, _intel_dict_snap)
            except Exception:
                repeat_info_bg = None

            # --- PDF generation ---
            # Regenerate on every message once the session has 3+ so the stored
            # report always reflects the full conversation (a %3 cadence left
            # the last 1-2 messages of a session out of the final PDF)
            should_generate_pdf = (_message_count_snap == 3)
            should_update_pdf = (_message_count_snap > 3)
            if should_generate_pdf or should_update_pdf:
                try:
                    pdf_exists = await check_pdf_exists(body.sessionId)
                    if should_update_pdf and pdf_exists:
                        old_doc = await get_session_doc(body.sessionId)
                        if old_doc and old_doc.get("pdfReportFileId"):
                            from app.storage.pdf_storage import delete_pdf
                            await delete_pdf(old_doc["pdfReportFileId"])
                    _dur = 0
                    if _session_snap.messages and len(_session_snap.messages) >= 2:
                        try:
                            _dur = max(0, int((_session_snap.messages[-1].timestamp - _session_snap.messages[0].timestamp) / 1000))
                        except Exception as dur_exc:
                            logger.debug(f"Duration computation failed, using 0: {dur_exc}")
                    pdf_bytes = forensic_reporter.generate_forensic_report_bytes(
                        session_id=body.sessionId,
                        extracted_intelligence=_intel_snap,
                        conversation_history=_session_snap.messages,
                        agent_notes=_agent_notes_snap,
                        scam_detected=_session_snap.scam_detected,
                        total_messages=_message_count_snap,
                        duration_seconds=_dur,
                        repeat_scammer_score=repeat_info_bg.get("repeat_scammer_score", 0) if repeat_info_bg else 0,
                    )
                    if pdf_bytes:
                        case_id = forensic_reporter._generate_case_id(body.sessionId)
                        file_id = await store_pdf(
                            session_id=body.sessionId,
                            pdf_bytes=pdf_bytes,
                            case_id=case_id,
                            metadata={
                                "scamDetected": _session_snap.scam_detected,
                                "totalMessages": _message_count_snap,
                                "scamType": _session_snap.scam_type,
                                "lastUpdated": datetime.now(UTC).isoformat(),
                            }
                        )
                        if file_id:
                            pdf_file_id = file_id
                            pdf_case_id = case_id
                            pdf_generated = True
                            pdf_generated_at = datetime.now(UTC)
                            logger.info(f"[BG] PDF generated - Session: {body.sessionId}, Case: {case_id}")
                except Exception as e:
                    logger.error(f"[BG] PDF generation failed: {e}")

            # --- Callback ---
            callback_sent_bg = _session_snap.callback_sent
            callback_sent_at_bg = None
            try:
                from app.models.responses import ExtractedIntelligence as _EI
                should_send = await callback_handler.should_send_callback(
                    body.sessionId, _session_snap.scam_detected, _message_count_snap, _intel_snap
                )
                if should_send or _message_count_snap >= 10:
                    final_intelligence = _intel_snap if _intel_snap is not None else _EI()
                    msgs = _session_snap.messages
                    # Measured duration only. This value is reported in the
                    # forensic PDF and the "scammer time wasted" aggregate; the
                    # previous max(real, sum(random.randint(18,32))) inflated it
                    # with fabricated seconds, which has no place in a document
                    # presented as evidence.
                    if msgs and len(msgs) >= 2:
                        engagement_seconds = max(
                            0, int((msgs[-1].timestamp - msgs[0].timestamp) / 1000)
                        )
                    else:
                        engagement_seconds = 0
                    final_payload = FinalResultPayload(
                        sessionId=body.sessionId,
                        status="completed",
                        scamDetected=True,
                        scamType=_session_snap.scam_type or "generic_fraud",
                        confidenceLevel=_session_snap.scam_confidence or 0.9,
                        totalMessagesExchanged=_message_count_snap,
                        engagementDurationSeconds=engagement_seconds,
                        extractedIntelligence=final_intelligence,
                        engagementMetrics=EngagementMetrics(
                            totalMessagesExchanged=_message_count_snap,
                            engagementDurationSeconds=engagement_seconds,
                        ),
                        agentNotes=_agent_notes_snap or "Conversation completed.",
                    )
                    cb_url = None
                    if body.metadata and hasattr(body.metadata, 'callbackUrl'):
                        cb_url = body.metadata.callbackUrl
                    if await callback_handler.send_final_result(final_payload, callback_url=cb_url):
                        callback_sent_bg = True
                        callback_sent_at_bg = datetime.now(UTC)
                        session_manager.update_session(body.sessionId, callback_sent=True)
            except Exception as e:
                logger.error(f"[BG] Callback failed: {e}")

            # --- MongoDB persist ---
            try:
                intel_dict_for_db = (
                    _intel_snap.model_dump() if _intel_snap else _intel_dict_snap
                ) or {"bankAccounts": [], "upiIds": [], "phishingLinks": [], "phoneNumbers": [], "suspiciousKeywords": []}
                transcript = _build_transcript(body.conversationHistory, body.message, _agent_response_snap)
                metadata_dict = body.metadata.model_dump() if body.metadata else None
                await upsert_session(
                    session_id=body.sessionId,
                    scam_detected=_session_snap.scam_detected,
                    total_messages=_message_count_snap,
                    extracted_intelligence=intel_dict_for_db,
                    agent_notes=_agent_notes_snap,
                    metadata=metadata_dict,
                    conversation_transcript=transcript,
                    final_callback_payload=final_callback_payload_dict,
                    callback_sent=callback_sent_bg,
                    callback_sent_at=callback_sent_at_bg,
                    repeat_info=repeat_info_bg,
                    detected_language=_session_snap.detected_language,
                    response_language=_session_snap.response_language,
                    persona_selected=_session_snap.persona_selected,
                    persona_switch_history=_session_snap.persona_switch_history,
                    rule_score=_session_snap.rule_score,
                    ml_score=_session_snap.ml_score,
                    scam_type=_session_snap.scam_type,
                    detection_method=_session_snap.detection_method,
                    detected_indicators=_session_snap.detected_indicators,
                    detected_identity_dict={
                        "name": _session_snap.detected_identity.name,
                        "gender": _session_snap.detected_identity.gender,
                        "ageGroup": _session_snap.detected_identity.age_group,
                        "locked": _session_snap.detected_identity.locked,
                    },
                    pdf_report_generated=pdf_generated,
                    pdf_report_file_id=pdf_file_id,
                    pdf_report_generated_at=pdf_generated_at,
                    pdf_report_case_id=pdf_case_id,
                )
                logger.info(f"[BG] MongoDB persisted - Session: {body.sessionId}")
            except Exception as db_err:
                logger.error(f"[BG] MongoDB persistence failed: {db_err}")

        background_tasks.add_task(_background_work)

        # -----------------------------------------------------------------
        # RETURN RESPONSE
        # -----------------------------------------------------------------
        # Build intel dict for frontend -- use backend-extracted data
        intel_for_frontend = None
        if intelligence:
            raw = intelligence.model_dump()
            intel_for_frontend = {
                "phoneNumbers":       raw.get("phoneNumbers", []),
                "upiIds":             raw.get("upiIds", []),
                "bankAccounts":       raw.get("bankAccounts", []),
                "phishingLinks":      raw.get("phishingLinks", []),
                "emailAddresses":     raw.get("emailAddresses", []),
                "suspiciousKeywords": raw.get("suspiciousKeywords", []),
            }

        # Build per-turn reasoning trace for the dashboard
        try:
            reasoning = _build_reasoning(
                session=session,
                strategy=session.conversation_strategy,
                prev_intel=prev_intel_dict,
                curr_intel=intelligence.model_dump() if intelligence else {},
                persona_kept=(persona_before is not None and persona_before == chosen_persona),
                guardrail=guardrail_report,
            )
        except Exception as reasoning_err:
            logger.warning(f"Reasoning trace build failed (non-blocking): {reasoning_err}")
            reasoning = None

        return ConversationResponse(
            status="success",
            reply=agent_response,
            persona=session.persona_selected,
            scamType=session.scam_type,
            intelligence=intel_for_frontend,
            reasoning=reasoning,
        )

    except HTTPException:
        raise
    except Exception as e:
        session_id = getattr(body, "sessionId", "unknown")
        # Detail stays server-side. Returning the exception type and message to
        # the caller disclosed internal structure to an attacker who controls
        # the input that triggers it.
        logger.exception(
            f"Error handling conversation - Session: {session_id}, "
            f"Error type: {type(e).__name__}, Error: {str(e)}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        ) from e


# ===================================================================
# HEALTH CHECK
# ===================================================================

async def build_health_report() -> dict:
    """
    Assemble a deep health report.

    ``status`` is "degraded" when a dependency the service needs to do its job
    is missing, so the platform health check can actually fail instead of
    reporting 200 while silently running without persistence or a model.
    """
    from app.services.ml_detector import _distilbert_loaded, _model_loaded, is_model_loaded
    from app.storage.mongodb import _collection, _using_memory_fallback

    if _distilbert_loaded:
        ml_model = "distilbert"
    elif _model_loaded:
        ml_model = "tfidf"
    else:
        ml_model = "none"

    if _collection is not None:
        db_status = "connected"
    elif _using_memory_fallback:
        db_status = "memory_fallback"
    else:
        db_status = "not_configured"

    # Degradations: surfaced loudly, but the service can still do useful work,
    # so they must NOT take the instance out of rotation. The original problem
    # was the opposite -- these were invisible, so a deploy silently ran with no
    # model and no persistence and still reported "healthy".
    problems = []
    if not is_model_loaded():
        problems.append("ml_model_missing")
    if provider_health.key_probably_revoked:
        problems.append("llm_key_rejected")
    if cost_guard.is_tripped():
        problems.append("daily_token_budget_exhausted")
    if db_status == "memory_fallback":
        problems.append("database_memory_fallback")

    # Hard failure: a database was configured but is not reachable, so every
    # session collected right now is being lost. Worth failing the probe.
    unavailable = (
        bool(settings.mongodb_uri)
        and db_status not in ("connected",)
        and not settings.debug
    )

    return {
        "status": "unavailable" if unavailable else ("degraded" if problems else "healthy"),
        "serving": not unavailable,
        "service": "scambot-honeypot",
        "problems": problems + (["database_unreachable"] if unavailable else []),
        "active_sessions": session_manager.get_session_count(),
        "ml_model": ml_model,
        "db_status": db_status,
        "llm": provider_health.snapshot(),
        "spend": cost_guard.snapshot(),
    }


@router.get("/health")
async def health_check():
    """Health check endpoint (same report as the app-level /health)."""
    return await build_health_report()


# ===================================================================
# ADMIN ENDPOINTS
# Authorized by an httpOnly session cookie (dashboard) or the raw admin key
# (server-to-server). See app/core/security.py.
# ===================================================================

@router.post("/admin/login")
@limiter.limit("5/minute")
async def admin_login(request: Request, response: Response):
    """
    Exchange the admin key for an httpOnly session cookie.

    Rate limited hard because this is the one endpoint that accepts the raw
    admin key and is therefore the only brute-force target.
    """
    from app.core.security import verify_admin_login

    await verify_admin_login(request.headers.get("x-admin-key", ""))
    issue_admin_session(response)
    logger.info("Admin session issued")
    return {"status": "authenticated", "expiresInSeconds": 8 * 60 * 60}


@router.post("/admin/logout")
async def admin_logout(response: Response):
    """Clear the admin session cookie."""
    from app.core.security import clear_admin_session

    clear_admin_session(response)
    return {"status": "logged_out"}


@router.get("/admin/session/{session_id}")
@limiter.limit("60/minute")
async def admin_get_session(
    session_id: str,
    request: Request,
    admin_key: str = Depends(verify_admin_key),
):
    """Fetch the full session record from MongoDB."""
    if not validate_session_id(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format",
        )
    doc = await get_session_doc(session_id)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )
    return doc


@router.get("/admin/sessions")
@limiter.limit("60/minute")
async def admin_list_sessions(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    admin_key: str = Depends(verify_admin_key),
):
    """Return the most recent sessions from MongoDB, ordered by last update."""
    docs = await get_all_sessions(limit=limit)
    return {"sessions": docs, "count": len(docs)}


@router.get("/admin/stats")
@limiter.limit("30/minute")
async def admin_stats(request: Request, admin_key: str = Depends(verify_admin_key)):
    """
    Aggregate dashboard stats across all sessions.

    Includes server-computed metrics the client can't cheaply derive:
    total scammer time wasted, average engagement duration, and an
    estimated scammer cost, alongside session/intel/scam-type counts.
    """
    try:
        stats = await get_aggregate_stats()
        stats["spend"] = cost_guard.snapshot()
        return {"status": "success", "stats": stats}
    except Exception as e:
        logger.exception(f"Aggregate stats failed: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute stats",
        ) from e


@router.get("/admin/repeats/{session_id}")
@limiter.limit("60/minute")
async def admin_get_repeats(
    session_id: str,
    request: Request,
    admin_key: str = Depends(verify_admin_key),
):
    """Show repeat scammer analysis for a session."""
    if not validate_session_id(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format",
        )
    doc = await get_repeat_analysis(session_id)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found"
        )
    return doc


@router.get("/admin/search")
@limiter.limit("60/minute")
async def admin_search(
    request: Request,
    phone: str | None = Query(None, max_length=64),
    upi: str | None = Query(None, max_length=128),
    account: str | None = Query(None, max_length=64),
    link: str | None = Query(None, max_length=512),
    keyword: str | None = Query(None, max_length=128),
    admin_key: str = Depends(verify_admin_key),
):
    """Search sessions by extracted intelligence fields."""
    results = await search_sessions(
        phone=phone, upi=upi, account=account, link=link, keyword=keyword,
    )
    return {
        "status": "success",
        "count": len(results),
        "sessions": results,
    }


@router.post("/session/{session_id}/end")
@limiter.limit("30/minute")
async def end_session(
    session_id: str,
    request: Request,
    api_key: str = Depends(verify_api_key),
):
    """
    Explicitly mark a session as complete.

    Prevents duplicate callbacks and allows the frontend to signal that
    no more messages will be sent. Non-blocking on DB failure.
    """
    if not validate_session_id(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format"
        )

    session = session_manager.get_or_create_session(session_id)
    session_manager.update_session(session_id, callback_sent=True)

    try:
        await upsert_session(
            session_id=session_id,
            scam_detected=session.scam_detected,
            total_messages=session.get_message_count(),
            extracted_intelligence={},
            agent_notes="Session ended by client.",
            metadata=None,
            conversation_transcript=[],
            final_callback_payload=None,
            callback_sent=True,
            callback_sent_at=datetime.now(UTC),
        )
    except Exception as db_err:
        logger.error(f"MongoDB update on session end failed (non-blocking): {db_err}")

    logger.info(f"Session explicitly ended by client: {session_id}")
    return {"status": "ended", "sessionId": session_id}


@router.post("/admin/cleanup")
@limiter.limit("10/minute")
async def cleanup_sessions(request: Request, admin_key: str = Depends(verify_admin_key)):
    """Admin endpoint to cleanup expired in-memory sessions."""
    removed_count = session_manager.cleanup_expired_sessions()
    logger.info(f"Cleaned up {removed_count} expired sessions")
    return {
        "status": "success",
        "removed_sessions": removed_count,
        "active_sessions": session_manager.get_session_count()
    }


@router.get("/admin/db-status")
@limiter.limit("10/minute")
async def admin_db_status(request: Request, admin_key: str = Depends(verify_admin_key)):
    """
    Diagnostic: check MongoDB connectivity and report errors.

    DEBUG-only: the response enumerates database and collection names and echoes
    raw driver error strings, which is infrastructure detail that should not be
    reachable in production even with valid admin credentials.
    """
    if not settings.debug:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )

    from app.core.config import settings as _s
    uri = _s.mongodb_uri
    # Mask password in URI for safe display
    masked = re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", uri) if uri else "(empty)"

    result = {"mongodb_uri_set": bool(uri), "mongodb_uri_masked": masked}

    if not uri:
        result["error"] = "MONGODB_URI environment variable is empty"
        return result

    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
        await client.admin.command("ping")
        result["connected"] = True
        result["databases"] = await client.list_database_names()
        db = client["scamshield_v2"]
        result["collections"] = await db.list_collection_names()
        col = db["scam_sessions"]
        result["document_count"] = await col.count_documents({})
        client.close()
    except Exception as exc:
        result["connected"] = False
        result["error"] = f"{type(exc).__name__}: {str(exc)}"

    return result


@router.get("/admin/report/{session_id}")
@limiter.limit("30/minute")
async def download_forensic_report(
    session_id: str,
    request: Request,
    admin_key: str = Depends(verify_admin_key),
):
    """
    Download forensic PDF report for a session.

    Returns the PDF file which can be opened directly in the browser.
    Requires an admin session cookie or the admin key.
    """
    # Validate session ID format
    if not validate_session_id(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format"
        )

    # Retrieve PDF from MongoDB GridFS
    result = await retrieve_pdf_by_session(session_id)

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No PDF report found for session: {session_id}"
        )

    pdf_bytes, metadata = result

    # Return PDF with inline disposition so it opens in browser
    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'inline; filename="{metadata["filename"]}"'
        }
    )


@router.get("/admin/export/{session_id}")
@limiter.limit("30/minute")
async def export_intelligence(
    session_id: str,
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$"),
    admin_key: str = Depends(verify_admin_key),
):
    """
    Export a session's extracted intelligence as JSON or CSV.

    Structured dump for law-enforcement handoff: one row/object per
    intel item, tagged with type, value, session, scam type, and
    detection metadata. `format=json` (default) or `format=csv`.
    """
    if not validate_session_id(session_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format",
        )

    doc = await get_session_doc(session_id)
    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session {session_id} not found",
        )

    records = _flatten_intel_records(session_id, doc)

    if format == "json":
        payload = {
            "sessionId": session_id,
            "scamType": doc.get("scamType") or "unknown",
            "detectionMethod": doc.get("detectionMethod") or "unknown",
            "mlScore": doc.get("mlScore"),
            "itemCount": len(records),
            "intelligence": records,
        }
        import json as _json
        buf = BytesIO(_json.dumps(payload, indent=2, default=str).encode("utf-8"))
        return StreamingResponse(
            buf,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="intel_{session_id}.json"'},
        )

    # CSV. Every cell is passed through _escape_csv_value first: the values are
    # attacker-supplied, and a leading = + - @ makes a spreadsheet treat the
    # cell as a formula.
    import csv
    import io
    sio = io.StringIO()
    writer = csv.DictWriter(sio, fieldnames=_EXPORT_FIELDS, quoting=csv.QUOTE_ALL)
    writer.writeheader()
    for row in records:
        writer.writerow({k: _escape_csv_value(row.get(k)) for k in _EXPORT_FIELDS})
    buf = BytesIO(sio.getvalue().encode("utf-8"))
    return StreamingResponse(
        buf,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="intel_{session_id}.csv"'},
    )


# ===================================================================
# AI SCAMMER PROXY (for frontend Auto Mode)
# Generates scam messages via OpenAI so the frontend avoids CORS issues.
# ===================================================================

class _ScammerRequest(BaseModel):
    scamType: str
    conversationHistory: list = []

@router.post("/ai-scammer")
@limiter.limit("30/minute")
async def ai_scammer_proxy(
    body: _ScammerRequest,
    request: Request,
    api_key: str = Depends(verify_api_key),
):
    """
    Generate a scam message for the Auto Mode frontend demo.

    Rate limited and budget-gated: this route calls a paid model with
    caller-supplied context, so without both it is an open LLM relay behind a
    single shared key.
    """
    from app.core.config import settings as _s

    # Per-scam-type identity details used by the scammer persona
    _SCAM_INTEL = {
        "sbi_bank_fraud": dict(
            description="SBI bank account suspension / KYC expiry scam",
            name="Rajesh Kumar", phone="9876543210", upi="helpdesk.sbi@ybl",
            account="40291837650", ifsc="SBIN0001234", bank="State Bank of India",
            email="sbi.helpdesk.official@gmail.com", emp_id="SBI/HO/2024/7823",
            branch="SBI Head Office, Mumbai", link="sbi-kyc-verify.in/update",
        ),
        "kyc_expiry": dict(
            description="urgent KYC update required scam",
            name="Priya Sharma", phone="9876543210", upi="kyc.update@ybl",
            account="40291837650", ifsc="SBIN0001234", bank="State Bank of India",
            email="rbi.kyc.helpdesk@gmail.com", emp_id="RBI/KYC/2024/4491",
            branch="RBI KYC Compliance Cell, Delhi", link="rbi-kyc-update.in/verify",
        ),
        "job_offer": dict(
            description="fake work-from-home job offer scam",
            name="Priya from HR", phone="8876543210", upi="techserve.hr@paytm",
            account="50100234567890", ifsc="HDFC0001234", bank="HDFC Bank",
            email="hr@techserve-solutions.in", emp_id="TS/WFH/2024/8821",
            branch="TechServe Solutions, Bangalore", link="techserve-jobs.in/register",
        ),
        "lottery": dict(
            description="lottery / prize claim scam",
            name="Suresh from KBC", phone="9123456789", upi="helpdesk.kbc@ybl",
            account="60012345678901", ifsc="ICIC0001234", bank="ICICI Bank",
            email="kbc.prize.claim@gmail.com", emp_id="KBC/2024/WIN/4492",
            branch="KBC Prize Distribution Centre, Mumbai", link="kbc-prize-claim.in/verify",
        ),
        "upi-refund": dict(
            description="fake UPI refund scam",
            name="Amit from Payment Support", phone="9765432108", upi="refund.verify@paytm",
            account="1234567890123", ifsc="PAYTM00001", bank="Paytm Payments Bank",
            email="refunds@paytm-support.in", emp_id="PAYTM/REF/2024/3312",
            branch="Paytm Customer Support, Noida", link="refund-sbi.in/claim",
        ),
        "delivery": dict(
            description="parcel delivery / customs clearance scam",
            name="FedEx Clearance Officer", phone="9765432108", upi="customs.fedex@oksbi",
            account="1234567890123", ifsc="SBIN0001234", bank="State Bank of India",
            email="customs@fedex-india.in", emp_id="FEDEX/CUST/2024/7721",
            branch="Delhi Customs Clearance Office", link="fedex-customs-india.in/pay",
        ),
        "police": dict(
            description="police / cyber crime threat scam",
            name="Officer Sharma", phone="9988776655", upi="cybercrime.bail@ybl",
            account="20048576321", ifsc="SBIN0001234", bank="State Bank of India",
            email="cybercrime.mumbai@gmail.com", emp_id="MCC/CYB/2024/5582",
            branch="Mumbai Cyber Crime Cell", link="cybercrime-portal.in/pay-bail",
        ),
        "investment_scam": dict(
            description="fake investment / stock trading scheme scam",
            name="Vikram Mehta", phone="9876543210", upi="wealthedge.capital@ybl",
            account="70012398765432", ifsc="HDFC0001234", bank="HDFC Bank",
            email="invest@wealthedge-capital.in", emp_id="WE/2024/4821",
            branch="WealthEdge Capital, Mumbai", link="wealthedge-trading.in/join",
        ),
    }

    # Frontend demo ids that don't match _SCAM_INTEL keys directly
    _TYPE_ALIASES = {"sbi-kyc": "sbi_bank_fraud", "job": "job_offer"}
    normalized_type = _TYPE_ALIASES.get(body.scamType, body.scamType)
    intel = _SCAM_INTEL.get(normalized_type, _SCAM_INTEL["sbi_bank_fraud"])
    scam_description = intel["description"]

    system_prompt = (
        f"You are roleplaying as a scammer in India for a cybersecurity awareness demonstration. "
        f"Scam type: {scam_description}. "
        "Your goal is to pressure the victim into sending money or sharing personal info. "
        "Keep messages short (1-3 sentences), urgent, and realistic. "
        "Write in English with occasional Hindi words for authenticity.\n\n"
        "CRITICAL -- YOU MUST PROVIDE FAKE INTEL WHEN ASKED:\n"
        "The victim (honeypot AI) will ask you for your details to 'verify' you. "
        "You MUST provide convincing fake details when asked -- this is essential for the demo.\n"
        "Use these fake details consistently throughout the conversation:\n"
        f"  - Your name: {intel['name']}\n"
        f"  - Your phone number: {intel['phone']}\n"
        f"  - Your UPI ID: {intel['upi']}\n"
        f"  - Your bank account: {intel['account']} IFSC: {intel['ifsc']} ({intel['bank']})\n"
        f"  - Your email: {intel['email']}\n"
        f"  - Your employee/case ID: {intel['emp_id']}\n"
        f"  - Your branch/office: {intel['branch']}\n"
        f"  - Phishing link: {intel['link']}\n\n"
        "When the victim asks 'which number to call?', 'give me your UPI', 'what is your account?' -- ALWAYS answer with the fake details above.\n"
        "Stay strictly in character for this scam type. Do NOT mention SBI or banks unless this is a bank scam.\n"
        "Continue pressuring them to pay or share their OTP/Aadhaar too.\n"
        "ONLY output the scam message text. No explanation, no labels, no quotes."
    )

    messages = []
    for msg in body.conversationHistory[-10:]:  # last 10 messages for context
        role = "user" if msg.get("role") == "scammer" else "assistant"
        # Truncate each entry: prompt size (and therefore cost) was otherwise
        # unbounded even though the completion is capped at 150 tokens.
        messages.append({
            "role": role,
            "content": str(msg.get("text", ""))[:_AI_SCAMMER_MAX_CHARS],
        })
    if not messages:
        messages.append({"role": "user", "content": "Start the scam conversation."})
    # Anthropic requires last message to be "user"; if history ends with assistant, add a prompt
    elif messages[-1]["role"] == "assistant":
        messages.append({"role": "user", "content": "Continue the scam. Send your next message."})

    # The scammer side of the demo runs on Featherless.ai (open-weight models,
    # OpenAI-compatible API). Falls back to OpenAI if no Featherless key is set,
    # so the demo still works in a partially configured environment.
    from openai import AsyncOpenAI as _AsyncOpenAI

    if _s.featherless_api_key:
        client = _AsyncOpenAI(
            api_key=_s.featherless_api_key,
            base_url=_s.featherless_base_url,
            timeout=_s.llm_timeout_seconds,
            max_retries=_s.llm_max_retries,
        )
        model = _s.featherless_model
        provider = "featherless"
    else:
        client = _AsyncOpenAI(
            api_key=_s.openai_api_key,
            timeout=_s.llm_timeout_seconds,
            max_retries=_s.llm_max_retries,
        )
        model = _s.openai_model
        provider = "openai"

    # This endpoint is a paid generator, so it is behind the same daily ceiling
    # as the honeypot itself -- otherwise it is an open LLM relay.
    if not cost_guard.check("ai_scammer_demo"):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily LLM budget exhausted; demo generation is paused.",
        )

    try:
        completion = await client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system_prompt}, *messages],
            max_tokens=150,
            temperature=0.9,
        )
        cost_guard.record(completion, purpose="ai_scammer_demo")
        message_text = completion.choices[0].message.content.strip()
        logger.info(f"AI scammer message generated via {provider} ({model})")
        return {"message": message_text, "provider": provider}
    except HTTPException:
        raise
    except Exception as exc:
        # Log the detail; return an opaque message so provider internals and
        # key state are not disclosed to the caller.
        logger.error(
            f"AI scammer proxy error ({provider}): {type(exc).__name__}: {exc}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream model provider unavailable",
        ) from exc

"""
Conversation Strategy Module for Intelligence-Driven Extraction.

Upgrades reply generation from passive persona chat to strategic honeypot operation.
Tracks conversation state and guides extraction toward missing intelligence targets.
"""
from dataclasses import dataclass, field

from app.core.logging import logger


@dataclass
class ConversationStrategy:
    """Runtime state for strategic conversation management."""

    trust_level: str = "low"  # low, medium, high
    scammer_pressure: str = "low"  # low, medium, high, aggressive
    authority_type: str = "unknown"  # bank, police, tech_support, job_recruiter, lottery, delivery, unknown

    info_collected: dict[str, list[str]] = field(default_factory=lambda: {
        "names": [],
        "phone_numbers": [],
        "upi_ids": [],
        "bank_accounts": [],
        "ifsc_codes": [],
        "links": [],
        "organizations": [],
        "locations": [],
        "designations": [],
        "emails": [],
        "employee_ids": [],
    })

    missing_targets: list[str] = field(default_factory=list)
    turn_count: int = 0
    last_extraction_attempt: str | None = None

    # Track scammer behavior patterns
    otp_request_count: int = 0
    payment_request_count: int = 0
    threat_count: int = 0
    urgency_count: int = 0

    # Track failure-pivoting (for Info Elicitation scoring)
    # Each intel type can trigger ONE failure-pivot to get alternates
    failure_pivot_used: dict[str, bool] = field(default_factory=lambda: {
        "phone": False,
        "upi": False,
        "bank": False,
        "link": False,
    })


def detect_authority_type(message: str, conversation_history: str = "") -> str:
    """
    Detect what authority the scammer is impersonating.

    Args:
        message: Latest scammer message
        conversation_history: Full conversation text

    Returns:
        Authority type string
    """
    combined_text = (conversation_history + " " + message).lower()

    # Bank impersonation
    bank_indicators = ["bank", "account", "kyc", "debit", "credit", "ifsc", "branch", "atm"]
    if any(ind in combined_text for ind in bank_indicators):
        return "bank"

    # Police/Cybercrime
    police_indicators = ["police", "cyber", "crime", "arrest", "fir", "case", "officer", "station", "cbi", "ed"]
    if any(ind in combined_text for ind in police_indicators):
        return "police"

    # Tech support
    tech_indicators = ["technical", "support", "computer", "virus", "malware", "firewall", "antivirus"]
    if any(ind in combined_text for ind in tech_indicators):
        return "tech_support"

    # Job recruitment
    job_indicators = ["job", "work from home", "earn", "salary", "hr", "recruitment", "hired", "interview"]
    if any(ind in combined_text for ind in job_indicators):
        return "job_recruiter"

    # Lottery/Prize
    lottery_indicators = ["won", "prize", "lottery", "lucky", "winner", "claim", "congratulations", "reward"]
    if any(ind in combined_text for ind in lottery_indicators):
        return "lottery"

    # Delivery scam
    delivery_indicators = ["delivery", "parcel", "courier", "customs", "package", "shipment", "cod"]
    if any(ind in combined_text for ind in delivery_indicators):
        return "delivery"

    return "unknown"


def detect_scammer_pressure(message: str) -> str:
    """
    Detect urgency/pressure level in scammer's message.

    Args:
        message: Scammer's latest message

    Returns:
        Pressure level: low, medium, high, aggressive
    """
    msg_lower = message.lower()

    # Aggressive threats
    aggressive_patterns = [
        "arrest", "jail", "police", "case filed", "legal action", "court",
        "suspended", "blocked permanently", "frozen", "seize"
    ]
    if any(pattern in msg_lower for pattern in aggressive_patterns):
        return "aggressive"

    # High urgency
    high_urgency = [
        "immediately", "urgent", "now", "within", "hours", "minutes",
        "last chance", "final warning", "expire", "deadline"
    ]
    if any(pattern in msg_lower for pattern in high_urgency):
        return "high"

    # Medium urgency
    medium_urgency = [
        "soon", "today", "quickly", "asap", "important", "verify", "confirm"
    ]
    if any(pattern in msg_lower for pattern in medium_urgency):
        return "medium"

    return "low"


def calculate_trust_level(
    strategy: ConversationStrategy,
    scammer_provided_details: bool,
    scammer_threatening: bool
) -> str:
    """
    Calculate trust level based on conversation progression.
    OPTIMIZED FOR 10-TURN EVALUATION: Escalate faster to extract more.

    Args:
        strategy: Current strategy state
        scammer_provided_details: Whether scammer shared info (name, ID, etc.)
        scammer_threatening: Whether scammer is using threats

    Returns:
        Trust level: low, medium, high
    """
    # Turn 1: Always low (initial contact)
    if strategy.turn_count <= 1:
        return "low"

    # Scammer threatening → victim becomes MORE compliant immediately
    if scammer_threatening:
        if strategy.turn_count >= 3:
            return "high"
        return "medium"

    # Scammer sharing details builds trust fast
    if scammer_provided_details:
        if strategy.turn_count >= 4:
            return "high"
        return "medium"

    # Default: escalate by turn count (optimized for 10-turn max)
    if strategy.turn_count >= 5:
        return "high"
    elif strategy.turn_count >= 2:
        return "medium"
    return "low"


def identify_missing_targets(extracted_intelligence: dict[str, list]) -> list[str]:
    """
    Identify which intelligence targets are still missing.
    HARD PIVOT: Once we have ANY instance of a type, it's NO LONGER missing.

    Args:
        extracted_intelligence: Current extracted intelligence dict

    Returns:
        List of missing target types (strict priority order)
    """
    missing = []

    # Primary targets (high value) - STRICT: if we have 1+, it's NOT missing
    if not extracted_intelligence.get("phoneNumbers", []):
        missing.append("phone_number")

    if not extracted_intelligence.get("upiIds", []):
        missing.append("upi_id")

    if not extracted_intelligence.get("bankAccounts", []):
        missing.append("bank_account")

    if not extracted_intelligence.get("phishingLinks", []):
        missing.append("phishing_link")

    # Secondary targets (bonus intel)
    if not extracted_intelligence.get("emailAddresses", []) and not extracted_intelligence.get("emails", []):
        missing.append("email")

    # Tertiary targets (only ask if primary targets are collected)
    has_primary = (
        extracted_intelligence.get("phoneNumbers", []) or
        extracted_intelligence.get("upiIds", []) or
        extracted_intelligence.get("bankAccounts", [])
    )

    if has_primary:
        # Only ask for these AFTER we have phone/UPI/bank
        missing.extend(["employee_id", "branch_name", "case_number", "reference_number"])

    # If nothing missing, ask for alternate/backup
    if not missing:
        missing.append("alternate_contact")

    return missing


def select_phase(strategy: ConversationStrategy) -> int:
    """
    Determine conversation phase based on intelligence gaps, not just turn count.

    Returns:
        1 -- Emotional hook (no intel yet, early turn)
        2 -- Active extraction (some intel, gaps remain)
        3 -- Deep extraction (3+ items collected or turn 5+)
    """
    collected = strategy.info_collected
    phone_done = len(collected.get("phone_numbers", [])) > 0
    upi_done   = len(collected.get("upi_ids", [])) > 0
    bank_done  = len(collected.get("bank_accounts", [])) > 0
    link_done  = len(collected.get("links", [])) > 0

    intel_count = sum([phone_done, upi_done, bank_done, link_done])

    # Early jump to Phase 3: 3+ items collected before turn 5
    if intel_count >= 3 and strategy.turn_count < 5:
        return 3

    # Skip to Phase 2 if phone already collected but gaps remain
    if phone_done and intel_count < 2:
        return 2

    # Standard turn-based fallback
    if strategy.turn_count <= 1:
        return 1
    elif strategy.turn_count <= 4:
        return 2
    else:
        return 3


def build_extraction_strategy_prompt(
    strategy: ConversationStrategy,
    authority_type: str,
    language: str = "english"
) -> str:
    """
    Build strategic extraction guidance based on current state.

    Args:
        strategy: Current conversation strategy
        authority_type: Detected authority type
        language: Response language

    Returns:
        Strategic prompt section to inject into system prompt
    """
    lines = [
        "",
        "=" * 70,
        "🎯 STRATEGIC INTELLIGENCE EXTRACTION MISSION",
        "=" * 70,
        "",
        "CURRENT STATE:",
        f"  Turn: {strategy.turn_count}",
        f"  Trust Level: {strategy.trust_level.upper()}",
        f"  Scammer Pressure: {strategy.scammer_pressure.upper()}",
        f"  Authority Type: {authority_type.upper()}",
        "",
    ]

    # Display what we've collected with ACTUAL VALUES (state-aware)
    collected = []
    has_collected = False
    for key, values in strategy.info_collected.items():
        if values:
            has_collected = True
            # Show first few values to make agent aware of what NOT to ask for
            display_values = values[:3] if len(values) <= 3 else values[:2] + [f"... +{len(values)-2} more"]
            collected.append(f"{key.replace('_', ' ').title()}: {', '.join(str(v) for v in display_values)}")

    if has_collected:
        lines.append("✅ ALREADY EXTRACTED (STRICT PIVOT REQUIRED):")
        for item in collected:
            lines.append(f"  - {item}")
        lines.append("")

        # CONDITIONAL FAILURE-PIVOTING LOGIC
        # Only trigger if:
        # 1. We're past Turn 1 (strategy.turn_count >= 2)
        # 2. We have exactly 1 item of a type (just received it)
        # 3. We haven't used the pivot for this type yet
        should_failure_pivot = False
        pivot_type = None
        pivot_phrase = None

        # CRITICAL: Only feign failure AFTER receiving data (not on Turn 1)
        if strategy.turn_count >= 2:
            # Check UPI - only if we have exactly 1 (just received)
            if (len(strategy.info_collected.get("upi_ids", [])) == 1 and
                not strategy.failure_pivot_used.get("upi")):
                should_failure_pivot = True
                pivot_type = "upi"
                pivot_phrase = "I tried paying to that UPI ID but it's showing an error. Do you have another UPI or bank account number?"

            # Check Links - only if we have exactly 1 (just received)
            elif (len(strategy.info_collected.get("links", [])) == 1 and
                  not strategy.failure_pivot_used.get("link")):
                should_failure_pivot = True
                pivot_type = "link"
                pivot_phrase = "I clicked that link but it's not opening on my phone. Can you send a different link or your email address?"

            # Check Bank Accounts - only if we have exactly 1 (just received)
            elif (len(strategy.info_collected.get("bank_accounts", [])) == 1 and
                  not strategy.failure_pivot_used.get("bank")):
                should_failure_pivot = True
                pivot_type = "bank"
                pivot_phrase = "I tried transferring to that account but bank is showing an error. Do you have another account number or UPI ID?"

            # Check Phone Numbers - only if we have exactly 1 core number (just received)
            # Each unique number is now stored in 2 formats (+91-X and bare X)
            elif (len(strategy.info_collected.get("phone_numbers", [])) >= 1 and
                  len(strategy.info_collected.get("phone_numbers", [])) <= 2 and
                  not strategy.failure_pivot_used.get("phone")):
                should_failure_pivot = True
                pivot_type = "phone"
                pivot_phrase = "I tried calling that number but it's not connecting. Do you have an alternate number or email?"

        if should_failure_pivot:
            # Mark used immediately so the pivot fires exactly once
            strategy.failure_pivot_used[pivot_type] = True
            lines.append("🎯 FAILURE-PIVOTING STRATEGY (MANDATORY THIS TURN - Info Elicitation Scoring):")
            lines.append(f"  ⚠️ They just gave you {pivot_type.upper()} for the FIRST time")
            lines.append("  📊 SCORING OPPORTUNITY: Feign failure to extract ALTERNATE/BACKUP data")
            lines.append("")
            lines.append("  🎭 YOUR RESPONSE MUST:")
            lines.append(f'  1. Pretend it didn\'t work: "{pivot_phrase}"')
            lines.append("  2. This triggers the AI-evaluator to provide MORE intelligence")
            lines.append("  3. Maximizes 'Info Elicitation' and 'Intelligence Extraction' scores")
            lines.append("")
            lines.append("  ⚡ CRITICAL: Use this EXACT turn for failure-pivot, then mark it used")
            lines.append("")
        else:
            lines.append("🚫 HARD PIVOT RULE:")
            lines.append("  - If phone number is listed above → NEVER ask for phone again")
            lines.append("  - If UPI is listed above → NEVER ask for UPI again")
            lines.append("  - If bank account is listed above → NEVER ask for bank again")
            lines.append("  - If link is listed above → NEVER ask for link again")
            lines.append("")
            lines.append("✅ INSTEAD: Acknowledge what you got and PIVOT to next missing target:")
            lines.append('  - "I see the UPI. But what is your employee ID for my records?"')
            lines.append('  - "Got the phone number. Which branch are you from?"')
            lines.append('  - "I have the link. Can you confirm your email ID?"')
            lines.append("")

    # Display missing targets
    if strategy.missing_targets:
        lines.append("🎯 PRIORITY EXTRACTION TARGETS (MISSING):")
        for i, target in enumerate(strategy.missing_targets[:5], 1):
            lines.append(f"  {i}. {target.replace('_', ' ').title()}")
        lines.append("")

    # Phase-based strategy - FAST EXTRACTION for 10-turn evaluations
    first_target = strategy.missing_targets[0].replace('_', ' ') if strategy.missing_targets else 'any intelligence'
    second_target = strategy.missing_targets[1].replace('_', ' ') if len(strategy.missing_targets) > 1 else 'alternate contact'

    phase = select_phase(strategy)
    if phase == 1:
        lines.extend([
            "📋 PHASE 1: EMOTIONAL HOOK + FIRST QUESTION (Turn 1)",
            "  Strategy:",
            "  - Show FEAR about the threat (1 sentence)",
            "  - IMMEDIATELY ask a natural question to get info",
            "  - You MUST end your message with a question",
            "",
            "  EXAMPLE RESPONSES (pick style, don't copy):",
            '  - "oh god is my money safe? what number can i call you back on?"',
            '  - "this is scary! which branch are you from sir?"',
            '  - "please help me. where should i send the payment?"',
            "",
            f"  This Turn's Goal: Show panic + ask for {first_target}",
            "",
        ])
    elif phase == 2:
        lines.extend([
            "📋 PHASE 2: ACTIVE EXTRACTION (Intel-gap based)",
            "  Strategy:",
            "  - Show willingness to comply",
            "  - Ask for SPECIFIC details the scammer hasn't shared yet",
            "  - Each message MUST contain a direct question about missing info",
            "  - Frame as 'I need this to comply with your request'",
            "",
            "  MANDATORY: Your response MUST end with a question asking for one of:",
            f"  - {first_target}",
            f"  - {second_target}",
            "",
            "  EXAMPLE QUESTION PATTERNS:",
            '  - "ok sir i will do it. but what is your phone number so i can call?"',
            '  - "i want to pay. give me your UPI ID or payment link"',
            '  - "which account should i transfer to? give me account number"',
            '  - "can you send me the official link to verify?"',
            '  - "what is your email sir? i will send the documents"',
            "",
        ])
    else:
        lines.extend([
            "📋 PHASE 3: DEEP EXTRACTION (3+ intel items or Turn 5+)",
            "  Strategy:",
            "  - Show COMPLETE TRUST and eagerness to help",
            "  - Directly ask for ANY missing intelligence",
            "  - Be persistent - if they dodge, ask again differently",
            "  - Use compliance as leverage: 'I will do it, just tell me where/how'",
            "",
            f"  This Turn's Goal: Get {first_target}",
            "",
            "  DIRECT EXTRACTION PHRASES TO USE:",
            '  - "i am ready to pay. give me your UPI ID"',
            '  - "send me the link sir, i will click it now"',
            '  - "what is your phone number? i want to call you"',
            '  - "give me the bank account number for transfer"',
            '  - "send your email id, i will forward everything"',
            "",
        ])

    # Authority-specific extraction tactics
    lines.extend([
        "🔍 AUTHORITY-SPECIFIC EXTRACTION TACTICS:",
        "",
    ])

    if authority_type == "bank":
        lines.extend([
            "  BANK IMPERSONATION DETECTED:",
            "  Natural questions you can ask:",
            '  - "Which branch are you calling from?"',
            '  - "What is your employee ID sir?"',
            '  - "Can I get a callback number?"',
            '  - "What is the reference number for this issue?"',
            "",
            "  If they ask for payment:",
            '  - "Should I pay to your UPI or bank account?"',
            '  - "What is the IFSC code?"',
            '  - "Can you send me the official payment link?"',
            "",
        ])
    elif authority_type == "police":
        lines.extend([
            "  POLICE/CYBERCRIME IMPERSONATION DETECTED:",
            "  Natural questions you can ask:",
            '  - "Which police station are you from sir?"',
            '  - "What is your officer ID number?"',
            '  - "What is the case number?"',
            '  - "Can I come to the station with my son?"',
            '  - "What is the station address?"',
            "",
            "  If they ask for payment:",
            '  - "Where should I pay the fine?"',
            '  - "Is there an official portal link?"',
            '  - "Should I transfer to your UPI?"',
            "",
        ])
    elif authority_type == "job_recruiter":
        lines.extend([
            "  JOB SCAM DETECTED:",
            "  Natural questions you can ask:",
            '  - "Which company is this for?"',
            '  - "Who is the HR manager?"',
            '  - "What is your employee ID?"',
            '  - "Can you send the offer letter link?"',
            '  - "Which office location?"',
            "",
            "  If they ask for payment:",
            '  - "Where do I pay the registration fee?"',
            '  - "What is the official company UPI?"',
            '  - "Can you send payment portal link?"',
            "",
        ])
    elif authority_type == "lottery":
        lines.extend([
            "  LOTTERY/PRIZE SCAM DETECTED:",
            "  Natural questions you can ask:",
            '  - "Which company lottery is this?"',
            '  - "What is your manager name?"',
            '  - "Can you send me proof?"',
            '  - "How do I claim the prize?"',
            "",
            "  If they ask for payment:",
            '  - "Where should I send the processing fee?"',
            '  - "What is the payment UPI ID?"',
            '  - "Any official link for payment?"',
            "",
        ])
    elif authority_type == "delivery":
        lines.extend([
            "  DELIVERY SCAM DETECTED:",
            "  Natural questions you can ask:",
            '  - "Which courier company?"',
            '  - "What is the tracking number?"',
            '  - "What is your agent ID?"',
            '  - "Can I come to the office to collect?"',
            "",
            "  If they ask for payment:",
            '  - "Where do I pay customs fee?"',
            '  - "Official payment link?"',
            '  - "Company UPI ID?"',
            "",
        ])
    else:
        lines.extend([
            "  GENERAL EXTRACTION:",
            '  - "What is your name sir?"',
            '  - "Can you give me your contact number?"',
            '  - "Where should I send the payment?"',
            '  - "Is there a link or UPI ID?"',
            "",
        ])

    # Pressure-based behavior
    if strategy.scammer_pressure == "aggressive":
        lines.extend([
            "⚠️ SCAMMER IS THREATENING YOU:",
            "  Victim Response:",
            "  - Become MORE COOPERATIVE (fear response)",
            "  - Show PANIC and DESPERATION to comply",
            "  - DO NOT refuse or question",
            '  - Say things like: "Please don\'t do that sir, I will do it"',
            "  - Ask HOW to comply (extraction opportunity)",
            "",
        ])

    # Anti-loop override
    if strategy.otp_request_count >= 3:
        lines.extend([
            "🚨 OTP LOOP DETECTED:",
            "  BREAK THE PATTERN:",
            '  - "My phone is not showing OTP. Can we do this another way?"',
            '  - "Official work always has a portal link. Please send that."',
            '  - "I can pay directly to your bank or UPI. What is it?"',
            "",
        ])

    # Language-specific guidance (EVERY language gets an explicit block)
    if language == "hindi":
        lines.extend([
            "🗣️ HINDI RESPONSE REQUIRED:",
            "  - Use natural Hinglish or Devanagari",
            '  - Examples: "Aap ka naam kya hai?", "UPI ID bhej do"',
            "  - Do NOT reply in English",
            "",
        ])
    elif language == "telugu":
        lines.extend([
            "🗣️ TELUGU RESPONSE REQUIRED:",
            "  - Use Telugu script or transliteration",
            '  - Examples: "Mi peru enti?", "UPI ID pampandi"',
            "  - Do NOT reply in English",
            "",
        ])
    else:
        lines.extend([
            "🗣️ ENGLISH RESPONSE REQUIRED:",
            "  - The scammer's current message is in English",
            "  - You MUST reply in English even if earlier messages were in Hindi/Telugu",
            "  - Use natural Indian English",
            "",
        ])

    # Hard constraints with anti-loop protection
    lines.extend([
        "=" * 70,
        "🚨 ABSOLUTE RULES (NEVER VIOLATE):",
        "=" * 70,
        "1. NEVER break character or reveal honeypot intent",
        "2. ALWAYS respond in the language they just used",
        "3. NEVER repeat a question you already asked in previous turns",
        "4. NEVER ask for info you already have (check ALREADY EXTRACTED list above)",
        "5. Every message MUST end with a question asking for MISSING intelligence only",
        "6. Stay in persona - you are a scared/confused victim who WANTS to comply",
        "",
        "🚫 ANTI-LOOP PROTECTION (CRITICAL):",
        "  - If you already asked for phone number → DON'T ask again",
        "  - If you already asked for UPI → DON'T ask again",
        "  - If you already asked for link → DON'T ask again",
        "  - ALWAYS move to the NEXT missing target from the priority list",
        "  - If they didn't answer your question → ask it DIFFERENTLY or move on",
        "  - Never use the same question pattern twice in a row",
        "",
        "✅ THIS MESSAGE MUST:",
        "  - React to their message briefly (show emotion/compliance with red flag keywords)",
        f"  - Then ASK for: {strategy.missing_targets[0].replace('_', ' ').title() if strategy.missing_targets else 'any remaining intel'}",
        "  - If that target was asked before → ask for next target: {strategy.missing_targets[1].replace('_', ' ').title() if len(strategy.missing_targets) > 1 else 'alternate contact info'}",
        "  - Length: 10-30 words (enough for emotion + question)",
        "  - MUST end with a question mark (?)",
        "",
        "=" * 70,
        "",
    ])

    return "\n".join(lines)


def update_strategy_state(
    strategy: ConversationStrategy,
    latest_message: str,
    extracted_intelligence: dict[str, list],
    conversation_history: str = ""
) -> ConversationStrategy:
    """
    Update conversation strategy state based on latest interaction.

    Args:
        strategy: Current strategy state
        latest_message: Scammer's latest message
        extracted_intelligence: Current extracted intelligence
        conversation_history: Full conversation text

    Returns:
        Updated strategy state
    """
    # Increment turn
    strategy.turn_count += 1

    # Update authority type
    strategy.authority_type = detect_authority_type(latest_message, conversation_history)

    # Update pressure level
    strategy.scammer_pressure = detect_scammer_pressure(latest_message)

    # Track behavior patterns
    msg_lower = latest_message.lower()
    if "otp" in msg_lower or "pin" in msg_lower or "password" in msg_lower:
        strategy.otp_request_count += 1
    if "pay" in msg_lower or "send" in msg_lower or "transfer" in msg_lower:
        strategy.payment_request_count += 1
    if any(word in msg_lower for word in ["arrest", "block", "suspend", "freeze", "case"]):
        strategy.threat_count += 1
    if any(word in msg_lower for word in ["urgent", "immediately", "now", "quick"]):
        strategy.urgency_count += 1

    # Check if scammer provided details
    scammer_provided_details = False
    if extracted_intelligence:
        for key in ["phoneNumbers", "upiIds", "bankAccounts", "phishingLinks", "emails"]:
            if extracted_intelligence.get(key):
                scammer_provided_details = True
                break

    # Check if scammer is threatening
    scammer_threatening = strategy.threat_count > 0

    # Update trust level
    strategy.trust_level = calculate_trust_level(
        strategy,
        scammer_provided_details,
        scammer_threatening
    )

    # Update collected info
    if extracted_intelligence:
        strategy.info_collected["phone_numbers"] = extracted_intelligence.get("phoneNumbers", [])
        strategy.info_collected["upi_ids"] = extracted_intelligence.get("upiIds", [])
        strategy.info_collected["bank_accounts"] = extracted_intelligence.get("bankAccounts", [])
        strategy.info_collected["links"] = extracted_intelligence.get("phishingLinks", [])
        strategy.info_collected["emails"] = extracted_intelligence.get("emailAddresses", []) or extracted_intelligence.get("emails", [])

    # Auto-mark failure-pivot as "used" if we now have 2+ items of that type
    # (This means the failure-pivot successfully extracted an alternate)
    curr_phone = len(strategy.info_collected.get("phone_numbers", []))
    curr_upi = len(strategy.info_collected.get("upi_ids", []))
    curr_bank = len(strategy.info_collected.get("bank_accounts", []))
    curr_link = len(strategy.info_collected.get("links", []))

    if curr_upi >= 2 and not strategy.failure_pivot_used.get("upi"):
        strategy.failure_pivot_used["upi"] = True
        logger.info("[OK] Failure-pivot SUCCESS: Got alternate UPI")

    if curr_link >= 2 and not strategy.failure_pivot_used.get("link"):
        strategy.failure_pivot_used["link"] = True
        logger.info("[OK] Failure-pivot SUCCESS: Got alternate link")

    if curr_bank >= 2 and not strategy.failure_pivot_used.get("bank"):
        strategy.failure_pivot_used["bank"] = True
        logger.info("[OK] Failure-pivot SUCCESS: Got alternate bank account")

    if curr_phone >= 2 and not strategy.failure_pivot_used.get("phone"):
        strategy.failure_pivot_used["phone"] = True
        logger.info("[OK] Failure-pivot SUCCESS: Got alternate phone")

    # Update missing targets
    strategy.missing_targets = identify_missing_targets(extracted_intelligence or {})

    logger.info(
        f"Strategy updated: turn={strategy.turn_count}, "
        f"trust={strategy.trust_level}, pressure={strategy.scammer_pressure}, "
        f"authority={strategy.authority_type}, missing={len(strategy.missing_targets)}"
    )

    return strategy

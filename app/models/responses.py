"""
Response models for the Scambot Honeypot API.
"""

from pydantic import BaseModel, Field


class AgentReasoning(BaseModel):
    """
    Per-turn decision trace of the honeypot agent.

    Surfaces every decision the pipeline made this turn (detection tier,
    persona choice, strategy phase, extraction targets) so the dashboard
    can show the agent's reasoning live.
    """
    turn: int = Field(default=0, description="Scammer turn number in this session")
    detectionMethod: str | None = Field(default=None, description="Which tier detected the scam (rules/ml/llm/fail_open/restored)")
    detectionConfidence: float | None = Field(default=None, description="Final scam confidence 0.0-1.0")
    ruleScore: float | None = Field(default=None, description="Rule engine score")
    mlScore: float | None = Field(default=None, description="ML classifier score")
    scamType: str | None = Field(default=None, description="Classified scam type")
    indicators: list[str] = Field(default_factory=list, description="Detected scam indicators")
    personaSelected: str | None = Field(default=None, description="Active victim persona")
    personaReason: str | None = Field(default=None, description="Why this persona was chosen/kept")
    languageDetected: str | None = Field(default=None, description="Detected scammer language")
    responseLanguage: str | None = Field(default=None, description="Language the agent replies in")
    phase: int = Field(default=1, description="Extraction strategy phase (1-3)")
    phaseName: str = Field(default="", description="Human-readable phase name")
    phaseTrigger: str = Field(default="", description="What triggered this phase")
    trustLevel: str = Field(default="low", description="Victim trust level shown to scammer")
    scammerPressure: str = Field(default="low", description="Detected pressure level from scammer")
    authorityType: str = Field(default="unknown", description="Authority the scammer impersonates")
    missingTargets: list[str] = Field(default_factory=list, description="Intel gaps the agent targets next")
    newIntelThisTurn: list[str] = Field(default_factory=list, description="Intelligence newly extracted this turn")
    injectionDetected: bool = Field(default=False, description="Prompt-injection attempt detected in scammer message")
    guardrailAction: str | None = Field(default=None, description="Guardrail action taken this turn, if any")


class ConversationResponse(BaseModel):
    """Response model for conversation endpoint."""
    status: str = Field(..., description="Response status (success/error)")
    reply: str = Field(..., description="Agent's response to the scammer")
    persona: str | None = Field(default=None, description="Active honeypot persona (e.g. grandmother, professional)")
    scamType: str | None = Field(default=None, description="Detected scam type")
    intelligence: dict | None = Field(default=None, description="Extracted intelligence from the conversation so far")
    reasoning: AgentReasoning | None = Field(default=None, description="Per-turn agent decision trace")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "reply": "Why is my account being suspended?",
                "persona": "grandmother",
                "scamType": "bank_fraud",
                "intelligence": {
                    "phoneNumbers": [], "upiIds": [], "bankAccounts": [],
                    "phishingLinks": [], "emailAddresses": [], "suspiciousKeywords": []
                }
            }
        }


class ExtractedIntelligence(BaseModel):
    """
    Intelligence extracted from the conversation.

    All evaluation-relevant fields are included in serialization.
    """
    # === REQUIRED FIELDS FOR EVALUATION ===
    bankAccounts: list[str] = Field(default_factory=list, description="Extracted bank account numbers")
    upiIds: list[str] = Field(default_factory=list, description="Extracted UPI IDs")
    phishingLinks: list[str] = Field(default_factory=list, description="Phishing URLs found")
    phoneNumbers: list[str] = Field(default_factory=list, description="Phone numbers extracted")
    emailAddresses: list[str] = Field(default_factory=list, description="Email addresses extracted")
    suspiciousKeywords: list[str] = Field(default_factory=list, description="Suspicious keywords detected")

    # === EVALUATION-SCORED FIELDS (case IDs, policy numbers, order numbers) ===
    caseIds: list[str] = Field(default_factory=list, description="Case/reference IDs mentioned by scammer")
    policyNumbers: list[str] = Field(default_factory=list, description="Policy numbers mentioned by scammer")
    orderNumbers: list[str] = Field(default_factory=list, description="Order/tracking IDs mentioned by scammer")

    # === INTERNAL FIELDS (excluded from callback serialization) ===
    emails: list[str] = Field(default_factory=list, description="Email addresses (internal)", exclude=True)
    amounts: list[str] = Field(default_factory=list, description="Monetary amounts mentioned", exclude=True)
    employeeIds: list[str] = Field(default_factory=list, description="Employee/Reference IDs extracted", exclude=True)
    impersonationTargets: list[str] = Field(default_factory=list, description="Banks/companies being impersonated", exclude=True)


class EngagementMetrics(BaseModel):
    """Engagement metrics for evaluation scoring."""
    totalMessagesExchanged: int = Field(default=0, description="Total messages exchanged")
    engagementDurationSeconds: int = Field(default=0, description="Duration of engagement in seconds")


class FinalResultPayload(BaseModel):
    """Payload sent to evaluation callback endpoint."""
    sessionId: str = Field(..., description="Session identifier")
    status: str = Field(default="completed", description="Session status")
    scamDetected: bool = Field(..., description="Whether scam was detected")
    scamType: str | None = Field(default=None, description="Detected scam type (e.g. bank_fraud, upi_fraud, phishing)")
    confidenceLevel: float | None = Field(default=None, description="Scam detection confidence 0.0-1.0")
    totalMessagesExchanged: int = Field(..., description="Total message count")
    engagementDurationSeconds: int = Field(default=0, description="Total engagement duration in seconds")
    extractedIntelligence: ExtractedIntelligence = Field(..., description="Extracted intelligence data")
    engagementMetrics: EngagementMetrics = Field(
        default_factory=EngagementMetrics,
        description="Engagement duration and message metrics"
    )
    agentNotes: str = Field(..., description="Summary of scammer behavior")

    class Config:
        json_schema_extra = {
            "example": {
                "sessionId": "abc123-session-id",
                "status": "completed",
                "scamDetected": True,
                "totalMessagesExchanged": 18,
                "extractedIntelligence": {
                    "bankAccounts": ["XXXX-XXXX-XXXX"],
                    "upiIds": ["scammer@upi"],
                    "phishingLinks": ["http://malicious-link.example"],
                    "phoneNumbers": ["+91-XXXXXXXXXX"],
                    "emailAddresses": ["scammer@example.com"],
                    "suspiciousKeywords": ["urgent", "verify now", "account blocked"]
                },
                "engagementMetrics": {
                    "totalMessagesExchanged": 18,
                    "engagementDurationSeconds": 120
                },
                "agentNotes": "Scammer used urgency tactics and payment redirection"
            }
        }

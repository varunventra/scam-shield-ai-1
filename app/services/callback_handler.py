"""
Callback handler for sending final results to an external callback endpoint.
"""
from typing import TYPE_CHECKING, Optional

import httpx

from app.core.config import settings
from app.core.logging import logger
from app.models.responses import FinalResultPayload

if TYPE_CHECKING:
    from app.models.responses import ExtractedIntelligence


class CallbackHandler:
    """Handles callbacks to an external endpoint."""

    def __init__(self):
        """Initialize callback handler."""
        self.callback_url = settings.callback_url
        self.timeout = 10.0  # seconds

    async def send_final_result(self, payload: FinalResultPayload, callback_url: str | None = None) -> bool:
        """
        Send final result to external callback endpoint with retry mechanism.

        Args:
            payload: Final result data to send
            callback_url: Optional callback URL override. If not provided, uses default from settings.

        Returns:
            True if successful (or no-op when URL not configured), False otherwise
        """
        # Use provided callback_url or fall back to default from settings
        target_url = callback_url or self.callback_url

        # No-op mode: if no callback URL is configured, log locally and return success
        if not target_url:
            import json
            logger.info(
                f"Callback URL not configured -- logging result locally. "
                f"Session: {payload.sessionId}, Scam: {payload.scamDetected}, "
                f"Messages: {payload.totalMessagesExchanged}"
            )
            logger.debug(f"Payload: {json.dumps(payload.model_dump(), default=str)}")
            return True

        # Retry logic: 3 attempts with 2-second delays
        max_retries = 3
        retry_delay = 2.0

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(
                    f"[Attempt {attempt}/{max_retries}] Sending final result to callback - "
                    f"Session: {payload.sessionId}, Scam: {payload.scamDetected}, "
                    f"Messages: {payload.totalMessagesExchanged}, URL: {target_url}"
                )

                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        target_url,
                        json=payload.model_dump(),
                        headers={"Content-Type": "application/json"}
                    )

                    if response.status_code == 200:
                        logger.info(
                            f"[OK] Successfully sent final result - Session: {payload.sessionId}, "
                            f"Response: {response.text}"
                        )
                        return True
                    else:
                        logger.error(
                            f"[FAIL] Failed to send final result (HTTP {response.status_code}) - "
                            f"Session: {payload.sessionId}, Response: {response.text}"
                        )
                        if attempt < max_retries:
                            logger.info(f"[WAIT] Waiting {retry_delay}s before retry...")
                            import asyncio
                            await asyncio.sleep(retry_delay)
                            continue
                        return False

            except httpx.TimeoutException:
                logger.error(
                    f"[TIMEOUT] Timeout sending final result (attempt {attempt}/{max_retries}) - "
                    f"Session: {payload.sessionId}"
                )
                if attempt < max_retries:
                    logger.info(f"[WAIT] Waiting {retry_delay}s before retry...")
                    import asyncio
                    await asyncio.sleep(retry_delay)
                    continue
                return False
            except Exception as e:
                logger.error(
                    f"[ERROR] Error sending final result (attempt {attempt}/{max_retries}) - "
                    f"Session: {payload.sessionId}, Error: {str(e)}"
                )
                if attempt < max_retries:
                    logger.info(f"[WAIT] Waiting {retry_delay}s before retry...")
                    import asyncio
                    await asyncio.sleep(retry_delay)
                    continue
                return False

        logger.error(
            f"[FAIL] All {max_retries} callback attempts failed - Session: {payload.sessionId}"
        )
        return False

    async def should_send_callback(
        self,
        session_id: str,
        scam_detected: bool,
        message_count: int,
        intelligence: Optional['ExtractedIntelligence'] = None
    ) -> bool:
        """
        Determine if callback should be sent.

        Evaluation uses max 10 turns (= 20 messages).  Send the callback
        early (>= 5 messages) and RE-SEND on every subsequent turn so the
        evaluator always has the latest intelligence snapshot.

        Args:
            session_id: Session identifier
            scam_detected: Whether scam was detected
            message_count: Number of messages exchanged
            intelligence: Extracted intelligence (not used for trigger decision)

        Returns:
            True if callback should be sent
        """
        # FAIL-OPEN: Always send callback regardless of scam_detected.
        # The honeypot extracts intelligence from every conversation.
        # Send from turn 1 so the evaluator always has our latest snapshot.
        should_send = message_count >= 1

        if should_send:
            logger.info(
                f"Callback criteria met - Session: {session_id}, "
                f"Messages: {message_count}"
            )
        else:
            logger.debug(
                f"Callback criteria not met - Session: {session_id}, "
                f"Messages: {message_count}"
            )

        return should_send

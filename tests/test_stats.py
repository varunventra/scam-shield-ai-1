"""
Tests for aggregate stats: duration helpers, the aggregator, and the
/admin/stats endpoint.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.utils.helpers import (
    format_duration,
    transcript_duration_seconds,
)

client = TestClient(app)
VALID_ADMIN_KEY = settings.admin_api_key


class TestDurationHelpers:
    def test_duration_from_transcript(self):
        transcript = [
            {"sender": "scammer", "text": "hi", "timestamp": 1_000_000},
            {"sender": "user", "text": "hello", "timestamp": 1_090_000},  # +90s
        ]
        assert transcript_duration_seconds(transcript) == 90

    def test_duration_uses_full_span(self):
        transcript = [
            {"timestamp": 1_000_000},
            {"timestamp": 1_030_000},
            {"timestamp": 1_120_000},  # 120s span
        ]
        assert transcript_duration_seconds(transcript) == 120

    @pytest.mark.parametrize("transcript", [None, [], [{"timestamp": 5}], [{"no": "ts"}]])
    def test_duration_degrades_to_zero(self, transcript):
        assert transcript_duration_seconds(transcript) == 0

    def test_format_duration(self):
        assert format_duration(0) == "0s"
        assert format_duration(45) == "45s"
        assert format_duration(95) == "1m 35s"
        assert format_duration(3600) == "60m 0s"


class TestStatsEndpoint:
    def test_requires_admin_key(self):
        response = client.get("/api/v1/admin/stats")
        assert response.status_code in (401, 403)

    def test_stats_shape(self):
        if not VALID_ADMIN_KEY:
            pytest.skip("No admin key configured")
        response = client.get(
            "/api/v1/admin/stats",
            headers={"x-admin-key": VALID_ADMIN_KEY},
        )
        assert response.status_code == 200
        stats = response.json()["stats"]
        for key in [
            "totalSessions", "intelTotal", "intelByCategory", "scamTypeCounts",
            "repeatScammers", "avgTurns", "scammerTimeWastedSeconds",
            "scammerTimeWastedHuman", "avgEngagementSeconds", "estimatedScammerCost",
        ]:
            assert key in stats
        assert isinstance(stats["intelByCategory"], dict)
        assert isinstance(stats["scamTypeCounts"], dict)

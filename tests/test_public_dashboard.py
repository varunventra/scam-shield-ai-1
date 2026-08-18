"""
Tests for PUBLIC_DASHBOARD evaluation mode.

When enabled, read-only (GET) admin endpoints are served without credentials
so evaluators can open the dashboard without being handed the admin key.
Mutating admin endpoints must still require real credentials.
"""
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app

client = TestClient(app)


@pytest.fixture
def public_mode(monkeypatch):
    monkeypatch.setattr(settings, "public_dashboard", True)


@pytest.fixture
def private_mode(monkeypatch):
    monkeypatch.setattr(settings, "public_dashboard", False)


class TestPublicDashboardEnabled:
    def test_get_stats_open_without_key(self, public_mode):
        response = client.get("/api/v1/admin/stats")
        assert response.status_code == 200

    def test_get_sessions_open_without_key(self, public_mode):
        response = client.get("/api/v1/admin/sessions", params={"limit": 1})
        assert response.status_code == 200

    def test_cleanup_still_requires_key(self, public_mode):
        # POST /admin/cleanup is destructive and must never be opened by
        # public mode, which only bypasses auth for GET requests.
        response = client.post("/api/v1/admin/cleanup")
        assert response.status_code in (401, 403)

    def test_login_still_validates_key(self, public_mode):
        response = client.post(
            "/api/v1/admin/login", headers={"x-admin-key": "wrong-key"}
        )
        assert response.status_code in (401, 403)


class TestPublicDashboardDisabled:
    def test_get_stats_requires_key(self, private_mode):
        response = client.get("/api/v1/admin/stats")
        assert response.status_code in (401, 403)

    def test_get_sessions_requires_key(self, private_mode):
        response = client.get("/api/v1/admin/sessions", params={"limit": 1})
        assert response.status_code in (401, 403)

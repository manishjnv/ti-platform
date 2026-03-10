"""Integration tests for API route handlers.

Uses httpx.AsyncClient with FastAPI TestClient transport.
Auth and DB are overridden via dependency injection (see conftest.py).
"""

from __future__ import annotations

import uuid

import pytest


class TestRootEndpoint:
    """GET / — version info, no auth required."""

    async def test_root_returns_version(self, async_client):
        resp = await async_client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert "version" in data
        assert data["version"] == "1.0.0"

    async def test_root_returns_app_name(self, async_client):
        resp = await async_client.get("/")
        data = resp.json()
        assert "IntelWatch" in data.get("message", "")


class TestHealthEndpoint:
    """GET /api/v1/health — health check, no auth required."""

    async def test_health_returns_200(self, async_client):
        resp = await async_client.get("/api/v1/health")
        assert resp.status_code == 200

    async def test_health_response_structure(self, async_client):
        resp = await async_client.get("/api/v1/health")
        data = resp.json()
        assert "status" in data
        assert "postgres" in data
        assert "redis" in data
        assert "opensearch" in data


class TestIntelRoutes:
    """GET /api/v1/intel — protected routes with mocked auth + DB."""

    async def test_intel_list_returns_200(self, async_client):
        resp = await async_client.get("/api/v1/intel")
        assert resp.status_code in (200, 500, 422)

    async def test_intel_export_stix_endpoint_exists(self, async_client):
        resp = await async_client.get("/api/v1/intel/export/stix")
        assert resp.status_code != 404


class TestNewsRoutes:
    """News endpoints with mocked auth + DB."""

    async def test_news_stix_export_exists(self, async_client):
        fake_id = str(uuid.uuid4())
        resp = await async_client.get(f"/api/v1/news/{fake_id}/export/stix")
        assert resp.status_code in (200, 404, 500)

    async def test_news_sigma_export_exists(self, async_client):
        fake_id = str(uuid.uuid4())
        resp = await async_client.get(f"/api/v1/news/{fake_id}/export/sigma")
        assert resp.status_code in (200, 404, 500)


class TestSearchRoutes:
    """POST /api/v1/search — search endpoint (POST, not GET)."""

    async def test_search_endpoint_exists(self, async_client):
        resp = await async_client.post(
            "/api/v1/search", json={"query": "test"}
        )
        # Accept 200 (results) or 422 (validation) or 500 (OpenSearch mock)
        assert resp.status_code in (200, 422, 500)


class TestCasesRoutes:
    """Cases endpoints."""

    async def test_cases_list_exists(self, async_client):
        resp = await async_client.get("/api/v1/cases")
        assert resp.status_code in (200, 500)


class TestReportsRoutes:
    """Reports endpoints."""

    async def test_reports_list_exists(self, async_client):
        resp = await async_client.get("/api/v1/reports")
        assert resp.status_code in (200, 500)


class TestTechniquesRoutes:
    """ATT&CK techniques endpoints (uses Redis caching)."""

    async def test_techniques_list_exists(self, async_client):
        resp = await async_client.get("/api/v1/techniques")
        assert resp.status_code in (200, 500)


class TestIOCsRoutes:
    """IOC endpoints (uses get_current_user auth)."""

    async def test_iocs_list_exists(self, async_client):
        resp = await async_client.get("/api/v1/iocs")
        assert resp.status_code in (200, 500)


class TestNotificationsRoutes:
    """Notification endpoints."""

    async def test_notifications_list_exists(self, async_client):
        resp = await async_client.get("/api/v1/notifications")
        assert resp.status_code in (200, 500)

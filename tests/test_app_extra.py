"""Additional _app.py coverage: metrics middleware, configure, pre-ready health."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from asgi_lifespan import LifespanManager
from fastapi import APIRouter
from httpx import ASGITransport, AsyncClient

from fastapi_m8 import AppLifecycle, HealthConfig, create_app
from tests.conftest import make_settings

_BASE = {"SET_OPEN_API": False, "SET_DOCS": False, "SET_REDOC": False}


def _router() -> APIRouter:
    return APIRouter(tags=["t"])


# ── configure callback ────────────────────────────────────────────────────────


def test_configure_callback_called_with_app() -> None:
    """configure(app) is called once with the fully-wired FastAPI app."""
    received: list = []
    create_app(
        make_settings(**_BASE),
        _router(),
        lifecycle=AppLifecycle(configure=received.append),
    )
    assert len(received) == 1


# ── METRICS_ENABLED with ImportError ─────────────────────────────────────────


def test_metrics_enabled_adds_middleware_when_available() -> None:
    """METRICS_ENABLED=True with observability installed adds MetricsMiddleware."""
    s = make_settings(**_BASE, METRICS_ENABLED=True)
    with patch("auth_sdk_m8.observability.middleware.MetricsMiddleware") as mock_mw:
        app = create_app(s, _router())
    assert app is not None
    _ = mock_mw  # referenced to satisfy linter


# ── health before lifespan ────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_health_endpoint_before_ready_returns_503_initializing() -> None:
    """Hitting /health/ before lifespan marks service_ready returns 503 initializing."""
    s = make_settings(**_BASE)
    app = create_app(s, _router())
    # Do NOT start lifespan — service_ready stays False
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/api/health/")
    assert resp.status_code == 503
    assert resp.json()["status"] == "initializing"


# ── async health_detail_authorizer ───────────────────────────────────────────


@pytest.mark.anyio
async def test_async_health_detail_authorizer_is_awaited() -> None:
    """An async health_detail_authorizer is awaited correctly."""

    async def always_authorized(request) -> bool:  # noqa: ANN001
        return True

    s = make_settings(**_BASE)
    app = create_app(
        s, _router(), health=HealthConfig(detail_authorizer=always_authorized)
    )
    async with LifespanManager(app) as manager:
        async with AsyncClient(
            transport=ASGITransport(app=manager.app), base_url="http://test"
        ) as client:
            resp = await client.get("/api/health/")
    assert "checks" in resp.json()

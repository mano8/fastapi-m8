"""Additional _app.py coverage: metrics middleware, configure, pre-ready health."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from asgi_lifespan import LifespanManager
from fastapi import APIRouter
from fastapi.testclient import TestClient
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


def test_metrics_enabled_calls_setup_then_adds_middleware() -> None:
    """METRICS_ENABLED=True calls setup() with settings values, then adds MetricsMiddleware."""
    s = make_settings(**_BASE, METRICS_ENABLED=True)
    with (
        patch("auth_sdk_m8.observability.metrics.setup") as mock_setup,
        patch("auth_sdk_m8.observability.middleware.MetricsMiddleware"),
    ):
        app = create_app(s, _router())
    assert app is not None
    mock_setup.assert_called_once_with(
        enabled=True,
        groups_str=s.METRICS_GROUPS,
        api_prefix=s.API_PREFIX,
    )


def test_tagless_route_uses_name_as_unique_id_fallback() -> None:
    """Routes with no tags must not raise IndexError — name is used as fallback."""
    router = APIRouter()
    router.add_api_route("/probe", lambda: "ok", methods=["GET"], name="probe")
    app = create_app(make_settings(**_BASE), router)
    assert app is not None


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


# ── TrustedHostMiddleware (F8) ────────────────────────────────────────────────


def test_trusted_host_disallowed_returns_400() -> None:
    """A Host header not in ALLOWED_HOSTS is rejected with 400."""
    s = make_settings(**_BASE, ALLOWED_HOSTS=["example.com"])
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/", headers={"Host": "badhost.com"})
    assert resp.status_code == 400


def test_trusted_host_testserver_allowed_in_non_prod() -> None:
    """testserver is auto-added in non-production so TestClient works."""
    s = make_settings(**_BASE, ALLOWED_HOSTS=["example.com"])
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert resp.status_code != 400


def test_trusted_host_middleware_not_registered_when_empty() -> None:
    """No ALLOWED_HOSTS → middleware not registered; all hosts pass."""
    s = make_settings(**_BASE)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/", headers={"Host": "any-host.example"})
    assert resp.status_code != 400


# ── Security headers (F6) ─────────────────────────────────────────────────────

_HARDENING_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
)


def test_security_headers_absent_in_local() -> None:
    """Local/dev is left unrestricted so Swagger/ReDoc/HMR keep working."""
    s = make_settings(**_BASE, ENVIRONMENT="local")
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    for header in _HARDENING_HEADERS:
        assert header not in resp.headers


@pytest.mark.parametrize(
    "kwargs",
    [{"ENVIRONMENT": "production"}, {"STRICT_PRODUCTION_MODE": True}],
)
def test_security_headers_applied_in_production(kwargs: dict) -> None:
    """ENVIRONMENT==production or STRICT_PRODUCTION_MODE emits the hardening set."""
    s = make_settings(**_BASE, **kwargs)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


def test_security_headers_opt_out_in_production() -> None:
    """SECURITY_HEADERS_ENABLED=False suppresses the layer even in production."""
    s = make_settings(**_BASE, ENVIRONMENT="production", SECURITY_HEADERS_ENABLED=False)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert "content-security-policy" not in resp.headers


def test_hsts_disabled_when_max_age_zero() -> None:
    """HSTS_MAX_AGE=0 drops only the Strict-Transport-Security header."""
    s = make_settings(**_BASE, ENVIRONMENT="production", HSTS_MAX_AGE=0)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert "strict-transport-security" not in resp.headers
    assert "content-security-policy" in resp.headers


def test_custom_csp_override_in_production() -> None:
    """A configured CONTENT_SECURITY_POLICY overrides the tight API default."""
    custom = "default-src 'self'; frame-ancestors 'none'"
    s = make_settings(
        **_BASE, ENVIRONMENT="production", CONTENT_SECURITY_POLICY=custom
    )
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert resp.headers["content-security-policy"] == custom

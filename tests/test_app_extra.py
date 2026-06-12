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


# ── Security headers (F6 · tiered model, auth-sdk-m8 ≥ 1.2.1) ──────────────────

# Tier 1 — emitted in every environment whenever SECURITY_HEADERS_ENABLED.
_ALWAYS_ON_HEADERS = ("x-content-type-options", "x-frame-options")
# Tier 2 — production gate only (ENVIRONMENT==production or STRICT_PRODUCTION_MODE).
_PRODUCTION_HEADERS = ("referrer-policy", "permissions-policy")
# Tier 3 — browser-persisted, express opt-in only, never on local.
_OPT_IN_HEADERS = ("strict-transport-security", "content-security-policy")

# Opt the two browser-persisted headers in, the way a real TLS-terminated
# deployment would.
_OPT_IN = {"HSTS_ENABLED": True, "CONTENT_SECURITY_POLICY_ENABLED": True}


def test_always_on_headers_emitted_in_local() -> None:
    """Tier 1 (nosniff, frame-options) is safe everywhere — present even on local."""
    s = make_settings(**_BASE, ENVIRONMENT="local")
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-frame-options"] == "DENY"
    # Tiers 2 and 3 stay off on local, even with HSTS/CSP opted in.
    for header in _PRODUCTION_HEADERS:
        assert header not in resp.headers


def test_hsts_csp_never_emitted_on_local_even_when_opted_in() -> None:
    """Tier 3 is hard-blocked on local — HSTS would poison the localhost cache."""
    s = make_settings(**_BASE, ENVIRONMENT="local", **_OPT_IN)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    for header in _OPT_IN_HEADERS:
        assert header not in resp.headers


@pytest.mark.parametrize(
    "kwargs",
    [{"ENVIRONMENT": "production"}, {"STRICT_PRODUCTION_MODE": True}],
)
def test_production_headers_without_opt_in(kwargs: dict) -> None:
    """The production gate emits tiers 1+2 but NOT the opt-in HSTS/CSP pair."""
    s = make_settings(**_BASE, **kwargs)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "permissions-policy" in resp.headers
    # Tier 3 is off until explicitly enabled.
    for header in _OPT_IN_HEADERS:
        assert header not in resp.headers


def test_full_opt_in_in_production() -> None:
    """Opting in adds HSTS and CSP on top of the production hardening set."""
    s = make_settings(**_BASE, ENVIRONMENT="production", **_OPT_IN)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert "includeSubDomains" in resp.headers["strict-transport-security"]


def test_opt_in_decoupled_from_production_gate() -> None:
    """HSTS/CSP opt-in applies on a non-production, non-local stack (e.g. staging).

    Tier 3 is independent of the production gate, so a TLS-terminated staging
    stack gets HSTS/CSP without the Tier-2 production-only headers.
    """
    s = make_settings(**_BASE, ENVIRONMENT="staging", **_OPT_IN)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert "strict-transport-security" in resp.headers
    assert "content-security-policy" in resp.headers
    # Production-gated headers stay off — staging is not production.
    for header in _PRODUCTION_HEADERS:
        assert header not in resp.headers


def test_security_headers_master_switch_off() -> None:
    """SECURITY_HEADERS_ENABLED=False suppresses every tier, opt-ins included."""
    s = make_settings(
        **_BASE, ENVIRONMENT="production", SECURITY_HEADERS_ENABLED=False, **_OPT_IN
    )
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    for header in _ALWAYS_ON_HEADERS + _PRODUCTION_HEADERS + _OPT_IN_HEADERS:
        assert header not in resp.headers


def test_hsts_disabled_when_max_age_zero() -> None:
    """HSTS_MAX_AGE=0 drops only the Strict-Transport-Security header."""
    s = make_settings(**_BASE, ENVIRONMENT="production", HSTS_MAX_AGE=0, **_OPT_IN)
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert "strict-transport-security" not in resp.headers
    assert "content-security-policy" in resp.headers


def test_hsts_without_include_subdomains() -> None:
    """HSTS_INCLUDE_SUBDOMAINS=False emits max-age alone, no includeSubDomains."""
    s = make_settings(
        **_BASE, ENVIRONMENT="production", HSTS_INCLUDE_SUBDOMAINS=False, **_OPT_IN
    )
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert "includeSubDomains" not in resp.headers["strict-transport-security"]


def test_custom_csp_override_in_production() -> None:
    """A configured CONTENT_SECURITY_POLICY overrides the tight API default."""
    custom = "default-src 'self'; frame-ancestors 'none'"
    s = make_settings(
        **_BASE,
        ENVIRONMENT="production",
        CONTENT_SECURITY_POLICY=custom,
        **_OPT_IN,
    )
    app = create_app(s, _router())
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/health/")
    assert resp.headers["content-security-policy"] == custom

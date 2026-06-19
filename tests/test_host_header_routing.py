"""Host-header routing tests for fastapi-m8 (item 5.3).

Validates that ``TrustedHostMiddleware`` behaves correctly under the
``ALLOWED_HOSTS`` lifecycle:
- No ALLOWED_HOSTS → permissive; any Host is accepted.
- ALLOWED_HOSTS set in dev (local/staging) → configured hosts pass; unlisted
  hosts get 400; "testserver" is auto-added so the test client always works.
- ALLOWED_HOSTS set in production or under STRICT_PRODUCTION_MODE → "testserver"
  is NOT auto-added; only explicitly listed hosts pass.

All tests drive the ASGI stack directly (no real server, no LifespanManager)
so they are fast, deterministic, and isolate the middleware layer from startup
validators (``check_config_health``).  The ``/hello`` endpoint comes from a
minimal router that carries no dependency on ``service_ready``, so acceptance
cases return 200 without a running lifespan.
"""

from __future__ import annotations

import pytest
from fastapi import APIRouter
from httpx import ASGITransport, AsyncClient

from fastapi_m8 import create_app
from tests.conftest import make_settings

# Shared kwargs that suppress doc/OpenAPI endpoints (not relevant to this suite).
_BASE = {"SET_OPEN_API": False, "SET_DOCS": False, "SET_REDOC": False}

# Production-safe CORS origins (no localhost) for tests that set ENVIRONMENT=production.
_PROD_CORS = {
    "BACKEND_CORS_ORIGINS": "https://app.example.com",
    "FRONTEND_HOST": "https://app.example.com",
    "BACKEND_HOST": "https://api.example.com",
}


def _make_router() -> APIRouter:
    """Minimal router with a single GET /hello that needs no service_ready."""
    r = APIRouter(tags=["test"])

    @r.get("/hello")
    def hello() -> dict:  # noqa: ANN201
        """Return hello world."""
        return {"hello": "world"}

    return r


async def _get(app, *, base_url: str, path: str = "/hello") -> int:
    """Send a GET request against *app* with the Host derived from *base_url*."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url=base_url
    ) as client:
        resp = await client.get(path)
    return resp.status_code


# ── No ALLOWED_HOSTS configured ───────────────────────────────────────────────


@pytest.mark.anyio
async def test_no_allowed_hosts_permits_any_host() -> None:
    """ALLOWED_HOSTS=None skips TrustedHostMiddleware; any Host is accepted."""
    app = create_app(
        make_settings(**_BASE, ALLOWED_HOSTS=None),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://arbitrary.host.example") == 200


# ── ALLOWED_HOSTS configured in dev (ENVIRONMENT=local) ──────────────────────


@pytest.mark.anyio
async def test_allowed_host_accepted_in_dev() -> None:
    """A listed host is accepted when ALLOWED_HOSTS is set in the local environment."""
    app = create_app(
        make_settings(**_BASE, ALLOWED_HOSTS=["api.example.com"]),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://api.example.com") == 200


@pytest.mark.anyio
async def test_disallowed_host_rejected_in_dev() -> None:
    """An unlisted host is rejected with 400 when ALLOWED_HOSTS is set."""
    app = create_app(
        make_settings(**_BASE, ALLOWED_HOSTS=["api.example.com"]),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://evil.example.com") == 400


@pytest.mark.anyio
async def test_dev_auto_adds_testserver() -> None:
    """In non-production, testserver is auto-injected so the HTTPX test client works."""
    app = create_app(
        make_settings(**_BASE, ALLOWED_HOSTS=["api.example.com"]),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://testserver") == 200


@pytest.mark.anyio
async def test_explicit_testserver_in_dev_accepted() -> None:
    """testserver listed explicitly is accepted even without the auto-inject path."""
    app = create_app(
        make_settings(**_BASE, ALLOWED_HOSTS=["api.example.com", "testserver"]),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://testserver") == 200


# ── ALLOWED_HOSTS in ENVIRONMENT=production ───────────────────────────────────


@pytest.mark.anyio
async def test_production_allowed_host_accepted() -> None:
    """A listed host is still accepted in production."""
    app = create_app(
        make_settings(
            **_BASE,
            **_PROD_CORS,
            ENVIRONMENT="production",
            ALLOWED_HOSTS=["api.example.com"],
        ),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://api.example.com") == 200


@pytest.mark.anyio
async def test_production_testserver_not_auto_added() -> None:
    """In production, testserver is NOT auto-added; Host: testserver → 400."""
    app = create_app(
        make_settings(
            **_BASE,
            **_PROD_CORS,
            ENVIRONMENT="production",
            ALLOWED_HOSTS=["api.example.com"],
        ),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://testserver") == 400


@pytest.mark.anyio
async def test_production_disallowed_host_rejected() -> None:
    """Unlisted host is rejected with 400 in production."""
    app = create_app(
        make_settings(
            **_BASE,
            **_PROD_CORS,
            ENVIRONMENT="production",
            ALLOWED_HOSTS=["api.example.com"],
        ),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://evil.example.com") == 400


# ── ALLOWED_HOSTS under STRICT_PRODUCTION_MODE ────────────────────────────────


@pytest.mark.anyio
async def test_strict_mode_allowed_host_accepted() -> None:
    """A listed host is accepted under STRICT_PRODUCTION_MODE."""
    app = create_app(
        make_settings(
            **_BASE,
            STRICT_PRODUCTION_MODE=True,
            ALLOWED_HOSTS=["api.example.com"],
        ),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://api.example.com") == 200


@pytest.mark.anyio
async def test_strict_mode_testserver_not_auto_added() -> None:
    """Under STRICT_PRODUCTION_MODE, testserver is NOT auto-added; Host: testserver → 400."""
    app = create_app(
        make_settings(
            **_BASE,
            STRICT_PRODUCTION_MODE=True,
            ALLOWED_HOSTS=["api.example.com"],
        ),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://testserver") == 400


@pytest.mark.anyio
async def test_strict_mode_disallowed_host_rejected() -> None:
    """Unlisted host is rejected with 400 under STRICT_PRODUCTION_MODE."""
    app = create_app(
        make_settings(
            **_BASE,
            STRICT_PRODUCTION_MODE=True,
            ALLOWED_HOSTS=["api.example.com"],
        ),
        _make_router(),
        service_name="test",
        service_version="1.0.0",
    )
    assert await _get(app, base_url="http://evil.example.com") == 400

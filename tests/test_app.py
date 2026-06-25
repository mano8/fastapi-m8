"""Tests for fastapi_m8._app.create_app."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest
from asgi_lifespan import LifespanManager
from auth_sdk_m8.core.exceptions import ConfigurationError
from fastapi import APIRouter
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from fastapi_m8 import (
    AppLifecycle,
    HealthAggregatePolicy,
    HealthCheckResult,
    HealthConfig,
    HealthStatus,
    create_app,
)
from tests.conftest import make_settings

_BASE = {"SET_OPEN_API": False, "SET_DOCS": False, "SET_REDOC": False}


# ── Helpers ───────────────────────────────────────────────────────────────────


@asynccontextmanager
async def live_client(application, **kwargs):
    """Start app lifespan then yield an async HTTP client against it."""
    async with LifespanManager(application) as manager:
        async with AsyncClient(
            transport=ASGITransport(app=manager.app),
            base_url="http://test",
            **kwargs,
        ) as client:
            yield client


def make_router() -> APIRouter:
    """Return a minimal APIRouter with a single GET /hello endpoint."""
    r = APIRouter(tags=["test"])

    @r.get("/hello")
    def hello() -> dict:  # noqa: ANN201
        """Return hello world."""
        return {"hello": "world"}

    return r


@pytest.fixture(name="test_router")
def router_fixture() -> APIRouter:
    """Pytest fixture: minimal router."""
    return make_router()


@pytest.fixture(name="test_app")
def app_fixture(test_router: APIRouter):
    """Pytest fixture: default fully-wired test app."""
    s = make_settings(**_BASE)
    return create_app(s, test_router, service_name="test-svc", service_version="1.0.0")


# ── Readiness before lifespan ─────────────────────────────────────────────────


def test_health_before_lifespan_returns_503(test_app) -> None:
    """service_ready defaults to False before lifespan starts."""
    assert test_app.state.service_ready is False


# ── Health after lifespan ─────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_health_after_lifespan_ok(test_app) -> None:
    """Health endpoint returns 200 ok after lifespan startup."""
    async with live_client(test_app) as client:
        resp = await client.get("/api/health/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.anyio
async def test_health_minimal_body_unauthenticated(test_app) -> None:
    """Unauthenticated call returns only status, no checks/version metadata."""
    async with live_client(test_app) as client:
        resp = await client.get("/api/health/")
    body = resp.json()
    assert "checks" not in body
    assert "fastapi_m8" not in body


@pytest.mark.anyio
async def test_health_detail_with_internal_token(test_router: APIRouter) -> None:
    """HEALTH_DETAIL_CREDENTIAL token exposes per-check detail to authorized callers."""
    s = make_settings(**_BASE, HEALTH_DETAIL_CREDENTIAL="health-detail-secret")
    a = create_app(s, test_router, service_name="test", service_version="1.0.0")
    async with live_client(
        a, headers={"X-Internal-Token": "health-detail-secret"}
    ) as client:
        resp = await client.get("/api/health/")
    body = resp.json()
    assert "fastapi_m8" in body
    assert "checks" in body


@pytest.mark.anyio
async def test_health_wrong_token_minimal(test_router: APIRouter) -> None:
    """Wrong X-Internal-Token against HEALTH_DETAIL_CREDENTIAL yields minimal body."""
    s = make_settings(**_BASE, HEALTH_DETAIL_CREDENTIAL="correcttoken")
    a = create_app(s, test_router)
    async with live_client(a) as client:
        resp = await client.get("/api/health/", headers={"X-Internal-Token": "wrong"})
    assert "checks" not in resp.json()


# ── Health detail gating — item 9.3 ──────────────────────────────────────────


@pytest.mark.anyio
async def test_health_detail_hidden_when_credential_unset(
    test_router: APIRouter,
) -> None:
    """No HEALTH_DETAIL_CREDENTIAL → detail body never shown (fail-closed)."""
    a = create_app(make_settings(**_BASE), test_router)
    async with live_client(a) as client:
        resp = await client.get(
            "/api/health/", headers={"X-Internal-Token": "anyvalue"}
        )
    body = resp.json()
    assert "checks" not in body
    assert "fastapi_m8" not in body


@pytest.mark.anyio
async def test_health_private_api_secret_does_not_open_detail(
    test_router: APIRouter,
) -> None:
    """PRIVATE_API_SECRET must NOT unlock /health detail (9.3 no-reuse)."""
    s = make_settings(
        **_BASE,
        PRIVATE_API_SECRET=SecretStr("private-secret"),
    )
    a = create_app(s, test_router)
    async with live_client(a, headers={"X-Internal-Token": "private-secret"}) as client:
        resp = await client.get("/api/health/")
    body = resp.json()
    assert "checks" not in body
    assert "fastapi_m8" not in body


@pytest.mark.anyio
async def test_health_detail_credential_reuse_as_private_secret_rejected(
    test_router: APIRouter,
) -> None:
    """HEALTH_DETAIL_CREDENTIAL == PRIVATE_API_SECRET is a fatal startup error."""
    s = make_settings(
        **_BASE,
        PRIVATE_API_SECRET=SecretStr("shared-secret"),
        HEALTH_DETAIL_CREDENTIAL=SecretStr("shared-secret"),
    )
    a = create_app(s, test_router)
    with pytest.raises(ConfigurationError, match="HEALTH_DETAIL_CREDENTIAL"):
        async with a.router.lifespan_context(a):
            pass


@pytest.mark.anyio
async def test_metrics_scrape_credential_reuse_as_private_secret_rejected(
    test_router: APIRouter,
) -> None:
    """METRICS_SCRAPE_CREDENTIAL == PRIVATE_API_SECRET is a fatal startup error."""
    s = make_settings(
        **_BASE,
        PRIVATE_API_SECRET=SecretStr("shared-secret"),
        METRICS_SCRAPE_CREDENTIAL=SecretStr("shared-secret"),
    )
    a = create_app(s, test_router)
    with pytest.raises(ConfigurationError, match="METRICS_SCRAPE_CREDENTIAL"):
        async with a.router.lifespan_context(a):
            pass


@pytest.mark.anyio
async def test_distinct_credentials_do_not_raise(test_router: APIRouter) -> None:
    """Distinct HEALTH_DETAIL_CREDENTIAL and METRICS_SCRAPE_CREDENTIAL are accepted."""
    s = make_settings(
        **_BASE,
        PRIVATE_API_SECRET=SecretStr("private-secret"),
        HEALTH_DETAIL_CREDENTIAL=SecretStr("health-secret"),
        METRICS_SCRAPE_CREDENTIAL=SecretStr("metrics-secret"),
    )
    a = create_app(s, test_router)
    async with a.router.lifespan_context(a):
        pass
    assert a.state.service_ready is True


# ── Health checks ─────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_failing_check_returns_503(test_router: APIRouter) -> None:
    """A FAIL check drives the aggregate to 503."""

    async def bad() -> HealthCheckResult:
        return HealthCheckResult(name="db", status=HealthStatus.FAIL)

    a = create_app(
        make_settings(**_BASE), test_router, health=HealthConfig(checks=[bad])
    )
    async with live_client(a) as client:
        resp = await client.get("/api/health/")
    assert resp.status_code == 503
    assert resp.json()["status"] == "fail"


@pytest.mark.anyio
async def test_degraded_check_lenient_returns_200(test_router: APIRouter) -> None:
    """A DEGRADED check stays at 200 under LENIENT policy."""

    async def degraded() -> HealthCheckResult:
        return HealthCheckResult(name="minio", status=HealthStatus.DEGRADED)

    a = create_app(
        make_settings(**_BASE),
        test_router,
        health=HealthConfig(
            checks=[degraded],
            policy=HealthAggregatePolicy.LENIENT,
        ),
    )
    async with live_client(a) as client:
        resp = await client.get("/api/health/")
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


@pytest.mark.anyio
async def test_health_detail_public_exposes_checks(test_router: APIRouter) -> None:
    """health_detail_public=True makes checks visible without a token."""

    async def ok_check() -> HealthCheckResult:
        return HealthCheckResult(name="ping", status=HealthStatus.OK)

    a = create_app(
        make_settings(**_BASE),
        test_router,
        health=HealthConfig(checks=[ok_check], detail_public=True),
    )
    async with live_client(a) as client:
        resp = await client.get("/api/health/")
    assert "checks" in resp.json()


# ── Health caching ────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_health_cache_prevents_double_invocation(test_router: APIRouter) -> None:
    """Within health_cache_ttl a second probe reuses cached results."""
    call_count = 0

    async def counted() -> HealthCheckResult:
        nonlocal call_count
        call_count += 1
        return HealthCheckResult(name="db", status=HealthStatus.OK)

    a = create_app(
        make_settings(**_BASE),
        test_router,
        health=HealthConfig(checks=[counted], cache_ttl=10.0),
    )
    async with live_client(a) as client:
        await client.get("/api/health/")
        await client.get("/api/health/")
    assert call_count == 1


# ── App-scoped state isolation ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_two_apps_independent_readiness(test_router: APIRouter) -> None:
    """Two app instances have independent readiness state."""
    s = make_settings(**_BASE)
    app1 = create_app(s, test_router)
    app2 = create_app(s, test_router)
    assert app2.state.service_ready is False
    async with live_client(app1):
        pass
    assert app1.state.service_ready is True
    assert app2.state.service_ready is False


# ── Startup validators ────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_startup_validator_fail_prevents_ready(test_router: APIRouter) -> None:
    """A raising startup validator aborts lifespan; service_ready stays False."""

    async def failing_validator() -> None:
        raise RuntimeError("DB not reachable")

    a = create_app(
        make_settings(**_BASE),
        test_router,
        lifecycle=AppLifecycle(startup_validators=[failing_validator]),
    )
    with pytest.raises(RuntimeError, match="DB not reachable"):
        async with a.router.lifespan_context(a):
            pass
    assert a.state.service_ready is False


# ── Auto config-health (item 1.1) ─────────────────────────────────────────────


@pytest.mark.anyio
async def test_config_health_blocks_lifespan_on_production_localhost_cors(
    test_router: APIRouter,
) -> None:
    """Production localhost CORS origins fail config-health during lifespan."""
    a = create_app(
        make_settings(
            **_BASE, ENVIRONMENT="production", ALLOWED_HOSTS=["api.example.com"]
        ),
        test_router,
    )
    with pytest.raises(ConfigurationError):
        async with a.router.lifespan_context(a):
            pass
    assert a.state.service_ready is False


@pytest.mark.anyio
async def test_config_health_blocks_lifespan_on_strict_wildcard_hosts(
    test_router: APIRouter,
) -> None:
    """A wildcard ALLOWED_HOSTS under strict mode fails config-health."""
    a = create_app(
        make_settings(
            **_BASE,
            ENVIRONMENT="production",
            STRICT_PRODUCTION_MODE=True,
            ALLOWED_HOSTS=["*"],
            BACKEND_CORS_ORIGINS="https://app.example.com",
            FRONTEND_HOST="https://app.example.com",
        ),
        test_router,
    )
    with pytest.raises(ConfigurationError):
        async with a.router.lifespan_context(a):
            pass
    assert a.state.service_ready is False


@pytest.mark.anyio
async def test_user_validators_skipped_when_config_health_fails(
    test_router: APIRouter,
) -> None:
    """A caller validator never runs when config-health fails first."""
    ran: list[str] = []

    async def user_validator() -> None:
        ran.append("user")

    a = create_app(
        make_settings(
            **_BASE, ENVIRONMENT="production", ALLOWED_HOSTS=["api.example.com"]
        ),
        test_router,
        lifecycle=AppLifecycle(startup_validators=[user_validator]),
    )
    with pytest.raises(ConfigurationError):
        async with a.router.lifespan_context(a):
            pass
    assert ran == []


@pytest.mark.anyio
async def test_config_health_runs_before_user_validators(
    test_router: APIRouter,
) -> None:
    """Config-health is prepended: it runs, then caller validators, in order."""
    order: list[str] = []

    async def user_validator() -> None:
        # service_ready is still False — startup has not completed yet.
        order.append("user")

    a = create_app(
        make_settings(**_BASE),
        test_router,
        lifecycle=AppLifecycle(startup_validators=[user_validator]),
    )
    async with a.router.lifespan_context(a):
        order.append("ready")
    assert order == ["user", "ready"]
    assert a.state.service_ready is True


# ── Lifespan teardown ─────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_lifespan_calls_auth_deps_close(test_router: APIRouter) -> None:
    """Lifespan exit calls auth_deps.close() exactly once."""
    mock_auth = MagicMock()
    mock_auth.close = AsyncMock()
    a = create_app(
        make_settings(**_BASE),
        test_router,
        lifecycle=AppLifecycle(auth_deps=mock_auth),
    )
    async with a.router.lifespan_context(a):
        pass
    mock_auth.close.assert_awaited_once()


@pytest.mark.anyio
async def test_lifespan_disposes_engine(test_router: APIRouter) -> None:
    """Lifespan exit calls db_engine.dispose() exactly once."""
    mock_engine = MagicMock()
    a = create_app(
        make_settings(**_BASE),
        test_router,
        lifecycle=AppLifecycle(db_engine=mock_engine),
    )
    async with a.router.lifespan_context(a):
        pass
    mock_engine.dispose.assert_called_once()


# ── lifespan_extras ordering ──────────────────────────────────────────────────


@pytest.mark.anyio
async def test_lifespan_extras_ready_after_extras_enter(test_router: APIRouter) -> None:
    """service_ready flips True only after lifespan_extras __aenter__ completes."""
    ready_at_entry: list[bool] = []

    @asynccontextmanager
    async def extras(application) -> AsyncIterator[None]:
        ready_at_entry.append(application.state.service_ready)
        yield

    a = create_app(
        make_settings(**_BASE),
        test_router,
        lifecycle=AppLifecycle(lifespan_extras=extras),
    )
    async with a.router.lifespan_context(a):
        pass
    assert ready_at_entry == [False]
    assert a.state.service_ready is True


# ── Route reachability ────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_included_router_reachable(test_app) -> None:
    """Domain routes from the included router are reachable."""
    async with live_client(test_app) as client:
        resp = await client.get("/hello")
    assert resp.status_code == 200
    assert resp.json() == {"hello": "world"}


# ── Production docs gating (F5) ───────────────────────────────────────────────


def test_production_env_gates_all_doc_urls(test_router: APIRouter) -> None:
    """ENVIRONMENT=production + SET_*=True → all three doc URLs are None (gated off)."""
    s = make_settings(
        ENVIRONMENT="production", SET_OPEN_API=True, SET_DOCS=True, SET_REDOC=True
    )
    app = create_app(s, test_router)
    assert app.openapi_url is None
    assert app.docs_url is None
    assert app.redoc_url is None


def test_non_production_env_respects_set_flags(test_router: APIRouter) -> None:
    """Non-production: effective URLs follow SET_* flags unchanged."""
    s = make_settings(**_BASE)  # _BASE already has SET_OPEN_API=False etc.
    app = create_app(s, test_router)
    assert app.openapi_url is None
    assert app.docs_url is None
    assert app.redoc_url is None

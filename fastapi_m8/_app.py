"""App factory for fastapi-m8 consumer services.

``create_app`` wires CORS, optional metrics middleware, the health endpoint,
OpenAPI schema, and a managed lifespan (startup validators + graceful teardown).
"""

from __future__ import annotations

import inspect
import logging
import secrets
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import anyio
from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from fastapi_m8._compat import _COMPAT_STATE, _assert_compat
from fastapi_m8._health import (
    DEFAULT_TIMEOUT,
    HealthAggregatePolicy,
    HealthCheck,
    HealthCheckResult,
    HealthStatus,
    aggregate,
    run_check,
)
from fastapi_m8._version import __version__

if TYPE_CHECKING:
    from fastapi_m8._deps import AuthDeps
    from fastapi_m8._engine import DbEngine
    from fastapi_m8.config import ConsumerServiceSettings

logger = logging.getLogger(__name__)

StartupValidator = Callable[[], Awaitable[None]]

_CORS_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
_CORS_HEADERS = ["Authorization", "Content-Type", "X-Requested-With"]


def _mark_ready(app: FastAPI) -> None:
    app.state.service_ready = True
    app.state.ready_since = time.monotonic()


def _build_lifespan(
    auth_deps: AuthDeps | None,
    db_engine: DbEngine | None,
    startup_validators: list[StartupValidator] | None,
    lifespan_extras: Callable | None,
) -> Callable:
    """Return an asynccontextmanager lifespan for the app."""

    async def _run_startup() -> None:
        for v in startup_validators or []:
            await v()

    async def _teardown() -> None:
        if auth_deps is not None:
            await auth_deps.close()
        if db_engine is not None:
            db_engine.dispose()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:  # type: ignore[misc]
        await _run_startup()
        if lifespan_extras is not None:
            async with lifespan_extras(app):
                _mark_ready(app)
                yield
        else:
            _mark_ready(app)
            yield
        await _teardown()

    return lifespan


def _add_metrics_middleware(app: FastAPI, settings: ConsumerServiceSettings) -> None:
    if not settings.METRICS_ENABLED:
        return
    try:
        from auth_sdk_m8.observability.middleware import (  # noqa: PLC0415
            MetricsMiddleware,
        )

        app.add_middleware(MetricsMiddleware)
    except ImportError:  # pragma: no cover — only fires without [observability] extra
        logger.warning(
            "METRICS_ENABLED but auth-sdk-m8[observability] missing; skipping"
        )


def _build_default_authorizer(
    settings: ConsumerServiceSettings,
) -> Callable[[Request], bool]:
    """Return a token authorizer closed over the private API secret."""
    sec = settings.PRIVATE_API_SECRET

    def _authorizer(request: Request) -> bool:
        if not sec:
            return False
        return secrets.compare_digest(
            request.headers.get("X-Internal-Token", ""),
            sec.get_secret_value(),
        )

    return _authorizer


async def _gather_health_results(
    app: FastAPI,
    checks: list[HealthCheck],
    timeout: float,
    policy: HealthAggregatePolicy,
    cache_ttl: float,
) -> tuple[list[HealthCheckResult], HealthStatus, int]:
    """Run all health checks with caching; return results, status, HTTP code."""
    cache = app.state.health_cache
    if cache and (time.monotonic() - cache[0]) < cache_ttl:
        return cache[1], cache[2], cache[3]
    results: list[HealthCheckResult] = [None] * len(checks)  # type: ignore[list-item]

    async def _run_one(idx: int, check: HealthCheck) -> None:
        results[idx] = await run_check(check, timeout=timeout)

    async with anyio.create_task_group() as tg:
        for i, c in enumerate(checks):
            tg.start_soon(_run_one, i, c)
    overall = aggregate(results, policy)
    code = 503 if overall is HealthStatus.FAIL else 200
    app.state.health_cache = (time.monotonic(), results, overall, code)
    return results, overall, code


def _build_health_body(
    results: list[HealthCheckResult],
    service_name: str | None,
    service_version: str | None,
) -> dict[str, Any]:
    """Return the detailed health response body."""
    return {
        "checks": [r.model_dump() for r in results],
        "service": service_name,
        "version": service_version,
        "fastapi_m8": __version__,
        "auth_sdk_m8": _COMPAT_STATE.get("auth_version"),
    }


def _openapi_config(
    settings: ConsumerServiceSettings,
    service_name: str | None,
    service_version: str | None,
) -> dict[str, Any]:
    """Build FastAPI constructor kwargs for title, version, and OpenAPI URLs."""
    return {
        "title": service_name or settings.PROJECT_NAME,
        "version": service_version or "0.0.0",
        "openapi_url": (
            f"{settings.API_PREFIX}/openapi.json" if settings.SET_OPEN_API else None
        ),
        "docs_url": f"{settings.API_PREFIX}/docs" if settings.SET_DOCS else None,
        "redoc_url": f"{settings.API_PREFIX}/redoc" if settings.SET_REDOC else None,
        "generate_unique_id_function": lambda r: f"{r.tags[0]}-{r.name}",
    }


def _register_health_route(
    app: FastAPI,
    api_prefix: str,
    checks: list[HealthCheck],
    health_check_timeout: float,
    health_policy: HealthAggregatePolicy,
    health_detail_public: bool,
    health_cache_ttl: float,
    authorize: Callable[[Request], bool | Awaitable[bool]],
    service_name: str | None,
    service_version: str | None,
) -> None:
    """Register the /health/ endpoint on the app."""

    async def _is_authorized(request: Request) -> bool:
        res = authorize(request)
        return await res if inspect.isawaitable(res) else bool(res)

    @app.get(f"{api_prefix}/health/", include_in_schema=False, tags=["health"])
    async def health(request: Request) -> JSONResponse:
        if not request.app.state.service_ready:
            return JSONResponse(
                {"status": "initializing", "ready": False}, status_code=503
            )
        results, overall, code = await _gather_health_results(
            app, checks, health_check_timeout, health_policy, health_cache_ttl
        )
        logger.debug("health: %s (%d checks)", overall.value, len(results))
        body: dict[str, Any] = {"status": overall.value}
        if health_detail_public or await _is_authorized(request):
            body |= _build_health_body(results, service_name, service_version)
        return JSONResponse(body, status_code=code)


def create_app(
    settings: ConsumerServiceSettings,
    router: APIRouter,
    *,
    service_name: str | None = None,
    service_version: str | None = None,
    auth_deps: AuthDeps | None = None,
    db_engine: DbEngine | None = None,
    health_checks: list[HealthCheck] | None = None,
    health_check_timeout: float = DEFAULT_TIMEOUT,
    health_policy: HealthAggregatePolicy = HealthAggregatePolicy.LENIENT,
    health_detail_public: bool = False,
    health_detail_authorizer: Callable[[Request], bool | Awaitable[bool]] | None = None,
    health_cache_ttl: float = 2.0,
    startup_validators: list[StartupValidator] | None = None,
    configure: Callable[[FastAPI], None] | None = None,
    lifespan_extras: Callable | None = None,
) -> FastAPI:
    """Wire and return a consumer FastAPI app.

    Args:
        settings: Service settings (a ``ConsumerServiceSettings`` subclass).
        router: The domain ``APIRouter`` to include.
        service_name: Human-readable service name (falls back to
            ``settings.PROJECT_NAME``).
        service_version: Semantic version string for this service.
        auth_deps: ``AuthDeps`` built by ``build_auth_deps()``.  Teardown
            is called on shutdown.
        db_engine: ``DbEngine`` built by ``create_db_engine()``.  Disposed on
            shutdown.  Pass ``None`` for DB-less services.
        health_checks: List of async callables returning
            ``HealthCheckResult``.
        health_check_timeout: Per-check timeout in seconds.
        health_policy: ``LENIENT`` (default) or ``STRICT`` aggregate policy.
        health_detail_public: If True, expose per-check detail to everyone.
        health_detail_authorizer: Override the default ``X-Internal-Token``
            gate.  Accepts sync or async callables.
        health_cache_ttl: Seconds to cache health-check results.
        startup_validators: Async callables run before traffic; a raise
            aborts lifespan so the container never reports ready.
        configure: Receives the fully-wired app for static additions
            (middleware, exception handlers).
        lifespan_extras: Async context manager run inside the managed
            lifespan, after auth/engine exist and before their teardown.

    Returns:
        A fully configured ``FastAPI`` instance.
    """
    _assert_compat()
    checks = list(health_checks or [])

    app = FastAPI(
        lifespan=_build_lifespan(
            auth_deps, db_engine, startup_validators, lifespan_extras
        ),
        **_openapi_config(settings, service_name, service_version),
    )
    app.state.service_ready = False
    app.state.ready_since = None
    app.state.health_cache = None

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=_CORS_METHODS,
        allow_headers=_CORS_HEADERS,
        max_age=3600,
    )

    _add_metrics_middleware(app, settings)

    authorize = health_detail_authorizer or _build_default_authorizer(settings)
    _register_health_route(
        app,
        settings.API_PREFIX,
        checks,
        health_check_timeout,
        health_policy,
        health_detail_public,
        health_cache_ttl,
        authorize,
        service_name,
        service_version,
    )

    app.include_router(router)
    logger.info(
        "fastapi-m8 %s | service=%s version=%s | auth-sdk-m8=%s",
        __version__,
        service_name,
        service_version,
        _COMPAT_STATE.get("auth_version"),
    )

    if configure is not None:
        configure(app)

    return app

"""
App factory for fastapi-m8 consumer services.

``create_app`` wires CORS, optional metrics middleware, the health endpoint,
OpenAPI schema, and a managed lifespan (startup validators + graceful teardown).
"""

from __future__ import annotations

import inspect
import logging
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import anyio
from auth_sdk_m8.controllers.meta import mount_service_meta
from auth_sdk_m8.core.config import check_config_health
from auth_sdk_m8.core.exceptions import ConfigurationError
from auth_sdk_m8.security.guards import (
    make_internal_token_authorizer,
    make_scrape_credential_guard,
)
from auth_sdk_m8.security.headers import add_security_headers_middleware
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

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


@dataclass
class HealthConfig:
    """
    Configuration for the health endpoint.

    Attributes
    ----------
    checks
        List of health-check callables returning HealthCheckResult.
    timeout
        Per-check timeout in seconds.
    policy
        LENIENT (default) or STRICT aggregate policy.
    detail_public
        If True, expose per-check detail to everyone.
    detail_authorizer
        Override the default X-Internal-Token gate.
    cache_ttl
        Seconds to cache health-check results.

    """

    checks: list[HealthCheck] | None = None
    timeout: float = DEFAULT_TIMEOUT
    policy: HealthAggregatePolicy = field(
        default_factory=lambda: HealthAggregatePolicy.LENIENT
    )
    detail_public: bool = False
    detail_authorizer: Callable[[Request], bool | Awaitable[bool]] | None = None
    cache_ttl: float = 2.0


@dataclass
class AppLifecycle:
    """
    App lifecycle configuration.

    Attributes
    ----------
    auth_deps
        AuthDeps instance for token validation teardown.
    db_engine
        DbEngine instance to dispose on shutdown.
    startup_validators
        Async callables run before traffic; a raise aborts lifespan.
    configure
        Receives the fully-wired app for static additions.
    lifespan_extras
        Async context manager run inside the managed lifespan.

    """

    auth_deps: AuthDeps | None = None
    db_engine: DbEngine | None = None
    startup_validators: list[StartupValidator] | None = None
    configure: Callable[[FastAPI], None] | None = None
    lifespan_extras: Callable | None = None


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


def _check_credential_no_reuse(settings: ConsumerServiceSettings) -> None:
    """Raise ConfigurationError when an operational credential reuses PRIVATE_API_SECRET."""
    pri = settings.PRIVATE_API_SECRET
    if pri is None:
        return
    pri_val = pri.get_secret_value()
    health_cred = settings.HEALTH_DETAIL_CREDENTIAL
    if health_cred and health_cred.get_secret_value() == pri_val:
        raise ConfigurationError(
            "CONFIG: HEALTH_DETAIL_CREDENTIAL must not equal PRIVATE_API_SECRET — "
            "operational credentials must be independently rotatable from the "
            "private-API bootstrap secret (item 9.3). Set a distinct value."
        )
    metrics_cred = settings.METRICS_SCRAPE_CREDENTIAL
    if metrics_cred and metrics_cred.get_secret_value() == pri_val:
        raise ConfigurationError(
            "CONFIG: METRICS_SCRAPE_CREDENTIAL must not equal PRIVATE_API_SECRET — "
            "operational credentials must be independently rotatable from the "
            "private-API bootstrap secret (item 9.3). Set a distinct value."
        )


def _build_config_health_validator(
    settings: ConsumerServiceSettings,
) -> StartupValidator:
    """
    Return a startup validator running the shared ``check_config_health``.

    The validator runs inside the lifespan (not at import time) and raises
    ``ConfigurationError`` on fatal misconfiguration, aborting startup before
    any caller-provided validators run.
    """

    async def _validate_config_health() -> None:
        check_config_health(settings, logger)
        _check_credential_no_reuse(settings)

    return _validate_config_health


def _add_metrics_middleware(app: FastAPI, settings: ConsumerServiceSettings) -> None:
    if not settings.METRICS_ENABLED:
        return
    try:
        from auth_sdk_m8.observability.metrics import setup  # noqa: PLC0415
        from auth_sdk_m8.observability.middleware import (  # noqa: PLC0415
            MetricsMiddleware,
        )

        setup(
            enabled=settings.METRICS_ENABLED,
            groups_str=settings.METRICS_GROUPS,
            api_prefix=settings.API_PREFIX,
        )
        app.add_middleware(MetricsMiddleware)
    except ImportError:  # pragma: no cover — only fires without [observability] extra
        logger.warning(
            "METRICS_ENABLED but auth-sdk-m8[observability] missing; skipping"
        )


def _build_default_authorizer(
    settings: ConsumerServiceSettings,
) -> Callable[[Request], bool]:
    """Return a predicate gating /health detail on HEALTH_DETAIL_CREDENTIAL (fail-closed)."""
    cred = settings.HEALTH_DETAIL_CREDENTIAL
    return make_internal_token_authorizer(cred.get_secret_value() if cred else None)


def _register_metrics_route(app: FastAPI, settings: ConsumerServiceSettings) -> None:
    """
    Register ``/metrics`` with an optional scrape-credential guard (1.4).

    The route is only wired when ``METRICS_ENABLED=True``.  When
    ``METRICS_SCRAPE_CREDENTIAL`` is unset the guard is a no-op and the network
    boundary (internal entrypoint) remains the sole control.  When set, requests
    must present ``Authorization: Bearer <credential>`` (constant-time match).
    """
    if not settings.METRICS_ENABLED:
        return
    cred_field = settings.METRICS_SCRAPE_CREDENTIAL
    guard = make_scrape_credential_guard(
        cred_field.get_secret_value() if cred_field else None
    )
    try:
        from auth_sdk_m8.observability import metrics as _obs  # noqa: PLC0415
    except ImportError:  # pragma: no cover
        logger.warning(
            "METRICS_ENABLED but auth-sdk-m8[observability] missing; "
            "skipping /metrics route"
        )
        return

    @app.get("/metrics", include_in_schema=False, dependencies=[Depends(guard)])
    def _metrics_endpoint() -> Response:
        data, content_type = _obs.render()
        return Response(content=data, media_type=content_type)


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
        "version": service_version or settings.SERVICE_VERSION,
        "openapi_url": (
            f"{settings.API_PREFIX}/openapi.json"
            if settings.effective_set_open_api
            else None
        ),
        "docs_url": (
            f"{settings.API_PREFIX}/docs" if settings.effective_set_docs else None
        ),
        "redoc_url": (
            f"{settings.API_PREFIX}/redoc" if settings.effective_set_redoc else None
        ),
        "generate_unique_id_function": lambda r: (
            f"{r.tags[0] if r.tags else r.name}-{r.name}"
        ),
    }


def _init_app_state(app: FastAPI) -> None:
    app.state.service_ready = False
    app.state.ready_since = None
    app.state.health_cache = None


def _add_cors_middleware(app: FastAPI, settings: ConsumerServiceSettings) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=_CORS_METHODS,
        allow_headers=_CORS_HEADERS,
        max_age=3600,
    )


def _add_trusted_host_middleware(
    app: FastAPI, settings: ConsumerServiceSettings
) -> None:
    if not settings.ALLOWED_HOSTS:
        return
    hosts = list(settings.ALLOWED_HOSTS)
    is_production = (
        settings.ENVIRONMENT == "production" or settings.STRICT_PRODUCTION_MODE
    )
    if not is_production and "testserver" not in hosts:
        hosts = [*hosts, "testserver"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)


def _register_health_route(
    app: FastAPI,
    api_prefix: str,
    checks: list[HealthCheck],
    config: HealthConfig,
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
            app, checks, config.timeout, config.policy, config.cache_ttl
        )
        logger.debug("health: %s (%d checks)", overall.value, len(results))
        body: dict[str, Any] = {"status": overall.value}
        if config.detail_public or await _is_authorized(request):
            body |= _build_health_body(results, service_name, service_version)
        return JSONResponse(body, status_code=code)


def _register_meta_routes(app: FastAPI, settings: ConsumerServiceSettings) -> None:
    """
    Mount the shared ``/meta`` + ``/ping`` routes (fail-closed at boot).

    Sources the values from ``settings.build_service_meta()`` so the whole
    consumer fleet exposes an identical shape and *can't forget* — a consumer
    without valid version/contract settings fails to boot here.
    """
    mount_service_meta(app, settings.build_service_meta(), prefix=settings.API_PREFIX)


def create_app(
    settings: ConsumerServiceSettings,
    router: APIRouter,
    *,
    service_name: str | None = None,
    service_version: str | None = None,
    health: HealthConfig | None = None,
    lifecycle: AppLifecycle | None = None,
) -> FastAPI:
    """
    Wire and return a consumer FastAPI app.

    Parameters
    ----------
    settings
        Service settings (a ConsumerServiceSettings subclass).
    router
        The domain APIRouter to include.
    service_name
        Human-readable service name (falls back to settings.PROJECT_NAME).
    service_version
        Semantic version string for this service.
    health
        Health endpoint config; defaults to HealthConfig().
    lifecycle
        Lifecycle config (auth, engine, validators); defaults to AppLifecycle().

    Returns
    -------
    FastAPI
        A fully configured instance.

    """
    _assert_compat()
    h = health or HealthConfig()
    lc = lifecycle or AppLifecycle()
    checks = list(h.checks or [])
    startup_validators = [
        _build_config_health_validator(settings),
        *(lc.startup_validators or []),
    ]
    app = FastAPI(
        lifespan=_build_lifespan(
            lc.auth_deps, lc.db_engine, startup_validators, lc.lifespan_extras
        ),
        **_openapi_config(settings, service_name, service_version),
    )
    _init_app_state(app)
    _add_cors_middleware(app, settings)
    _add_trusted_host_middleware(app, settings)
    add_security_headers_middleware(app, settings)
    _add_metrics_middleware(app, settings)
    _register_metrics_route(app, settings)
    authorize = h.detail_authorizer or _build_default_authorizer(settings)
    _register_health_route(
        app, settings.API_PREFIX, checks, h, authorize, service_name, service_version
    )
    _register_meta_routes(app, settings)
    app.include_router(router)
    logger.info(
        "fastapi-m8 %s svc=%s v=%s sdk=%s",
        __version__,
        service_name,
        service_version,
        _COMPAT_STATE.get("auth_version"),
    )
    if lc.configure is not None:
        lc.configure(app)
    return app

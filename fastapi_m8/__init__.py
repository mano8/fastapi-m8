"""
fastapi-m8 — FastAPI application framework for m8 consumer microservices.

Public surface (stable):

Tier 1 — everyday service API::

    from fastapi_m8 import create_app, build_auth_deps, AuthDeps
    from fastapi_m8 import create_db_engine, DbEngine
    from fastapi_m8 import ConsumerServiceSettings

Tier 1 — auth event stream (fa-auth SSE bridge)::

    from fastapi_m8 import build_event_stream_client
    from fastapi_m8 import AuthEventStreamClient, AuthStreamEvent, derive_stream_url

Tier 2 — health building blocks::

    from fastapi_m8 import (
        HealthStatus, HealthCheckResult, HealthCheck, HealthAggregatePolicy,
    )

Tier 3 — informational / future::

    from fastapi_m8 import create_async_app, CAPABILITIES, capabilities
    from fastapi_m8 import COMPAT_MATRIX, __version__
"""

# Tier 1
from fastapi_m8._app import AppLifecycle, HealthConfig, create_app

# Tier 3
from fastapi_m8._async_stub import CAPABILITIES, capabilities, create_async_app
from fastapi_m8._compat import COMPAT_MATRIX
from fastapi_m8._deps import AuthDeps, build_auth_deps
from fastapi_m8._engine import DbEngine, create_db_engine

# Tier 1 — auth event stream
from fastapi_m8._events import (
    AuthEventStreamClient,
    AuthStreamEvent,
    build_event_stream_client,
    derive_stream_url,
)

# Tier 2
from fastapi_m8._health import (
    HealthAggregatePolicy,
    HealthCheck,
    HealthCheckResult,
    HealthStatus,
)
from fastapi_m8._version import __version__
from fastapi_m8.config import ConsumerServiceSettings

__all__ = [
    "__version__",
    # Tier 1
    "create_app",
    "HealthConfig",
    "AppLifecycle",
    "build_auth_deps",
    "AuthDeps",
    "create_db_engine",
    "DbEngine",
    "ConsumerServiceSettings",
    # Tier 1 — auth event stream
    "build_event_stream_client",
    "AuthEventStreamClient",
    "AuthStreamEvent",
    "derive_stream_url",
    # Tier 2
    "HealthStatus",
    "HealthCheckResult",
    "HealthCheck",
    "HealthAggregatePolicy",
    # Tier 3
    "create_async_app",
    "CAPABILITIES",
    "capabilities",
    "COMPAT_MATRIX",
]

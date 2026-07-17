"""
fastapi-m8 — FastAPI application framework for m8 consumer microservices.

Public surface (stable):

Tier 1 — everyday service API::

    from fastapi_m8 import create_app, build_auth_deps, AuthDeps
    from fastapi_m8 import create_db_engine, DbEngine
    from fastapi_m8 import ConsumerServiceSettings

Tier 1 — remote API-key principal (issuer introspection)::

    from fastapi_m8 import API_KEY_HEADER, derive_api_key_introspection_url
    from fastapi_m8 import ApiKeyIntrospectionError, ApiKeyQuotaExceededError

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
from fastapi_m8._api_key import (
    ApiKeyIntrospectionError,
    ApiKeyQuotaExceededError,
    derive_api_key_introspection_url,
)
from fastapi_m8._app import AppLifecycle, HealthConfig, create_app

# Tier 3
from fastapi_m8._async_stub import CAPABILITIES, capabilities, create_async_app
from fastapi_m8._compat import COMPAT_MATRIX
from fastapi_m8._deps import API_KEY_HEADER, AuthDeps, build_auth_deps
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

# Tier 1 — per-consumer internal-auth for private calls (Phase 9.1)
from fastapi_m8._internal_auth import (
    InternalAuthProvider,
    ServiceTokenInternalAuth,
    build_internal_auth,
    derive_service_token_url,
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
    # Tier 1 — remote API-key principal (§3.12)
    "API_KEY_HEADER",
    "ApiKeyIntrospectionError",
    "ApiKeyQuotaExceededError",
    "derive_api_key_introspection_url",
    # Tier 1 — per-consumer internal-auth
    "build_internal_auth",
    "InternalAuthProvider",
    "ServiceTokenInternalAuth",
    "derive_service_token_url",
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

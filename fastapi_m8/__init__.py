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
    from fastapi_m8 import audit_api_key_routes, BareApiKeyDependency

Tier 1 — auth event stream (fa-auth SSE bridge)::

    from fastapi_m8 import build_event_stream_client
    from fastapi_m8 import AuthEventStreamClient, AuthStreamEvent, derive_stream_url

Tier 2 — health building blocks::

    from fastapi_m8 import (
        HealthStatus, HealthCheckResult, HealthCheck, HealthAggregatePolicy,
    )

Reusable SDK primitives (re-exported from auth-sdk-m8, so consumers depend
only on fastapi-m8 — a consumer service must never import ``auth_sdk_m8``
directly)::

    from fastapi_m8 import has_superuser_privileges, has_minimum_role, RoleType
    from fastapi_m8 import BaseController, ResponseModelBase, ResponseMessage
    from fastapi_m8 import TimestampMixin, UserModel, ValidationConstants
    from fastapi_m8 import find_dotenv, render_metrics, REGISTRY
    from fastapi_m8 import make_scrape_credential_guard

``BaseController`` and ``TimestampMixin`` are the only two of those that need
the ``[db]`` extra; both are resolved lazily — see ``__getattr__`` below.

Tier 3 — informational / future::

    from fastapi_m8 import create_async_app, CAPABILITIES, capabilities
    from fastapi_m8 import COMPAT_MATRIX, __version__
"""

from typing import TYPE_CHECKING, Any

# Tier 1
# Reusable SDK primitives — re-exported so consumers only need fastapi-m8,
# never a direct auth-sdk-m8 dependency.
from auth_sdk_m8 import has_superuser_privileges
from auth_sdk_m8.authorization import has_minimum_role
from auth_sdk_m8.observability.metrics import REGISTRY
from auth_sdk_m8.observability.metrics import render as render_metrics
from auth_sdk_m8.schemas.base import ResponseMessage, ResponseModelBase, RoleType
from auth_sdk_m8.schemas.shared import ValidationConstants
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security.guards import make_scrape_credential_guard
from auth_sdk_m8.utils.paths import find_dotenv

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

# Tier 1 — API-key route-wiring audit (§3.3.1)
from fastapi_m8._route_audit import BareApiKeyDependency, audit_api_key_routes
from fastapi_m8._version import __version__
from fastapi_m8.config import ConsumerServiceSettings

if TYPE_CHECKING:  # pragma: no cover - type-checker-only, never executed
    # Imported eagerly for type checkers and IDEs only. At runtime these two
    # names are served by ``__getattr__`` below, so a bare install can import
    # the package without the ``[db]`` extra.
    from auth_sdk_m8.controllers.base import BaseController
    from auth_sdk_m8.models.shared import TimestampMixin

# The SDK re-exports that require the ``[db]`` extra, mapped to their source
# module. ``auth_sdk_m8.controllers.base`` imports ``sqlalchemy.exc`` and
# ``sqlmodel``; ``auth_sdk_m8.models.shared`` imports ``sqlalchemy`` and
# ``sqlmodel``. Every other re-export above is extra-free.
_DB_REEXPORTS: dict[str, str] = {
    "BaseController": "auth_sdk_m8.controllers.base",
    "TimestampMixin": "auth_sdk_m8.models.shared",
}


def __getattr__(name: str) -> Any:
    """
    Resolve the ``[db]``-extra SDK re-exports on first access (PEP 562).

    ``pip install fastapi-m8`` with no extras must yield an importable
    package. Importing ``BaseController`` / ``TimestampMixin`` at module level
    made ``import fastapi_m8`` raise ``ModuleNotFoundError: No module named
    'sqlalchemy'`` on a bare install, because both come from SQLModel-backed
    SDK modules and SQLAlchemy arrives only through the ``db`` extra.

    Deferring them costs a bare install nothing and keeps the import boundary
    intact: a consumer still writes ``from fastapi_m8 import BaseController``.
    The object returned **is** the SDK object — identity is preserved, so ORM
    models mixing in the re-exported ``TimestampMixin`` register exactly the
    same metadata as before, and the resolved value is cached in the module
    globals so later lookups skip this function entirely.

    Note on where the failure now surfaces: PEP 562 moves it from
    ``import fastapi_m8`` to first attribute access. For both of these names
    that is still the consumer's own module-import time — ``BaseController``
    is subclassed and ``TimestampMixin`` is mixed in at class-definition
    time — so the deferral does **not** push an ``ImportError`` into a request
    path. It is a packaging fix, not a runtime-path hazard.
    """
    module_path = _DB_REEXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module  # noqa: PLC0415

    try:
        value = getattr(import_module(module_path), name)
    except ModuleNotFoundError as exc:
        raise ModuleNotFoundError(
            f"fastapi_m8.{name} is re-exported from {module_path}, which requires"
            f" the 'db' extra: install fastapi-m8[db] (or fastapi-m8[all])."
        ) from exc
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Keep the lazy names discoverable by ``dir()`` and tab completion."""
    return sorted(set(globals()) | set(_DB_REEXPORTS))


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
    "audit_api_key_routes",
    "BareApiKeyDependency",
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
    # Reusable SDK primitives (from auth-sdk-m8)
    "has_superuser_privileges",
    "has_minimum_role",
    "RoleType",
    "BaseController",
    "ResponseModelBase",
    "ResponseMessage",
    "TimestampMixin",
    "UserModel",
    "ValidationConstants",
    "find_dotenv",
    "render_metrics",
    "REGISTRY",
    "make_scrape_credential_guard",
    # Tier 3
    "create_async_app",
    "CAPABILITIES",
    "capabilities",
    "COMPAT_MATRIX",
]

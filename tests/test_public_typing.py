"""Public typing contract tests (§5.2).

Complements the mypy CI gate (`mypy fastapi_m8`), which only checks the
*package's own* source. This proves the *public* surface a consumer imports —
exactly as `fastapi_m8/__init__.py`'s module docstring documents it — actually
type-checks too, so a renamed export, a stale docstring example, or a drifted
return type (e.g. an accidental `Any` leaking where `ApiKeyPrincipal` /
`UserModel` is expected, §3.12) fails a test instead of only surfacing at a
consumer's own mypy run.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import fastapi_m8

REPO_ROOT = Path(__file__).resolve().parents[1]

# Typed usage of the documented public surface — one function per docstring
# tier, using the exact names fastapi_m8/__init__.py's docstring shows.
_TYPING_SNIPPET = '''
from __future__ import annotations

from fastapi import Depends, FastAPI

from fastapi_m8 import (
    API_KEY_HEADER,
    CAPABILITIES,
    ApiKeyIntrospectionError,
    ApiKeyQuotaExceededError,
    AppLifecycle,
    AuthDeps,
    AuthEventStreamClient,
    AuthStreamEvent,
    BareApiKeyDependency,
    COMPAT_MATRIX,
    ConsumerServiceSettings,
    DbEngine,
    HealthAggregatePolicy,
    HealthCheck,
    HealthCheckResult,
    HealthConfig,
    HealthStatus,
    InternalAuthProvider,
    ServiceTokenInternalAuth,
    __version__,
    audit_api_key_routes,
    build_auth_deps,
    build_event_stream_client,
    build_internal_auth,
    capabilities,
    create_app,
    create_async_app,
    create_db_engine,
    derive_api_key_introspection_url,
    derive_service_token_url,
    derive_stream_url,
)
from auth_sdk_m8.schemas.api_key import ApiKeyPrincipal
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.user import UserModel


def build(settings: ConsumerServiceSettings) -> AuthDeps:
    """build_auth_deps returns the documented AuthDeps type, not Any."""
    return build_auth_deps(settings)


def use_reader_guard(auth: AuthDeps, app: FastAPI) -> None:
    """The JWT reader dependency resolves to a typed UserModel (Phase 7)."""

    @app.get("/reader-thing")
    def route(user: UserModel = Depends(auth.get_current_active_reader)) -> dict:
        return {"role": user.role.value}


def use_require_role_factory(auth: AuthDeps, app: FastAPI) -> None:
    """require_role is typed as a factory returning a UserModel dependency."""
    dependency = auth.require_role(RoleType.READER)

    @app.get("/factory-thing")
    def route(user: UserModel = Depends(dependency)) -> dict:
        return {"role": user.role.value}


def use_writer_guard(auth: AuthDeps, app: FastAPI) -> None:
    """The JWT writer dependency resolves to a typed UserModel."""

    @app.get("/thing")
    def route(user: UserModel = Depends(auth.get_current_active_writer)) -> dict:
        return {"role": user.role.value}


def use_api_key_writer_guard(auth: AuthDeps, app: FastAPI) -> None:
    """The remote API-key writer dependency resolves to a typed ApiKeyPrincipal."""
    writer_dep = auth.get_current_api_key_writer
    if writer_dep is None:
        return

    @app.get("/api-thing")
    def route(principal: ApiKeyPrincipal = Depends(writer_dep)) -> dict:
        return {"role": principal.role.value, "mode": principal.access_mode.value}


def audit(app: FastAPI, auth: AuthDeps) -> list[BareApiKeyDependency]:
    """audit_api_key_routes requires a concrete Callable, not Optional."""
    bare_dep = auth.get_current_api_key_principal
    if bare_dep is None:
        return []
    return audit_api_key_routes(app, bare_dependency=bare_dep)
'''


def test_documented_public_surface_type_checks(tmp_path: Path) -> None:
    """Every name the package docstring documents imports and type-checks."""
    snippet = tmp_path / "typing_probe.py"
    snippet.write_text(_TYPING_SNIPPET)
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--ignore-missing-imports", str(snippet)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_all_exports_resolve_to_real_objects() -> None:
    """__all__ names an object that actually exists on the package — no stale exports."""
    for name in fastapi_m8.__all__:
        assert hasattr(fastapi_m8, name), (
            f"{name!r} is listed in fastapi_m8.__all__ but is not importable"
        )

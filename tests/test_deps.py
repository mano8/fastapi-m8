"""Tests for fastapi_m8._deps — build_auth_deps, AuthDeps, closures."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock

import jwt
import pytest
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.user import UserModel
from fastapi import HTTPException

from fastapi_m8._deps import _LoggingHooks, build_auth_deps
from fastapi_m8._revocation import RevocationCheckError
from tests.conftest import VALID_KEY, make_settings

pytestmark = pytest.mark.anyio

_VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"

# ── token helpers ─────────────────────────────────────────────────────────────


def _access_token(**extra: Any) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": _VALID_UUID,
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "jti-0001",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
        **extra,
    }
    return jwt.encode(payload, VALID_KEY, algorithm="HS256")


# ── _LoggingHooks ─────────────────────────────────────────────────────────────


def test_logging_hooks_on_success_logs_debug(caplog) -> None:
    """on_success emits a DEBUG log."""
    hooks = _LoggingHooks()
    with caplog.at_level(logging.DEBUG, logger="fastapi_m8._deps"):
        hooks.on_success(jti="j1", sub="u1", token_type="access")
    assert "token.valid" in caplog.text


def test_logging_hooks_on_failure_logs_warning(caplog) -> None:
    """on_failure emits a WARNING log."""
    hooks = _LoggingHooks()
    with caplog.at_level(logging.WARNING, logger="fastapi_m8._deps"):
        hooks.on_failure(reason="expired", token_type="access")
    assert "token.invalid" in caplog.text


# ── build_auth_deps ───────────────────────────────────────────────────────────


def test_build_auth_deps_stateless_no_revocation_client() -> None:
    """Stateless mode: revocation_client is None."""
    auth = build_auth_deps(make_settings())
    assert auth.revocation_client is None
    assert callable(auth.get_current_user)
    assert callable(auth.get_current_active_admin)
    assert callable(auth.get_current_active_superuser)


def test_build_auth_deps_stateful_creates_revocation_client() -> None:
    """Stateful consumer mode: revocation_client is set."""
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
    )
    auth = build_auth_deps(s)
    assert auth.revocation_client is not None


# ── AuthDeps.close ────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_auth_deps_close_noop_without_client() -> None:
    """close() is a no-op when revocation_client is None."""
    auth = build_auth_deps(make_settings())
    await auth.close()  # must not raise


@pytest.mark.anyio
async def test_auth_deps_close_calls_client_close() -> None:
    """close() delegates to the revocation client."""
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
    )
    auth = build_auth_deps(s)
    assert auth.revocation_client is not None
    auth.revocation_client._client.aclose = AsyncMock()
    await auth.close()
    auth.revocation_client._client.aclose.assert_awaited_once()


# ── get_current_user ──────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_get_current_user_valid_token() -> None:
    """Valid token → returns UserModel."""
    auth = build_auth_deps(make_settings())
    user = await auth.get_current_user(_access_token())
    assert isinstance(user, UserModel)


@pytest.mark.anyio
async def test_get_current_user_invalid_token_raises_403() -> None:
    """Invalid token → 403 HTTPException."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user("not.a.valid.token")
    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_get_current_user_inactive_user_raises_403() -> None:
    """Token for inactive user → 403 HTTPException."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(_access_token(is_active=False))
    assert exc_info.value.status_code == 403
    assert "Inactive" in exc_info.value.detail


@pytest.mark.anyio
async def test_get_current_user_revoked_token_raises_403() -> None:
    """Revoked token → 403 HTTPException."""
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
    )
    auth = build_auth_deps(s)
    assert auth.revocation_client is not None
    auth.revocation_client.is_revoked = AsyncMock(return_value=True)  # type: ignore[method-assign]

    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(_access_token())
    assert exc_info.value.status_code == 403
    assert "revoked" in exc_info.value.detail.lower()


@pytest.mark.anyio
async def test_get_current_user_revocation_error_raises_503() -> None:
    """RevocationCheckError → 503 HTTPException."""
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
    )
    auth = build_auth_deps(s)
    assert auth.revocation_client is not None
    auth.revocation_client.is_revoked = AsyncMock(  # type: ignore[method-assign]
        side_effect=RevocationCheckError("timeout")
    )

    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(_access_token())
    assert exc_info.value.status_code == 503


# ── get_current_active_admin ──────────────────────────────────────────────────


def _make_user(role: RoleType, is_superuser: bool = False) -> UserModel:
    import uuid

    return UserModel(
        id=uuid.UUID(_VALID_UUID),
        email="user@example.com",
        is_active=True,
        role=role,
        is_superuser=is_superuser,
    )


def test_get_current_active_admin_passes_for_admin() -> None:
    """ADMIN role passes the admin guard."""
    auth = build_auth_deps(make_settings())
    admin = _make_user(RoleType.ADMIN)
    result = auth.get_current_active_admin(admin)
    assert result is admin


def test_get_current_active_admin_raises_for_regular_user() -> None:
    """Non-admin role raises 403."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_admin(_make_user(RoleType.USER))
    assert exc_info.value.status_code == 403


# ── get_current_active_superuser ──────────────────────────────────────────────


def test_get_current_active_superuser_passes_for_superuser() -> None:
    """SUPERADMIN passes the superuser guard."""
    auth = build_auth_deps(make_settings())
    su = _make_user(RoleType.SUPERADMIN, is_superuser=True)
    result = auth.get_current_active_superuser(su)
    assert result is su


def test_get_current_active_superuser_raises_for_admin() -> None:
    """ADMIN (is_superuser=False) raises 403."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_superuser(_make_user(RoleType.ADMIN))
    assert exc_info.value.status_code == 403


def test_get_current_active_superuser_raises_for_non_superuser_flag() -> None:
    """SUPERADMIN role but is_superuser=False raises 403."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_superuser(
            _make_user(RoleType.SUPERADMIN, is_superuser=False)
        )
    assert exc_info.value.status_code == 403


def test_get_current_active_superuser_raises_for_superuser_flag_with_insufficient_role() -> (
    None
):
    """is_superuser=True but ADMIN role fails the SUPERADMIN role check."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_superuser(_make_user(RoleType.ADMIN, is_superuser=True))
    assert exc_info.value.status_code == 403

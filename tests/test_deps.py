"""Tests for fastapi_m8._deps — build_auth_deps, AuthDeps, closures."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security.jwks_resolver import JwksKeyResolver
from fastapi import HTTPException

from fastapi_m8._deps import _LoggingHooks, build_auth_deps
from fastapi_m8._revocation import RevocationCheckError
from tests.conftest import jwks_document, make_access_token, make_settings

pytestmark = pytest.mark.anyio

_VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"


# ── _LoggingHooks ─────────────────────────────────────────────────────────────


def test_logging_hooks_on_success_logs_debug(caplog) -> None:
    """on_success emits a DEBUG log."""
    hooks = _LoggingHooks()
    with caplog.at_level(logging.DEBUG, logger="fastapi_m8._deps"):
        hooks.on_success(jti="j1", sub="u1", token_type="access")
    assert "auth.ok" in caplog.text


def test_logging_hooks_on_failure_logs_warning(caplog) -> None:
    """on_failure emits a WARNING log."""
    hooks = _LoggingHooks()
    with caplog.at_level(logging.WARNING, logger="fastapi_m8._deps"):
        hooks.on_failure(reason="expired", token_type="access")
    assert "auth.fail" in caplog.text


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
    mock_aclose = AsyncMock()
    setattr(auth.revocation_client._client, "aclose", mock_aclose)
    await auth.close()
    mock_aclose.assert_awaited_once()


# ── get_current_user ──────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_get_current_user_valid_token() -> None:
    """Valid RS256 token bound to the configured iss/aud → returns UserModel."""
    auth = build_auth_deps(make_settings())
    user = await auth.get_current_user(make_access_token())
    assert isinstance(user, UserModel)


# ── tenant_id passthrough (auth-sdk-m8 >= 1.3.0) ──────────────────────────────


@pytest.mark.anyio
async def test_get_current_user_forwards_tenant_id() -> None:
    """A token carrying tenant_id flows through to CurrentUser.tenant_id as a UUID."""
    import uuid

    tenant = "7f1c4e2a-9b3d-4c5e-8a6f-1234567890ab"
    auth = build_auth_deps(make_settings())
    user = await auth.get_current_user(make_access_token(tenant_id=tenant))
    assert user.tenant_id == uuid.UUID(tenant)


@pytest.mark.anyio
async def test_get_current_user_tenant_id_defaults_to_none() -> None:
    """A token without tenant_id yields CurrentUser.tenant_id is None."""
    auth = build_auth_deps(make_settings())
    user = await auth.get_current_user(make_access_token())
    assert user.tenant_id is None


# ── secure-by-default: RS256 + strict iss/aud binding (F1/F2) ──────────────────


def test_build_auth_deps_logs_validation_posture(caplog) -> None:
    """The factory logs the inherited RS256 + strict validation posture."""
    with caplog.at_level(logging.INFO, logger="fastapi_m8._deps"):
        build_auth_deps(make_settings())
    assert "auth.validation algorithm=RS256 strict=True" in caplog.text


@pytest.mark.anyio
async def test_get_current_user_wrong_audience_rejected() -> None:
    """A token minted for a different audience is rejected out of the box."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(make_access_token(audience="other-service"))
    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_get_current_user_wrong_issuer_rejected() -> None:
    """A token from an unexpected issuer is rejected out of the box."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(make_access_token(issuer="https://evil.test"))
    assert exc_info.value.status_code == 403


@pytest.mark.anyio
async def test_hs256_token_rejected_under_rs256_default() -> None:
    """An HS256-signed token is refused when the default posture is RS256."""
    import jwt

    from tests.conftest import TOKEN_AUDIENCE, TOKEN_ISSUER, VALID_KEY

    auth = build_auth_deps(make_settings())
    forged = jwt.encode(
        {
            "sub": _VALID_UUID,
            "type": "access",
            "jti": "j",
            "exp": 9999999999,
            "iat": 0,
            "nbf": 0,
            "iss": TOKEN_ISSUER,
            "aud": TOKEN_AUDIENCE,
            "email": "x@example.com",
            "role": "user",
        },
        VALID_KEY,
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(forged)
    assert exc_info.value.status_code == 403


# ── consumer-mode validation via JWKS (zero-downtime key rotation) ─────────────


@pytest.mark.anyio
async def test_get_current_user_via_jwks(monkeypatch) -> None:
    """JWKS_URI wires a JwksKeyResolver that validates RS256 tokens by kid."""
    monkeypatch.setattr(
        JwksKeyResolver, "_fetch_jwks", lambda self: jwks_document()["keys"]
    )
    s = make_settings(JWKS_URI="https://auth.test/.well-known/jwks.json")
    auth = build_auth_deps(s)
    user = await auth.get_current_user(make_access_token())
    assert isinstance(user, UserModel)


@pytest.mark.anyio
async def test_get_current_user_via_jwks_unknown_kid_rejected(monkeypatch) -> None:
    """A token whose kid is absent from the JWKS document is rejected."""
    monkeypatch.setattr(
        JwksKeyResolver, "_fetch_jwks", lambda self: jwks_document()["keys"]
    )
    s = make_settings(JWKS_URI="https://auth.test/.well-known/jwks.json")
    auth = build_auth_deps(s)
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(make_access_token(kid="rotated-away"))
    assert exc_info.value.status_code == 403


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
        await auth.get_current_user(make_access_token(is_active=False))
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
        await auth.get_current_user(make_access_token())
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
        await auth.get_current_user(make_access_token())
    assert exc_info.value.status_code == 503


# ── 5.5 consumer-side degradation matrix (end-to-end through get_current_user) ──


@pytest.mark.anyio
async def test_fail_closed_introspection_down_returns_503() -> None:
    """fail_closed + unreachable introspection → get_current_user raises 503."""
    import httpx

    auth = _stateful_auth(ACCESS_REVOCATION_FAILURE_MODE="fail_closed")
    assert auth.revocation_client is not None
    setattr(
        auth.revocation_client._client,
        "post",
        AsyncMock(side_effect=httpx.ConnectError("down")),
    )
    with pytest.raises(HTTPException) as exc_info:
        await auth.get_current_user(make_access_token())
    assert exc_info.value.status_code == 503
    await auth.close()


@pytest.mark.anyio
async def test_fail_open_introspection_down_accepts_token() -> None:
    """fail_open opt-out + unreachable introspection → token is accepted."""
    import httpx

    auth = _stateful_auth(ACCESS_REVOCATION_FAILURE_MODE="fail_open")
    assert auth.revocation_client is not None
    setattr(
        auth.revocation_client._client,
        "post",
        AsyncMock(side_effect=httpx.ConnectError("down")),
    )
    user = await auth.get_current_user(make_access_token())
    assert isinstance(user, UserModel)
    await auth.close()


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


# ── AuthDeps cache eviction helpers ──────────────────────────────────────────


def _stateful_auth(**overrides):  # type: ignore[return]
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
        **overrides,
    )
    return build_auth_deps(s)


def test_evict_jti_noop_without_revocation_client() -> None:
    """evict_jti is a no-op in stateless mode (no revocation client)."""
    auth = build_auth_deps(make_settings())
    auth.evict_jti("jti-x")  # must not raise


def test_evict_user_noop_without_revocation_client() -> None:
    """evict_user is a no-op in stateless mode."""
    auth = build_auth_deps(make_settings())
    auth.evict_user("user-x")  # must not raise


def test_flush_cache_noop_without_revocation_client() -> None:
    """flush_cache is a no-op in stateless mode."""
    auth = build_auth_deps(make_settings())
    auth.flush_cache()  # must not raise


def test_evict_jti_delegates_when_cache_enabled() -> None:
    """evict_jti reaches the revocation client cache."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is not None
    auth.revocation_client._cache.put("jti-1", "user-a")
    auth.evict_jti("jti-1")
    assert auth.revocation_client._cache.get("jti-1") is None


def test_evict_user_delegates_when_cache_enabled() -> None:
    """evict_user reaches the revocation client cache."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is not None
    auth.revocation_client._cache.put("jti-1", "user-a")
    auth.evict_user("user-a")
    assert auth.revocation_client._cache.get("jti-1") is None


def test_flush_cache_delegates_when_cache_enabled() -> None:
    """flush_cache clears the revocation client cache."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is not None
    auth.revocation_client._cache.put("jti-1", "user-a")
    auth.flush_cache()
    assert auth.revocation_client._cache.get("jti-1") is None


def test_revocation_cache_disabled_by_default() -> None:
    """REVOCATION_CACHE_TTL_SECONDS=0 (default) means no cache is allocated."""
    auth = _stateful_auth()
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is None


def test_revocation_cache_enabled_when_ttl_set() -> None:
    """REVOCATION_CACHE_TTL_SECONDS > 0 allocates the cache."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=60)
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is not None

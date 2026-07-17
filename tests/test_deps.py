"""Tests for fastapi_m8._deps — build_auth_deps, AuthDeps, closures."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock

import pytest
from auth_sdk_m8.events import AuthStreamEvent
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
    assert callable(auth.get_current_active_writer)
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


# ── single-builder contract: no implicit cache across calls ──────────────────


def test_second_build_call_yields_an_independent_revocation_client() -> None:
    """A second build_auth_deps() call builds its own validator/client — no cache.

    ``build_auth_deps`` is documented as a one-call-per-service factory; a
    second call must not silently reuse or share state with the first, or two
    services (or two calls in the same process) would cross-contaminate their
    revocation caches.
    """
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/private/v1/jti-status",
        PRIVATE_API_SECRET="supersecret",
    )
    first = build_auth_deps(s)
    second = build_auth_deps(s)
    assert first.revocation_client is not None
    assert second.revocation_client is not None
    assert first.revocation_client is not second.revocation_client
    assert first is not second


def test_second_build_call_yields_an_independent_api_key_client() -> None:
    """A second build_auth_deps() call builds its own API-key client too."""
    s = make_settings(
        API_KEY_INTROSPECTION_ENABLED=True,
        INTERNAL_CLIENT_ID="consumer-a",
        PRIVATE_API_SECRET="supersecret",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
    )
    first = build_auth_deps(s)
    second = build_auth_deps(s)
    assert first.api_key_client is not None
    assert second.api_key_client is not None
    assert first.api_key_client is not second.api_key_client
    assert (
        first.get_current_api_key_principal is not second.get_current_api_key_principal
    )


def test_second_build_call_yields_independent_jwt_guard_closures() -> None:
    """The JWT guards themselves are fresh closures each call, not memoized."""
    auth1 = build_auth_deps(make_settings())
    auth2 = build_auth_deps(make_settings())
    assert auth1.get_current_user is not auth2.get_current_user
    assert auth1.get_current_active_writer is not auth2.get_current_active_writer


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
async def test_get_current_user_revocation_error_raises_503(caplog) -> None:
    """RevocationCheckError → 503 HTTPException."""
    raw_jti = "jti-secret-log-value"
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

    with caplog.at_level(logging.WARNING, logger="fastapi_m8._deps"):
        with pytest.raises(HTTPException) as exc_info:
            await auth.get_current_user(make_access_token(extra={"jti": raw_jti}))
    assert exc_info.value.status_code == 503
    assert "security.revocation_denied" in caplog.text
    assert raw_jti not in caplog.text
    assert "jti=" not in caplog.text


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


# ── role guards: the §3.3 canonical matrix ────────────────────────────────────


def _make_user(role: RoleType, is_superuser: bool | None = None) -> UserModel:
    """Build a canonical user; is_superuser is derived unless given explicitly."""
    import uuid

    if is_superuser is None:
        is_superuser = role is RoleType.SUPERADMIN
    return UserModel(
        id=uuid.UUID(_VALID_UUID),
        email="user@example.com",
        is_active=True,
        role=role,
        is_superuser=is_superuser,
    )


def _make_inconsistent_user(role: RoleType, is_superuser: bool) -> UserModel:
    """Build a user whose claims violate the canonical invariant.

    auth-sdk-m8 3.0.0 rejects such a pair in ``UserModel`` itself, so the pair
    must be forced past validation to prove the guards deny it on their own
    (defense in depth) rather than relying on the model invariant.
    """
    import uuid

    return UserModel.model_construct(
        id=uuid.UUID(_VALID_UUID),
        email="user@example.com",
        is_active=True,
        role=role,
        is_superuser=is_superuser,
    )


# role → (writer allowed, admin allowed, superuser allowed) — §3.3 truth table.
_ROLE_MATRIX = [
    (RoleType.USER, False, False, False),
    (RoleType.READER, False, False, False),
    (RoleType.WRITER, True, False, False),
    (RoleType.ADMIN, True, True, False),
    (RoleType.SUPERADMIN, True, True, True),
]


def _assert_guard(guard, user: UserModel, allowed: bool) -> None:
    """Assert *guard* either returns *user* unchanged or denies with a 403."""
    if allowed:
        assert guard(user) is user
        return
    with pytest.raises(HTTPException) as exc_info:
        guard(user)
    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "The user doesn't have enough privileges"


@pytest.mark.parametrize("role,writer_ok,admin_ok,su_ok", _ROLE_MATRIX)
def test_role_matrix_writer_dependency(
    role: RoleType, writer_ok: bool, admin_ok: bool, su_ok: bool
) -> None:
    """Every canonical role gets the §3.3 writer-dependency outcome."""
    auth = build_auth_deps(make_settings())
    _assert_guard(auth.get_current_active_writer, _make_user(role), writer_ok)


@pytest.mark.parametrize("role,writer_ok,admin_ok,su_ok", _ROLE_MATRIX)
def test_role_matrix_admin_dependency(
    role: RoleType, writer_ok: bool, admin_ok: bool, su_ok: bool
) -> None:
    """Every canonical role gets the §3.3 admin-dependency outcome."""
    auth = build_auth_deps(make_settings())
    _assert_guard(auth.get_current_active_admin, _make_user(role), admin_ok)


@pytest.mark.parametrize("role,writer_ok,admin_ok,su_ok", _ROLE_MATRIX)
def test_role_matrix_superuser_dependency(
    role: RoleType, writer_ok: bool, admin_ok: bool, su_ok: bool
) -> None:
    """Every canonical role gets the §3.3 superuser-dependency outcome."""
    auth = build_auth_deps(make_settings())
    _assert_guard(auth.get_current_active_superuser, _make_user(role), su_ok)


# ── no privilege escalation through the is_superuser flag ─────────────────────


@pytest.mark.parametrize("role", [RoleType.USER, RoleType.READER])
def test_superuser_flag_never_bypasses_writer_guard(role: RoleType) -> None:
    """is_superuser=True on a sub-writer role still fails the writer guard."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_writer(_make_inconsistent_user(role, True))
    assert exc_info.value.status_code == 403


@pytest.mark.parametrize("role", [RoleType.USER, RoleType.READER, RoleType.WRITER])
def test_superuser_flag_never_bypasses_admin_guard(role: RoleType) -> None:
    """is_superuser=True on a sub-admin role still fails the admin guard."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_admin(_make_inconsistent_user(role, True))
    assert exc_info.value.status_code == 403


@pytest.mark.parametrize(
    "role", [RoleType.USER, RoleType.READER, RoleType.WRITER, RoleType.ADMIN]
)
def test_superuser_flag_never_bypasses_superuser_guard(role: RoleType) -> None:
    """is_superuser=True without the SUPERADMIN role is never superuser."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_superuser(_make_inconsistent_user(role, True))
    assert exc_info.value.status_code == 403


def test_superuser_role_without_flag_denied() -> None:
    """SUPERADMIN role with is_superuser=False lacks the dual evidence → 403."""
    auth = build_auth_deps(make_settings())
    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_active_superuser(
            _make_inconsistent_user(RoleType.SUPERADMIN, False)
        )
    assert exc_info.value.status_code == 403


def test_superuser_role_without_flag_still_passes_admin_guard() -> None:
    """The admin guard is a pure role check: the flag neither grants nor blocks."""
    auth = build_auth_deps(make_settings())
    user = _make_inconsistent_user(RoleType.SUPERADMIN, False)
    assert auth.get_current_active_admin(user) is user


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
    auth.revocation_client._cache.put("jti-1", "user-a", 1)
    auth.evict_jti("jti-1")
    assert auth.revocation_client._cache.get("jti-1") is None


def test_evict_user_delegates_when_cache_enabled() -> None:
    """evict_user reaches the revocation client cache."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is not None
    auth.revocation_client._cache.put("jti-1", "user-a", 1)
    auth.evict_user("user-a")
    assert auth.revocation_client._cache.get("jti-1") is None


def test_flush_cache_delegates_when_cache_enabled() -> None:
    """flush_cache clears the revocation client cache."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    assert auth.revocation_client._cache is not None
    auth.revocation_client._cache.put("jti-1", "user-a", 1)
    auth.flush_cache()
    assert auth.revocation_client._cache.get("jti-1") is None


def _event(event_type: str, payload: dict) -> AuthStreamEvent:
    return AuthStreamEvent(event_type=event_type, payload=payload, event_id="7-1")


@pytest.mark.anyio
async def test_handle_auth_event_applies_session_revoked() -> None:
    """The SSE handler routes session-revoked into the watermark rule."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    cache = auth.revocation_client._cache
    assert cache is not None
    cache.put("jti-1", "user-a", 1)
    await auth.handle_auth_event(
        _event(
            "session-revoked",
            {
                "event_type": "session.revoked",
                "user_id": "user-a",
                "jti": "jti-1",
                "auth_generation": 2,
                "event_id": "evt-1",
            },
        )
    )
    assert cache.get("jti-1") is None


@pytest.mark.anyio
async def test_handle_auth_event_applies_user_deleted() -> None:
    """user-deleted evicts every entry the deleted account still holds."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    cache = auth.revocation_client._cache
    assert cache is not None
    cache.put("jti-1", "user-a", 9)
    await auth.handle_auth_event(
        _event("user-deleted", {"event_type": "user.deleted", "user_id": "user-a"})
    )
    assert cache.get("jti-1") is None


@pytest.mark.anyio
async def test_handle_auth_event_accepts_the_dotted_spelling() -> None:
    """The payload's canonical dot spelling routes identically to the SSE one."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    cache = auth.revocation_client._cache
    assert cache is not None
    cache.put("jti-1", "user-a", 9)
    await auth.handle_auth_event(
        _event("user.deleted", {"event_type": "user.deleted", "user_id": "user-a"})
    )
    assert cache.get("jti-1") is None


@pytest.mark.anyio
async def test_handle_auth_event_ignores_unknown_type() -> None:
    """An event type this release does not act on is dropped, never raised on."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    await auth.handle_auth_event(_event("something-else", {"user_id": "user-a"}))


@pytest.mark.anyio
async def test_handle_auth_event_ignores_user_deleted_without_a_user() -> None:
    """A user-deleted payload with no usable user id evicts nothing."""
    auth = _stateful_auth(REVOCATION_CACHE_TTL_SECONDS=30)
    assert auth.revocation_client is not None
    cache = auth.revocation_client._cache
    assert cache is not None
    cache.put("jti-1", "user-a", 1)
    await auth.handle_auth_event(_event("user-deleted", {"event_type": "user.deleted"}))
    assert cache.get("jti-1") is False


@pytest.mark.anyio
async def test_handle_auth_event_noop_in_stateless_mode() -> None:
    """With no revocation client there is no cache to evict from."""
    auth = build_auth_deps(make_settings())
    await auth.handle_auth_event(
        _event("session-revoked", {"event_type": "session.revoked", "user_id": "u"})
    )


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

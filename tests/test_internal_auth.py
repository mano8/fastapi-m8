"""Tests for fastapi_m8._internal_auth — per-consumer private-call auth (9.1)."""

import logging

import httpx
import pytest
from pydantic import SecretStr

from fastapi_m8._internal_auth import (
    ServiceTokenInternalAuth,
    _secret_value,
    _StaticInternalAuth,
    build_internal_auth,
    derive_service_token_url,
    describe_internal_auth_mode,
)
from tests.conftest import IsolatedConsumerSettings, make_settings

pytestmark = pytest.mark.anyio

_SECRET = "bootstrap-secret"
_INTROSPECTION = "http://auth:8000/private/v1/jti-status"


def _settings(**overrides: object) -> IsolatedConsumerSettings:
    """Build a settings stub carrying just the internal-auth fields."""
    base = {
        "PRIVATE_API_SECRET": SecretStr(_SECRET),
        "INTROSPECTION_URL": _INTROSPECTION,
        "INTERNAL_CLIENT_ID": None,
        "SERVICE_TOKEN_EXCHANGE_ENABLED": False,
        "SERVICE_TOKEN_SCOPES": None,
        "SERVICE_TOKEN_REFRESH_LEEWAY_SECONDS": 30,
    }
    base.update(overrides)
    return make_settings(**base)


# ── derive_service_token_url ──────────────────────────────────────────────────


def test_derive_service_token_url_strips_jti_status() -> None:
    assert (
        derive_service_token_url(_INTROSPECTION)
        == "http://auth:8000/private/v1/service-token"
    )


def test_derive_service_token_url_from_bare_base() -> None:
    assert (
        derive_service_token_url("http://auth:8000/private/v1/")
        == "http://auth:8000/private/v1/service-token"
    )


# ── build_internal_auth: mode selection ───────────────────────────────────────


async def test_legacy_mode_when_no_client_id() -> None:
    """Unset INTERNAL_CLIENT_ID → single X-Internal-Token header."""
    provider = build_internal_auth(_settings())
    assert isinstance(provider, _StaticInternalAuth)
    assert await provider.headers() == {"X-Internal-Token": _SECRET}
    assert await provider.invalidate() is False
    await provider.close()


async def test_bootstrap_mode_sends_client_and_token() -> None:
    """INTERNAL_CLIENT_ID set, exchange off → both bootstrap headers."""
    provider = build_internal_auth(_settings(INTERNAL_CLIENT_ID="svc-a"))
    assert isinstance(provider, _StaticInternalAuth)
    assert await provider.headers() == {
        "X-Internal-Client": "svc-a",
        "X-Internal-Token": _SECRET,
    }
    await provider.close()


async def test_service_token_mode_built_with_defaults() -> None:
    """Exchange enabled → ServiceTokenInternalAuth; scopes default to introspection."""
    provider = build_internal_auth(
        _settings(INTERNAL_CLIENT_ID="svc-a", SERVICE_TOKEN_EXCHANGE_ENABLED=True)
    )
    assert isinstance(provider, ServiceTokenInternalAuth)
    assert provider._scopes == ["introspection"]
    assert provider._url == "http://auth:8000/private/v1/service-token"
    await provider.close()


async def test_service_token_mode_honours_explicit_scopes() -> None:
    provider = build_internal_auth(
        _settings(
            INTERNAL_CLIENT_ID="svc-a",
            SERVICE_TOKEN_EXCHANGE_ENABLED=True,
            SERVICE_TOKEN_SCOPES=["introspection", "event-stream"],
        )
    )
    assert isinstance(provider, ServiceTokenInternalAuth)
    assert provider._scopes == ["introspection", "event-stream"]
    await provider.close()


def test_build_internal_auth_accepts_plain_str_secret() -> None:
    """_secret_value falls back to str() for a non-SecretStr value."""
    assert _secret_value("plain") == "plain"


# ── describe_internal_auth_mode ───────────────────────────────────────────────


def test_describe_mode_legacy() -> None:
    assert describe_internal_auth_mode(_settings()) == "legacy"


def test_describe_mode_bootstrap() -> None:
    assert (
        describe_internal_auth_mode(_settings(INTERNAL_CLIENT_ID="svc-a"))
        == "bootstrap"
    )


def test_describe_mode_service_token() -> None:
    assert (
        describe_internal_auth_mode(
            _settings(INTERNAL_CLIENT_ID="svc-a", SERVICE_TOKEN_EXCHANGE_ENABLED=True)
        )
        == "service_token"
    )


# ── ServiceTokenInternalAuth ──────────────────────────────────────────────────


def _exchange_resp(token: str = "minted-token", expires_in: int = 300):
    from unittest.mock import MagicMock

    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json.return_value = {"access_token": token, "expires_in": expires_in}
    return resp


def _make_service_auth(
    *, scopes: list[str] | None = None, refresh_leeway: int = 30
) -> ServiceTokenInternalAuth:
    return ServiceTokenInternalAuth(
        client_id="svc-a",
        secret=_SECRET,
        exchange_url="http://auth:8000/private/v1/service-token",
        scopes=["introspection"] if scopes is None else scopes,
        refresh_leeway=refresh_leeway,
    )


async def test_service_token_exchange_returns_bearer() -> None:
    from unittest.mock import AsyncMock

    auth = _make_service_auth()
    post = AsyncMock(return_value=_exchange_resp())
    setattr(auth._client, "post", post)

    assert await auth.headers() == {"Authorization": "Bearer minted-token"}
    # The bootstrap credential is sent on the exchange call, with the scopes body.
    _, kwargs = post.call_args
    assert kwargs["headers"] == {
        "X-Internal-Client": "svc-a",
        "X-Internal-Token": _SECRET,
    }
    assert kwargs["json"] == {"scopes": ["introspection"]}
    await auth.close()


async def test_service_token_is_cached_until_refresh_window() -> None:
    """A live token is reused without a second exchange call."""
    from unittest.mock import AsyncMock

    auth = _make_service_auth()
    post = AsyncMock(return_value=_exchange_resp())
    setattr(auth._client, "post", post)

    await auth.headers()
    await auth.headers()
    post.assert_awaited_once()
    await auth.close()


async def test_service_token_refreshes_after_expiry(monkeypatch) -> None:
    """Past the refresh window the token is re-exchanged."""
    from unittest.mock import AsyncMock

    import fastapi_m8._internal_auth as mod

    auth = _make_service_auth(refresh_leeway=0)
    post = AsyncMock(
        side_effect=[_exchange_resp("tok-1", 100), _exchange_resp("tok-2", 100)]
    )
    setattr(auth._client, "post", post)

    monkeypatch.setattr(mod.time, "monotonic", lambda: 0.0)
    assert (await auth.headers())["Authorization"] == "Bearer tok-1"
    monkeypatch.setattr(mod.time, "monotonic", lambda: 1_000.0)
    assert (await auth.headers())["Authorization"] == "Bearer tok-2"
    assert post.await_count == 2
    await auth.close()


async def test_service_token_invalidate_forces_reexchange() -> None:
    from unittest.mock import AsyncMock

    auth = _make_service_auth()
    post = AsyncMock(side_effect=[_exchange_resp("tok-1"), _exchange_resp("tok-2")])
    setattr(auth._client, "post", post)

    assert (await auth.headers())["Authorization"] == "Bearer tok-1"
    assert await auth.invalidate() is True
    assert (await auth.headers())["Authorization"] == "Bearer tok-2"
    await auth.close()


async def test_service_token_empty_scopes_sends_empty_body() -> None:
    from unittest.mock import AsyncMock

    auth = _make_service_auth(scopes=[])
    post = AsyncMock(return_value=_exchange_resp())
    setattr(auth._client, "post", post)

    await auth.headers()
    _, kwargs = post.call_args
    assert kwargs["json"] == {}
    await auth.close()


async def test_service_token_exchange_logs_no_secret(caplog) -> None:
    from unittest.mock import AsyncMock

    auth = _make_service_auth()
    setattr(auth._client, "post", AsyncMock(return_value=_exchange_resp("tok-x", 120)))

    with caplog.at_level(logging.INFO, logger="fastapi_m8._internal_auth"):
        await auth.headers()
    assert "internal_auth.service_token refreshed client=svc-a expires_in=120" in (
        caplog.text
    )
    assert _SECRET not in caplog.text
    assert "tok-x" not in caplog.text
    await auth.close()


async def test_service_token_close_closes_client() -> None:
    from unittest.mock import AsyncMock

    auth = _make_service_auth()
    aclose = AsyncMock()
    setattr(auth._client, "aclose", aclose)
    await auth.close()
    aclose.assert_awaited_once()


# ── _StaticInternalAuth ───────────────────────────────────────────────────────


async def test_static_headers_returns_copy() -> None:
    provider = _StaticInternalAuth({"X-Internal-Token": _SECRET})
    first = await provider.headers()
    first["mutated"] = "x"
    assert "mutated" not in await provider.headers()
    await provider.close()


async def test_exchange_propagates_http_error() -> None:
    """A non-2xx exchange raises (the caller decides fail-open/closed)."""
    from unittest.mock import AsyncMock, MagicMock

    auth = _make_service_auth()
    resp = MagicMock()
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock(status_code=401)
        )
    )
    setattr(auth._client, "post", AsyncMock(return_value=resp))

    with pytest.raises(httpx.HTTPStatusError):
        await auth.headers()
    await auth.close()

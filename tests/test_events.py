"""Tests for fastapi_m8._events (auth event-stream surface)."""

from __future__ import annotations

import pytest
from pydantic import SecretStr

import fastapi_m8
from fastapi_m8 import (
    AuthEventStreamClient,
    AuthStreamEvent,
    build_event_stream_client,
    derive_stream_url,
)
from fastapi_m8._internal_auth import (
    ServiceTokenInternalAuth,
    _StaticInternalAuth,
)
from tests.conftest import make_settings


async def _noop_event(event: AuthStreamEvent) -> None:  # pragma: no cover - stub
    """No-op on_event callback."""


async def _noop_gap() -> None:  # pragma: no cover - stub
    """No-op on_gap callback."""


def _stateful_settings(**overrides: object):
    """Stateful consumer settings with stream prerequisites set."""
    return make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        PRIVATE_API_SECRET=SecretStr("supersecret"),
        **overrides,
    )


# ── re-exports ──────────────────────────────────────────────────────────────


def test_reexports_are_public() -> None:
    """The SDK client surface is re-exported on the package root."""
    for name in (
        "build_event_stream_client",
        "AuthEventStreamClient",
        "AuthStreamEvent",
        "derive_stream_url",
    ):
        assert name in fastapi_m8.__all__
        assert hasattr(fastapi_m8, name)


def test_derive_stream_url_strips_jti_suffix() -> None:
    """derive_stream_url maps the introspection URL to the stream endpoint."""
    url = derive_stream_url("http://auth:8000/user/private/v1/jti-status")
    assert url == "http://auth:8000/user/private/v1/events/stream"


# ── factory: happy path ─────────────────────────────────────────────────────


def test_build_event_stream_client_from_settings() -> None:
    """Factory builds a client with derived URL and a legacy auth provider."""
    settings = _stateful_settings()
    client = build_event_stream_client(
        settings,
        on_event=_noop_event,
        on_gap=_noop_gap,
    )
    assert isinstance(client, AuthEventStreamClient)
    assert client._url == "http://auth:8000/user/private/v1/events/stream"
    # Legacy mode (no INTERNAL_CLIENT_ID) → static provider with X-Internal-Token.
    assert isinstance(client._auth, _StaticInternalAuth)
    # EVENT_SIGNING_KEY is unwrapped from SecretStr.
    assert client._signing_key is not None
    # Timeouts default from settings.
    assert client._connect_timeout == 5.0
    assert client._read_timeout == 60.0


def test_build_event_stream_client_legacy_provider_headers() -> None:
    """Legacy mode: provider emits only X-Internal-Token."""
    import asyncio

    settings = _stateful_settings()
    client = build_event_stream_client(settings, on_event=_noop_event, on_gap=_noop_gap)
    headers = asyncio.run(client._auth.headers())
    assert headers == {"X-Internal-Token": "supersecret"}


def test_build_event_stream_client_bootstrap_provider() -> None:
    """Bootstrap mode: provider emits X-Internal-Client + X-Internal-Token."""
    import asyncio

    settings = _stateful_settings(INTERNAL_CLIENT_ID="media-svc")
    client = build_event_stream_client(settings, on_event=_noop_event, on_gap=_noop_gap)
    assert isinstance(client._auth, _StaticInternalAuth)
    headers = asyncio.run(client._auth.headers())
    assert headers == {
        "X-Internal-Client": "media-svc",
        "X-Internal-Token": "supersecret",
    }


def test_build_event_stream_client_service_token_provider() -> None:
    """Service-token mode: provider is ServiceTokenInternalAuth."""
    settings = _stateful_settings(
        INTERNAL_CLIENT_ID="media-svc",
        SERVICE_TOKEN_EXCHANGE_ENABLED=True,
    )
    client = build_event_stream_client(settings, on_event=_noop_event, on_gap=_noop_gap)
    assert isinstance(client._auth, ServiceTokenInternalAuth)


def test_build_event_stream_client_timeout_overrides_from_settings() -> None:
    """EVENT_STREAM_* settings feed the client timeouts."""
    settings = _stateful_settings(
        EVENT_STREAM_CONNECT_TIMEOUT=2.5,
        EVENT_STREAM_READ_TIMEOUT=90.0,
    )
    client = build_event_stream_client(
        settings,
        on_event=_noop_event,
        on_gap=_noop_gap,
    )
    assert client._connect_timeout == 2.5
    assert client._read_timeout == 90.0


def test_build_event_stream_client_explicit_timeouts_win() -> None:
    """Explicit timeout args override the settings-derived defaults."""
    settings = _stateful_settings(
        EVENT_STREAM_CONNECT_TIMEOUT=2.5,
        EVENT_STREAM_READ_TIMEOUT=90.0,
    )
    client = build_event_stream_client(
        settings,
        on_event=_noop_event,
        on_gap=_noop_gap,
        connect_timeout=1.0,
        read_timeout=10.0,
    )
    assert client._connect_timeout == 1.0
    assert client._read_timeout == 10.0


def test_build_event_stream_client_signing_disabled() -> None:
    """A None EVENT_SIGNING_KEY yields a client with signing disabled."""
    settings = _stateful_settings(
        EVENT_SIGNING_ENABLED=False,
        EVENT_SIGNING_KEY=None,
    )
    client = build_event_stream_client(
        settings,
        on_event=_noop_event,
        on_gap=_noop_gap,
    )
    assert client._signing_key is None


# ── factory: error paths ────────────────────────────────────────────────────


def test_build_event_stream_client_requires_introspection_url() -> None:
    """Missing INTROSPECTION_URL is a configuration error."""
    settings = make_settings()  # stateless default → INTROSPECTION_URL is None
    with pytest.raises(ValueError, match="INTROSPECTION_URL"):
        build_event_stream_client(
            settings,
            on_event=_noop_event,
            on_gap=_noop_gap,
        )

"""Tests for fastapi_m8._events (auth event-stream surface)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

import fastapi_m8
from fastapi_m8 import (
    AuthEventStreamClient,
    AuthStreamEvent,
    build_event_stream_client,
    derive_stream_url,
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
    """Factory builds a client with derived URL and unwrapped secrets."""
    settings = _stateful_settings()
    client = build_event_stream_client(
        settings,
        on_event=_noop_event,
        on_gap=_noop_gap,
    )
    assert isinstance(client, AuthEventStreamClient)
    assert client._url == "http://auth:8000/user/private/v1/events/stream"
    assert client._secret == "supersecret"
    # EVENT_SIGNING_KEY (VALID_KEY) is unwrapped from SecretStr.
    assert client._signing_key is not None
    # Timeouts default from settings.
    assert client._connect_timeout == 5.0
    assert client._read_timeout == 60.0


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


def test_build_event_stream_client_plain_string_attrs() -> None:
    """Plain-string secret/signing attrs (no SecretStr) are accepted."""
    settings = SimpleNamespace(
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        PRIVATE_API_SECRET="plain-secret",
        EVENT_SIGNING_KEY="plain-signing-key",
    )
    client = build_event_stream_client(
        settings,
        on_event=_noop_event,
        on_gap=_noop_gap,
    )
    assert client._secret == "plain-secret"
    assert client._signing_key == "plain-signing-key"
    # No EVENT_STREAM_* attrs on the namespace → fall back to library defaults.
    assert client._connect_timeout == 5.0
    assert client._read_timeout == 60.0


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


def test_build_event_stream_client_requires_private_api_secret() -> None:
    """Missing PRIVATE_API_SECRET is a configuration error."""
    settings = SimpleNamespace(
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        PRIVATE_API_SECRET=None,
        EVENT_SIGNING_KEY="k",
    )
    with pytest.raises(ValueError, match="PRIVATE_API_SECRET"):
        build_event_stream_client(
            settings,
            on_event=_noop_event,
            on_gap=_noop_gap,
        )

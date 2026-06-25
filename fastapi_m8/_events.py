"""
Auth event-stream surface for fastapi-m8 consumers.

Re-exports the SDK client types and provides a convenience factory that
builds an :class:`~auth_sdk_m8.events.AuthEventStreamClient` directly from
a :class:`~fastapi_m8.config.ConsumerServiceSettings` instance, so callers
never touch SDK internals.

The factory routes through :func:`~fastapi_m8._internal_auth.build_internal_auth`
so the SSE stream authenticates with the same provider the revocation client
uses — legacy ``X-Internal-Token``, per-consumer bootstrap, or a short-TTL
``Authorization: Bearer`` service token, all selected purely by config (item 9.1).

Typical lifespan wiring::

    from fastapi_m8 import build_event_stream_client

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = build_event_stream_client(
            settings,
            on_event=handle_auth_event,
            on_gap=flush_all_caches,
        )
        client.start()
        try:
            yield
        finally:
            await client.stop()

"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from auth_sdk_m8.events import (
    AuthEventStreamClient,
    AuthStreamEvent,
    derive_stream_url,
)

from fastapi_m8._internal_auth import build_internal_auth

if TYPE_CHECKING:
    from fastapi_m8.config import ConsumerServiceSettings

__all__ = [
    "AuthEventStreamClient",
    "AuthStreamEvent",
    "derive_stream_url",
    "build_event_stream_client",
]


def build_event_stream_client(
    settings: ConsumerServiceSettings,
    *,
    on_event: Callable[[AuthStreamEvent], Awaitable[None]],
    on_gap: Callable[[], Awaitable[None]],
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
) -> AuthEventStreamClient:
    """
    Build an :class:`AuthEventStreamClient` from consumer service settings.

    Reads ``INTROSPECTION_URL`` from *settings* and derives the stream URL via
    :func:`derive_stream_url`. The internal-auth provider is built via
    :func:`~fastapi_m8._internal_auth.build_internal_auth`, selecting the mode
    from ``INTERNAL_CLIENT_ID`` / ``SERVICE_TOKEN_EXCHANGE_ENABLED``:

    * **legacy** (``INTERNAL_CLIENT_ID`` unset) — single ``X-Internal-Token``;
    * **bootstrap** (``INTERNAL_CLIENT_ID`` set) — per-consumer ``X-Internal-Client``
      + ``X-Internal-Token`` on every connection;
    * **service token** (+ ``SERVICE_TOKEN_EXCHANGE_ENABLED``) — short-TTL
      ``Authorization: Bearer`` token, refreshed before expiry and re-exchanged on
      a ``401``.

    The same provider is used by :class:`~fastapi_m8._revocation.RemoteRevocationClient`
    for JTI-status introspection calls, so credential configuration is a single knob.

    Args:
        settings: A :class:`ConsumerServiceSettings` instance exposing
            ``INTROSPECTION_URL``, ``PRIVATE_API_SECRET``, ``EVENT_SIGNING_KEY``,
            and the 9.1 provider fields (``INTERNAL_CLIENT_ID``, etc.).
        on_event: Async callback invoked for each verified
            :class:`AuthStreamEvent`.
        on_gap: Async callback invoked when the stream is unresumable; caller
            must flush all locally cached validation state.
        connect_timeout: Seconds to wait for the initial HTTP connection.
            ``None`` (default) reads ``EVENT_STREAM_CONNECT_TIMEOUT`` from
            *settings*, falling back to ``5.0``.
        read_timeout: Seconds to wait between SSE frames — set above the
            server's heartbeat interval (default 15 s). ``None`` (default)
            reads ``EVENT_STREAM_READ_TIMEOUT`` from *settings*, falling back
            to ``60.0``.

    Returns:
        A configured :class:`AuthEventStreamClient` (not yet started). The
        client owns the auth provider lifecycle and closes it on
        :meth:`~auth_sdk_m8.events.AuthEventStreamClient.stop`.

    Raises:
        ValueError: If ``INTROSPECTION_URL`` is not set on *settings*.

    """
    introspection_url: object | None = getattr(settings, "INTROSPECTION_URL", None)

    if introspection_url is None:
        raise ValueError(
            "build_event_stream_client requires INTROSPECTION_URL to be set "
            "on settings (needed to derive the SSE stream URL)."
        )

    if connect_timeout is None:
        connect_timeout = float(getattr(settings, "EVENT_STREAM_CONNECT_TIMEOUT", 5.0))
    if read_timeout is None:
        read_timeout = float(getattr(settings, "EVENT_STREAM_READ_TIMEOUT", 60.0))

    raw_url = str(introspection_url)
    stream_url = derive_stream_url(raw_url)

    # EVENT_SIGNING_KEY is Optional[SecretStr]; None means signing disabled.
    signing_key_field: object | None = getattr(settings, "EVENT_SIGNING_KEY", None)
    signing_key: str | None = None
    if signing_key_field is not None:
        signing_key = (
            signing_key_field.get_secret_value()  # type: ignore[union-attr]
            if hasattr(signing_key_field, "get_secret_value")
            else str(signing_key_field)
        )

    provider = build_internal_auth(settings)

    return AuthEventStreamClient(
        stream_url=stream_url,
        auth_provider=provider,
        signing_key=signing_key,
        on_event=on_event,
        on_gap=on_gap,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )

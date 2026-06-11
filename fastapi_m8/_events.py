"""
Auth event-stream surface for fastapi-m8 consumers.

Re-exports the SDK client types and provides a convenience factory that
builds an :class:`~auth_sdk_m8.events.AuthEventStreamClient` directly from
a :class:`~fastapi_m8.config.ConsumerServiceSettings` instance, so callers
never touch SDK internals.

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

Yield
        await client.stop()

"""

from __future__ import annotations

from collections.abc import Awaitable, Callable

from auth_sdk_m8.events import (
    AuthEventStreamClient,
    AuthStreamEvent,
    derive_stream_url,
)

__all__ = [
    "AuthEventStreamClient",
    "AuthStreamEvent",
    "derive_stream_url",
    "build_event_stream_client",
]


def build_event_stream_client(
    settings: object,
    *,
    on_event: Callable[[AuthStreamEvent], Awaitable[None]],
    on_gap: Callable[[], Awaitable[None]],
    connect_timeout: float | None = None,
    read_timeout: float | None = None,
) -> AuthEventStreamClient:
    """
    Build an :class:`AuthEventStreamClient` from consumer service settings.

    Reads ``INTROSPECTION_URL``, ``PRIVATE_API_SECRET``, and
    ``EVENT_SIGNING_KEY`` from *settings* (all available on
    :class:`~fastapi_m8.config.ConsumerServiceSettings`).  Derives the stream
    URL via :func:`derive_stream_url` so callers need only the single
    ``INTROSPECTION_URL`` they already configure for JTI-status checks.

    Args:
        settings: A :class:`ConsumerServiceSettings` instance (or any object
            exposing ``INTROSPECTION_URL``, ``PRIVATE_API_SECRET``, and
            ``EVENT_SIGNING_KEY`` with the same types).
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
        A configured :class:`AuthEventStreamClient` (not yet started).

    Raises:
        ValueError: If ``INTROSPECTION_URL`` or ``PRIVATE_API_SECRET`` is not
            set on *settings*.

    """
    introspection_url: object | None = getattr(settings, "INTROSPECTION_URL", None)
    private_api_secret: object | None = getattr(settings, "PRIVATE_API_SECRET", None)
    signing_key_field: object | None = getattr(settings, "EVENT_SIGNING_KEY", None)

    if introspection_url is None:
        raise ValueError(
            "build_event_stream_client requires INTROSPECTION_URL to be set "
            "on settings (needed to derive the SSE stream URL)."
        )
    if private_api_secret is None:
        raise ValueError(
            "build_event_stream_client requires PRIVATE_API_SECRET to be set "
            "on settings (used for X-Internal-Token authentication)."
        )

    if connect_timeout is None:
        connect_timeout = float(getattr(settings, "EVENT_STREAM_CONNECT_TIMEOUT", 5.0))
    if read_timeout is None:
        read_timeout = float(getattr(settings, "EVENT_STREAM_READ_TIMEOUT", 60.0))

    raw_url = str(introspection_url)
    stream_url = derive_stream_url(raw_url)

    # PRIVATE_API_SECRET is a pydantic SecretStr; fall back to plain str.
    secret_str: str = (
        private_api_secret.get_secret_value()  # type: ignore[union-attr]
        if hasattr(private_api_secret, "get_secret_value")
        else str(private_api_secret)
    )

    # EVENT_SIGNING_KEY is Optional[SecretStr]; None means signing disabled.
    signing_key: str | None = None
    if signing_key_field is not None:
        signing_key = (
            signing_key_field.get_secret_value()  # type: ignore[union-attr]
            if hasattr(signing_key_field, "get_secret_value")
            else str(signing_key_field)
        )

    return AuthEventStreamClient(
        stream_url=stream_url,
        private_api_secret=secret_str,
        signing_key=signing_key,
        on_event=on_event,
        on_gap=on_gap,
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
    )

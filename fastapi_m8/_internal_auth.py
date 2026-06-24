"""
Per-consumer internal-auth credentials for fastapi-m8 private calls (Phase 9.1).

A consumer authenticates its private calls to the fa-auth-m8 issuer — today the
JTI-status / revocation introspection endpoint — by one of three modes, selected
purely by configuration so the home lab keeps working unchanged:

* **legacy** — ``INTERNAL_CLIENT_ID`` unset: send the single shared
  ``PRIVATE_API_SECRET`` as ``X-Internal-Token`` (the pre-9.1 behaviour; matches
  the issuer's legacy fallback when it has no per-consumer registry).
* **bootstrap** — ``INTERNAL_CLIENT_ID`` set, exchange disabled: send the
  per-consumer ``X-Internal-Client`` + ``X-Internal-Token`` bootstrap pair on
  every private call. The blast radius is now one consumer, and the issuer gates
  each route by the credential's granted scope.
* **service_token** — ``INTERNAL_CLIENT_ID`` set + ``SERVICE_TOKEN_EXCHANGE_ENABLED``:
  exchange the bootstrap credential once at ``…/private/v1/service-token`` for a
  short-TTL scoped JWT and present it as ``Authorization: Bearer``. Rotation
  comes for free from the short TTL; the token is refreshed shortly before expiry
  and re-exchanged once if the issuer rejects it (``401``).

The *verification* primitives live in auth-sdk-m8 / fa-auth-m8 (issuer side); this
is the **consumer** side that emits the credentials. Header names are imported
from the SDK so the consumer and issuer can never drift.

Build a provider with :func:`build_internal_auth` and let
``RemoteRevocationClient`` own it; the provider is framework-agnostic and can be
reused for any other private call a consumer makes.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx
from auth_sdk_m8.security.consumer_auth import INTERNAL_CLIENT_HEADER, ConsumerScope
from auth_sdk_m8.security.guards import INTERNAL_TOKEN_HEADER

if TYPE_CHECKING:
    from fastapi_m8.config import ConsumerServiceSettings

_logger = logging.getLogger(__name__)

_JTI_STATUS_SUFFIX = "/jti-status"
_SERVICE_TOKEN_SUFFIX = "/service-token"
_AUTHORIZATION_HEADER = "Authorization"


def derive_service_token_url(introspection_url: str) -> str:
    """
    Derive the service-token exchange URL from the JTI-status introspection URL.

    The introspection URL points at ``…/private/v1/jti-status``; the exchange
    lives at ``…/private/v1/service-token`` on the same host/prefix. Mirrors the
    SDK's ``derive_stream_url`` so a consumer configures only ``INTROSPECTION_URL``.
    """
    url = introspection_url.rstrip("/")
    if url.endswith(_JTI_STATUS_SUFFIX):
        url = url[: -len(_JTI_STATUS_SUFFIX)]
    return url.rstrip("/") + _SERVICE_TOKEN_SUFFIX


@runtime_checkable
class InternalAuthProvider(Protocol):
    """Supplies (and refreshes) the auth headers for a private call."""

    async def headers(self) -> dict[str, str]:
        """Return the headers to attach to the next private request."""
        ...

    async def invalidate(self) -> bool:
        """
        Drop any cached credential after a rejected (401) call.

        Returns ``True`` when a retry is worthwhile (a fresh credential will be
        minted on the next :meth:`headers` call), ``False`` for static modes
        where a 401 means a misconfigured secret and retrying cannot help.
        """
        ...

    async def close(self) -> None:
        """Release any owned resources (e.g. an exchange HTTP client)."""
        ...


class _StaticInternalAuth:
    """Static-header provider for the legacy and bootstrap modes."""

    def __init__(self, headers: dict[str, str]) -> None:
        self._headers = headers

    async def headers(self) -> dict[str, str]:
        """Return a copy of the fixed header set."""
        return dict(self._headers)

    async def invalidate(self) -> bool:
        """No cached credential to drop; a 401 here is a config error."""
        return False

    async def close(self) -> None:
        """Nothing to release for a static provider."""
        return None


class ServiceTokenInternalAuth:
    """
    Exchange a bootstrap credential for short-TTL ``Authorization: Bearer`` tokens.

    Caches the minted token until ``refresh_leeway`` seconds before its ``exp``,
    then re-exchanges. The exchange is serialised by a lock so concurrent calls
    mint at most one token. Never logs the bootstrap secret or the token value.
    """

    def __init__(
        self,
        *,
        client_id: str,
        secret: str,
        exchange_url: str,
        scopes: list[str],
        refresh_leeway: int = 30,
        connect_timeout: float = 2.0,
        read_timeout: float = 3.0,
    ) -> None:
        """Initialise the exchange client and credential cache."""
        self._client_id = client_id
        self._exchange_headers = {
            INTERNAL_CLIENT_HEADER: client_id,
            INTERNAL_TOKEN_HEADER: secret,
        }
        self._url = exchange_url
        self._scopes = scopes
        self._leeway = refresh_leeway
        self._token: str | None = None
        self._expires_at = 0.0
        self._lock = asyncio.Lock()
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=connect_timeout, read=read_timeout, write=2.0, pool=2.0
            )
        )

    async def headers(self) -> dict[str, str]:
        """Return ``Authorization: Bearer <token>``, refreshing if stale."""
        token = await self._ensure_token()
        return {_AUTHORIZATION_HEADER: f"Bearer {token}"}

    async def _ensure_token(self) -> str:
        """Return a live token, exchanging once under the lock if needed."""
        async with self._lock:
            if self._token is not None and time.monotonic() < self._expires_at:
                return self._token
            return await self._exchange()

    async def _exchange(self) -> str:
        """POST the bootstrap credential and cache the minted token."""
        body = {"scopes": self._scopes} if self._scopes else {}
        response = await self._client.post(
            self._url, headers=self._exchange_headers, json=body
        )
        response.raise_for_status()
        data = response.json()
        token = data["access_token"]
        expires_in = int(data["expires_in"])
        self._token = token
        self._expires_at = time.monotonic() + max(0, expires_in - self._leeway)
        # Log identity + lifetime only — never the bootstrap secret or token.
        _logger.info(
            "internal_auth.service_token refreshed client=%s expires_in=%d",
            self._client_id,
            expires_in,
        )
        return token

    async def invalidate(self) -> bool:
        """Drop the cached token so the next call re-exchanges (retry worthwhile)."""
        async with self._lock:
            self._token = None
            self._expires_at = 0.0
        return True

    async def close(self) -> None:
        """Close the underlying exchange HTTP client."""
        await self._client.aclose()


def _secret_value(secret: object) -> str:
    """Return the raw string of a pydantic ``SecretStr`` (or any value)."""
    if hasattr(secret, "get_secret_value"):
        return secret.get_secret_value()  # type: ignore[union-attr]
    return str(secret)


def build_internal_auth(settings: ConsumerServiceSettings) -> InternalAuthProvider:
    """
    Build the private-call auth provider from consumer settings (Phase 9.1).

    Selects the mode from configuration:

    * ``INTERNAL_CLIENT_ID`` unset → **legacy** single ``X-Internal-Token``;
    * set, exchange off → **bootstrap** ``X-Internal-Client`` + ``X-Internal-Token``;
    * set, ``SERVICE_TOKEN_EXCHANGE_ENABLED`` → **service token** Bearer exchange.

    Args:
        settings: A ``ConsumerServiceSettings`` instance. ``PRIVATE_API_SECRET``
            carries the shared secret (legacy) or this consumer's bootstrap secret
            (per-consumer modes).

    Returns:
        An :class:`InternalAuthProvider`; the caller owns its lifecycle and must
        ``await provider.close()`` on teardown.

    """
    secret = _secret_value(settings.PRIVATE_API_SECRET)
    client_id = settings.INTERNAL_CLIENT_ID
    if not client_id:
        return _StaticInternalAuth({INTERNAL_TOKEN_HEADER: secret})
    if settings.SERVICE_TOKEN_EXCHANGE_ENABLED:
        scopes = settings.SERVICE_TOKEN_SCOPES or [str(ConsumerScope.INTROSPECTION)]
        return ServiceTokenInternalAuth(
            client_id=client_id,
            secret=secret,
            exchange_url=derive_service_token_url(str(settings.INTROSPECTION_URL)),
            scopes=scopes,
            refresh_leeway=settings.SERVICE_TOKEN_REFRESH_LEEWAY_SECONDS,
        )
    return _StaticInternalAuth(
        {INTERNAL_CLIENT_HEADER: client_id, INTERNAL_TOKEN_HEADER: secret}
    )


def describe_internal_auth_mode(settings: ConsumerServiceSettings) -> str:
    """Return the configured internal-auth mode name, for startup logging."""
    if not settings.INTERNAL_CLIENT_ID:
        return "legacy"
    return "service_token" if settings.SERVICE_TOKEN_EXCHANGE_ENABLED else "bootstrap"

"""
Async HTTP API-key introspection client — internal to fastapi-m8.

Resolves a user API key presented by an external client to its owner's
**current** authority by calling the issuer's private
``POST /private/v1/api-keys/introspect`` endpoint. A consumer service does not
share the issuer database, so this call *is* the distributed implementation of
the API-key rule: the key is an opaque bearer pointer to its owner, and the
resolved principal — not the key — carries role awareness.

Mirrors the ``RemoteRevocationClient`` split: the SDK owns the schemas, the
transport lives here. Instantiated only by ``build_auth_deps``; never import
directly.

Fail-closed by construction. There is no failure mode in which an
unconfirmable key yields authority: outage, timeout, open circuit, shed load,
oversized/malformed response, unknown schema version, and an audience that does
not match this consumer all raise :class:`ApiKeyIntrospectionError`, which the
dependency maps to ``503``. No successful principal is ever cached, so a
transport failure can never be answered from a stale result, and a role
downgrade takes effect on the key's next request.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import anyio
import httpx
from auth_sdk_m8.schemas.api_key import (
    API_KEY_INTROSPECTION_SCHEMA_VERSION,
    ApiKeyIntrospectionActiveResponse,
    ApiKeyIntrospectionRequest,
    ApiKeyIntrospectionResponse,
    ApiKeyPrincipal,
)
from pydantic import SecretStr, TypeAdapter, ValidationError

from fastapi_m8._internal_auth import InternalAuthProvider

_logger = logging.getLogger(__name__)

_UNAUTHORIZED = 401
_FORBIDDEN = 403
_TOO_MANY_REQUESTS = 429
_SERVER_ERROR = 500
_RETRY_AFTER_HEADER = "Retry-After"

_JTI_STATUS_SUFFIX = "/jti-status"
_API_KEY_INTROSPECT_SUFFIX = "/api-keys/introspect"

_RESPONSE_ADAPTER: TypeAdapter[ApiKeyIntrospectionResponse] = TypeAdapter(
    ApiKeyIntrospectionResponse
)


def derive_api_key_introspection_url(introspection_url: str) -> str:
    """
    Derive the API-key introspection URL from the JTI-status introspection URL.

    The JTI-status URL points at ``…/private/v1/jti-status``; API-key
    introspection lives at ``…/private/v1/api-keys/introspect`` on the same
    host/prefix. Mirrors :func:`~fastapi_m8._internal_auth.derive_service_token_url`
    so a consumer that already configures ``INTROSPECTION_URL`` need not repeat
    the issuer's base URL. An explicit ``API_KEY_INTROSPECTION_URL`` always wins.
    """
    url = introspection_url.rstrip("/")
    if url.endswith(_JTI_STATUS_SUFFIX):
        url = url[: -len(_JTI_STATUS_SUFFIX)]
    return url.rstrip("/") + _API_KEY_INTROSPECT_SUFFIX


class ApiKeyIntrospectionError(Exception):
    """
    Raised when a key's principal cannot be confirmed with the issuer.

    Carries a bounded, secret-free reason code only — never the presented key,
    the response body, or the internal credential — so it is safe to log and to
    chain into the dependency's ``503``.
    """


class ApiKeyQuotaExceededError(Exception):
    """
    Raised when the issuer reports the key's own quota is exhausted (``429``).

    Distinct from :class:`ApiKeyIntrospectionError`: the issuer answered
    authoritatively, so the dependency relays the ``429`` (with any
    ``Retry-After``) to its caller instead of failing closed with a ``503``.
    """

    def __init__(self, retry_after: str | None) -> None:
        """Record the issuer's ``Retry-After`` value, if it sent one."""
        super().__init__("api_key_quota_exceeded")
        self.retry_after = retry_after


class _CircuitBreaker:
    """
    Consecutive-failure circuit breaker for the introspection call.

    Opens after *failure_threshold* consecutive issuer failures and stays open
    for *reset_seconds*, after which a single trial call is admitted: it either
    closes the circuit on success or re-opens it immediately. While open, calls
    are denied without a round trip — the dependency answers ``503`` rather than
    queueing more load onto an issuer that is already failing.
    """

    def __init__(self, *, failure_threshold: int, reset_seconds: float) -> None:
        """Initialise a closed circuit."""
        self._threshold = failure_threshold
        self._reset = reset_seconds
        self._failures = 0
        self._opened_at: float | None = None

    def allows_call(self) -> bool:
        """Return whether a call may proceed, admitting one trial when due."""
        if self._opened_at is None:
            return True
        if time.monotonic() - self._opened_at < self._reset:
            return False
        # Half-open: admit one trial. Leave the failure count one short of the
        # threshold so a failed trial re-opens the circuit immediately.
        self._opened_at = None
        self._failures = self._threshold - 1
        return True

    def record_success(self) -> None:
        """Close the circuit and forget the failure streak."""
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        """Count an issuer failure, opening the circuit at the threshold."""
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = time.monotonic()
            _logger.warning(
                "api_key.introspection circuit_open failures=%d reset_seconds=%.1f",
                self._failures,
                self._reset,
            )


@dataclass(frozen=True)
class ApiKeyIntrospectionTuning:
    """
    Tuning knobs for :class:`ApiKeyIntrospectionClient`.

    Bundles timeouts, concurrency, response-size, and circuit-breaker limits so
    the client's constructor stays small regardless of how many independent
    limits it enforces.
    """

    schema_version: str = API_KEY_INTROSPECTION_SCHEMA_VERSION
    connect_timeout: float = 2.0
    read_timeout: float = 3.0
    pool_timeout: float = 2.0
    max_concurrency: int = 20
    max_response_bytes: int = 8192
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 30.0


class ApiKeyIntrospectionClient:
    """
    Async HTTP client resolving an API key to its owner's canonical principal.

    Private-call authentication is delegated to an
    :class:`~fastapi_m8._internal_auth.InternalAuthProvider`, exactly like
    ``RemoteRevocationClient`` — the internal-service credential identifies this
    *consumer* and determines the audience the issuer evaluates; it never
    represents the key's owner.

    Args:
        introspection_url: The issuer's ``…/private/v1/api-keys/introspect`` URL.
        auth_provider: Supplies this consumer's internal-credential headers.
        audience_id: This consumer's own registry identity. An active response
            must echo it back, or the result is refused as a trusted-configuration
            failure.
        tuning: Timeouts, concurrency, response-size, and circuit-breaker knobs.
            See :class:`ApiKeyIntrospectionTuning`.

    """

    def __init__(
        self,
        *,
        introspection_url: str,
        auth_provider: InternalAuthProvider,
        audience_id: str,
        tuning: ApiKeyIntrospectionTuning = ApiKeyIntrospectionTuning(),
    ) -> None:
        """Initialise the bounded HTTP client, semaphore, and circuit breaker."""
        self._url = introspection_url
        self._auth = auth_provider
        self._audience_id = audience_id
        self._schema_version = tuning.schema_version
        self._max_response_bytes = tuning.max_response_bytes
        self._pool_timeout = tuning.pool_timeout
        # anyio (not asyncio) primitives: fastapi-m8 supports any AnyIO backend.
        self._semaphore = anyio.Semaphore(tuning.max_concurrency)
        self._breaker = _CircuitBreaker(
            failure_threshold=tuning.circuit_failure_threshold,
            reset_seconds=tuning.circuit_reset_seconds,
        )
        self._client = httpx.AsyncClient(
            # Redirects are never followed: a redirect would replay the raw key
            # to a host this consumer never authenticated to.
            follow_redirects=False,
            limits=httpx.Limits(max_connections=tuning.max_concurrency),
            timeout=httpx.Timeout(
                connect=tuning.connect_timeout,
                read=tuning.read_timeout,
                write=2.0,
                pool=tuning.pool_timeout,
            ),
        )
        # URL/identity are configuration, not secrets; the credential never is.
        _logger.info(  # nosemgrep — logs audience/schema_version/concurrency only
            "api_key.introspection enabled audience=%s schema_version=%s "
            "max_concurrency=%d",
            audience_id,
            tuning.schema_version,
            tuning.max_concurrency,
        )

    async def introspect(self, api_key: SecretStr) -> ApiKeyPrincipal | None:
        """
        Resolve *api_key* to its owner's current principal.

        Args:
            api_key: The raw key an external client presented to this service.

        Returns:
            The canonical principal for an active key, or ``None`` when the
            issuer reports the key unusable — unknown, revoked, expired,
            missing/inactive/inconsistent owner, or an audience the key does not
            carry all share that one generic outcome, so the caller cannot probe
            another account's state.

        Raises:
            ApiKeyQuotaExceededError: The key's quota is exhausted (``429``).
            ApiKeyIntrospectionError: The principal could not be confirmed. The
                caller must deny; there is no fallback to bare key validity.

        """
        request = ApiKeyIntrospectionRequest(
            api_key=api_key, schema_version=self._schema_version
        )
        if not self._breaker.allows_call():
            raise ApiKeyIntrospectionError("circuit_open")
        async with self._acquire_slot():
            status_code, body, retry_after = await self._send(request)
        return await self._interpret(status_code, body, retry_after)

    def _acquire_slot(self) -> _SemaphoreSlot:
        """Return the bounded-wait guard for one in-flight introspection call."""
        return _SemaphoreSlot(self._semaphore, self._pool_timeout)

    async def _send(
        self, request: ApiKeyIntrospectionRequest
    ) -> tuple[int, bytes, str | None]:
        """
        Send one authenticated introspection request.

        Introspection consumes the key's quota, so the POST is **not**
        side-effect-free: only a failure known to have occurred *before*
        transmission (connection establishment) is retried. Once the request may
        have reached the issuer — read timeout, ``5xx``, a rejected credential —
        it is never automatically replayed; doing so would double-charge the
        owner's quota. A safe post-transmission retry needs a caller-generated
        idempotency id and issuer-side deduplication, which this contract does
        not define.
        """
        try:
            return await self._transmit(request)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            # Pre-transmission only: the connection was never established, so
            # the issuer cannot have seen the request or charged the quota.
            _logger.warning(  # nosemgrep — logs the exception type only, never its value
                "api_key.introspection connect_retry error=%s", type(exc)
            )
            try:
                return await self._transmit(request)
            except httpx.HTTPError as retry_exc:
                self._breaker.record_failure()
                raise ApiKeyIntrospectionError("transport") from retry_exc
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            raise ApiKeyIntrospectionError("transport") from exc

    async def _transmit(
        self, request: ApiKeyIntrospectionRequest
    ) -> tuple[int, bytes, str | None]:
        """
        Build the outbound body at the transmission point and stream the reply.

        The key is a ``SecretStr`` in every model, so generic serialization of
        *request* would put the **masked** value on the wire. The real
        credential is unwrapped only here, into a temporary body that exists for
        the duration of the call: it is never logged, never attached to an
        exception, and never reused for diagnostics, traces, or metrics. The
        guarantee is exactly that — the secret appears only in the intentional
        outbound payload, never in accidental or loggable serialization.

        The response body is read incrementally and abandoned the moment it
        exceeds ``max_response_bytes``, so a compromised or malfunctioning issuer
        cannot exhaust this consumer's memory.
        """
        body = {
            "api_key": request.api_key.get_secret_value(),
            "schema_version": self._schema_version,
        }
        headers = await self._auth.headers()
        async with self._client.stream(
            "POST", self._url, json=body, headers=headers
        ) as response:
            payload = bytearray()
            async for chunk in response.aiter_bytes():
                payload.extend(chunk)
                if len(payload) > self._max_response_bytes:
                    raise ApiKeyIntrospectionError("response_too_large")
            return (
                response.status_code,
                bytes(payload),
                response.headers.get(_RETRY_AFTER_HEADER),
            )

    async def _interpret(
        self, status_code: int, body: bytes, retry_after: str | None
    ) -> ApiKeyPrincipal | None:
        """Map one issuer reply to a principal, a generic denial, or a failure."""
        if status_code == _TOO_MANY_REQUESTS:
            # The issuer answered authoritatively about the key's own quota;
            # relaying it is not a fail-closed event and never trips the breaker.
            raise ApiKeyQuotaExceededError(retry_after)
        if status_code in (_UNAUTHORIZED, _FORBIDDEN):
            # This consumer's internal credential was rejected or lacks the
            # api-key-introspection scope: a deployment fault, not a decision
            # about the key. Drop any cached credential so the next request can
            # re-mint one, but never replay this request — it may already have
            # been counted by the issuer.
            await self._auth.invalidate()
            raise ApiKeyIntrospectionError("consumer_unauthorized")
        if status_code >= _SERVER_ERROR:
            self._breaker.record_failure()
            raise ApiKeyIntrospectionError("issuer_unavailable")
        if status_code != httpx.codes.OK:
            self._breaker.record_failure()
            raise ApiKeyIntrospectionError("unexpected_status")
        result = self._parse(body)
        self._breaker.record_success()
        if not isinstance(result, ApiKeyIntrospectionActiveResponse):
            return None
        if result.audience_id != self._audience_id:
            # An active principal minted for someone else means the internal
            # credential or the registry mapping is wrong. That is a trusted
            # configuration failure, not a denial of this key — 503, never 401.
            _logger.error(  # nosemgrep — logs this consumer's own audience id, not a secret
                "api_key.introspection audience_mismatch expected=%s",
                self._audience_id,
            )
            raise ApiKeyIntrospectionError("audience_mismatch")
        return result.principal

    def _parse(self, body: bytes) -> ApiKeyIntrospectionResponse:
        """
        Validate the issuer's reply against the SDK contract, or fail closed.

        A response this release cannot interpret — malformed, or declaring an
        unknown ``schema_version`` — is refused rather than read for whatever
        fields happen to parse. The ``ValidationError`` embeds the raw input, so
        it is neither logged nor chained; only a bounded reason travels.
        """
        try:
            return _RESPONSE_ADAPTER.validate_json(body)
        except ValidationError:
            _logger.warning("api_key.introspection malformed_response")
            raise ApiKeyIntrospectionError("malformed_response") from None

    async def close(self) -> None:
        """Close the underlying httpx session and the auth provider."""
        await self._client.aclose()
        await self._auth.close()


class _SemaphoreSlot:
    """
    Bounded-wait async context manager around the concurrency semaphore.

    Load shedding, not queueing: a request that cannot get capacity within the
    pool timeout is denied with ``503`` instead of piling onto an issuer that is
    already saturated.
    """

    def __init__(self, semaphore: anyio.Semaphore, timeout: float) -> None:
        """Bind the slot to *semaphore* with a bounded acquisition *timeout*."""
        self._semaphore = semaphore
        self._timeout = timeout

    async def __aenter__(self) -> None:
        """Acquire a slot, shedding the request if capacity never frees up."""
        try:
            with anyio.fail_after(self._timeout):
                await self._semaphore.acquire()
        except TimeoutError:
            _logger.warning("api_key.introspection load_shed")
            raise ApiKeyIntrospectionError("load_shed") from None

    async def __aexit__(self, *_exc_info: object) -> None:
        """Release the slot."""
        self._semaphore.release()

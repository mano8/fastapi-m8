"""Tests for fastapi_m8._api_key — the issuer introspection client (§3.12)."""

from __future__ import annotations

import contextlib
import logging

import httpx
import pytest
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType
from pydantic import SecretStr

from fastapi_m8._api_key import (
    ApiKeyIntrospectionClient,
    ApiKeyIntrospectionError,
    ApiKeyIntrospectionTuning,
    ApiKeyQuotaExceededError,
    _CircuitBreaker,
    derive_api_key_introspection_url,
)

pytestmark = pytest.mark.anyio

_VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"
AUDIENCE = "prompt-engine-m8"
RAW_KEY = "sk-live-real-presented-key-value"  # noqa: S105  # nosec B105 — test fixture
URL = "http://auth:8000/user/private/v1/api-keys/introspect"


class _FakeAuth:
    """Minimal InternalAuthProvider double recording invalidate() calls."""

    def __init__(self) -> None:
        self.invalidated = 0
        self.closed = False

    async def headers(self) -> dict[str, str]:
        return {"X-Internal-Client": "prompt-engine-m8", "X-Internal-Token": "boot"}

    async def invalidate(self) -> bool:
        self.invalidated += 1
        return True

    async def close(self) -> None:
        self.closed = True


def _active_body(
    *,
    role: str = "writer",
    is_superuser: bool = False,
    access_mode: str = "read_write",
    audience: str = AUDIENCE,
    schema_version: str = "1",
) -> dict:
    return {
        "active": True,
        "schema_version": schema_version,
        "audience_id": audience,
        "principal": {
            "user_id": _VALID_UUID,
            "role": role,
            "is_superuser": is_superuser,
            "access_mode": access_mode,
            "authentication_method": "api_key",
            "auth_generation": 7,
        },
        "key_expires_at": None,
    }


def _make_client(handler, **overrides) -> ApiKeyIntrospectionClient:
    """Build a real client and swap only its transport for *handler*.

    Replacing the transport (rather than the whole ``httpx.AsyncClient``) keeps
    the client's real timeouts, connection limits, and redirect policy under
    test — the configuration the fail-closed posture depends on.
    """
    client = ApiKeyIntrospectionClient(
        introspection_url=URL,
        auth_provider=overrides.pop("auth_provider", _FakeAuth()),
        audience_id=overrides.pop("audience_id", AUDIENCE),
        tuning=ApiKeyIntrospectionTuning(**overrides),
    )
    client._client._transport = httpx.MockTransport(handler)
    return client


def _responder(status_code: int, json_body: dict | None = None, **kwargs):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body, **kwargs)

    return handler


# ── derive_api_key_introspection_url ──────────────────────────────────────────


def test_derive_url_from_jti_status_url() -> None:
    """The API-key endpoint is derived from the JTI-status URL's base."""
    assert (
        derive_api_key_introspection_url("http://auth:8000/user/private/v1/jti-status")
        == "http://auth:8000/user/private/v1/api-keys/introspect"
    )


def test_derive_url_tolerates_trailing_slash() -> None:
    """A trailing slash on the configured URL does not double up."""
    assert (
        derive_api_key_introspection_url("http://auth:8000/user/private/v1/jti-status/")
        == "http://auth:8000/user/private/v1/api-keys/introspect"
    )


def test_derive_url_from_bare_private_prefix() -> None:
    """A URL that is already the private prefix just gains the suffix."""
    assert (
        derive_api_key_introspection_url("http://auth:8000/user/private/v1")
        == "http://auth:8000/user/private/v1/api-keys/introspect"
    )


# ── _CircuitBreaker ───────────────────────────────────────────────────────────


def test_circuit_closed_allows_calls() -> None:
    """A fresh circuit admits calls."""
    breaker = _CircuitBreaker(failure_threshold=2, reset_seconds=60)
    assert breaker.allows_call() is True


def test_circuit_opens_at_threshold() -> None:
    """Consecutive failures up to the threshold open the circuit."""
    breaker = _CircuitBreaker(failure_threshold=2, reset_seconds=60)
    breaker.record_failure()
    assert breaker.allows_call() is True
    breaker.record_failure()
    assert breaker.allows_call() is False


def test_circuit_success_resets_failure_streak() -> None:
    """A success in between means the failures are not consecutive."""
    breaker = _CircuitBreaker(failure_threshold=2, reset_seconds=60)
    breaker.record_failure()
    breaker.record_success()
    breaker.record_failure()
    assert breaker.allows_call() is True


def test_circuit_half_opens_after_reset_window() -> None:
    """Once the reset window elapses a single trial call is admitted."""
    breaker = _CircuitBreaker(failure_threshold=1, reset_seconds=0)
    breaker.record_failure()
    assert breaker.allows_call() is True


def test_circuit_reopens_immediately_on_failed_trial() -> None:
    """A failed trial call re-opens the circuit without a new streak."""
    breaker = _CircuitBreaker(failure_threshold=3, reset_seconds=0)
    for _ in range(3):
        breaker.record_failure()
    assert breaker.allows_call() is True  # half-open trial
    breaker.record_failure()
    breaker._reset = 60
    assert breaker.allows_call() is False


def test_circuit_open_logs_without_secrets(caplog) -> None:
    """Opening the circuit logs bounded counters only."""
    breaker = _CircuitBreaker(failure_threshold=1, reset_seconds=60)
    with caplog.at_level(logging.WARNING, logger="fastapi_m8._api_key"):
        breaker.record_failure()
    assert "circuit_open" in caplog.text


# ── active / inactive resolution ──────────────────────────────────────────────


async def test_introspect_active_returns_principal() -> None:
    """An active response yields the canonical owner principal."""
    client = _make_client(_responder(200, _active_body()))
    principal = await client.introspect(SecretStr(RAW_KEY))
    assert principal is not None
    assert principal.user_id == _VALID_UUID
    assert principal.role is RoleType.WRITER
    assert principal.access_mode is ApiKeyAccessMode.READ_WRITE
    assert principal.auth_generation == 7
    await client.close()


async def test_introspect_inactive_returns_none() -> None:
    """The generic inactive shape resolves to no principal, not an error."""
    client = _make_client(_responder(200, {"active": False, "schema_version": "1"}))
    assert await client.introspect(SecretStr(RAW_KEY)) is None
    await client.close()


async def test_inactive_response_is_indistinguishable_across_causes() -> None:
    """Every inactive cause is one shape, so no cause can be told from another."""
    client = _make_client(_responder(200, {"active": False, "schema_version": "1"}))
    # Unknown key, revoked key, and inactive owner all produce this same reply;
    # the client cannot and must not distinguish them.
    assert await client.introspect(SecretStr("unknown")) is None
    assert await client.introspect(SecretStr("revoked")) is None
    await client.close()


# ── audience verification ─────────────────────────────────────────────────────


async def test_audience_mismatch_fails_closed_with_503_reason(caplog) -> None:
    """An active principal minted for another audience is refused, not accepted."""
    client = _make_client(_responder(200, _active_body(audience="other-service")))
    with caplog.at_level(logging.ERROR, logger="fastapi_m8._api_key"):
        with pytest.raises(ApiKeyIntrospectionError, match="audience_mismatch"):
            await client.introspect(SecretStr(RAW_KEY))
    assert "audience_mismatch" in caplog.text
    await client.close()


# ── status mapping ────────────────────────────────────────────────────────────


async def test_quota_exhausted_raises_with_retry_after() -> None:
    """A 429 is relayed as a quota error carrying the issuer's Retry-After."""
    client = _make_client(
        _responder(429, {"detail": "slow down"}, headers={"Retry-After": "17"})
    )
    with pytest.raises(ApiKeyQuotaExceededError) as exc_info:
        await client.introspect(SecretStr(RAW_KEY))
    assert exc_info.value.retry_after == "17"
    await client.close()


async def test_quota_exhausted_without_retry_after_header() -> None:
    """A 429 with no Retry-After still relays as a quota error."""
    client = _make_client(_responder(429, {"detail": "slow down"}))
    with pytest.raises(ApiKeyQuotaExceededError) as exc_info:
        await client.introspect(SecretStr(RAW_KEY))
    assert exc_info.value.retry_after is None
    await client.close()


async def test_quota_response_never_trips_the_circuit() -> None:
    """A 429 is an authoritative answer about the key, not an issuer failure."""
    client = _make_client(
        _responder(429, {"detail": "slow"}), circuit_failure_threshold=1
    )
    with pytest.raises(ApiKeyQuotaExceededError):
        await client.introspect(SecretStr(RAW_KEY))
    assert client._breaker.allows_call() is True
    await client.close()


@pytest.mark.parametrize("status_code", [401, 403])
async def test_rejected_consumer_credential_fails_closed(status_code: int) -> None:
    """A rejected/unscoped consumer credential denies; it never grants."""
    auth = _FakeAuth()
    client = _make_client(_responder(status_code, {"detail": "no"}), auth_provider=auth)
    with pytest.raises(ApiKeyIntrospectionError, match="consumer_unauthorized"):
        await client.introspect(SecretStr(RAW_KEY))
    # The cached credential is dropped so the next request can re-mint one …
    assert auth.invalidated == 1
    await client.close()


async def test_rejected_credential_is_not_retried() -> None:
    """… but this request is never replayed: the issuer may already have counted it."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(401, json={"detail": "no"})

    client = _make_client(handler)
    with pytest.raises(ApiKeyIntrospectionError):
        await client.introspect(SecretStr(RAW_KEY))
    assert len(calls) == 1
    await client.close()


async def test_issuer_500_fails_closed_and_counts_a_failure() -> None:
    """A 5xx denies and counts toward opening the circuit."""
    client = _make_client(_responder(503, {"detail": "db down"}))
    with pytest.raises(ApiKeyIntrospectionError, match="issuer_unavailable"):
        await client.introspect(SecretStr(RAW_KEY))
    assert client._breaker._failures == 1
    await client.close()


async def test_unexpected_status_fails_closed() -> None:
    """An unmodelled status is refused rather than interpreted."""
    client = _make_client(_responder(404, {"detail": "nope"}))
    with pytest.raises(ApiKeyIntrospectionError, match="unexpected_status"):
        await client.introspect(SecretStr(RAW_KEY))
    await client.close()


# ── malformed / unknown-schema responses ──────────────────────────────────────


async def test_malformed_response_fails_closed(caplog) -> None:
    """A response missing the contract's fields is refused, not partially read."""
    client = _make_client(_responder(200, {"nonsense": True}))
    with caplog.at_level(logging.WARNING, logger="fastapi_m8._api_key"):
        with pytest.raises(ApiKeyIntrospectionError, match="malformed_response"):
            await client.introspect(SecretStr(RAW_KEY))
    await client.close()


async def test_unparseable_body_fails_closed() -> None:
    """A non-JSON body is refused."""
    client = _make_client(lambda _r: httpx.Response(200, content=b"<html>nope</html>"))
    with pytest.raises(ApiKeyIntrospectionError, match="malformed_response"):
        await client.introspect(SecretStr(RAW_KEY))
    await client.close()


async def test_unknown_schema_version_fails_closed() -> None:
    """A response declaring a version this release cannot speak is refused."""
    client = _make_client(_responder(200, _active_body(schema_version="99")))
    with pytest.raises(ApiKeyIntrospectionError, match="malformed_response"):
        await client.introspect(SecretStr(RAW_KEY))
    await client.close()


async def test_inconsistent_owner_claims_fail_closed() -> None:
    """A principal whose role/is_superuser disagree cannot be built at all."""
    client = _make_client(
        _responder(200, _active_body(role="writer", is_superuser=True))
    )
    with pytest.raises(ApiKeyIntrospectionError, match="malformed_response"):
        await client.introspect(SecretStr(RAW_KEY))
    await client.close()


async def test_oversized_response_is_abandoned() -> None:
    """A response beyond the size cap is dropped mid-read, not buffered whole."""
    client = _make_client(
        lambda _r: httpx.Response(200, content=b"x" * 5000), max_response_bytes=256
    )
    with pytest.raises(ApiKeyIntrospectionError, match="response_too_large"):
        await client.introspect(SecretStr(RAW_KEY))
    await client.close()


# ── transport failures and the pre-transmission-only retry rule ───────────────


async def test_connect_error_retries_once_then_succeeds() -> None:
    """A failed connection never reached the issuer, so it is safe to retry once."""
    attempts: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            raise httpx.ConnectError("refused")
        return httpx.Response(200, json=_active_body())

    client = _make_client(handler)
    principal = await client.introspect(SecretStr(RAW_KEY))
    assert principal is not None
    assert len(attempts) == 2
    await client.close()


async def test_connect_error_twice_fails_closed() -> None:
    """A second connection failure denies; there is no third attempt."""
    attempts: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ConnectError("refused")

    client = _make_client(handler)
    with pytest.raises(ApiKeyIntrospectionError, match="transport"):
        await client.introspect(SecretStr(RAW_KEY))
    assert len(attempts) == 2
    await client.close()


async def test_read_timeout_is_never_retried() -> None:
    """A read timeout may have reached the issuer, so replaying it could double-charge."""
    attempts: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ReadTimeout("too slow")

    client = _make_client(handler)
    with pytest.raises(ApiKeyIntrospectionError, match="transport"):
        await client.introspect(SecretStr(RAW_KEY))
    assert len(attempts) == 1
    await client.close()


async def test_transport_failure_counts_toward_the_circuit() -> None:
    """Transport failures are issuer-health signals and open the circuit."""
    client = _make_client(
        lambda _r: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
        circuit_failure_threshold=1,
    )
    with pytest.raises(ApiKeyIntrospectionError):
        await client.introspect(SecretStr(RAW_KEY))
    assert client._breaker.allows_call() is False
    await client.close()


async def test_open_circuit_denies_without_a_round_trip() -> None:
    """While the circuit is open the issuer is not called at all."""
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        raise httpx.ReadTimeout("slow")

    client = _make_client(
        handler, circuit_failure_threshold=1, circuit_reset_seconds=60
    )
    with pytest.raises(ApiKeyIntrospectionError):
        await client.introspect(SecretStr(RAW_KEY))
    with pytest.raises(ApiKeyIntrospectionError, match="circuit_open"):
        await client.introspect(SecretStr(RAW_KEY))
    assert len(calls) == 1
    await client.close()


async def test_successful_call_closes_the_circuit() -> None:
    """A recovered issuer closes the circuit again."""
    client = _make_client(_responder(200, _active_body()), circuit_failure_threshold=2)
    client._breaker.record_failure()
    await client.introspect(SecretStr(RAW_KEY))
    assert client._breaker._failures == 0
    await client.close()


# ── load shedding ─────────────────────────────────────────────────────────────


async def test_load_is_shed_when_capacity_never_frees(caplog) -> None:
    """A request that cannot get capacity is denied, not queued indefinitely."""
    client = _make_client(
        _responder(200, _active_body()), max_concurrency=1, pool_timeout=0.01
    )
    await client._semaphore.acquire()
    with caplog.at_level(logging.WARNING, logger="fastapi_m8._api_key"):
        with pytest.raises(ApiKeyIntrospectionError, match="load_shed"):
            await client.introspect(SecretStr(RAW_KEY))
    assert "load_shed" in caplog.text
    client._semaphore.release()
    await client.close()


async def test_slot_is_released_after_a_failed_call() -> None:
    """A denied call still frees its concurrency slot."""
    client = _make_client(_responder(503, {"detail": "down"}), max_concurrency=1)
    with pytest.raises(ApiKeyIntrospectionError):
        await client.introspect(SecretStr(RAW_KEY))
    assert client._semaphore.value == 1
    await client.close()


# ── no positive caching ───────────────────────────────────────────────────────


async def test_every_request_reintrospects_the_issuer() -> None:
    """A successful principal is never reused, so a downgrade lands immediately."""
    calls: list[int] = []
    roles = iter(["writer", "reader"])

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json=_active_body(role=next(roles)))

    client = _make_client(handler)
    first = await client.introspect(SecretStr(RAW_KEY))
    second = await client.introspect(SecretStr(RAW_KEY))
    assert len(calls) == 2, "the second request must re-introspect, not reuse a cache"
    assert first is not None and first.role is RoleType.WRITER
    assert second is not None and second.role is RoleType.READER
    await client.close()


async def test_transport_failure_is_never_answered_from_an_earlier_success() -> None:
    """A prior success must not paper over a later outage."""
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(200, json=_active_body())
        raise httpx.ReadTimeout("down")

    client = _make_client(handler)
    assert await client.introspect(SecretStr(RAW_KEY)) is not None
    with pytest.raises(ApiKeyIntrospectionError):
        await client.introspect(SecretStr(RAW_KEY))
    await client.close()


# ── APIKEY-TRANSPORT-01: the secret reaches the wire and nothing else ─────────


async def test_issuer_receives_the_real_secret_and_declared_version() -> None:
    """The outbound body carries the actual key, not the SecretStr mask."""
    seen: list[bytes] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.content)
        return httpx.Response(200, json=_active_body())

    client = _make_client(handler)
    await client.introspect(SecretStr(RAW_KEY))
    body = seen[0].decode()
    assert RAW_KEY in body
    assert "**********" not in body
    assert '"schema_version":"1"' in body.replace(" ", "")
    await client.close()


async def test_key_never_appears_in_the_url_or_query() -> None:
    """The key travels in the body only — never somewhere a proxy would log it."""
    seen: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url)
        return httpx.Response(200, json=_active_body())

    client = _make_client(handler)
    await client.introspect(SecretStr(RAW_KEY))
    assert RAW_KEY not in str(seen[0])
    assert seen[0].query == b""
    await client.close()


async def test_consumer_credential_travels_on_the_internal_headers() -> None:
    """The internal credential is separate from the user key it is resolving."""
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json=_active_body())

    client = _make_client(handler)
    await client.introspect(SecretStr(RAW_KEY))
    assert seen[0]["X-Internal-Client"] == "prompt-engine-m8"
    assert seen[0]["X-Internal-Token"] == "boot"
    await client.close()


@pytest.mark.parametrize(
    "handler",
    [
        _responder(200, {"active": False, "schema_version": "1"}),
        _responder(200, {"garbage": 1}),
        _responder(500, {"detail": "boom"}),
        _responder(429, {"detail": "slow"}),
    ],
)
async def test_key_never_reaches_logs_on_any_outcome(handler, caplog) -> None:
    """No outcome — denial, failure, or success — logs the presented key."""
    client = _make_client(handler)
    with caplog.at_level(logging.DEBUG, logger="fastapi_m8._api_key"):
        with contextlib.suppress(ApiKeyIntrospectionError, ApiKeyQuotaExceededError):
            await client.introspect(SecretStr(RAW_KEY))
    assert RAW_KEY not in caplog.text
    await client.close()


async def test_key_never_reaches_exception_text() -> None:
    """A raised failure carries a bounded reason code, never the credential."""
    client = _make_client(_responder(500, {"detail": "boom"}))
    with pytest.raises(ApiKeyIntrospectionError) as exc_info:
        await client.introspect(SecretStr(RAW_KEY))
    chain = repr(exc_info.value) + repr(exc_info.value.__cause__)
    assert RAW_KEY not in chain
    await client.close()


# ── redirects ─────────────────────────────────────────────────────────────────


async def test_redirects_are_never_followed() -> None:
    """A redirect would replay the raw key to an unauthenticated host."""
    calls: list[httpx.URL] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        return httpx.Response(307, headers={"Location": "http://evil.test/collect"})

    client = _make_client(handler)
    with pytest.raises(ApiKeyIntrospectionError, match="unexpected_status"):
        await client.introspect(SecretStr(RAW_KEY))
    assert len(calls) == 1
    assert "evil.test" not in str(calls[0])
    await client.close()


# ── lifecycle ─────────────────────────────────────────────────────────────────


async def test_close_releases_the_client_and_auth_provider() -> None:
    """close() is the teardown owner for both owned resources."""
    auth = _FakeAuth()
    client = _make_client(_responder(200, _active_body()), auth_provider=auth)
    await client.close()
    assert auth.closed is True
    assert client._client.is_closed is True


def test_construction_logs_configuration_not_secrets(caplog) -> None:
    """The startup line names the audience and bounds, never a credential."""
    with caplog.at_level(logging.INFO, logger="fastapi_m8._api_key"):
        ApiKeyIntrospectionClient(
            introspection_url=URL, auth_provider=_FakeAuth(), audience_id=AUDIENCE
        )
    assert "api_key.introspection enabled" in caplog.text
    assert AUDIENCE in caplog.text

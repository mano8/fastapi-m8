"""Tests for fastapi_m8._revocation.RemoteRevocationClient and JtiRevocationCache."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from fastapi_m8._revocation import (
    JtiRevocationCache,
    RemoteRevocationClient,
    RevocationCheckError,
)

pytestmark = pytest.mark.anyio

_URL = "http://auth:8000/private/v1/jti-status"
_SECRET = "supersecret"


def _make_client(**kwargs) -> RemoteRevocationClient:
    return RemoteRevocationClient(
        introspection_url=_URL, private_api_secret=_SECRET, **kwargs
    )


@pytest.mark.anyio
async def test_is_revoked_returns_true_when_not_active() -> None:
    """active=False in response → token is revoked."""
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": False}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    assert await client.is_revoked("jti-123") is True
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_returns_false_when_active() -> None:
    """active=True in response → token is not revoked."""
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    assert await client.is_revoked("jti-123") is False
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_fail_open_on_network_error() -> None:
    """Network error with fail_closed=False (opt-in) → returns False."""
    client = _make_client(fail_closed=False)
    setattr(
        client._client, "post", AsyncMock(side_effect=httpx.ConnectError("unreachable"))
    )

    assert await client.is_revoked("jti-999") is False
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_default_fail_closed_raises_on_error() -> None:
    """Network error with default construction → raises RevocationCheckError."""
    client = _make_client()
    setattr(
        client._client, "post", AsyncMock(side_effect=httpx.ConnectError("unreachable"))
    )

    with pytest.raises(RevocationCheckError):
        await client.is_revoked("jti-999")
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_fail_closed_raises_on_error() -> None:
    """Network error with fail_closed=True → raises RevocationCheckError."""
    client = _make_client(fail_closed=True)
    setattr(
        client._client, "post", AsyncMock(side_effect=httpx.ConnectError("unreachable"))
    )

    with pytest.raises(RevocationCheckError):
        await client.is_revoked("jti-999")
    await client.close()


@pytest.mark.anyio
async def test_close_calls_aclose() -> None:
    """close() delegates to the httpx session."""
    client = _make_client()
    mock_aclose = AsyncMock()
    setattr(client._client, "aclose", mock_aclose)
    await client.close()
    mock_aclose.assert_awaited_once()


# ── Per-consumer internal-auth wiring (item 9.1) ──────────────────────────────


class _FakeAuth:
    """Minimal InternalAuthProvider double tracking calls."""

    def __init__(self, headers: dict, retry: bool) -> None:
        self._headers = headers
        self._retry = retry
        self.invalidated = 0
        self.closed = False

    async def headers(self) -> dict:
        return dict(self._headers)

    async def invalidate(self) -> bool:
        self.invalidated += 1
        return self._retry

    async def close(self) -> None:
        self.closed = True


def test_requires_exactly_one_credential_source() -> None:
    """Neither or both of private_api_secret/auth_provider is a config error."""
    with pytest.raises(ValueError, match="exactly one"):
        RemoteRevocationClient(introspection_url=_URL)
    with pytest.raises(ValueError, match="exactly one"):
        RemoteRevocationClient(
            introspection_url=_URL,
            private_api_secret=_SECRET,
            auth_provider=_FakeAuth({}, retry=False),
        )


@pytest.mark.anyio
async def test_legacy_secret_sent_as_internal_token_header() -> None:
    """The legacy path attaches X-Internal-Token on every request."""
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    post = AsyncMock(return_value=mock_resp)
    setattr(client._client, "post", post)

    await client.is_revoked("jti-1")
    _, kwargs = post.call_args
    assert kwargs["headers"] == {"X-Internal-Token": _SECRET}
    await client.close()


@pytest.mark.anyio
async def test_provider_headers_attached_per_request() -> None:
    """A per-consumer provider's headers are attached to the call."""
    auth = _FakeAuth(
        {"X-Internal-Client": "svc-a", "X-Internal-Token": _SECRET}, retry=False
    )
    client = RemoteRevocationClient(introspection_url=_URL, auth_provider=auth)
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    post = AsyncMock(return_value=mock_resp)
    setattr(client._client, "post", post)

    await client.is_revoked("jti-1")
    _, kwargs = post.call_args
    assert kwargs["headers"]["X-Internal-Client"] == "svc-a"
    await client.close()
    assert auth.closed is True


def _status_error(code: int) -> httpx.HTTPStatusError:
    return httpx.HTTPStatusError(
        str(code), request=MagicMock(), response=MagicMock(status_code=code)
    )


@pytest.mark.anyio
async def test_401_reexchanges_and_retries_once() -> None:
    """Service-token mode: a 401 invalidates, re-mints, and retries once."""
    auth = _FakeAuth({"Authorization": "Bearer t"}, retry=True)
    client = RemoteRevocationClient(introspection_url=_URL, auth_provider=auth)
    ok = MagicMock()
    ok.raise_for_status = MagicMock()
    ok.json.return_value = {"active": True}
    bad = MagicMock()
    bad.raise_for_status = MagicMock(side_effect=_status_error(401))
    setattr(client._client, "post", AsyncMock(side_effect=[bad, ok]))

    assert await client.is_revoked("jti-1") is False
    assert auth.invalidated == 1
    await client.close()


@pytest.mark.anyio
async def test_401_not_retried_in_static_mode() -> None:
    """Legacy/bootstrap (invalidate→False): a 401 is not retried, fails closed."""
    auth = _FakeAuth({"X-Internal-Token": _SECRET}, retry=False)
    client = RemoteRevocationClient(introspection_url=_URL, auth_provider=auth)
    bad = MagicMock()
    bad.raise_for_status = MagicMock(side_effect=_status_error(401))
    setattr(client._client, "post", AsyncMock(return_value=bad))

    with pytest.raises(RevocationCheckError):
        await client.is_revoked("jti-1")
    assert auth.invalidated == 1
    await client.close()


@pytest.mark.anyio
async def test_non_401_status_error_not_retried() -> None:
    """A 500 is never retried regardless of provider mode."""
    auth = _FakeAuth({"Authorization": "Bearer t"}, retry=True)
    client = RemoteRevocationClient(introspection_url=_URL, auth_provider=auth)
    bad = MagicMock()
    bad.raise_for_status = MagicMock(side_effect=_status_error(500))
    setattr(client._client, "post", AsyncMock(return_value=bad))

    with pytest.raises(RevocationCheckError):
        await client.is_revoked("jti-1")
    assert auth.invalidated == 0
    await client.close()


# ── JtiRevocationCache ────────────────────────────────────────────────────────


class TestJtiRevocationCache:
    def test_miss_on_empty_cache(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        assert cache.get("jti-x") is None

    def test_hit_returns_false_not_revoked(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        cache.put("jti-1", "user-a")
        assert cache.get("jti-1") is False

    def test_expired_entry_treated_as_miss(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        cache.put("jti-1", "user-a")
        with patch("fastapi_m8._revocation.time") as mock_time:
            mock_time.monotonic.return_value = 9_999_999_999.0
            assert cache.get("jti-1") is None
        assert "jti-1" not in cache._store

    def test_evict_jti_removes_entry(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        cache.put("jti-1", "user-a")
        cache.evict_jti("jti-1")
        assert cache.get("jti-1") is None

    def test_evict_jti_noop_on_missing(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        cache.evict_jti("nonexistent")  # must not raise

    def test_evict_user_removes_all_user_jtis(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        cache.put("jti-1", "user-a")
        cache.put("jti-2", "user-a")
        cache.put("jti-3", "user-b")
        cache.evict_user("user-a")
        assert cache.get("jti-1") is None
        assert cache.get("jti-2") is None
        assert cache.get("jti-3") is False

    def test_flush_all_clears_everything(self) -> None:
        cache = JtiRevocationCache(ttl_seconds=30)
        cache.put("jti-1", "user-a")
        cache.put("jti-2", "user-b")
        cache.flush_all()
        assert cache.get("jti-1") is None
        assert cache.get("jti-2") is None


# ── RemoteRevocationClient with cache ─────────────────────────────────────────


@pytest.mark.anyio
async def test_cache_hit_skips_http() -> None:
    """A cached active JTI is returned without an HTTP call."""
    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-cached", "user-1")
    mock_post = AsyncMock()
    setattr(client._client, "post", mock_post)

    assert await client.is_revoked("jti-cached", user_id="user-1") is False
    mock_post.assert_not_called()
    await client.close()


@pytest.mark.anyio
async def test_cache_miss_calls_http_and_caches_active() -> None:
    """A cache miss triggers HTTP; active=True populates the cache."""
    client = _make_client(cache_ttl=30)
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    assert await client.is_revoked("jti-new", user_id="user-1") is False
    assert client._cache is not None
    assert client._cache.get("jti-new") is False
    await client.close()


@pytest.mark.anyio
async def test_revoked_result_not_cached() -> None:
    """active=False (revoked) result is never put in the cache."""
    client = _make_client(cache_ttl=30)
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": False}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    assert await client.is_revoked("jti-rev", user_id="user-1") is True
    assert client._cache is not None
    assert client._cache.get("jti-rev") is None
    await client.close()


@pytest.mark.anyio
async def test_no_cache_when_ttl_zero() -> None:
    """Default cache_ttl=0 means no cache is allocated."""
    client = _make_client()
    assert client._cache is None
    await client.close()


# ── Revocation-cache observability (item 7.x.2) ───────────────────────────────


@pytest.fixture
def fresh_metrics(monkeypatch):
    """Isolate observability state: fresh registry, metrics enabled, clean cache.

    Restores the real ``REGISTRY``/``_m`` and resets the module-level metric
    cache afterwards so no metric registration leaks across tests.
    """
    from auth_sdk_m8.observability import metrics as obs_mod
    from prometheus_client import CollectorRegistry

    import fastapi_m8._revocation as rev_mod

    fresh = CollectorRegistry(auto_describe=False)
    monkeypatch.setattr(obs_mod, "REGISTRY", fresh)
    monkeypatch.setattr(obs_mod, "_m", None)
    monkeypatch.setattr(rev_mod, "_cache_metrics", None)
    obs_mod.setup(enabled=True, groups_str="auth", api_prefix="")
    return obs_mod


@pytest.fixture
def disabled_metrics(monkeypatch):
    """Observability disabled: ``metrics.get()`` returns ``None``."""
    from auth_sdk_m8.observability import metrics as obs_mod

    import fastapi_m8._revocation as rev_mod

    monkeypatch.setattr(obs_mod, "_m", None)
    monkeypatch.setattr(rev_mod, "_cache_metrics", None)
    return obs_mod


def _sv(registry, name: str, labels: dict | None = None) -> float:
    return registry.get_sample_value(name, labels) or 0.0


@pytest.mark.anyio
async def test_cache_hit_records_hit_metric_and_ttl(fresh_metrics) -> None:
    """A cache hit increments the hit counter and publishes the TTL gauge."""
    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-cached", "user-1")
    setattr(client._client, "post", AsyncMock())

    assert await client.is_revoked("jti-cached", user_id="user-1") is False
    reg = fresh_metrics.REGISTRY
    assert _sv(reg, "revocation_cache_lookups_total", {"result": "hit"}) == 1.0
    assert _sv(reg, "revocation_cache_lookups_total", {"result": "miss"}) == 0.0
    assert _sv(reg, "revocation_cache_ttl_seconds") == 30.0
    await client.close()


@pytest.mark.anyio
async def test_cache_miss_records_miss_metric(fresh_metrics) -> None:
    """A cache miss increments the miss counter (then the HTTP call runs)."""
    client = _make_client(cache_ttl=30)
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    assert await client.is_revoked("jti-new", user_id="user-1") is False
    reg = fresh_metrics.REGISTRY
    assert _sv(reg, "revocation_cache_lookups_total", {"result": "miss"}) == 1.0
    assert _sv(reg, "revocation_cache_lookups_total", {"result": "hit"}) == 0.0
    await client.close()


@pytest.mark.anyio
async def test_ttl_zero_records_no_lookup_metric(fresh_metrics) -> None:
    """With caching disabled (ttl=0) no lookup metric is ever emitted."""
    client = _make_client(cache_ttl=0)
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    assert await client.is_revoked("jti-x", user_id="user-1") is False
    reg = fresh_metrics.REGISTRY
    assert _sv(reg, "revocation_cache_lookups_total", {"result": "hit"}) == 0.0
    assert _sv(reg, "revocation_cache_lookups_total", {"result": "miss"}) == 0.0
    await client.close()


@pytest.mark.anyio
async def test_metrics_disabled_is_noop(disabled_metrics) -> None:
    """When observability is disabled the cache still works and emits nothing."""
    from fastapi_m8._revocation import _get_cache_metrics

    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-cached", "user-1")
    setattr(client._client, "post", AsyncMock())

    assert await client.is_revoked("jti-cached", user_id="user-1") is False
    assert _get_cache_metrics() is None
    await client.close()


def test_get_cache_metrics_idempotent(fresh_metrics) -> None:
    """Repeated calls reuse the same metric objects on a stable registry."""
    from fastapi_m8._revocation import _get_cache_metrics

    first = _get_cache_metrics()
    second = _get_cache_metrics()
    assert first is not None
    assert first is second


@pytest.mark.anyio
async def test_no_jti_or_secret_in_metrics_output(fresh_metrics) -> None:
    """Acceptance: rendered metrics carry no JTI, user ID, or secret."""
    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-secret-value", "user-secret-value")
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    setattr(client._client, "post", AsyncMock(return_value=mock_resp))

    await client.is_revoked("jti-secret-value", user_id="user-secret-value")
    await client.is_revoked("jti-fresh-value", user_id="user-secret-value")

    body, _ = fresh_metrics.render()
    text = body.decode()
    assert "jti-secret-value" not in text
    assert "jti-fresh-value" not in text
    assert "user-secret-value" not in text
    assert _SECRET not in text
    # Only the result dimension is exported (hit/miss), never an identifier.
    assert "result=" in text
    await client.close()


def test_cache_enabled_logs_ttl_without_secret(caplog) -> None:
    """Construction logs the configured TTL only — never the secret or URL."""
    import logging

    with caplog.at_level(logging.INFO, logger="fastapi_m8._revocation"):
        client = _make_client(cache_ttl=45)
    assert "revocation.cache enabled ttl_seconds=45" in caplog.text
    assert _SECRET not in caplog.text
    assert client._cache is not None


def test_evict_jti_delegates_to_cache() -> None:
    """evict_jti forwards to the cache when enabled."""
    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-1", "user-a")
    client.evict_jti("jti-1")
    assert client._cache.get("jti-1") is None


def test_evict_user_delegates_to_cache() -> None:
    """evict_user forwards to the cache when enabled."""
    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-1", "user-a")
    client.evict_user("user-a")
    assert client._cache.get("jti-1") is None


def test_flush_cache_delegates_to_cache() -> None:
    """flush_cache forwards to the cache when enabled."""
    client = _make_client(cache_ttl=30)
    assert client._cache is not None
    client._cache.put("jti-1", "user-a")
    client.flush_cache()
    assert client._cache.get("jti-1") is None


# ── Consumer-side degradation matrix (item 5.5) ───────────────────────────────


@pytest.mark.anyio
async def test_fail_closed_raises_and_counts_failure(fresh_metrics) -> None:
    """fail_closed + unreachable introspection → raises and counts mode=fail_closed."""
    client = _make_client(fail_closed=True)
    setattr(client._client, "post", AsyncMock(side_effect=httpx.ConnectError("down")))

    with pytest.raises(RevocationCheckError):
        await client.is_revoked("jti-1")
    reg = fresh_metrics.REGISTRY
    assert _sv(reg, "revocation_check_failures_total", {"mode": "fail_closed"}) == 1.0
    assert _sv(reg, "revocation_check_failures_total", {"mode": "fail_open"}) == 0.0
    await client.close()


@pytest.mark.anyio
async def test_fail_open_accepts_logs_and_counts_optout(fresh_metrics, caplog) -> None:
    """fail_open opt-out: token accepted, logged loudly, and counted mode=fail_open."""
    import logging

    client = _make_client(fail_closed=False)
    setattr(client._client, "post", AsyncMock(side_effect=httpx.ConnectError("down")))

    with caplog.at_level(logging.WARNING, logger="fastapi_m8._revocation"):
        assert await client.is_revoked("jti-1") is False
    assert "security.revocation_fail_open" in caplog.text
    reg = fresh_metrics.REGISTRY
    assert _sv(reg, "revocation_check_failures_total", {"mode": "fail_open"}) == 1.0
    assert _sv(reg, "revocation_check_failures_total", {"mode": "fail_closed"}) == 0.0
    await client.close()


@pytest.mark.anyio
async def test_failure_metric_no_jti_in_output(fresh_metrics) -> None:
    """The failure counter exposes only the mode dimension — never the JTI."""
    client = _make_client(fail_closed=False)
    setattr(client._client, "post", AsyncMock(side_effect=httpx.ConnectError("down")))
    await client.is_revoked("jti-secret-value")
    body, _ = fresh_metrics.render()
    text = body.decode()
    assert "jti-secret-value" not in text
    assert 'mode="fail_open"' in text
    await client.close()


def test_evict_jti_noop_without_cache() -> None:
    """evict_jti is a no-op when cache is disabled."""
    client = _make_client()
    client.evict_jti("jti-x")  # must not raise


def test_evict_user_noop_without_cache() -> None:
    """evict_user is a no-op when cache is disabled."""
    client = _make_client()
    client.evict_user("user-x")  # must not raise


def test_flush_cache_noop_without_cache() -> None:
    """flush_cache is a no-op when cache is disabled."""
    client = _make_client()
    client.flush_cache()  # must not raise

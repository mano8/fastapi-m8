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

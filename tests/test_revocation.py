"""Tests for fastapi_m8._revocation.RemoteRevocationClient."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from fastapi_m8._revocation import RemoteRevocationClient, RevocationCheckError

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
    client._client.post = AsyncMock(return_value=mock_resp)

    assert await client.is_revoked("jti-123") is True
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_returns_false_when_active() -> None:
    """active=True in response → token is not revoked."""
    client = _make_client()
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"active": True}
    client._client.post = AsyncMock(return_value=mock_resp)

    assert await client.is_revoked("jti-123") is False
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_fail_open_on_network_error() -> None:
    """Network error with fail_closed=False (default) → returns False."""
    client = _make_client()
    client._client.post = AsyncMock(side_effect=httpx.ConnectError("unreachable"))

    assert await client.is_revoked("jti-999") is False
    await client.close()


@pytest.mark.anyio
async def test_is_revoked_fail_closed_raises_on_error() -> None:
    """Network error with fail_closed=True → raises RevocationCheckError."""
    client = _make_client(fail_closed=True)
    client._client.post = AsyncMock(side_effect=httpx.ConnectError("unreachable"))

    with pytest.raises(RevocationCheckError):
        await client.is_revoked("jti-999")
    await client.close()


@pytest.mark.anyio
async def test_close_calls_aclose() -> None:
    """close() delegates to the httpx session."""
    client = _make_client()
    client._client.aclose = AsyncMock()
    await client.close()
    client._client.aclose.assert_awaited_once()

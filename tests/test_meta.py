"""Tests for the consumer /meta + /ping routes wired by create_app."""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
from asgi_lifespan import LifespanManager
from fastapi import APIRouter
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from fastapi_m8 import create_app
from tests.conftest import make_settings

_BASE = {"SET_OPEN_API": False, "SET_DOCS": False, "SET_REDOC": False}


@asynccontextmanager
async def live_client(application):
    """Start app lifespan then yield an async HTTP client against it."""
    async with LifespanManager(application) as manager:
        async with AsyncClient(
            transport=ASGITransport(app=manager.app), base_url="http://test"
        ) as client:
            yield client


def _router() -> APIRouter:
    return APIRouter(tags=["test"])


# ── /meta ─────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_meta_route_returns_settings_values() -> None:
    """create_app mounts {API_PREFIX}/meta sourced from settings."""
    s = make_settings(**_BASE)  # API_PREFIX=/api, PROJECT_NAME=test-service
    app = create_app(s, _router())
    async with live_client(app) as client:
        resp = await client.get("/api/meta")
    assert resp.status_code == 200
    assert resp.json() == {
        "service": "test-service",
        "version": "1.0.0",
        "api_version": "v1",
        "contract": {
            "name": "test-service",
            "version": "1.0",
            "range": ">=1.0.0 <2.0.0",
        },
    }


@pytest.mark.anyio
async def test_meta_route_sets_cache_control() -> None:
    s = make_settings(**_BASE)
    app = create_app(s, _router())
    async with live_client(app) as client:
        resp = await client.get("/api/meta")
    assert resp.headers["Cache-Control"] == "public, max-age=300"


@pytest.mark.anyio
async def test_meta_contract_name_override() -> None:
    """CONTRACT_NAME overrides the PROJECT_NAME default in the contract block."""
    s = make_settings(**_BASE, CONTRACT_NAME="custom-contract")
    app = create_app(s, _router())
    async with live_client(app) as client:
        resp = await client.get("/api/meta")
    assert resp.json()["contract"]["name"] == "custom-contract"


# ── /ping ─────────────────────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_ping_route_is_prefix_independent() -> None:
    """/ping is mounted at the root regardless of API_PREFIX."""
    s = make_settings(**_BASE)
    app = create_app(s, _router())
    async with live_client(app) as client:
        resp = await client.get("/ping")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


# ── Fail-closed at boot ───────────────────────────────────────────────────────


def test_missing_contract_version_fails_closed() -> None:
    """A consumer without CONTRACT_VERSION cannot construct settings."""
    with pytest.raises(ValidationError):
        make_settings(**_BASE, CONTRACT_VERSION=None)

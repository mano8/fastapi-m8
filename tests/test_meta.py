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
async def test_ping_route_is_prefix_only_when_prefix_set() -> None:
    """/ping lives only at {API_PREFIX}/ping when a prefix is configured (single-mount)."""
    s = make_settings(**_BASE)  # API_PREFIX=/api
    app = create_app(s, _router())
    async with live_client(app) as client:
        prefixed = await client.get("/api/ping")
        root = await client.get("/ping")
    assert prefixed.status_code == 200
    assert prefixed.json() == {"status": "ok"}
    # root /ping is NOT mounted when a prefix is set (single-mount, auth-sdk-m8 2.0.0)
    assert root.status_code == 404


@pytest.mark.anyio
async def test_ping_route_is_reachable_under_prefix() -> None:
    """{API_PREFIX}/ping is the authoritative liveness probe behind a prefix-routing proxy."""
    s = make_settings(**_BASE)  # API_PREFIX=/api
    app = create_app(s, _router())
    async with live_client(app) as client:
        resp = await client.get("/api/ping")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ping_schema_carries_single_operation() -> None:
    """The single {API_PREFIX}/ping mount appears in the OpenAPI schema."""
    s = make_settings(**_BASE)  # API_PREFIX=/api
    app = create_app(s, _router())
    paths = app.openapi()["paths"]
    ping_paths = [p for p in paths if p.endswith("/ping")]
    assert ping_paths == ["/api/ping"]


# ── Fail-closed at boot ───────────────────────────────────────────────────────


def test_missing_contract_version_fails_closed() -> None:
    """A consumer without CONTRACT_VERSION cannot construct settings."""
    with pytest.raises(ValidationError):
        make_settings(**_BASE, CONTRACT_VERSION=None)

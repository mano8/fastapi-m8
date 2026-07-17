"""Tests for the remote API-key principal dependencies and their config (§3.12).

The client's own behaviour is covered in ``test_api_key.py``; this module covers
what ``build_auth_deps`` wires up — the dependency family, its status mapping,
and the fail-closed configuration that must stop the service at boot.
"""

from __future__ import annotations

import logging

import httpx
import pytest
from auth_sdk_m8.core.exceptions import ApiKeyCapabilityCeilingError
from auth_sdk_m8.schemas.base import RoleType
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_m8._deps import build_auth_deps
from tests.conftest import make_settings
from tests.test_api_key import AUDIENCE, RAW_KEY, _active_body, _responder

pytestmark = pytest.mark.anyio

_INACTIVE = {"active": False, "schema_version": "1"}
_INVALID_KEY_DETAIL = "Invalid or expired API key"


def _api_key_settings(**overrides):
    """Settings with the remote API-key dependencies fully configured."""
    return make_settings(
        API_KEY_INTROSPECTION_ENABLED=True,
        INTERNAL_CLIENT_ID=AUDIENCE,
        PRIVATE_API_SECRET="supersecret",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        **overrides,
    )


def _auth_with(handler, **overrides):
    """Build AuthDeps whose introspection client answers through *handler*."""
    auth = build_auth_deps(_api_key_settings(**overrides))
    assert auth.api_key_client is not None
    auth.api_key_client._client._transport = httpx.MockTransport(handler)
    return auth


def _client_for(auth, dependency) -> TestClient:
    """Mount *dependency* on one route and return a client for it."""
    app = FastAPI()

    @app.get("/thing")
    def route(principal=Depends(dependency)) -> dict:  # noqa: ANN001
        return {"user_id": principal.user_id, "role": principal.role.value}

    return TestClient(app)


# ── enablement ────────────────────────────────────────────────────────────────


def test_api_key_dependencies_absent_by_default() -> None:
    """Remote API-key auth is off unless a deployment explicitly enables it."""
    auth = build_auth_deps(make_settings())
    assert auth.api_key_client is None
    assert auth.get_current_api_key_principal is None
    assert auth.require_api_key_role is None
    assert auth.get_current_api_key_reader is None
    assert auth.get_current_api_key_writer is None


def test_disabled_deployment_has_no_api_key_authorization_path_at_all() -> None:
    """With the feature off there is no dependency that could admit a key."""
    auth = build_auth_deps(make_settings())
    # Not merely "denies" — the callable that would resolve a principal is
    # absent, so a disabled service cannot authorize an API key by any route.
    assert auth.get_current_api_key_writer is None
    assert auth.api_key_client is None


def test_enabling_builds_the_whole_family_on_the_single_authdeps() -> None:
    """One build_auth_deps call yields the JWT and API-key surfaces together."""
    auth = build_auth_deps(_api_key_settings())
    assert auth.api_key_client is not None
    assert callable(auth.get_current_api_key_principal)
    assert callable(auth.require_api_key_role)
    assert callable(auth.get_current_api_key_reader)
    assert callable(auth.get_current_api_key_writer)
    # …and the JWT members are untouched.
    assert callable(auth.get_current_active_writer)


def test_no_admin_or_superuser_api_key_dependency_exists() -> None:
    """APIKEY-CAP-01: the surface offers no administrative API-key member."""
    auth = build_auth_deps(_api_key_settings())
    for forbidden in (
        "get_current_api_key_admin",
        "get_current_api_key_superuser",
    ):
        assert not hasattr(auth, forbidden), (
            f"{forbidden} must not exist: API-key authorization is capped at WRITER."
        )


# ── configuration is fail-closed at startup ───────────────────────────────────


def test_enabled_without_any_url_fails_at_startup() -> None:
    """No endpoint means no way to confirm a principal, so boot stops."""
    with pytest.raises(ValueError, match="API_KEY_INTROSPECTION_URL"):
        make_settings(
            API_KEY_INTROSPECTION_ENABLED=True,
            INTERNAL_CLIENT_ID=AUDIENCE,
            PRIVATE_API_SECRET="supersecret",
        )


def test_enabled_without_internal_client_id_fails_at_startup() -> None:
    """Without a registry identity there is no audience to verify against."""
    with pytest.raises(ValueError, match="INTERNAL_CLIENT_ID"):
        make_settings(
            API_KEY_INTROSPECTION_ENABLED=True,
            PRIVATE_API_SECRET="supersecret",
            INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        )


def test_enabled_without_private_api_secret_fails_at_startup() -> None:
    """Introspection is a private route and needs this consumer's credential."""
    with pytest.raises(ValueError, match="PRIVATE_API_SECRET"):
        make_settings(
            API_KEY_INTROSPECTION_ENABLED=True,
            INTERNAL_CLIENT_ID=AUDIENCE,
            INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        )


def test_enabled_with_unknown_schema_version_fails_at_startup() -> None:
    """An unspeakable contract version is caught at boot, not mid-decision."""
    with pytest.raises(ValueError, match="API_KEY_INTROSPECTION_SCHEMA_VERSION"):
        _api_key_settings(API_KEY_INTROSPECTION_SCHEMA_VERSION="99")


def test_disabled_config_is_never_validated() -> None:
    """A service that does not enable the feature needs none of its config."""
    settings = make_settings(API_KEY_INTROSPECTION_ENABLED=False)
    assert settings.API_KEY_INTROSPECTION_URL is None


def test_url_is_derived_from_the_jti_status_url() -> None:
    """A consumer that already configures INTROSPECTION_URL need not repeat it."""
    settings = _api_key_settings()
    assert (
        settings.effective_api_key_introspection_url()
        == "http://auth:8000/user/private/v1/api-keys/introspect"
    )


def test_explicit_url_overrides_the_derived_one() -> None:
    """An explicit endpoint always wins over derivation."""
    settings = _api_key_settings(
        API_KEY_INTROSPECTION_URL="http://issuer:9000/custom/introspect"
    )
    assert (
        settings.effective_api_key_introspection_url()
        == "http://issuer:9000/custom/introspect"
    )


def test_explicit_url_alone_is_enough() -> None:
    """INTROSPECTION_URL is not required when the endpoint is given explicitly."""
    settings = make_settings(
        API_KEY_INTROSPECTION_ENABLED=True,
        INTERNAL_CLIENT_ID=AUDIENCE,
        PRIVATE_API_SECRET="supersecret",
        API_KEY_INTROSPECTION_URL="http://issuer:9000/custom/introspect",
    )
    assert (
        settings.effective_api_key_introspection_url()
        == "http://issuer:9000/custom/introspect"
    )


def test_settings_are_carried_onto_the_client() -> None:
    """The dedicated config group reaches the client, not just the settings object."""
    auth = build_auth_deps(
        _api_key_settings(
            API_KEY_INTROSPECTION_MAX_CONCURRENCY=3,
            API_KEY_INTROSPECTION_MAX_RESPONSE_BYTES=1024,
            API_KEY_INTROSPECTION_CIRCUIT_FAILURE_THRESHOLD=2,
        )
    )
    client = auth.api_key_client
    assert client is not None
    assert client._audience_id == AUDIENCE
    assert client._max_response_bytes == 1024
    assert client._semaphore.value == 3
    assert client._breaker._threshold == 2


# ── status mapping through the dependency ─────────────────────────────────────


def test_missing_header_is_the_generic_denial() -> None:
    """A request with no key gets the same generic 401 as a bad one."""
    auth = _auth_with(_responder(200, _active_body()))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing")
    assert response.status_code == 401
    assert response.json()["detail"] == _INVALID_KEY_DETAIL


def test_inactive_key_maps_to_the_same_generic_401() -> None:
    """The issuer's 200 active:false becomes this service's generic 401."""
    auth = _auth_with(_responder(200, _INACTIVE))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 401
    assert response.json()["detail"] == _INVALID_KEY_DETAIL


def test_missing_and_invalid_keys_are_indistinguishable() -> None:
    """No response detail lets a caller tell absent from rejected."""
    auth = _auth_with(_responder(200, _INACTIVE))
    client = _client_for(auth, auth.get_current_api_key_writer)
    absent = client.get("/thing")
    rejected = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert absent.status_code == rejected.status_code == 401
    assert absent.json() == rejected.json()


def test_quota_exhaustion_relays_429_and_retry_after() -> None:
    """The issuer's 429 and Retry-After reach this service's caller intact."""
    auth = _auth_with(
        _responder(429, {"detail": "slow"}, headers={"Retry-After": "42"})
    )
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"


def test_quota_exhaustion_without_retry_after_still_relays_429() -> None:
    """A 429 with no Retry-After relays the status alone."""
    auth = _auth_with(_responder(429, {"detail": "slow"}))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 429
    assert "Retry-After" not in response.headers


def test_issuer_outage_fails_closed_with_503(caplog) -> None:
    """An unconfirmable principal is a denial, never a fallback to key validity."""
    auth = _auth_with(_responder(503, {"detail": "db down"}))
    client = _client_for(auth, auth.get_current_api_key_writer)
    with caplog.at_level(logging.WARNING, logger="fastapi_m8._deps"):
        response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 503
    assert "security.api_key_denied" in caplog.text
    assert RAW_KEY not in caplog.text


def test_malformed_response_fails_closed_with_503() -> None:
    """A response this release cannot interpret denies rather than being guessed at."""
    auth = _auth_with(_responder(200, {"active": True, "nonsense": 1}))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 503


def test_unknown_schema_version_fails_closed_with_503() -> None:
    """A response declaring a contract version this consumer cannot speak denies."""
    auth = _auth_with(_responder(200, _active_body(schema_version="99")))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 503


def test_audience_mismatch_fails_closed_with_503_not_401() -> None:
    """A principal minted for another audience is a config fault, not a bad key."""
    auth = _auth_with(_responder(200, _active_body(audience="someone-else")))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 503


def test_fail_open_revocation_mode_never_leaks_onto_the_api_key_path() -> None:
    """ACCESS_REVOCATION_FAILURE_MODE=fail_open must not weaken this path."""
    auth = _auth_with(
        _responder(503, {"detail": "down"}),
        TOKEN_MODE="stateful",
        ACCESS_REVOCATION_FAILURE_MODE="fail_open",
    )
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 503, (
        "the API-key path has no fail-open option; it must deny regardless"
    )


# ── the capability decision (APIKEY-OWNER-01 / APIKEY-MODE-01 / APIKEY-CAP-01) ─


def test_writer_owner_with_read_write_key_is_allowed() -> None:
    """Owner role and access mode both permit the write → allowed."""
    auth = _auth_with(_responder(200, _active_body(role="writer")))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 200
    assert response.json()["role"] == "writer"


def test_reader_owner_is_denied_the_writer_capability() -> None:
    """The owner's live role caps the key: a reader cannot write."""
    auth = _auth_with(_responder(200, _active_body(role="reader")))
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 403
    assert response.json()["detail"] == "The user doesn't have enough privileges"


def test_read_only_key_of_a_writer_owner_is_denied_the_write() -> None:
    """The key's immutable access mode narrows an owner who could otherwise write."""
    auth = _auth_with(
        _responder(200, _active_body(role="writer", access_mode="read_only"))
    )
    client = _client_for(auth, auth.get_current_api_key_writer)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 403


def test_read_only_key_of_a_writer_owner_still_reads() -> None:
    """A read-only key keeps the read capability its owner has."""
    auth = _auth_with(
        _responder(200, _active_body(role="writer", access_mode="read_only"))
    )
    client = _client_for(auth, auth.get_current_api_key_reader)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 200


def test_reader_owner_is_allowed_the_reader_capability() -> None:
    """A reader owner reads through the key."""
    auth = _auth_with(
        _responder(200, _active_body(role="reader", access_mode="read_only"))
    )
    client = _client_for(auth, auth.get_current_api_key_reader)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 200


def test_user_owner_is_denied_even_the_reader_capability() -> None:
    """USER is below READER, so the key grants nothing."""
    auth = _auth_with(
        _responder(200, _active_body(role="user", access_mode="read_only"))
    )
    client = _client_for(auth, auth.get_current_api_key_reader)
    response = client.get("/thing", headers={"X-API-Key": RAW_KEY})
    assert response.status_code == 403


@pytest.mark.parametrize("role", ["admin", "superadmin"])
def test_privileged_owner_gets_no_more_than_writer_through_a_key(role: str) -> None:
    """An ADMIN/SUPERADMIN owner's key is still only a writer-level credential."""
    is_superuser = role == "superadmin"
    auth = _auth_with(
        _responder(200, _active_body(role=role, is_superuser=is_superuser))
    )
    client = _client_for(auth, auth.get_current_api_key_writer)
    assert client.get("/thing", headers={"X-API-Key": RAW_KEY}).status_code == 200


@pytest.mark.parametrize("required", [RoleType.ADMIN, RoleType.SUPERADMIN])
def test_requiring_an_administrative_role_is_rejected_at_wiring_time(
    required: RoleType,
) -> None:
    """Asking a key for admin/superuser is a programming error, not a 403."""
    auth = build_auth_deps(_api_key_settings())
    assert auth.require_api_key_role is not None
    with pytest.raises(ApiKeyCapabilityCeilingError):
        auth.require_api_key_role(required)


def test_require_api_key_role_builds_a_usable_writer_dependency() -> None:
    """The factory is the one shape; the shipped specializations are its output."""
    auth = _auth_with(_responder(200, _active_body(role="writer")))
    assert auth.require_api_key_role is not None
    dependency = auth.require_api_key_role(RoleType.WRITER)
    client = _client_for(auth, dependency)
    assert client.get("/thing", headers={"X-API-Key": RAW_KEY}).status_code == 200


def test_base_principal_dependency_grants_no_capability() -> None:
    """Depending on the bare principal proves a live owner, never writer rights."""
    auth = _auth_with(_responder(200, _active_body(role="user")))
    client = _client_for(auth, auth.get_current_api_key_principal)
    # The same owner a capability dependency would deny is admitted here …
    assert client.get("/thing", headers={"X-API-Key": RAW_KEY}).status_code == 200
    # … which is exactly why a capability-bearing route must use a role dependency.
    capability_client = _client_for(auth, auth.get_current_api_key_writer)
    assert (
        capability_client.get("/thing", headers={"X-API-Key": RAW_KEY}).status_code
        == 403
    )


def test_downgrade_denies_the_next_request_with_no_cached_principal() -> None:
    """A writer→reader downgrade lands on the key's very next request."""
    roles = iter(["writer", "reader"])

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_active_body(role=next(roles)))

    auth = _auth_with(handler)
    client = _client_for(auth, auth.get_current_api_key_writer)
    assert client.get("/thing", headers={"X-API-Key": RAW_KEY}).status_code == 200
    assert client.get("/thing", headers={"X-API-Key": RAW_KEY}).status_code == 403


# ── lifecycle ─────────────────────────────────────────────────────────────────


async def test_close_tears_down_the_api_key_client() -> None:
    """AuthDeps.close owns the introspection client's teardown too."""
    auth = build_auth_deps(_api_key_settings())
    assert auth.api_key_client is not None
    await auth.close()
    assert auth.api_key_client._client.is_closed is True


async def test_close_tears_down_both_clients() -> None:
    """A stateful consumer with API-key auth closes revocation and introspection."""
    auth = build_auth_deps(_api_key_settings(TOKEN_MODE="stateful"))
    assert auth.revocation_client is not None
    assert auth.api_key_client is not None
    await auth.close()
    assert auth.revocation_client._client.is_closed is True
    assert auth.api_key_client._client.is_closed is True

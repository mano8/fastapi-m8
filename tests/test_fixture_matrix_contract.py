"""Consume the SDK-owned canonical fixture matrix (§5.5, FIXTURE-01, Phase 5).

``auth-sdk-m8`` is the single canonical owner of the shared role/flag/
decision/event/introspection fixture matrix. This module consumes it — rather
than re-deriving local expectations — so that a contract change on the SDK
side (a new schema version, a changed decision, a checksum mismatch from a
hand-edit) fails this suite immediately instead of silently drifting.
``load_authorization_fixture_matrix()`` itself raises
``UnsupportedFixtureMatrixSchemaVersionError``/``FixtureChecksumMismatchError``
on drift or tampering, so merely importing/calling it here is already part of
the CI gate against contract drift.
"""

from __future__ import annotations

import json

import httpx
import pytest
from auth_sdk_m8 import (
    ApiKeyAccessMode,
    has_api_key_capability,
    has_superuser_privileges,
)
from auth_sdk_m8.schemas.api_key import ApiKeyIntrospectionActiveResponse
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.jti_status import (
    JtiStatusActiveResponse,
    JtiStatusInactiveResponse,
)
from auth_sdk_m8.testing import load_authorization_fixture_matrix
from fastapi import HTTPException

from fastapi_m8._api_key import ApiKeyIntrospectionClient, ApiKeyIntrospectionError
from fastapi_m8._deps import _require_role
from fastapi_m8._revocation import RemoteRevocationClient

pytestmark = pytest.mark.anyio


@pytest.fixture(scope="module")
def matrix() -> dict:
    return load_authorization_fixture_matrix()


class _FakeUser:
    """Minimal duck-typed stand-in for ``UserModel`` — ``_require_role`` reads
    only ``.role``."""

    def __init__(self, role: str) -> None:
        self.role = RoleType(role)


class TestRoleFlagAndMinimumRoleParity:
    """fastapi-m8's own guard functions must agree with the canonical matrix."""

    def test_require_role_matches_minimum_role_matrix(self, matrix: dict) -> None:
        for row in matrix["minimum_role_matrix"]:
            user = _FakeUser(row["current_role"])
            required = RoleType(row["required_role"])
            if row["satisfied"]:
                _require_role(user, required)  # must not raise
            else:
                with pytest.raises(HTTPException):
                    _require_role(user, required)

    def test_superuser_guard_matches_role_flag_matrix(self, matrix: dict) -> None:
        for row in matrix["role_flag_matrix"]:
            role = RoleType(row["role"])
            assert (
                has_superuser_privileges(role, row["is_superuser"])
                is row["has_superuser_privileges"]
            )


class TestJtiStatusFixtureParsing:
    """``RemoteRevocationClient`` must parse the canonical v1/v2 shapes."""

    def _client(self) -> RemoteRevocationClient:
        return RemoteRevocationClient(
            introspection_url="http://auth:8000/user/private/v1/jti-status",
            private_api_secret="supersecret",  # nosec B106 — test fixture
        )

    def test_v1_active_is_refused_as_malformed(self, matrix: dict) -> None:
        """A pre-2.0 issuer's bare ``{"active": true}`` carries no
        ``auth_generation`` to tag a cache entry with, so the v2-only response
        adapter refuses it — the client fails closed rather than trusting an
        active result it cannot tag (documented on ``RemoteRevocationClient._parse``)."""
        from fastapi_m8._revocation import RevocationDecisionError

        client = self._client()
        body = matrix["jti_status_fixtures"]["v1"]["active"]
        with pytest.raises(RevocationDecisionError):
            client._parse(httpx.Response(200, json=body))

    def test_v1_inactive_parses_as_inactive(self, matrix: dict) -> None:
        client = self._client()
        body = matrix["jti_status_fixtures"]["v1"]["inactive"]
        result = client._parse(httpx.Response(200, json=body))
        assert isinstance(result, JtiStatusInactiveResponse)

    def test_v2_active_parses_with_generation(self, matrix: dict) -> None:
        client = self._client()
        v2 = matrix["jti_status_fixtures"]["v2"]
        result = client._parse(httpx.Response(200, json=v2["active"]))
        assert isinstance(result, JtiStatusActiveResponse)
        assert result.user_id == v2["request"]["expected_user_id"]
        assert result.auth_generation == v2["active"]["auth_generation"]

    def test_v2_subject_mismatch_parses_as_generic_inactive(self, matrix: dict) -> None:
        client = self._client()
        v2 = matrix["jti_status_fixtures"]["v2"]
        result = client._parse(
            httpx.Response(200, json=v2["subject_mismatch_inactive"])
        )
        assert isinstance(result, JtiStatusInactiveResponse)

    def test_unsupported_schema_version_is_refused(self, matrix: dict) -> None:
        from fastapi_m8._revocation import RevocationDecisionError

        client = self._client()
        bad = matrix["jti_status_fixtures"]["unsupported_schema_version_response"]
        with pytest.raises(RevocationDecisionError):
            client._parse(httpx.Response(200, json=bad))


class TestApiKeyIntrospectionFixtureParsing:
    """``ApiKeyIntrospectionClient`` must parse the canonical shapes (§3.12)."""

    def _client(self, audience_id: str) -> ApiKeyIntrospectionClient:
        return ApiKeyIntrospectionClient(
            introspection_url="http://auth:8000/user/private/v1/api-keys/introspect",
            auth_provider=_FakeAuthProvider(),
            audience_id=audience_id,
        )

    def test_active_response_resolves_the_fixture_principal(self, matrix: dict) -> None:
        fixtures = matrix["api_key_introspection_fixtures"]
        active = fixtures["active_response"]
        client = self._client(active["audience_id"])
        parsed = client._parse(json.dumps(active).encode())
        assert isinstance(parsed, ApiKeyIntrospectionActiveResponse)
        assert parsed.principal.model_dump(mode="json") == active["principal"]

    def test_inactive_response_parses_generic(self, matrix: dict) -> None:
        fixtures = matrix["api_key_introspection_fixtures"]
        client = self._client("any-consumer")
        parsed = client._parse(json.dumps(fixtures["inactive_response"]).encode())
        assert parsed.active is False

    def test_unsupported_schema_version_response_is_refused(self, matrix: dict) -> None:
        fixtures = matrix["api_key_introspection_fixtures"]
        client = self._client("any-consumer")
        with pytest.raises(ApiKeyIntrospectionError):
            client._parse(
                json.dumps(fixtures["unsupported_schema_version_response"]).encode()
            )

    async def test_audience_mismatch_fails_closed(self, matrix: dict) -> None:
        fixtures = matrix["api_key_introspection_fixtures"]
        active = fixtures["active_response"]
        # Configured for a different consumer identity than the fixture echoes.
        client = self._client(active["audience_id"] + "-different-consumer")
        with pytest.raises(ApiKeyIntrospectionError):
            await client._interpret(200, json.dumps(active).encode(), None)


class _FakeAuthProvider:
    async def headers(self) -> dict[str, str]:
        return {}

    async def invalidate(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class TestLocalRemotePrincipalEquivalence:
    """Both halves of the API-key rule must resolve one identical principal."""

    def test_every_fixture_pair_is_identical(self, matrix: dict) -> None:
        for pair in matrix["local_remote_principal_equivalence"]:
            assert pair["local"] == pair["remote"]

    def test_has_capability_agrees_for_every_pair(self, matrix: dict) -> None:
        for pair in matrix["local_remote_principal_equivalence"]:
            local, remote = pair["local"], pair["remote"]
            for required_role in (RoleType.USER, RoleType.READER, RoleType.WRITER):
                local_decision = has_api_key_capability(
                    RoleType(local["role"]),
                    local["is_superuser"],
                    ApiKeyAccessMode(local["access_mode"]),
                    required_role,
                )
                remote_decision = has_api_key_capability(
                    RoleType(remote["role"]),
                    remote["is_superuser"],
                    ApiKeyAccessMode(remote["access_mode"]),
                    required_role,
                )
                assert local_decision is remote_decision


class TestAudienceAndCapabilityPolicyMatrix:
    """The fixture's policy table must match live SDK predicate evaluation."""

    def test_rows_reproduce_from_live_predicates(self, matrix: dict) -> None:
        for row in matrix["audience_and_capability_policy_matrix"]:
            if row["role"] is None:
                # The ceiling-denied admin/superadmin rows carry no
                # role/access_mode dimension — covered by the ceiling test below.
                continue
            allowed = has_api_key_capability(
                RoleType(row["role"]),
                RoleType(row["role"]) == RoleType.SUPERADMIN,
                ApiKeyAccessMode(row["access_mode"]),
                RoleType(row["required_role"]),
            )
            assert allowed is row["issuer_local_allowed"]
            assert row["remote_allowed"] == (allowed and row["has_audience"])

    def test_admin_and_superuser_rows_are_ceiling_denied(self, matrix: dict) -> None:
        rows = [
            row
            for row in matrix["audience_and_capability_policy_matrix"]
            if row["role"] is None
        ]
        assert len(rows) == 2
        for row in rows:
            assert row["capability_ceiling_error"] is True
            assert row["remote_allowed"] is False


class TestSchemaVersionContract:
    def test_sdk_floor_and_fixture_schema_version_agree(self, matrix: dict) -> None:
        from auth_sdk_m8.testing import FIXTURE_MATRIX_SCHEMA_VERSION

        assert matrix["schema_version"] == FIXTURE_MATRIX_SCHEMA_VERSION

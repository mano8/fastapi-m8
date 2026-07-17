"""Tests for fastapi_m8._route_audit.audit_api_key_routes (§3.3.1, APIKEY-CAP-01)."""

from __future__ import annotations

from fastapi import Depends, FastAPI
from starlette.routing import Route

from fastapi_m8._deps import build_auth_deps
from fastapi_m8._route_audit import BareApiKeyDependency, audit_api_key_routes
from tests.conftest import make_settings

AUDIENCE = "prompt-engine-m8"


def _api_key_auth():
    return build_auth_deps(
        make_settings(
            API_KEY_INTROSPECTION_ENABLED=True,
            INTERNAL_CLIENT_ID=AUDIENCE,
            PRIVATE_API_SECRET="supersecret",
            INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        )
    )


def test_capability_wired_route_is_not_flagged() -> None:
    """A route depending on the role-capped dependency passes clean."""
    auth = _api_key_auth()
    app = FastAPI()

    @app.get("/writer-thing")
    def route(principal=Depends(auth.get_current_api_key_writer)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app, bare_dependency=auth.get_current_api_key_principal
    )
    assert findings == []


def test_bare_dependency_route_is_flagged() -> None:
    """A route depending directly on the bare principal is a finding."""
    auth = _api_key_auth()
    app = FastAPI()

    @app.get("/bare-thing")
    def route(principal=Depends(auth.get_current_api_key_principal)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app, bare_dependency=auth.get_current_api_key_principal
    )
    assert findings == [
        BareApiKeyDependency(path="/bare-thing", methods=frozenset({"GET"}))
    ]


def test_jwt_routes_are_never_flagged() -> None:
    """Routes with no API-key dependency at all are untouched by the audit."""
    auth = _api_key_auth()
    app = FastAPI()

    @app.get("/jwt-thing")
    def route(user=Depends(auth.get_current_active_writer)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app, bare_dependency=auth.get_current_api_key_principal
    )
    assert findings == []


def test_reader_capability_route_is_not_flagged() -> None:
    """The reader specialization is also a capability dependency, not the bare one."""
    auth = _api_key_auth()
    app = FastAPI()

    @app.get("/reader-thing")
    def route(principal=Depends(auth.get_current_api_key_reader)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app, bare_dependency=auth.get_current_api_key_principal
    )
    assert findings == []


def test_exempt_path_is_never_flagged() -> None:
    """An explicitly exempted route (e.g. a read-only /verify) is excluded."""
    auth = _api_key_auth()
    app = FastAPI()

    @app.get("/verify")
    def route(principal=Depends(auth.get_current_api_key_principal)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app,
        bare_dependency=auth.get_current_api_key_principal,
        exempt_paths=["/verify"],
    )
    assert findings == []


def test_multiple_offending_routes_are_all_reported() -> None:
    """The audit is exhaustive, not first-match."""
    auth = _api_key_auth()
    app = FastAPI()

    @app.get("/bare-one")
    def route_one(principal=Depends(auth.get_current_api_key_principal)) -> dict:  # noqa: ANN001
        return {}

    @app.post("/bare-two")
    def route_two(principal=Depends(auth.get_current_api_key_principal)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app, bare_dependency=auth.get_current_api_key_principal
    )
    assert {f.path for f in findings} == {"/bare-one", "/bare-two"}


def test_a_different_services_bare_dependency_is_never_confused_with_this_ones() -> (
    None
):
    """Matching is by identity: another AuthDeps' bare dependency never matches."""
    auth_a = _api_key_auth()
    auth_b = _api_key_auth()
    app = FastAPI()

    @app.get("/bare-thing")
    def route(principal=Depends(auth_a.get_current_api_key_principal)) -> dict:  # noqa: ANN001
        return {}

    findings = audit_api_key_routes(
        app, bare_dependency=auth_b.get_current_api_key_principal
    )
    assert findings == []


def test_non_api_route_entries_are_skipped_without_error() -> None:
    """A plain Starlette Route (no dependant) does not crash the walk."""
    auth = _api_key_auth()
    app = FastAPI()
    app.router.routes.append(Route("/plain", lambda request: None))

    findings = audit_api_key_routes(
        app, bare_dependency=auth.get_current_api_key_principal
    )
    assert findings == []

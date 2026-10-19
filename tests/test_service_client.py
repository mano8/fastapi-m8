"""Tests for fastapi_m8._service_client — the service-client route guard."""

from __future__ import annotations

import logging

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import fastapi_m8
from fastapi_m8 import (
    INTERNAL_CLIENT_HEADER,
    INTERNAL_TOKEN_HEADER,
    ConsumerCredential,
    ConsumerCredentialRegistry,
    build_service_client_guard,
)

_SECRET = "s3cret-canary-" + "a" * 50  # noqa: S105 - test fixture
_WRONG = "wrong-canary-" + "b" * 50


def _registry() -> ConsumerCredentialRegistry:
    return ConsumerCredentialRegistry(
        [
            ConsumerCredential.create(
                "media-worker", _SECRET, ("execute:ocr", "job-context:issue")
            ),
            ConsumerCredential.create("media-service", _SECRET, ("execute:embedding",)),
        ]
    )


def _client(*scopes: str) -> TestClient:
    app = FastAPI()
    guard = build_service_client_guard(_registry(), required_scopes=scopes)

    @app.post("/execute")
    def route(client_id: str = Depends(guard)) -> dict[str, str]:
        return {"client_id": client_id}

    return TestClient(app)


def _headers(client: str | None, token: str | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if client is not None:
        headers[INTERNAL_CLIENT_HEADER] = client
    if token is not None:
        headers[INTERNAL_TOKEN_HEADER] = token
    return headers


# ── outcomes ──────────────────────────────────────────────────────────────────


def test_success_returns_the_authenticated_client_id() -> None:
    response = _client("execute:ocr").post(
        "/execute", headers=_headers("media-worker", _SECRET)
    )
    assert response.status_code == 200
    assert response.json() == {"client_id": "media-worker"}


@pytest.mark.parametrize(
    ("client", "token"),
    [
        (None, None),
        ("media-worker", None),
        (None, _SECRET),
        ("media-worker", ""),
        ("", _SECRET),
    ],
    ids=["no-headers", "no-token", "no-client", "empty-token", "empty-client"],
)
def test_missing_credentials_are_401(client: str | None, token: str | None) -> None:
    response = _client("execute:ocr").post("/execute", headers=_headers(client, token))
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthorized"}


def test_unknown_client_is_401() -> None:
    response = _client("execute:ocr").post(
        "/execute", headers=_headers("intruder", _SECRET)
    )
    assert response.status_code == 401


def test_wrong_secret_is_401() -> None:
    response = _client("execute:ocr").post(
        "/execute", headers=_headers("media-worker", _WRONG)
    )
    assert response.status_code == 401


def test_unknown_client_and_wrong_secret_are_indistinguishable() -> None:
    client = _client("execute:ocr")
    unknown = client.post("/execute", headers=_headers("intruder", _WRONG))
    wrong = client.post("/execute", headers=_headers("media-worker", _WRONG))
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.content == wrong.content
    assert dict(unknown.headers) == dict(wrong.headers)


def test_authenticated_client_without_the_scope_is_403() -> None:
    response = _client("execute:ocr").post(
        "/execute", headers=_headers("media-service", _SECRET)
    )
    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}


def test_every_required_scope_must_be_held() -> None:
    both = _client("execute:ocr", "job-context:issue")
    assert (
        both.post("/execute", headers=_headers("media-worker", _SECRET)).status_code
        == 200
    )
    one_missing = _client("execute:ocr", "execute:rerank")
    assert (
        one_missing.post(
            "/execute", headers=_headers("media-worker", _SECRET)
        ).status_code
        == 403
    )


def test_wrong_secret_with_a_missing_scope_is_still_401() -> None:
    """Authentication is decided before authorization: no scope oracle."""
    response = _client("execute:rerank").post(
        "/execute", headers=_headers("media-service", _WRONG)
    )
    assert response.status_code == 401


# ── constant-time comparison in both failure branches ────────────────────────


def test_unknown_client_and_wrong_secret_both_run_a_digest_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry's dummy credential answers an unknown id, so both run one."""
    calls: list[str] = []
    original = ConsumerCredential.verify_secret

    def spy(self: ConsumerCredential, provided: str | None) -> bool:
        calls.append(self.client_id)
        return original(self, provided)

    monkeypatch.setattr(ConsumerCredential, "verify_secret", spy)
    client = _client("execute:ocr")

    client.post("/execute", headers=_headers("intruder", _WRONG))
    assert calls == ["\x00dummy"]

    calls.clear()
    client.post("/execute", headers=_headers("media-worker", _WRONG))
    assert calls == ["media-worker"]


# ── the token never leaks ─────────────────────────────────────────────────────


def test_the_token_is_never_logged_or_echoed(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    client = _client("execute:rerank")
    responses = [
        client.post("/execute", headers=_headers("media-worker", _WRONG)),
        client.post("/execute", headers=_headers("intruder", _SECRET)),
        client.post("/execute", headers=_headers("media-worker", _SECRET)),
    ]
    for response in responses:
        assert _SECRET not in response.text
        assert _WRONG not in response.text
    assert _SECRET not in caplog.text
    assert _WRONG not in caplog.text


# ── construction refusals ─────────────────────────────────────────────────────


def test_a_bare_string_scope_is_refused() -> None:
    with pytest.raises(TypeError, match="not a str"):
        build_service_client_guard(_registry(), required_scopes="execute:ocr")


def test_an_empty_scope_set_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one scope"):
        build_service_client_guard(_registry(), required_scopes=())


@pytest.mark.parametrize("bad", ["", 7])
def test_an_empty_or_non_string_scope_is_refused(bad: object) -> None:
    with pytest.raises(ValueError, match="non-empty string"):
        build_service_client_guard(
            _registry(),
            required_scopes=("execute:ocr", bad),  # type: ignore[arg-type]
        )


def test_the_guard_is_reexported_from_the_package() -> None:
    assert fastapi_m8.build_service_client_guard is build_service_client_guard
    assert "build_service_client_guard" in fastapi_m8.__all__

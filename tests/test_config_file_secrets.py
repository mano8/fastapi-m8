"""Regression tests for the inherited ``*_FILE`` secret mechanism (6.1).

``fastapi-m8`` consumers do **not** re-implement secret sourcing — they inherit
``settings_customise_sources`` (and therefore the Docker/K8s ``<FIELD>_FILE``
convention) from ``auth_sdk_m8.core.config.CommonSettings``. The production
overlay relies on this so secrets can be mounted under ``/run/secrets/*`` instead
of being inlined as plaintext env values.

These tests lock that inheritance in place *at the consumer layer*: a future MRO
change, field rename, or accidental override of ``settings_customise_sources``
on ``ConsumerServiceSettings`` would break secret-file mounting silently, and
this suite is what catches it. They prove the ``_FILE`` source covers fields from
all three origins in the MRO:

* consumer-declared — ``METRICS_SCRAPE_CREDENTIAL`` (fastapi-m8 ``config.py``),
* ``ConsumerAuthMixin`` — ``PRIVATE_API_SECRET``,
* ``CommonSettings`` — ``DB_PASSWORD``.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr

from tests.conftest import BASE_KWARGS, IsolatedConsumerSettings, make_settings


def _make_without(*omit: str, **overrides: object) -> IsolatedConsumerSettings:
    """Build settings from ``BASE_KWARGS`` with *omit* fields left unset.

    Init kwargs outrank the ``_FILE`` source, so any field whose file mount is
    under test must be absent from the constructor for the source to win.
    """
    kwargs = {k: v for k, v in BASE_KWARGS.items() if k not in omit}
    return IsolatedConsumerSettings(**{**kwargs, **overrides})


def test_consumer_declared_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """A consumer-declared secret reads its ``<FIELD>_FILE`` mount."""
    secret = tmp_path / "scrape_credential"  # type: ignore[operator]
    secret.write_text("scrape-from-file\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = make_settings()

    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert s.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == "scrape-from-file"


def test_consumer_auth_mixin_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """A ``ConsumerAuthMixin`` secret (``PRIVATE_API_SECRET``) reads its mount."""
    secret = tmp_path / "private_api_secret"  # type: ignore[operator]
    secret.write_text("internal-token-from-file\n", encoding="utf-8")
    monkeypatch.setenv("PRIVATE_API_SECRET_FILE", str(secret))

    s = make_settings()

    assert s.PRIVATE_API_SECRET is not None
    assert s.PRIVATE_API_SECRET.get_secret_value() == "internal-token-from-file"


def test_common_settings_secret_sourced_from_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """A ``CommonSettings`` secret (``DB_PASSWORD``) reads its mount."""
    secret = tmp_path / "db_password"  # type: ignore[operator]
    secret.write_text("ValidPass1!\n", encoding="utf-8")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(secret))

    s = _make_without("DB_PASSWORD")

    assert s.DB_PASSWORD is not None
    assert s.DB_PASSWORD.get_secret_value() == "ValidPass1!"


def test_file_mount_overrides_plaintext_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """``<FIELD>_FILE`` outranks a plaintext env value for the same field."""
    secret = tmp_path / "scrape_credential"  # type: ignore[operator]
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL", "from-plain-env")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = make_settings()

    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert s.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == "from-file"


def test_init_kwarg_outranks_file_mount(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """Explicit constructor kwargs still win over a ``<FIELD>_FILE`` mount."""
    secret = tmp_path / "scrape_credential"  # type: ignore[operator]
    secret.write_text("from-file\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = make_settings(METRICS_SCRAPE_CREDENTIAL=SecretStr("from-init"))

    assert s.METRICS_SCRAPE_CREDENTIAL is not None
    assert s.METRICS_SCRAPE_CREDENTIAL.get_secret_value() == "from-init"


def test_missing_secret_file_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """Pointing ``<FIELD>_FILE`` at an absent file fails closed at construction."""
    monkeypatch.setenv(
        "METRICS_SCRAPE_CREDENTIAL_FILE",
        str(tmp_path / "absent"),  # type: ignore[operator]
    )

    with pytest.raises(
        ValueError, match="METRICS_SCRAPE_CREDENTIAL_FILE points to a missing file"
    ):
        make_settings()


def test_file_sourced_secret_is_masked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: object
) -> None:
    """A file-sourced ``SecretStr`` is never rendered in ``repr``."""
    secret = tmp_path / "scrape_credential"  # type: ignore[operator]
    secret.write_text("super-sensitive\n", encoding="utf-8")
    monkeypatch.setenv("METRICS_SCRAPE_CREDENTIAL_FILE", str(secret))

    s = make_settings()

    assert "super-sensitive" not in repr(s)
    assert "super-sensitive" not in str(s.METRICS_SCRAPE_CREDENTIAL)

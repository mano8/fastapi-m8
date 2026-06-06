"""Tests for fastapi_m8.config.ConsumerServiceSettings."""

import pytest
from pydantic import SecretStr, ValidationError

from tests.conftest import make_settings


def test_consumer_service_settings_defaults() -> None:
    s = make_settings()
    assert s.AUTH_PREFIX == "/auth"
    assert s.TABLES_PREFIX == "app"
    assert s.METRICS_ENABLED is False
    assert s.INTROSPECTION_URL is None
    assert s.PRIVATE_API_SECRET is None


def test_consumer_service_settings_stateful_valid() -> None:
    s = make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        PRIVATE_API_SECRET=SecretStr("secret"),
    )
    assert s.is_stateful is True
    assert s.INTROSPECTION_URL is not None


def test_consumer_service_settings_stateful_missing_raises() -> None:
    with pytest.raises(ValidationError, match="INTROSPECTION_URL"):
        make_settings(TOKEN_MODE="stateful")


def test_allowed_origins_never_wildcard_with_credentials() -> None:
    """ALLOWED_ORIGINS should never be ['*'] when auth credentials are in use."""
    s = make_settings()
    assert "*" not in s.ALLOWED_ORIGINS


def test_consumer_service_settings_mro() -> None:
    """MRO provides all expected inherited fields."""
    s = make_settings()
    assert hasattr(s, "METRICS_ENABLED")  # ObservabilitySettingsMixin
    assert hasattr(s, "INTROSPECTION_URL")  # ConsumerAuthMixin
    assert hasattr(s, "is_stateful")  # CommonSettings
    assert hasattr(s, "SQLALCHEMY_DATABASE_URI")  # CommonSettings


def test_allowed_hosts_parsed_from_string() -> None:
    """ALLOWED_HOSTS accepts a comma-separated string (env-var form)."""
    s = make_settings(ALLOWED_HOSTS="api.example.com, localhost")
    assert s.ALLOWED_HOSTS == ["api.example.com", "localhost"]


def test_allowed_hosts_empty_by_default() -> None:
    """ALLOWED_HOSTS defaults to an empty list (middleware not registered)."""
    s = make_settings()
    assert s.ALLOWED_HOSTS == []

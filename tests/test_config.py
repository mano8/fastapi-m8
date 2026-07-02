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
    """ALLOWED_HOSTS defaults to None (inherited from CommonSettings; unset)."""
    s = make_settings()
    assert s.ALLOWED_HOSTS is None


def test_event_stream_timeouts_default() -> None:
    """Auth event-stream timeouts have library-aligned defaults."""
    s = make_settings()
    assert s.EVENT_STREAM_CONNECT_TIMEOUT == 5.0
    assert s.EVENT_STREAM_READ_TIMEOUT == 60.0


def test_event_stream_timeouts_overridable() -> None:
    """EVENT_STREAM_* timeouts accept in-range overrides."""
    s = make_settings(
        EVENT_STREAM_CONNECT_TIMEOUT=3.0,
        EVENT_STREAM_READ_TIMEOUT=120.0,
    )
    assert s.EVENT_STREAM_CONNECT_TIMEOUT == 3.0
    assert s.EVENT_STREAM_READ_TIMEOUT == 120.0


def test_event_stream_connect_timeout_rejects_non_positive() -> None:
    """A non-positive connect timeout fails validation (gt=0)."""
    with pytest.raises(ValidationError, match="EVENT_STREAM_CONNECT_TIMEOUT"):
        make_settings(EVENT_STREAM_CONNECT_TIMEOUT=0)


def test_event_stream_read_timeout_rejects_out_of_range() -> None:
    """A read timeout above the ceiling fails validation (le=3600)."""
    with pytest.raises(ValidationError, match="EVENT_STREAM_READ_TIMEOUT"):
        make_settings(EVENT_STREAM_READ_TIMEOUT=99999)


# ── Per-consumer private-auth validation (item 11.2b) ─────────────────────────

_INTROSPECTION = "http://auth:8000/user/private/v1/jti-status"


@pytest.mark.parametrize(
    "prod_overrides",
    [
        {"ENVIRONMENT": "production"},
        {"STRICT_PRODUCTION_MODE": True},
    ],
)
def test_production_introspection_without_client_id_raises(
    prod_overrides: dict,
) -> None:
    """Prod/strict + INTROSPECTION_URL + no INTERNAL_CLIENT_ID is fatal (item 11.2b)."""
    with pytest.raises(ValidationError, match="INTERNAL_CLIENT_ID"):
        make_settings(
            INTROSPECTION_URL=_INTROSPECTION,
            PRIVATE_API_SECRET=SecretStr("bootstrap-secret"),
            **prod_overrides,
        )


def test_production_introspection_with_client_id_ok() -> None:
    """Prod + INTROSPECTION_URL + per-consumer identity is accepted."""
    s = make_settings(
        ENVIRONMENT="production",
        INTROSPECTION_URL=_INTROSPECTION,
        INTERNAL_CLIENT_ID="test-svc",
        PRIVATE_API_SECRET=SecretStr("bootstrap-secret"),
    )
    assert s.INTERNAL_CLIENT_ID == "test-svc"


def test_local_legacy_mode_allowed() -> None:
    """Development (local) legacy token-only mode remains valid (item 11.2b)."""
    s = make_settings(
        ENVIRONMENT="local",
        INTROSPECTION_URL=_INTROSPECTION,
        PRIVATE_API_SECRET=SecretStr("shared-secret"),
    )
    assert s.INTERNAL_CLIENT_ID is None


def test_production_without_introspection_allowed() -> None:
    """A prod consumer with no private calls at all is unaffected by 11.2b."""
    s = make_settings(ENVIRONMENT="production")
    assert s.INTROSPECTION_URL is None
    assert s.INTERNAL_CLIENT_ID is None


def test_service_token_exchange_without_client_id_raises() -> None:
    """Coherent-group: exchange has no identity to present without a client id."""
    with pytest.raises(ValidationError, match="SERVICE_TOKEN_EXCHANGE_ENABLED"):
        make_settings(
            INTROSPECTION_URL=_INTROSPECTION,
            PRIVATE_API_SECRET=SecretStr("bootstrap-secret"),
            SERVICE_TOKEN_EXCHANGE_ENABLED=True,
        )


def test_client_id_without_private_secret_raises() -> None:
    """Coherent-group: per-consumer mode needs this consumer's bootstrap secret."""
    with pytest.raises(ValidationError, match="PRIVATE_API_SECRET"):
        make_settings(INTERNAL_CLIENT_ID="test-svc")


def test_private_auth_validation_error_hides_secret() -> None:
    """The fatal 11.2b message must not echo the bootstrap secret value."""
    secret = "super-secret-bootstrap-value"
    with pytest.raises(ValidationError) as exc:
        make_settings(
            ENVIRONMENT="production",
            INTROSPECTION_URL=_INTROSPECTION,
            PRIVATE_API_SECRET=SecretStr(secret),
        )
    assert secret not in str(exc.value)

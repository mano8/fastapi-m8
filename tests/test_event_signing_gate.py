"""7.x.1 (consumer side) — event-signing rollout flags gate a consumer at boot.

``create_app`` auto-runs the shared ``check_config_health`` in its lifespan, so a
fastapi-m8 consumer inherits the event-signing gate with no extra wiring. These
tests assert the strict gate fires for a *consumer* settings instance: the gate
logs the offending flag at CRITICAL and ``check_config_health`` raises.
"""

import logging

import pytest
from auth_sdk_m8.core.config import check_config_health
from auth_sdk_m8.core.exceptions import ConfigurationError

from tests.conftest import make_settings

_LOGGER = logging.getLogger("tests.event_signing_gate")


def _strict(**overrides):
    """Consumer settings under production + STRICT_PRODUCTION_MODE."""
    return make_settings(
        ENVIRONMENT="production", STRICT_PRODUCTION_MODE=True, **overrides
    )


def test_event_signing_disabled_is_fatal_under_strict(caplog) -> None:
    """EVENT_SIGNING_ENABLED=false under strict → fatal gate fires for a consumer."""
    settings = _strict(EVENT_SIGNING_ENABLED=False)
    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(ConfigurationError):
            check_config_health(settings, _LOGGER)
    assert "EVENT_SIGNING_ENABLED=false" in caplog.text


def test_accept_unsigned_is_fatal_under_strict(caplog) -> None:
    """EVENT_SIGNING_ACCEPT_UNSIGNED=true under strict → fatal gate fires."""
    settings = _strict(EVENT_SIGNING_ACCEPT_UNSIGNED=True)
    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(ConfigurationError):
            check_config_health(settings, _LOGGER)
    assert "EVENT_SIGNING_ACCEPT_UNSIGNED=true" in caplog.text


def test_secure_event_signing_defaults_pass_the_gate(caplog) -> None:
    """Signing on + unsigned rejected (defaults) → no event-signing complaint."""
    # Local, secure-by-default consumer config boots cleanly.
    with caplog.at_level(logging.WARNING):
        check_config_health(make_settings(), _LOGGER)
    assert "EVENT_SIGNING" not in caplog.text

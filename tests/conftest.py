"""Shared fixtures for fastapi-m8 tests."""

import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from fastapi_m8.config import ConsumerServiceSettings

VALID_KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
VALID_PASSWORD = "ValidPass1!"

BASE_KWARGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/api",
    "PROJECT_NAME": "test-service",
    "STACK_NAME": "test-stack",
    "BACKEND_HOST": "http://localhost:8000",
    "FRONTEND_HOST": "http://localhost:3000",
    "BACKEND_CORS_ORIGINS": "http://localhost:3000",
    "SECRET_KEY": VALID_KEY,
    "ACCESS_SECRET_KEY": VALID_KEY,
    "REFRESH_SECRET_KEY": VALID_KEY,
    "DB_HOST": "localhost",
    "DB_PORT": 3306,
    "DB_DATABASE": "testdb",
    "DB_USER": "testuser",
    "DB_PASSWORD": VALID_PASSWORD,
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_USER": "redisuser",
    "REDIS_PASSWORD": VALID_PASSWORD,
    "AUTH_SERVICE_ROLE": "consumer",
    "TOKEN_MODE": "stateless",
    "AUTH_PREFIX": "/auth",
}


class IsolatedConsumerSettings(ConsumerServiceSettings):
    """ConsumerServiceSettings that reads ONLY from constructor kwargs."""

    model_config = SettingsConfigDict(env_file=None)

    def placeholder(self) -> None:
        """Satisfy pylint public-methods requirement for test subclass."""


def make_settings(**overrides: object) -> IsolatedConsumerSettings:
    """Return a settings instance with overrides applied."""
    return IsolatedConsumerSettings(**{**BASE_KWARGS, **overrides})


@pytest.fixture
def settings() -> IsolatedConsumerSettings:
    """Provide a default stateless consumer settings instance."""
    return make_settings()


@pytest.fixture
def stateful_settings() -> IsolatedConsumerSettings:
    """Provide a stateful consumer settings instance with revocation config."""
    return make_settings(
        TOKEN_MODE="stateful",
        INTROSPECTION_URL="http://auth:8000/user/private/v1/jti-status",
        PRIVATE_API_SECRET=SecretStr("supersecret"),
    )

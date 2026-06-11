"""Shared fixtures for fastapi-m8 tests.

The default settings model the auth-sdk-m8 ``>=1.0.0`` *secure-by-default*
posture: RS256 access tokens, strict ``iss``/``aud`` binding, and HMAC-signed
event bus.  Test tokens are therefore signed with an in-process RSA key whose
public half is fed to the settings via ``ACCESS_PUBLIC_KEY_FILE``.
"""

from __future__ import annotations

import atexit
import json
import os
import tempfile
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from fastapi_m8.config import ConsumerServiceSettings

# A strong test key outside auth-sdk-m8's forbidden dev-placeholder set
# (the old "Abcdef-1234…" literal is now rejected in production by the SA.3
# guard shipped in auth-sdk-m8 1.2.0). Satisfies SECRET_KEY_REGEX.
VALID_KEY = "Fastapi-M8-Test_Key-2026_xyz-abc-9!"
VALID_PASSWORD = "ValidPass1!"

# Secure-by-default token binding — both services must agree on these values.
TOKEN_ISSUER = "https://auth.test"
TOKEN_AUDIENCE = "test-service"
KEY_ID = "test-kid"

# ── RS256 signing material (in-process) ────────────────────────────────────────
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()

_PRIVATE_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode()
_PUBLIC_PEM = _PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

# The SDK loads RSA key material only from a file path (ACCESS_PUBLIC_KEY_FILE),
# so persist the public key for the test session and clean it up on exit.
_pub_fd, PUBLIC_KEY_FILE = tempfile.mkstemp(suffix="_access_public.pem")
with os.fdopen(_pub_fd, "w") as _fh:
    _fh.write(_PUBLIC_PEM)


def _cleanup_public_key_file() -> None:
    """Remove the session's temporary public-key file on interpreter exit."""
    if os.path.exists(PUBLIC_KEY_FILE):
        os.remove(PUBLIC_KEY_FILE)


atexit.register(_cleanup_public_key_file)


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
    # Secure-by-default (auth-sdk-m8>=1.0.0): RS256 + strict iss/aud + signed events.
    "ACCESS_PUBLIC_KEY_FILE": PUBLIC_KEY_FILE,
    "TOKEN_ISSUER": TOKEN_ISSUER,
    "TOKEN_AUDIENCE": TOKEN_AUDIENCE,
    "EVENT_SIGNING_KEY": VALID_KEY,
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

_VALID_UUID = "550e8400-e29b-41d4-a716-446655440000"


def make_access_token(
    *,
    issuer: str = TOKEN_ISSUER,
    audience: str = TOKEN_AUDIENCE,
    kid: str | None = KEY_ID,
    **extra: Any,
) -> str:
    """Sign an RS256 access token bound to *issuer*/*audience*.

    Includes the full strict-profile claim set (``iat``/``nbf`` alongside
    ``exp``/``sub``/``jti``/``type``).  Pass ``extra`` to override any claim or
    add user fields; pass a different *issuer*/*audience*/*kid* to exercise the
    rejection paths.
    """
    now = datetime.now(UTC)
    payload = {
        "sub": _VALID_UUID,
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "jti-0001",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "iss": issuer,
        "aud": audience,
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
        **extra,
    }
    headers = {"kid": kid} if kid is not None else None
    return jwt.encode(payload, _PRIVATE_PEM, algorithm="RS256", headers=headers)


def jwks_document(kid: str = KEY_ID) -> dict:
    """Return a JWKS document publishing the test public key under *kid*."""
    jwk = json.loads(RSAAlgorithm.to_jwk(_PUBLIC_KEY))
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


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

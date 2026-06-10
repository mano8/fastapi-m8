"""
ConsumerServiceSettings — base settings for any fastapi-m8 consumer service.

Combines ``ObservabilitySettingsMixin``, ``ConsumerAuthMixin``, and
``CommonSettings`` in the same MRO order as the original template.

Example::

    from pathlib import Path
    from pydantic_settings import SettingsConfigDict
    from fastapi_m8 import ConsumerServiceSettings
    from auth_sdk_m8.utils.paths import find_dotenv

    class Settings(ConsumerServiceSettings):
        ENV_FILE_DIR = Path(__file__).resolve().parent
        model_config = SettingsConfigDict(
            env_file=find_dotenv(ENV_FILE_DIR),
            env_file_encoding="utf-8",
        )
"""

from auth_sdk_m8.core.config import CommonSettings
from auth_sdk_m8.core.consumer import ConsumerAuthMixin
from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin
from pydantic import field_validator


class ConsumerServiceSettings(
    ObservabilitySettingsMixin, ConsumerAuthMixin, CommonSettings
):
    """
    Base settings for a consumer FastAPI microservice.

    Inherits ``METRICS_ENABLED`` and ``METRICS_GROUPS`` from
    ``ObservabilitySettingsMixin``, ``INTROSPECTION_URL`` and
    ``PRIVATE_API_SECRET`` from ``ConsumerAuthMixin``, and all common
    fields (``SECRET_KEY``, ``TOKEN_MODE``, ``ALLOWED_ORIGINS``,
    ``SQLALCHEMY_DATABASE_URI``, ``API_PREFIX``, …) from ``CommonSettings``.
    """

    AUTH_PREFIX: str = "/auth"
    TABLES_PREFIX: str = "app"
    # Explicit host allowlist for TrustedHostMiddleware.
    # Empty (default) = middleware not registered (permissive, safe for dev).
    # In production set to your public hostname(s), e.g. "api.example.com".
    ALLOWED_HOSTS: list[str] = []

    # ── Response security headers (production/staging only) ───────────────────
    # The hardening header layer (HSTS + CSP + Referrer/Permissions policy) is
    # applied ONLY when ENVIRONMENT=="production" or STRICT_PRODUCTION_MODE — the
    # same gate as docs hiding and TrustedHostMiddleware. Local/dev stays
    # unrestricted so Swagger/ReDoc and tooling keep working. Set
    # SECURITY_HEADERS_ENABLED=false to opt out even in production.
    SECURITY_HEADERS_ENABLED: bool = True
    # HSTS max-age in seconds (0 disables the Strict-Transport-Security header).
    # Browsers ignore HSTS over plain HTTP, so emitting it behind a TLS-
    # terminating proxy is safe; set to 0 if TLS is not terminated upstream.
    HSTS_MAX_AGE: int = 31536000  # 1 year
    HSTS_INCLUDE_SUBDOMAINS: bool = True
    # Content-Security-Policy value. None → a tight default suitable for a JSON
    # API (`default-src 'none'; frame-ancestors 'none'; base-uri 'none';
    # form-action 'none'`). Override for services that serve HTML in production.
    CONTENT_SECURITY_POLICY: str | None = None
    REFERRER_POLICY: str = "strict-origin-when-cross-origin"
    PERMISSIONS_POLICY: str = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def _parse_allowed_hosts(cls, v: object) -> list[str]:
        """Accept a comma-separated string or list from the environment."""
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return list(v) if v else []  # type: ignore[call-overload]

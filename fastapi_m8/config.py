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

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def _parse_allowed_hosts(cls, v: object) -> list[str]:
        """Accept a comma-separated string or list from the environment."""
        if isinstance(v, str):
            return [h.strip() for h in v.split(",") if h.strip()]
        return list(v) if v else []  # type: ignore[call-overload]

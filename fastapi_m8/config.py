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
from auth_sdk_m8.schemas.meta import ServiceContract, ServiceMeta
from pydantic import Field, SecretStr


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

    **Secret files (`_FILE` mounts).** the ``settings_customise_sources``
    classmethod is inherited from ``CommonSettings``, so every secret field —
    including consumer-declared
    ones like ``METRICS_SCRAPE_CREDENTIAL`` — can be sourced from a mounted file by
    setting ``<FIELD>_FILE`` (e.g. ``DB_PASSWORD_FILE``, ``PRIVATE_API_SECRET_FILE``,
    ``METRICS_SCRAPE_CREDENTIAL_FILE``) to a path under ``/run/secrets/*``. The file
    mount outranks plaintext ``.env``/env values but not explicit constructor
    kwargs, and a missing file fails closed at construction. This lets the
    production overlay keep plaintext secrets out of env files with no consumer
    code change (security remediation 6.1).
    """

    AUTH_PREFIX: str = "/auth"
    TABLES_PREFIX: str = "app"
    # ``ALLOWED_HOSTS`` (host allowlist for TrustedHostMiddleware) is owned by
    # ``CommonSettings`` (auth-sdk-m8) — the single source of truth. Unset/empty
    # (default ``None``) = middleware not registered (permissive, safe for dev);
    # in production set your public hostname(s), e.g. "api.example.com". Its
    # production/strict gating lives in ``check_config_health``.

    # Response security-header knobs (SECURITY_HEADERS_ENABLED, HSTS_ENABLED,
    # HSTS_MAX_AGE, HSTS_INCLUDE_SUBDOMAINS, CONTENT_SECURITY_POLICY_ENABLED,
    # CONTENT_SECURITY_POLICY, REFERRER_POLICY, PERMISSIONS_POLICY) are inherited
    # from CommonSettings; the hardening layer is wired by
    # auth_sdk_m8.security.headers.add_security_headers_middleware. HSTS/CSP are
    # express opt-in (HSTS_ENABLED / CONTENT_SECURITY_POLICY_ENABLED) and never
    # emitted on a local stack — see auth-sdk-m8 1.2.1.

    # Auth event stream (fa-auth SSE bridge) — client-side timeouts for the
    # optional AuthEventStreamClient built by build_event_stream_client.
    # EVENT_SIGNING_KEY (HMAC verification) is inherited from CommonSettings;
    # INTROSPECTION_URL / PRIVATE_API_SECRET come from ConsumerAuthMixin.
    EVENT_STREAM_CONNECT_TIMEOUT: float = Field(5.0, gt=0, le=300)
    EVENT_STREAM_READ_TIMEOUT: float = Field(60.0, gt=0, le=3600)
    # Short-TTL positive validation cache for JTI revocation checks.
    # 0 (default) = disabled; cache per-request HTTP calls to fa-auth are made.
    # Set to e.g. 30 to cache active=True results for 30 s; stream events evict
    # by JTI/user, an unresumable gap flushes all (requires event stream client).
    REVOCATION_CACHE_TTL_SECONDS: int = Field(0, ge=0)

    # ── Per-consumer internal-auth (9.1, consumer side) ──────────────────────
    # Identity this consumer presents on private calls to fa-auth. Unset
    # (default) keeps the legacy single-secret mode: PRIVATE_API_SECRET is sent
    # as X-Internal-Token, matching the issuer's legacy fallback when it has no
    # PRIVATE_API_CONSUMERS registry. Set to this service's registered consumer
    # id to switch to the per-consumer model — PRIVATE_API_SECRET then carries
    # *this consumer's* bootstrap secret, and the issuer gates each private route
    # by the credential's granted scope (deny-by-default).
    INTERNAL_CLIENT_ID: str | None = Field(
        None,
        description=(
            "This consumer's X-Internal-Client id for per-consumer private auth. "
            "Unset = legacy single shared PRIVATE_API_SECRET mode."
        ),
    )
    # When INTERNAL_CLIENT_ID is set, opt into exchanging the bootstrap
    # credential for a short-TTL scoped service token (OAuth client-credentials
    # style) at {issuer}/private/v1/service-token, presented as
    # ``Authorization: Bearer``. Rotation comes for free from the short TTL.
    # False (default) sends the bootstrap X-Internal-Client/X-Internal-Token
    # pair directly on every private call.
    SERVICE_TOKEN_EXCHANGE_ENABLED: bool = Field(
        False,
        description=(
            "Exchange the bootstrap credential for short-TTL Bearer service "
            "tokens (requires INTERNAL_CLIENT_ID)."
        ),
    )
    # Scopes requested when exchanging for a service token; the issuer narrows to
    # the subset the bootstrap credential was granted. Empty/unset defaults to
    # ["introspection"] — the only private call fastapi-m8 makes today.
    SERVICE_TOKEN_SCOPES: list[str] | None = Field(
        None, description="Scopes to request when minting a service token."
    )
    # Refresh a cached service token this many seconds before its exp so a call
    # never races expiry.
    SERVICE_TOKEN_REFRESH_LEEWAY_SECONDS: int = Field(
        30, ge=0, description="Seconds before exp to refresh a service token."
    )

    # Metrics scrape credential for the ``/metrics`` endpoint (auth-sdk-m8 guard 1.4).
    # Unset (default) = network-isolation only; ``/metrics`` answers without auth.
    # Set to a long-lived static secret and configure Prometheus
    # ``scrape_configs.authorization.credentials`` to match — guards are
    # constant-time via ``auth_sdk_m8.security.guards.make_scrape_credential_guard``.
    METRICS_SCRAPE_CREDENTIAL: SecretStr | None = Field(
        None,
        description=(
            "Optional static bearer credential for the /metrics scrape endpoint. "
            "When set, requests must present Authorization: Bearer <value>. "
            "When unset, /metrics relies on network isolation only."
        ),
    )

    # Service/contract metadata served at ``{API_PREFIX}/meta`` (see
    # auth_sdk_m8.controllers.meta). These are **required** so every consumer
    # fails closed at boot if it doesn't declare its identity — clients read
    # /meta pre-auth to assert compatibility. ``/ping`` carries no values.
    SERVICE_VERSION: str = Field(
        ..., description="Service package version, e.g. '1.0.0'."
    )
    API_VERSION: str = Field("v1", description="Public API version, e.g. 'v1'.")
    CONTRACT_NAME: str | None = Field(
        None, description="Contract name; defaults to PROJECT_NAME when unset."
    )
    CONTRACT_VERSION: str = Field(..., description="Contract version, e.g. '1.0'.")
    CONTRACT_RANGE: str = Field(
        ..., description="Compatible contract semver range, e.g. '>=1.0.0 <2.0.0'."
    )

    def build_service_meta(self) -> ServiceMeta:
        """
        Build the public ``ServiceMeta`` served at ``{API_PREFIX}/meta``.

        Fails closed: the required version/contract settings must be present and
        non-empty (``ServiceMeta`` enforces ``min_length=1``) or this raises
        before the app serves traffic.
        """
        return ServiceMeta(
            service=self.PROJECT_NAME,
            version=self.SERVICE_VERSION,
            api_version=self.API_VERSION,
            contract=ServiceContract(
                name=self.CONTRACT_NAME or self.PROJECT_NAME,
                version=self.CONTRACT_VERSION,
                range=self.CONTRACT_RANGE,
            ),
        )

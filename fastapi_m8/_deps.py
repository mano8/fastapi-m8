"""
Auth dependency builder for fastapi-m8 services.

Call ``build_auth_deps(settings)`` **once** per service in ``core/deps.py``
and share the resulting ``AuthDeps`` instance everywhere.  A second call
builds a second validator and revocation client — there is no implicit cache.
"""

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any

from auth_sdk_m8 import has_minimum_role, has_superuser_privileges
from auth_sdk_m8.authorization import validate_api_key_required_role
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.events import AuthStreamEvent
from auth_sdk_m8.schemas.api_key import ApiKeyPrincipal
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import ValidationHooks, build_access_validator
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from pydantic import SecretStr

from fastapi_m8._api_key import (
    ApiKeyIntrospectionClient,
    ApiKeyIntrospectionError,
    ApiKeyQuotaExceededError,
)
from fastapi_m8._compat import _assert_compat
from fastapi_m8._internal_auth import build_internal_auth, describe_internal_auth_mode
from fastapi_m8._revocation import RemoteRevocationClient, RevocationCheckError

if TYPE_CHECKING:
    from fastapi_m8.config import ConsumerServiceSettings

_logger = logging.getLogger(__name__)

_UNAUTHORIZED = status.HTTP_401_UNAUTHORIZED
_FORBIDDEN = status.HTTP_403_FORBIDDEN
_TOO_MANY_REQUESTS = status.HTTP_429_TOO_MANY_REQUESTS
_UNAVAILABLE = status.HTTP_503_SERVICE_UNAVAILABLE
_NO_PRIVILEGES = "The user doesn't have enough privileges"

#: The one client-facing response for every unusable API key. Unknown, revoked,
#: expired, and every owner-state cause share it, so a caller cannot probe
#: another account's state by reading the denial.
_INVALID_API_KEY = "Invalid or expired API key"

#: Header an external client presents its user API key on — the same header the
#: issuer already reads, so a key works identically at either end.
API_KEY_HEADER = "X-API-Key"

#: Canonical stream event types this consumer acts on, dot-spelled as the SDK
#: payload writes them.
_SESSION_REVOKED = "session.revoked"
_USER_DELETED = "user.deleted"


def _validate_access_token(validator: Any, token: str) -> Any:
    try:
        return validator.validate_access_token(token)
    except InvalidToken as ex:
        raise HTTPException(
            status_code=_FORBIDDEN,
            detail="Could not validate credentials.",
        ) from ex


async def _check_token_revocation(
    revocation_client: RemoteRevocationClient | None, jti: str, user_id: str
) -> None:
    if revocation_client is None:
        return
    try:
        if await revocation_client.is_revoked(jti, user_id=user_id):
            raise HTTPException(
                status_code=_FORBIDDEN,
                detail="Token has been revoked.",
            )
    except RevocationCheckError as ex:
        _logger.warning("security.revocation_denied reason=unverifiable error=%s", ex)
        raise HTTPException(
            status_code=_UNAVAILABLE,
            detail="Token revocation check unavailable.",
        ) from ex


def _build_active_user(payload: Any) -> UserModel:
    payload_dict = payload.model_dump(exclude={"exp", "jti", "type", "sub"})
    payload_dict["id"] = payload.sub
    user = UserModel(**payload_dict)
    if not user.is_active:
        raise HTTPException(status_code=_FORBIDDEN, detail="Inactive user")
    return user


def _require_role(current_user: UserModel, role_limit: RoleType) -> None:
    # Role hierarchy lives only in the SDK (has_minimum_role). is_superuser is
    # deliberately not consulted: the flag alone never satisfies a role
    # threshold, so it can never bypass the writer/admin guards.
    if not has_minimum_role(current_user.role, role_limit):
        raise HTTPException(status_code=_FORBIDDEN, detail=_NO_PRIVILEGES)


def _build_api_key_client(
    settings: "ConsumerServiceSettings",
) -> ApiKeyIntrospectionClient | None:
    """
    Build the issuer introspection client, or None when the feature is off.

    Its configuration group is dedicated and fail-closed: the settings validator
    has already made a half-configured enable state impossible, and nothing here
    consults ``ACCESS_REVOCATION_FAILURE_MODE`` — the fail-open option on that
    knob must not reach this path.
    """
    if not settings.API_KEY_INTROSPECTION_ENABLED:
        return None
    return ApiKeyIntrospectionClient(
        introspection_url=settings.effective_api_key_introspection_url(),
        auth_provider=build_internal_auth(settings),
        # The issuer derives the evaluated audience from this consumer's
        # registry identity and echoes it back; the client refuses a principal
        # minted for anyone else.
        audience_id=str(settings.INTERNAL_CLIENT_ID),
        schema_version=settings.API_KEY_INTROSPECTION_SCHEMA_VERSION,
        connect_timeout=settings.API_KEY_INTROSPECTION_CONNECT_TIMEOUT,
        read_timeout=settings.API_KEY_INTROSPECTION_READ_TIMEOUT,
        pool_timeout=settings.API_KEY_INTROSPECTION_POOL_TIMEOUT,
        max_concurrency=settings.API_KEY_INTROSPECTION_MAX_CONCURRENCY,
        max_response_bytes=settings.API_KEY_INTROSPECTION_MAX_RESPONSE_BYTES,
        circuit_failure_threshold=(
            settings.API_KEY_INTROSPECTION_CIRCUIT_FAILURE_THRESHOLD
        ),
        circuit_reset_seconds=settings.API_KEY_INTROSPECTION_CIRCUIT_RESET_SECONDS,
    )


def _api_key_quota_denial(ex: ApiKeyQuotaExceededError) -> HTTPException:
    """Relay the issuer's 429 to this service's caller, Retry-After intact."""
    headers = {"Retry-After": ex.retry_after} if ex.retry_after else None
    return HTTPException(
        status_code=_TOO_MANY_REQUESTS,
        detail="API key rate limit exceeded",
        headers=headers,
    )


class _LoggingHooks:
    """Emit structured log lines for every token validation outcome."""

    def on_success(self, *, jti: str, sub: str, token_type: str) -> None:
        _logger.debug("auth.ok type=%s sub=%s jti=%s", token_type, sub, jti)

    def on_failure(self, *, reason: str, token_type: str) -> None:
        _logger.warning("auth.fail type=%s reason=%s", token_type, reason)


@dataclass(frozen=True)
class AuthDeps:
    """
    Frozen container for all auth-related FastAPI dependencies.

    Attributes
    ----------
    get_current_user
        Dependency function — returns the authenticated user.
    CurrentUser
        ``Annotated[UserModel, Depends(get_current_user)]``.
    get_current_active_writer
        Dependency that additionally requires at least WRITER role.
    get_current_active_admin
        Dependency that additionally requires at least ADMIN role.
    get_current_active_superuser
        Requires canonical superuser claims (SUPERADMIN *and* is_superuser).
    revocation_client
        The revocation client, or None for stateless mode.
    get_current_api_key_principal
        Resolves a presented API key to its owner's current authority via the
        issuer. None unless ``API_KEY_INTROSPECTION_ENABLED``.
    require_api_key_role
        Factory building an API-key capability dependency. None when disabled.
    get_current_api_key_reader
        API-key dependency requiring at least READER. None when disabled.
    get_current_api_key_writer
        API-key dependency requiring at least WRITER. None when disabled.
    api_key_client
        The introspection client, or None when disabled.

    Every JWT guard is authorized through the auth-sdk-m8 policy helpers, so
    the role hierarchy and the canonical-superuser predicate are never
    reimplemented here:

    ==================  =====  ======  ======  ==========
    Role                auth   writer  admin   superuser
    ==================  =====  ======  ======  ==========
    USER                allow  403     403     403
    READER              allow  403     403     403
    WRITER              allow  allow   403     403
    ADMIN               allow  allow   allow   403
    SUPERADMIN          allow  allow   allow   allow
    ==================  =====  ======  ======  ==========

    The API-key members mirror that table only up to ``WRITER``, and they are
    additionally capped by the key's immutable access mode. There is no API-key
    admin or superuser dependency and no setting that creates one: an owner's
    ADMIN/SUPERADMIN role grants an API-key request nothing beyond writer-level
    capability, because administrative and superuser operations are JWT-only.

    The API-key members are ``None`` unless ``API_KEY_INTROSPECTION_ENABLED``:
    with no issuer to resolve an owner against, no principal can be confirmed,
    so the dependency that would authorize one does not exist. Enable the
    feature before wiring an API-key route.

    """

    get_current_user: Callable
    CurrentUser: Any
    get_current_active_writer: Callable
    get_current_active_admin: Callable
    get_current_active_superuser: Callable
    revocation_client: RemoteRevocationClient | None
    get_current_api_key_principal: Callable | None = None
    require_api_key_role: Callable | None = None
    get_current_api_key_reader: Callable | None = None
    get_current_api_key_writer: Callable | None = None
    api_key_client: ApiKeyIntrospectionClient | None = None

    async def handle_auth_event(self, event: AuthStreamEvent) -> None:
        """
        Apply one auth stream event to the validation cache.

        Pass this straight to ``build_event_stream_client(..., on_event=...)``:
        it is the supported way to consume the stream, so no service re-derives
        the ``session.revoked`` generation/watermark rules (3.5.2) locally.
        Both v1 and v2 events are accepted. Unknown event types are ignored, and
        nothing here raises into the stream client.

        Async to satisfy the stream client's awaited callback contract; the work
        itself is in-memory and never blocks the event loop.
        """
        # The SSE `event:` field spells the type with a hyphen; the payload's own
        # `event_type` uses the SDK's canonical dot. Accept either spelling.
        event_type = event.event_type.replace("-", ".")
        if event_type == _SESSION_REVOKED and self.revocation_client is not None:
            self.revocation_client.apply_session_revoked_event(event.payload)
        elif event_type == _USER_DELETED:
            user_id = event.payload.get("user_id")
            if isinstance(user_id, str):
                self.evict_user(user_id)

    def evict_jti(self, jti: str) -> None:
        """Evict one JTI from the validation cache (on session.revoked event)."""
        if self.revocation_client is not None:
            self.revocation_client.evict_jti(jti)

    def evict_user(self, user_id: str) -> None:
        """Evict all JTIs for a user from the cache (on user.deleted event)."""
        if self.revocation_client is not None:
            self.revocation_client.evict_user(user_id)

    def flush_cache(self) -> None:
        """Flush the entire validation cache (on unresumable stream gap)."""
        if self.revocation_client is not None:
            self.revocation_client.flush_cache()

    async def close(self) -> None:
        """Teardown owner: close the revocation and API-key clients."""
        if self.revocation_client is not None:
            await self.revocation_client.close()
        if self.api_key_client is not None:
            await self.api_key_client.close()


def build_auth_deps(settings: "ConsumerServiceSettings") -> AuthDeps:
    """
    Build the auth dependency set from service settings.

    Call once at module load in ``core/deps.py``.  A second call creates a
    second validator and revocation client without sharing state.

    Parameters
    ----------
    settings
        A ``ConsumerServiceSettings`` instance.

    Returns
    -------
    AuthDeps
        Frozen dataclass with all auth dependencies.

    """
    _assert_compat()

    hooks: ValidationHooks = _LoggingHooks()  # type: ignore[assignment]
    # The SDK's build_access_validator reads ACCESS_TOKEN_ALGORITHM,
    # TOKEN_ISSUER/TOKEN_AUDIENCE, TOKEN_STRICT_VALIDATION and JWKS_URI straight
    # off the settings object, so a factory-built app inherits auth-sdk's
    # secure-by-default posture (RS256 + strict iss/aud binding, JWKS resolution
    # for consumers) with no extra wiring.  Log the effective posture so the
    # inherited defaults are visible at startup, mirroring revocation.mode below.
    validator = build_access_validator(settings, hooks)
    _logger.info(
        "auth.validation algorithm=%s strict=%s jwks=%s iss=%s aud=%s role=%s",
        settings.ACCESS_TOKEN_ALGORITHM,
        settings.TOKEN_STRICT_VALIDATION,
        bool(settings.JWKS_URI),
        bool(settings.TOKEN_ISSUER),
        bool(settings.TOKEN_AUDIENCE),
        settings.AUTH_SERVICE_ROLE,
    )

    revocation_client: RemoteRevocationClient | None = None
    if settings.is_stateful and settings.AUTH_SERVICE_ROLE == "consumer":
        revocation_mode = settings.effective_failure_mode("access_revocation")
        _logger.info(
            "revocation.mode effective=%s (ACCESS_REVOCATION_FAILURE_MODE=%s, AUTH_STRICT_MODE=%s)",
            revocation_mode,
            settings.ACCESS_REVOCATION_FAILURE_MODE,
            settings.AUTH_STRICT_MODE,
        )
        # Per-consumer internal-auth (9.1): legacy single-secret, per-consumer
        # bootstrap headers, or short-TTL service-token exchange — selected by
        # config. Log the mode only (never the client id or any secret).
        _logger.info("internal_auth.mode=%s", describe_internal_auth_mode(settings))
        revocation_client = RemoteRevocationClient(
            introspection_url=str(settings.INTROSPECTION_URL),
            auth_provider=build_internal_auth(settings),
            fail_closed=(revocation_mode == "fail_closed"),
            cache_ttl=settings.REVOCATION_CACHE_TTL_SECONDS,
        )

    reusable_oauth2 = OAuth2PasswordBearer(
        tokenUrl=f"{settings.AUTH_PREFIX}/login/access-token"
    )
    TokenDep = Annotated[str, Depends(reusable_oauth2)]

    async def get_current_user(token: TokenDep) -> UserModel:
        """Extract and validate the current user from the JWT access token."""
        payload = _validate_access_token(validator, token)
        await _check_token_revocation(revocation_client, payload.jti, payload.sub)
        return _build_active_user(payload)

    CurrentUser = Annotated[UserModel, Depends(get_current_user)]

    def get_current_active_writer(
        current_user: UserModel = Depends(get_current_user),
    ) -> UserModel:
        """Verify at least WRITER role."""
        _require_role(current_user, RoleType.WRITER)
        return current_user

    def get_current_active_admin(
        current_user: UserModel = Depends(get_current_user),
    ) -> UserModel:
        """Verify at least ADMIN role."""
        _require_role(current_user, RoleType.ADMIN)
        return current_user

    def get_current_active_superuser(
        current_user: UserModel = Depends(get_current_user),
    ) -> UserModel:
        """Verify canonical superuser claims (SUPERADMIN *and* is_superuser)."""
        # Dual-evidence predicate: neither claim grants privilege alone, so a
        # stray is_superuser=true on a lower role is denied here as well as by
        # the SDK model invariant (defense in depth).
        if not has_superuser_privileges(current_user.role, current_user.is_superuser):
            raise HTTPException(status_code=_FORBIDDEN, detail=_NO_PRIVILEGES)
        return current_user

    api_key_client = _build_api_key_client(settings)
    api_key_deps = (
        _build_api_key_deps(api_key_client) if api_key_client is not None else {}
    )

    return AuthDeps(
        get_current_user=get_current_user,
        CurrentUser=CurrentUser,
        get_current_active_writer=get_current_active_writer,
        get_current_active_admin=get_current_active_admin,
        get_current_active_superuser=get_current_active_superuser,
        revocation_client=revocation_client,
        api_key_client=api_key_client,
        **api_key_deps,
    )


def _build_api_key_deps(client: ApiKeyIntrospectionClient) -> dict[str, Callable]:
    """
    Build the remote API-key principal dependency family (§3.11, §3.12).

    The key never carries a role, so nothing here reads one off it: every
    capability-bearing request resolves the owner's **current** authority from
    the issuer and evaluates it with the same shared SDK predicate the JWT
    guards use. That is what makes a role downgrade take effect on the key's
    next request, in every token mode, without the key participating in the
    generation model at all.
    """
    api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)

    async def get_current_api_key_principal(
        api_key: str | None = Security(api_key_header),
    ) -> ApiKeyPrincipal:
        """
        Resolve the presented API key to its owner's current principal.

        Depending on this dependency proves only that a key resolves to a live
        owner — it never implies writer capability. A capability-bearing route
        must depend on a role dependency below.
        """
        if not api_key:
            raise HTTPException(status_code=_UNAUTHORIZED, detail=_INVALID_API_KEY)
        try:
            principal = await client.introspect(SecretStr(api_key))
        except ApiKeyQuotaExceededError as ex:
            raise _api_key_quota_denial(ex) from ex
        except ApiKeyIntrospectionError as ex:
            # Fail closed, always: an unconfirmable principal is a denial, never
            # a fallback to bare key validity or to a previously seen result.
            _logger.warning("security.api_key_denied reason=unverifiable error=%s", ex)
            raise HTTPException(
                status_code=_UNAVAILABLE,
                detail="API key verification unavailable.",
            ) from ex
        if principal is None:
            raise HTTPException(status_code=_UNAUTHORIZED, detail=_INVALID_API_KEY)
        return principal

    def require_api_key_role(required_role: RoleType) -> Callable:
        """
        Build a dependency requiring *required_role* of the key's owner.

        Args:
            required_role: The minimum role the operation needs, at most
                ``WRITER``.

        Returns:
            A FastAPI dependency returning the principal, or denying with 403.

        Raises:
            ApiKeyCapabilityCeilingError: If *required_role* is above the
                API-key ceiling. Administrative and superuser operations are
                JWT-only, so asking an API key for one is a programming error,
                not a denial — it is raised here, at wiring time, so the mistake
                cannot ship disguised as a routine authorization failure.

        """
        validate_api_key_required_role(required_role)

        async def _dependency(
            principal: ApiKeyPrincipal = Depends(get_current_api_key_principal),
        ) -> ApiKeyPrincipal:
            # One shared SDK decision: the owner's live role ∩ the key's
            # immutable access mode ∩ the API-key ceiling. Never is_superuser,
            # and never a role read off the key.
            if not principal.has_capability(required_role):
                raise HTTPException(status_code=_FORBIDDEN, detail=_NO_PRIVILEGES)
            return principal

        return _dependency

    return {
        "get_current_api_key_principal": get_current_api_key_principal,
        "require_api_key_role": require_api_key_role,
        "get_current_api_key_reader": require_api_key_role(RoleType.READER),
        "get_current_api_key_writer": require_api_key_role(RoleType.WRITER),
    }

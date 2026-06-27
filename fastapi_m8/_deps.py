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

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import ValidationHooks, build_access_validator
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from fastapi_m8._compat import _assert_compat
from fastapi_m8._internal_auth import build_internal_auth, describe_internal_auth_mode
from fastapi_m8._revocation import RemoteRevocationClient, RevocationCheckError

if TYPE_CHECKING:
    from fastapi_m8.config import ConsumerServiceSettings

_logger = logging.getLogger(__name__)

_FORBIDDEN = status.HTTP_403_FORBIDDEN
_UNAVAILABLE = status.HTTP_503_SERVICE_UNAVAILABLE
_NO_PRIVILEGES = "The user doesn't have enough privileges"


def _validate_access_token(validator: Any, token: str) -> Any:
    try:
        return validator.validate_access_token(token)
    except InvalidToken as ex:
        raise HTTPException(
            status_code=_FORBIDDEN,
            detail="Could not validate credentials.",
        ) from ex


async def _check_token_revocation(
    revocation_client: RemoteRevocationClient | None, jti: str, user_id: str = ""
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
    if not RoleType.is_valid_role_auth(
        current_role=current_user.role,
        role_limit=role_limit,
    ):
        raise HTTPException(status_code=_FORBIDDEN, detail=_NO_PRIVILEGES)


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
    get_current_active_admin
        Dependency that additionally checks ADMIN role.
    get_current_active_superuser
        Checks SUPERADMIN role.
    revocation_client
        The revocation client, or None for stateless mode.

    """

    get_current_user: Callable
    CurrentUser: Any
    get_current_active_admin: Callable
    get_current_active_superuser: Callable
    revocation_client: RemoteRevocationClient | None

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
        """Teardown owner: close the revocation client (and future clients)."""
        if self.revocation_client is not None:
            await self.revocation_client.close()


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

    def get_current_active_admin(
        current_user: UserModel = Depends(get_current_user),
    ) -> UserModel:
        """Verify at least ADMIN role."""
        _require_role(current_user, RoleType.ADMIN)
        return current_user

    def get_current_active_superuser(
        current_user: UserModel = Depends(get_current_user),
    ) -> UserModel:
        """Verify SUPERADMIN role."""
        if not current_user.is_superuser:
            raise HTTPException(status_code=_FORBIDDEN, detail=_NO_PRIVILEGES)
        _require_role(current_user, RoleType.SUPERADMIN)
        return current_user

    return AuthDeps(
        get_current_user=get_current_user,
        CurrentUser=CurrentUser,
        get_current_active_admin=get_current_active_admin,
        get_current_active_superuser=get_current_active_superuser,
        revocation_client=revocation_client,
    )

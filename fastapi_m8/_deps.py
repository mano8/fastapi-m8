"""
Auth dependency builder for fastapi-m8 services.

Call ``build_auth_deps(settings)`` **once** per service in ``core/deps.py``
and share the resulting ``AuthDeps`` instance everywhere.  A second call
builds a second validator and revocation client — there is no implicit cache.
"""

from __future__ import annotations

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
    revocation_client: RemoteRevocationClient | None, jti: str
) -> None:
    if revocation_client is None:
        return
    try:
        if await revocation_client.is_revoked(jti):
            raise HTTPException(
                status_code=_FORBIDDEN,
                detail="Token has been revoked.",
            )
    except RevocationCheckError as ex:
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

    async def close(self) -> None:
        """Teardown owner: close the revocation client (and future clients)."""
        if self.revocation_client is not None:
            await self.revocation_client.close()


def build_auth_deps(settings: ConsumerServiceSettings) -> AuthDeps:
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
    validator = build_access_validator(settings, hooks)

    revocation_client: RemoteRevocationClient | None = None
    if settings.is_stateful and settings.AUTH_SERVICE_ROLE == "consumer":
        revocation_client = RemoteRevocationClient(
            introspection_url=str(settings.INTROSPECTION_URL),
            private_api_secret=settings.PRIVATE_API_SECRET.get_secret_value(),  # type: ignore[union-attr]
        )

    reusable_oauth2 = OAuth2PasswordBearer(
        tokenUrl=f"{settings.AUTH_PREFIX}/login/access-token"
    )
    TokenDep = Annotated[str, Depends(reusable_oauth2)]

    async def get_current_user(token: TokenDep) -> UserModel:
        """Extract and validate the current user from the JWT access token."""
        payload = _validate_access_token(validator, token)
        await _check_token_revocation(revocation_client, payload.jti)
        return _build_active_user(payload)

    CurrentUser = Annotated[UserModel, Depends(get_current_user)]

    def get_current_active_admin(current_user: CurrentUser) -> UserModel:  # type: ignore[valid-type]
        """Verify at least ADMIN role."""
        _require_role(current_user, RoleType.ADMIN)
        return current_user

    def get_current_active_superuser(
        current_user: CurrentUser,  # type: ignore[valid-type]
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

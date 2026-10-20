"""
Service-client guard for consumer routes that other services call.

A consumer that exposes routes to other services (not to users) authenticates
each caller by the per-consumer credential pair the fleet already uses for
private calls to the issuer: ``X-Internal-Client`` names the calling service
and ``X-Internal-Token`` carries its secret. The verification primitives live
in auth-sdk-m8 (``ConsumerCredentialRegistry``) and are re-exported from
``fastapi_m8`` so a consumer never imports ``auth_sdk_m8`` directly.

:func:`build_service_client_guard` turns a registry and a required scope set
into a FastAPI dependency:

* a missing header, an unknown client id or a wrong secret → ``401`` with one
  fixed body. The registry runs its constant-time comparison in every one of
  these cases (against a throwaway credential when the id is unknown), so the
  guard adds no client-enumeration oracle;
* an authenticated client that lacks any required scope → ``403``;
* success → the authenticated client id (a ``str``).

The token is never logged, echoed or attached to an exception.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from auth_sdk_m8.security.consumer_auth import (
    INTERNAL_CLIENT_HEADER,
    INTERNAL_TOKEN_HEADER,
    ConsumerCredentialRegistry,
)
from fastapi import HTTPException, Request, status

_UNAUTHORIZED_DETAIL = "Unauthorized"
_FORBIDDEN_DETAIL = "Forbidden"


def _normalise_required_scopes(required_scopes: Iterable[str]) -> frozenset[str]:
    """Return the required scopes as a non-empty ``frozenset`` of strings."""
    if isinstance(required_scopes, str):
        # frozenset("execute:ocr") would require each character as a scope.
        raise TypeError(
            "required_scopes must be an iterable of scope strings, not a str"
        )
    scopes = frozenset(required_scopes)
    if not scopes:
        raise ValueError(
            "required_scopes must name at least one scope; a service-client "
            "guard is deny-by-default"
        )
    for scope in scopes:
        if not isinstance(scope, str) or not scope:
            raise ValueError("every required scope must be a non-empty string")
    return scopes


def build_service_client_guard(
    registry: ConsumerCredentialRegistry,
    *,
    required_scopes: Iterable[str],
) -> Callable[[Request], str]:
    """
    Build a FastAPI dependency that authenticates a service client.

    Parameters
    ----------
    registry : ConsumerCredentialRegistry
        The hashed, scoped client registry to verify against.
    required_scopes : Iterable[str]
        Every scope the route needs. The client must hold all of them. At
        least one is required, and a bare ``str`` is refused.

    Returns
    -------
    Callable[[Request], str]
        A dependency returning the authenticated client id. It raises
        ``HTTPException`` 401 for a missing or unknown client or a wrong
        secret, and 403 for an authenticated client lacking a scope.

    Raises
    ------
    TypeError
        If ``required_scopes`` is a ``str``.
    ValueError
        If ``required_scopes`` is empty or holds an empty or non-string scope.

    """
    scopes = _normalise_required_scopes(required_scopes)

    def _service_client(request: Request) -> str:
        client_id = request.headers.get(INTERNAL_CLIENT_HEADER)
        secret = request.headers.get(INTERNAL_TOKEN_HEADER)
        # verify() compares in constant time in every branch and reports an
        # unknown id and a wrong secret identically (None).
        credential = registry.verify(client_id, secret)
        if credential is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_UNAUTHORIZED_DETAIL,
            )
        if not all(credential.has_scope(scope) for scope in scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_FORBIDDEN_DETAIL,
            )
        return credential.client_id

    return _service_client

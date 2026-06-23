"""
Runtime compatibility guard between fastapi-m8 and auth-sdk-m8.

``_assert_compat()`` is called from ``create_app()`` and ``build_auth_deps()``
once per process (thread-safe via ``_lock``).
"""

import importlib.metadata as md
import logging
import threading

from packaging.specifiers import SpecifierSet

from fastapi_m8._version import __version__

logger = logging.getLogger(__name__)

# Declarative pairing: fastapi-m8 minor → required version ranges.
# Add future dependencies here without touching any other code.
COMPAT_MATRIX: dict[str, dict[str, str]] = {
    "1.0": {"auth-sdk-m8": ">=0.7.0,<0.8.0"},
    "1.1": {"auth-sdk-m8": ">=0.7.1,<0.8.0"},
    # 1.2 consumes auth-sdk-m8 1.0.0 secure-by-default (RS256/JWKS, strict
    # iss/aud binding, signed event bus) — see CHANGELOG.
    "1.2": {"auth-sdk-m8": ">=1.0.0,<2.0.0"},
    # 1.3 delegates the response security-header layer to auth-sdk-m8 1.1.0
    # (auth_sdk_m8.security.headers) — see CHANGELOG / N2.
    "1.3": {"auth-sdk-m8": ">=1.1.0,<2.0.0"},
    # 1.4 adds AuthEventStreamClient re-exports + build_event_stream_client factory
    # (auth-sdk-m8 1.2.0 ships the events/ package) — see CHANGELOG / SC.
    "1.4": {"auth-sdk-m8": ">=1.2.0,<2.0.0"},
    # 1.5 tracks auth-sdk-m8 1.2.1 tiered security headers: HSTS/CSP are now
    # express opt-in (HSTS_ENABLED / CONTENT_SECURITY_POLICY_ENABLED) and never
    # emitted on local — see CHANGELOG.
    "1.5": {"auth-sdk-m8": ">=1.2.1,<2.0.0"},
    # 1.6 consumes auth-sdk-m8 1.3.0, which adds the optional tenant_id claim to
    # the token payload + UserModel; _build_active_user forwards it unchanged so
    # CurrentUser.tenant_id is now populated — see CHANGELOG.
    "1.6": {"auth-sdk-m8": ">=1.3.0,<2.0.0"},
    # 2.0 auto-mounts the shared /meta + /ping routes in create_app, sourced from
    # the new required ConsumerServiceSettings version/contract fields (fail-closed
    # at boot). Requires auth-sdk-m8 1.4.0, which ships mount_service_meta +
    # ServiceMeta — see CHANGELOG. BREAKING: consumers must declare their meta.
    "2.0": {"auth-sdk-m8": ">=1.4.0,<2.0.0"},
    # 2.1 requires auth-sdk-m8 1.5.0, where mount_service_meta dual-mounts /ping:
    # the unchanged root /ping plus a {API_PREFIX}/ping copy so liveness stays
    # reachable behind a prefix-routing reverse proxy (Traefik forwards only
    # PathPrefix({API_PREFIX}), so a root-only /ping 404s at the gateway). The
    # create_app call site is unchanged — it already passes prefix=API_PREFIX — so
    # the prefixed probe is picked up automatically on upgrade. See CHANGELOG.
    "2.1": {"auth-sdk-m8": ">=1.5.0,<2.0.0"},
    # 3.0 (MAJOR) aligns with auth-sdk-m8 2.0.0 on two breaking fronts: (1) /ping
    # collapses to a single mount — when a prefix is set it lives only at
    # {prefix}/ping (no root copy), always in the OpenAPI schema, so consumers
    # that relied on root /ping behind a prefix must switch to {API_PREFIX}/ping;
    # (2) the required auth-sdk-m8 floor crosses a major (<2.0.0 → >=2.0.0), which
    # removed deprecated SDK APIs (Redis bus, decode_access_token, TOKEN_ALGORITHM,
    # module-level settings_customise_sources). Either alone forces this major bump.
    # See CHANGELOG.
    "3.0": {"auth-sdk-m8": ">=2.0.0,<3.0.0"},
}

_EXTRAS = "[config,security,fastapi,observability]"
_lock = threading.Lock()
_COMPAT_STATE: dict[str, object] = {"checked": False, "auth_version": None}


def _assert_compat() -> None:
    """
    Check installed dependency versions against COMPAT_MATRIX.

    Raises
    ------
    RuntimeError
        If a required dependency is outside its specified range.

    """
    with _lock:
        if _COMPAT_STATE["checked"]:
            return
        minor = ".".join(__version__.split(".")[:2])
        reqs = COMPAT_MATRIX.get(minor, {})
        for dist, spec in reqs.items():
            found = md.version(dist)
            if found not in SpecifierSet(spec):
                logger.error(
                    "fastapi-m8 %s needs %s%s (found %s)",
                    __version__,
                    dist,
                    spec,
                    found,
                )
                raise RuntimeError(
                    f"fastapi-m8 {__version__} requires {dist}{spec} "
                    f"(found {found}). "
                    f"Run: pip install '{dist}{_EXTRAS}{spec}'"
                )
        auth_v = md.version("auth-sdk-m8")
        _COMPAT_STATE.update(checked=True, auth_version=auth_v)

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

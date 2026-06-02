"""Async app stub — reserves the async interface for fastapi-m8 v2.0.0."""

from __future__ import annotations

from typing import Any

CAPABILITIES: dict[str, bool] = {
    "async": False,
    "plugin_system": False,
    "trace_context": False,
    "db_optional": True,
    "health_detail_gating": True,
}


def capabilities() -> dict[str, bool]:
    """Return a copy of the capability flags.

    Use this to introspect what the installed version supports before
    calling optional APIs.
    """
    return CAPABILITIES.copy()


def create_async_app(*args: Any, **kwargs: Any) -> Any:
    """Placeholder — async app support is planned for fastapi-m8 v2.0.0.

    Raises:
        NotImplementedError: Always. Check ``capabilities()['async']`` first.
    """
    raise NotImplementedError(
        "Async app support is planned for fastapi-m8 v2.0.0. "
        "Check CAPABILITIES['async']. "
        "Track: github.com/EliSerra/fa-auth-m8/issues/1"
    )

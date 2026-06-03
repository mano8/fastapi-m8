"""Tests for fastapi_m8._compat."""

import threading
from unittest.mock import patch

import pytest

from fastapi_m8._compat import (
    _COMPAT_STATE,
    COMPAT_MATRIX,
    _assert_compat,
    _lock,
)
from fastapi_m8._version import __version__


def _reset_compat() -> None:
    """Reset the compat-check guard between tests."""
    with _lock:
        _COMPAT_STATE["checked"] = False
        _COMPAT_STATE["auth_version"] = None


def test_compat_matrix_has_current_minor() -> None:
    minor = ".".join(__version__.split(".")[:2])
    assert minor in COMPAT_MATRIX
    assert "auth-sdk-m8" in COMPAT_MATRIX[minor]


def test_assert_compat_passes_with_installed_version() -> None:
    _reset_compat()
    _assert_compat()  # should not raise with 0.7.x installed
    assert _COMPAT_STATE["checked"] is True
    assert _COMPAT_STATE["auth_version"] is not None


def test_assert_compat_idempotent() -> None:
    _reset_compat()
    _assert_compat()
    _assert_compat()  # second call is a no-op
    assert _COMPAT_STATE["checked"] is True


def test_assert_compat_raises_on_bad_version() -> None:
    _reset_compat()
    with patch("fastapi_m8._compat.md.version", return_value="0.6.0"):
        with pytest.raises(RuntimeError, match="requires auth-sdk-m8"):
            _assert_compat()
    _reset_compat()  # clean up for subsequent tests


def test_assert_compat_thread_safe() -> None:
    """Concurrent calls must each see checked=True without racing."""
    _reset_compat()
    errors: list[Exception] = []

    def _run() -> None:
        try:
            _assert_compat()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_run) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert _COMPAT_STATE["checked"] is True

"""Tests for fastapi_m8._compat."""

import re
import threading
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from fastapi_m8._compat import (
    _COMPAT_STATE,
    COMPAT_MATRIX,
    _assert_compat,
    _lock,
)
from fastapi_m8._version import __version__

_PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def _reset_compat() -> None:
    """Reset the compat-check guard between tests."""
    with _lock:
        _COMPAT_STATE["checked"] = False
        _COMPAT_STATE["auth_version"] = None


def _current_minor() -> str:
    return ".".join(__version__.split(".")[:2])


def _pyproject_auth_sdk_specifier() -> str:
    """Return the auth-sdk-m8 version specifier declared in pyproject.toml."""
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    for dep in data["project"]["dependencies"]:
        # e.g. "auth-sdk-m8[config,security,...]>=3.1.2,<4.0.0"
        match = re.fullmatch(r"auth-sdk-m8(?:\[[^\]]*\])?\s*(.+)", dep.strip())
        if match:
            return match.group(1).replace(" ", "")
    raise AssertionError("pyproject.toml declares no auth-sdk-m8 dependency")


def test_compat_matrix_has_current_minor() -> None:
    minor = _current_minor()
    assert minor in COMPAT_MATRIX
    assert "auth-sdk-m8" in COMPAT_MATRIX[minor]


def test_compat_matrix_current_minor_row_matches_pyproject_floor() -> None:
    """The current minor's row must state the floor pyproject.toml declares.

    ``test_compat_matrix_has_current_minor`` only proves a row *exists*; a
    stale copy-pasted row passes it. This asserts the row is also *right*.
    """
    assert COMPAT_MATRIX[_current_minor()]["auth-sdk-m8"] == (
        _pyproject_auth_sdk_specifier()
    )


def test_assert_compat_fails_closed_on_unlisted_minor() -> None:
    """A minor with no COMPAT_MATRIX row must refuse to boot, not skip the check."""
    _reset_compat()
    unlisted = "99.99.0"
    assert "99.99" not in COMPAT_MATRIX
    with patch("fastapi_m8._compat.__version__", unlisted):
        with pytest.raises(RuntimeError, match="no COMPAT_MATRIX row"):
            _assert_compat()
    assert _COMPAT_STATE["checked"] is False
    _reset_compat()


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


def test_compat_matrix_40_row_matches_pyproject_floor() -> None:
    """The 4.0 gate is exactly the auth-sdk-m8 3.0.0 major floor."""
    assert COMPAT_MATRIX["4.0"] == {"auth-sdk-m8": ">=3.0.0,<4.0.0"}


def test_assert_compat_40_row_accepts_intended_sdk_major() -> None:
    """The 4.0 gate accepts the released/local SDK major it targets (3.0.0)."""
    _reset_compat()
    with (
        patch("fastapi_m8._compat.__version__", "4.0.0"),
        patch("fastapi_m8._compat.md.version", return_value="3.0.0"),
    ):
        _assert_compat()  # should not raise: 3.0.0 is in >=3.0.0,<4.0.0
    assert _COMPAT_STATE["checked"] is True
    assert _COMPAT_STATE["auth_version"] == "3.0.0"
    _reset_compat()


def test_assert_compat_40_row_rejects_old_major() -> None:
    """The 4.0 gate rejects the pre-invariant 2.x SDK it must not silently run against."""
    _reset_compat()
    with (
        patch("fastapi_m8._compat.__version__", "4.0.0"),
        patch("fastapi_m8._compat.md.version", return_value="2.1.1"),
    ):
        with pytest.raises(RuntimeError, match="requires auth-sdk-m8"):
            _assert_compat()
    _reset_compat()


def test_compat_matrix_45_row_matches_pyproject_floor() -> None:
    """The 4.5 gate is exactly the auth-sdk-m8 3.2.0 J3-fix floor."""
    assert COMPAT_MATRIX["4.5"] == {"auth-sdk-m8": ">=3.2.0,<4.0.0"}


def test_assert_compat_45_row_accepts_intended_sdk_major() -> None:
    """The 4.5 gate accepts the released SDK version it targets (3.2.0)."""
    _reset_compat()
    with (
        patch("fastapi_m8._compat.__version__", "4.5.0"),
        patch("fastapi_m8._compat.md.version", return_value="3.2.0"),
    ):
        _assert_compat()  # should not raise: 3.2.0 is in >=3.2.0,<4.0.0
    assert _COMPAT_STATE["checked"] is True
    assert _COMPAT_STATE["auth_version"] == "3.2.0"
    _reset_compat()


def test_assert_compat_45_row_rejects_old_major() -> None:
    """The 4.5 gate rejects the pre-fix 3.1.3 SDK it must not silently run against."""
    _reset_compat()
    with (
        patch("fastapi_m8._compat.__version__", "4.5.0"),
        patch("fastapi_m8._compat.md.version", return_value="3.1.3"),
    ):
        with pytest.raises(RuntimeError, match="requires auth-sdk-m8"):
            _assert_compat()
    _reset_compat()


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

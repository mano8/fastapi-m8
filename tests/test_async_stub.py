"""Tests for fastapi_m8._async_stub."""

import pytest

from fastapi_m8 import capabilities, create_async_app


def test_capabilities_returns_copy() -> None:
    c1 = capabilities()
    c2 = capabilities()
    assert c1 == c2
    assert c1 is not c2


def test_async_capability_false() -> None:
    assert capabilities()["async"] is False


def test_db_optional_capability_true() -> None:
    assert capabilities()["db_optional"] is True


def test_health_detail_gating_capability_true() -> None:
    assert capabilities()["health_detail_gating"] is True


def test_create_async_app_raises() -> None:
    with pytest.raises(NotImplementedError, match="v2.0.0"):
        create_async_app()


def test_compat_matrix_exported() -> None:
    from fastapi_m8 import COMPAT_MATRIX

    assert isinstance(COMPAT_MATRIX, dict)
    assert "1.0" in COMPAT_MATRIX

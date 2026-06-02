"""Tests for fastapi_m8.scripts.pre_start."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from fastapi_m8._engine import DbEngine
from fastapi_m8.scripts.pre_start import _wait_for_db, main

# ── _wait_for_db ──────────────────────────────────────────────────────────────


def test_wait_for_db_probes_successfully() -> None:
    """_wait_for_db calls session.exec(select(1)) once on a responsive engine."""
    mock_session = MagicMock()
    mock_sqlalchemy_engine = MagicMock()

    with (
        patch("sqlmodel.Session") as MockSession,
        patch("sqlalchemy.select"),
    ):
        MockSession.return_value.__enter__ = MagicMock(return_value=mock_session)
        MockSession.return_value.__exit__ = MagicMock(return_value=False)
        _wait_for_db(mock_sqlalchemy_engine)
        mock_session.exec.assert_called_once()


def test_wait_for_db_exits_on_missing_deps(monkeypatch: pytest.MonkeyPatch) -> None:
    """_wait_for_db calls sys.exit(1) when [db]/tenacity are missing."""
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name in ("sqlalchemy", "sqlmodel", "tenacity"):
            raise ImportError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    with pytest.raises(SystemExit) as exc_info:
        _wait_for_db(MagicMock())
    assert exc_info.value.code == 1


# ── main() ────────────────────────────────────────────────────────────────────


def test_main_skips_when_db_engine_unavailable(caplog) -> None:
    """main() returns early when fastapi_m8._engine cannot be imported."""
    import logging
    import sys

    saved = sys.modules.pop("fastapi_m8._engine", None)
    saved_pkg = sys.modules.pop("fastapi_m8", None)
    try:
        with caplog.at_level(logging.INFO):
            main()
    finally:
        if saved is not None:
            sys.modules["fastapi_m8._engine"] = saved
        if saved_pkg is not None:
            sys.modules["fastapi_m8"] = saved_pkg
    assert "skipping" in caplog.text.lower()


def test_main_skips_when_no_app_core_deps(caplog) -> None:
    """main() logs and returns when app.core.deps cannot be imported."""
    import logging

    mock_importlib = MagicMock()
    mock_importlib.import_module.side_effect = ImportError("no module")

    with (
        patch("fastapi_m8.scripts.pre_start.importlib", mock_importlib),
    ):
        with caplog.at_level(logging.INFO):
            main()
    assert "skipping" in caplog.text.lower()


def test_main_skips_when_engine_not_db_engine(caplog) -> None:
    """main() skips when app.core.deps.engine is not a DbEngine."""
    import logging

    mock_mod = MagicMock()
    mock_mod.engine = MagicMock()  # not a DbEngine

    mock_importlib = MagicMock()
    mock_importlib.import_module.return_value = mock_mod

    with patch("fastapi_m8.scripts.pre_start.importlib", mock_importlib):
        with caplog.at_level(logging.INFO):
            main()
    assert "not a dbengine" in caplog.text.lower()


def test_main_probes_and_disposes_engine(caplog) -> None:
    """main() calls _wait_for_db and engine.dispose() for a real DbEngine."""
    import logging

    mock_inner = MagicMock()
    db = DbEngine(_engine=mock_inner)

    mock_mod = MagicMock()
    mock_mod.engine = db

    mock_importlib = MagicMock()
    mock_importlib.import_module.return_value = mock_mod

    with (
        patch("fastapi_m8.scripts.pre_start.importlib", mock_importlib),
        patch("fastapi_m8.scripts.pre_start._wait_for_db") as mock_wait,
    ):
        with caplog.at_level(logging.INFO):
            main()

    mock_wait.assert_called_once_with(mock_inner)
    mock_inner.dispose.assert_called_once()

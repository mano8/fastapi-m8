"""Tests for fastapi_m8._engine.DbEngine and create_db_engine."""

from unittest.mock import MagicMock, patch

from fastapi_m8._engine import DbEngine, create_db_engine
from tests.conftest import make_settings


def _make_db_engine() -> tuple[DbEngine, MagicMock]:
    """Return a DbEngine with a mock inner engine and mock Session."""
    mock_inner = MagicMock()
    return DbEngine(_engine=mock_inner), mock_inner


def test_db_engine_dispose_delegates() -> None:
    """dispose() calls the underlying engine's dispose method."""
    db, mock_inner = _make_db_engine()
    db.dispose()
    mock_inner.dispose.assert_called_once()


def test_db_engine_session_context_manager() -> None:
    """session() yields a Session and closes it on exit."""
    db, mock_inner = _make_db_engine()
    mock_session = MagicMock()

    with patch("sqlmodel.Session") as MockSession:
        MockSession.return_value.__enter__ = MagicMock(return_value=mock_session)
        MockSession.return_value.__exit__ = MagicMock(return_value=False)
        with db.session() as s:
            assert s is mock_session


def test_db_engine_session_dep_yields_session() -> None:
    """session_dep() is a generator that yields one session."""
    db, _ = _make_db_engine()
    mock_session = MagicMock()

    with patch("sqlmodel.Session") as MockSession:
        MockSession.return_value.__enter__ = MagicMock(return_value=mock_session)
        MockSession.return_value.__exit__ = MagicMock(return_value=False)
        gen = db.session_dep()
        s = next(gen)
        assert s is mock_session
        try:
            next(gen)
        except StopIteration:
            pass


def test_create_db_engine_returns_db_engine() -> None:
    """create_db_engine returns a DbEngine wrapping a SQLAlchemy engine."""
    s = make_settings()
    with patch("sqlmodel.create_engine") as mock_create:
        mock_sqlalchemy_engine = MagicMock()
        mock_create.return_value = mock_sqlalchemy_engine
        db = create_db_engine(s)
    assert isinstance(db, DbEngine)
    assert db._engine is mock_sqlalchemy_engine
    mock_create.assert_called_once_with(str(s.SQLALCHEMY_DATABASE_URI))

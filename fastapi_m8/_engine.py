"""
DbEngine — public database engine wrapper for fastapi-m8 services.

Build via ``create_db_engine(settings)`` once at module load (``core/deps.py``).
``sqlmodel`` is imported lazily so the base install (no ``[db]`` extra) still
imports the package without errors.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fastapi_m8.config import ConsumerServiceSettings


@dataclass
class DbEngine:
    """
    Public wrapper around a SQLAlchemy/SQLModel engine.

    Build via ``create_db_engine()``; never construct directly.
    Use ``engine.session()`` in workers/scripts and ``engine.session_dep``
    as a FastAPI dependency.
    """

    _engine: Any = field(repr=False)
    is_async: bool = False

    @contextmanager
    def session(self) -> Generator[Any, None, None]:
        """
        Context manager for a database session.

        Usage::

            with engine.session() as s:
                s.exec(...)
        """
        from sqlmodel import Session  # lazy import

        with Session(self._engine) as s:
            yield s

    def session_dep(self) -> Generator[Any, None, None]:
        """
        Yield a database session as a FastAPI dependency.

        Usage::

            SessionDep = Annotated[Session, Depends(engine.session_dep)]
        """
        with self.session() as s:
            yield s

    def dispose(self) -> None:
        """Dispose the engine connection pool (called at shutdown)."""
        self._engine.dispose()


def create_db_engine(settings: ConsumerServiceSettings) -> DbEngine:
    """
    Create a synchronous DB engine from service settings.

    Parameters
    ----------
    settings
        A ``ConsumerServiceSettings`` instance with a valid
        ``SQLALCHEMY_DATABASE_URI``.

    Returns
    -------
    DbEngine
        A ``DbEngine`` wrapping the underlying SQLAlchemy engine.

    """
    from sqlmodel import create_engine  # lazy import

    return DbEngine(create_engine(str(settings.SQLALCHEMY_DATABASE_URI)))

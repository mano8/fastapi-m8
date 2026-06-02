"""Pre-start DB readiness probe.

Retries a trivial SELECT until the database is reachable.  Run before
uvicorn to prevent the service from starting with a dead DB.

Usage (in docker_start.sh or CMD)::

    python -m fastapi_m8.scripts.pre_start

Or via the installed script::

    fastapi-m8-prestart
"""

import importlib
import logging
import sys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_TRIES = 60 * 5
WAIT_SECONDS = 5


def _wait_for_db(engine: object) -> None:
    """Retry a SELECT until the database is awake.

    Args:
        engine: A SQLAlchemy/SQLModel engine instance.
    """
    try:
        from sqlalchemy import Engine  # noqa: PLC0415
        from sqlmodel import Session, select  # noqa: PLC0415
        from tenacity import (  # noqa: PLC0415
            after_log,
            before_log,
            retry,
            stop_after_attempt,
            wait_fixed,
        )
    except ImportError as exc:
        logger.error("pre_start requires fastapi-m8[db] and tenacity. %s", exc)
        sys.exit(1)

    @retry(
        stop=stop_after_attempt(MAX_TRIES),
        wait=wait_fixed(WAIT_SECONDS),
        before=before_log(logger, logging.INFO),
        after=after_log(logger, logging.WARN),
    )
    def _probe(db_engine: Engine) -> None:
        with Session(db_engine) as session:
            session.exec(select(1))

    _probe(engine)  # type: ignore[arg-type]


def main() -> None:
    """Entry point: import the service engine and probe the DB."""
    try:
        from fastapi_m8._engine import DbEngine  # noqa: PLC0415
    except ImportError:  # pragma: no cover — only fires when fastapi_m8 isn't installed
        logger.info("DB engine not configured; skipping DB probe.")
        return

    try:
        mod = importlib.import_module("app.core.deps")
        engine: object = getattr(mod, "engine", None)
    except (ImportError, AttributeError):
        logger.info("No app.core.deps.engine found; skipping DB probe.")
        return

    if not isinstance(engine, DbEngine):
        logger.info("app.core.deps.engine is not a DbEngine; skipping.")
        return

    logger.info("Initializing service — waiting for database…")
    _wait_for_db(engine._engine)
    logger.info("Database is ready.")
    engine.dispose()


if __name__ == "__main__":  # pragma: no cover
    main()

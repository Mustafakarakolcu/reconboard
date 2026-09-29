"""SQLAlchemy engine/session setup (SQLite, WAL, foreign keys on)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from . import config


SCHEMA_VERSION = 3  # bump whenever a table/column changes (no migrations yet)


class DatabaseVersionError(RuntimeError):
    pass


class Base(DeclarativeBase):
    pass


_engine = None
_SessionFactory: Optional[sessionmaker] = None


def make_engine(url: str):
    is_sqlite = url.startswith("sqlite")
    if is_sqlite and ":memory:" not in url:
        Path(url.split("///", 1)[1]).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    engine = create_engine(url, connect_args={"check_same_thread": False} if is_sqlite else {})
    if is_sqlite:

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn, _record):
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()

    return engine


def init(url: Optional[str] = None) -> None:
    """(Re)initialise the engine and create tables. Safe to call repeatedly."""
    global _engine, _SessionFactory
    from . import models  # noqa: F401  (registers tables on Base)

    url = url or config.db_url()
    engine = make_engine(url)
    is_sqlite = engine.dialect.name == "sqlite"
    fresh = True
    if is_sqlite:
        with engine.connect() as conn:
            fresh = conn.exec_driver_sql("SELECT count(*) FROM sqlite_master WHERE type='table'").scalar() == 0
            version = conn.exec_driver_sql("PRAGMA user_version").scalar()
        if not fresh and version != SCHEMA_VERSION:
            engine.dispose()
            raise DatabaseVersionError(
                f"The database was created by an older ReconBoard (schema {version}, need {SCHEMA_VERSION}). "
                "There are no migrations yet: move it away (e.g. mv ~/.reconboard/reconboard.db ~/.reconboard/old.db) "
                "and it will be recreated."
            )
    Base.metadata.create_all(engine)
    if is_sqlite and fresh:
        with engine.connect() as conn:
            conn.exec_driver_sql(f"PRAGMA user_version={SCHEMA_VERSION}")
            conn.commit()
        if ":memory:" not in url:
            try:
                os.chmod(url.split("///", 1)[1], 0o600)  # header values may be stored in it
            except OSError:
                pass
    _engine = engine
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)


def session() -> Session:
    if _SessionFactory is None:
        init()
    return _SessionFactory()  # type: ignore[misc]

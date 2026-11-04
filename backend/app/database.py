"""SQLite engine/session helpers — Phase 1."""
from __future__ import annotations

import os

from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool, StaticPool
from sqlalchemy.orm import sessionmaker

from .models import Base

# TRACEX_DB points the API at another store, e.g. the live monitor's data/live.db
DEFAULT_DB_URL = os.environ.get("TRACEX_DB", "sqlite:///./data/tracex.db")


def get_engine(db_url: str = DEFAULT_DB_URL):
    # NullPool: a SQLite file needs no connection pool, and a fixed pool ran dry under the
    # dashboard's 3-second live refresh (QueuePool limit reached -> every request hung for 30 s).
    # An in-memory SQLite database lives inside its connection, so NullPool would discard the
    # schema the moment create_all's connection closed; StaticPool keeps the one connection.
    in_memory = ":memory:" in db_url or "mode=memory" in db_url
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool if in_memory else NullPool,
    )
    Base.metadata.create_all(engine)
    return engine


def get_session_factory(db_url: str = DEFAULT_DB_URL):
    return sessionmaker(bind=get_engine(db_url), expire_on_commit=False)

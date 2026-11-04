"""Normalisation layer — Phase 3.

Thin layer with exactly one job: every parser output vocabulary maps onto
the canonical EventType enum, and all events merge into one `events` SQLite
table, sorted, deduplicated by hash.

Phase-2 parsers already emit canonical types directly, so this module:
  1. documents + enforces the raw->canonical vocabulary map (for any
     parser-native or legacy string that arrives, e.g. "4624", "visit"),
  2. coerces mixed inputs (CanonicalEvent | dict) to CanonicalEvent,
  3. sorts by timestamp,
  4. dedups by hash (keep first occurrence),
  5. bulk-ingests into SQLite idempotently (re-ingest of the same hash
     is a no-op, never a duplicate row).

Downstream modules (Phases 4+) read ONLY this table, never raw sources.
"""
from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_engine
from .models import CanonicalEvent, EventRow, EventType

PARSER_VERSION = "0.1.0"

# Parser-native / legacy vocabularies -> canonical EventType.
# Keys are lower-cased, stripped strings; numeric EVTX IDs kept as strings too.
RAW_EVENT_MAP: dict[str, EventType] = {
    # Windows EVTX (Security/System)
    "4624": EventType.LOGIN,
    "logon": EventType.LOGIN,
    "4625": EventType.LOGIN,  # failed logon; outcome stays in raw_metadata
    "failed logon": EventType.LOGIN,
    "4634": EventType.LOGOFF,
    "4647": EventType.LOGOFF,
    "logoff": EventType.LOGOFF,
    "1102": EventType.LOG_CLEARED,
    "104": EventType.LOG_CLEARED,
    "log cleared": EventType.LOG_CLEARED,
    "audit log cleared": EventType.LOG_CLEARED,
    "4663": EventType.FILE_ACCESSED,
    "object access": EventType.FILE_ACCESSED,
    "4688": EventType.PROCESS_CREATED,
    "process creation": EventType.PROCESS_CREATED,
    # Browser (Chrome/Firefox native words)
    "visit": EventType.PAGE_VISIT,
    "page visit": EventType.PAGE_VISIT,
    "page_visit": EventType.PAGE_VISIT,
    "download": EventType.FILE_DOWNLOAD,
    "file download": EventType.FILE_DOWNLOAD,
    "file_download": EventType.FILE_DOWNLOAD,
    # USB / Setupapi / registry native words
    "usb insert": EventType.DEVICE_CONNECTED,
    "device connected": EventType.DEVICE_CONNECTED,
    "device_connected": EventType.DEVICE_CONNECTED,
    "install": EventType.DEVICE_CONNECTED,
    "usb removal": EventType.DEVICE_DISCONNECTED,
    "device disconnected": EventType.DEVICE_DISCONNECTED,
    "device_disconnected": EventType.DEVICE_DISCONNECTED,
    "remove": EventType.DEVICE_DISCONNECTED,
    # Filesystem native words
    "accessed": EventType.FILE_ACCESSED,
    "modified": EventType.FILE_MODIFIED,
    "copied": EventType.FILE_COPIED,
    "deleted": EventType.FILE_DELETED,
    "created": EventType.FILE_CREATED,
}

# Canonical names map to themselves (case-insensitive safety net).
for _t in EventType:
    RAW_EVENT_MAP.setdefault(_t.value.lower(), _t)


def normalize_event_type(raw: str) -> EventType:
    """Map one raw vocabulary string onto the canonical enum.

    Raises KeyError on unknown vocabulary (fail loudly, not silently).
    """
    key = str(raw).strip().lower()
    if key in RAW_EVENT_MAP:
        return RAW_EVENT_MAP[key]
    raise KeyError(f"unknown event vocabulary: {raw!r}")


def coerce_event(item: CanonicalEvent | dict) -> CanonicalEvent:
    """Coerce a dict (possibly with a raw `event_type` string) to CanonicalEvent."""
    if isinstance(item, CanonicalEvent):
        if not item.hash:
            import builtins

            builtins.object.__setattr__(item, "hash", item.compute_hash())
        return item
    data = dict(item)
    raw_t = data.get("event_type", "")
    try:
        data["event_type"] = EventType(str(raw_t))
    except ValueError:
        data["event_type"] = normalize_event_type(str(raw_t))
    e = CanonicalEvent(**data)
    if not e.hash:
        import builtins

        builtins.object.__setattr__(e, "hash", e.compute_hash())
    return e


def normalize_events(items: Iterable[CanonicalEvent | dict]) -> list[CanonicalEvent]:
    """Coerce + sort by (timestamp, event_id) + dedup by hash (keep first)."""
    coerced = [coerce_event(i) for i in items]
    coerced.sort(key=lambda e: (e.timestamp, e.event_id))
    seen: set[str] = set()
    out: list[CanonicalEvent] = []
    for e in coerced:
        if e.hash in seen:
            continue
        seen.add(e.hash)
        out.append(e)
    return out


def ingest_events(
    items: Iterable[CanonicalEvent | dict],
    db_url: str | None = None,
    session: Session | None = None,
) -> dict[str, int]:
    """Merge-normalise events into the `events` table. Idempotent on hash.

    Returns {"received": N, "inserted": M, "skipped_duplicates": N-M}.
    Either pass an open Session or a db_url (default data/tracex.db).
    """
    material = list(items)
    events = normalize_events(material)
    received = len(material)
    own_session = False
    if session is None:
        engine = get_engine(db_url) if db_url else get_engine()
        session = Session(engine)
        own_session = True
    try:
        existing = set(session.scalars(select(EventRow.hash)).all())
        inserted = 0
        for e in events:
            if e.hash in existing:
                continue
            session.add(EventRow.from_event(e))
            existing.add(e.hash)
            inserted += 1
        session.commit()
        return {"received": received, "inserted": inserted,
                "skipped_duplicates": received - inserted}
    finally:
        if own_session:
            session.close()

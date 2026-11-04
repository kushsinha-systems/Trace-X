"""Normalisation layer tests — Phase 3. Synthetic/fixture data only."""
from __future__ import annotations

import sqlite3
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"


def _all_fixture_events(tmp_path):
    from backend.app.parsers.browser import parse_browser_sqlite
    from backend.app.parsers.evtx import parse_evtx_jsonl
    from backend.app.parsers.ntfs import parse_mft_csv
    from backend.app.parsers.usb import parse_setupapi_log, parse_usbstor_json

    # Chrome History built programmatically (same helper shape as parser tests)
    import sys

    sys.path.insert(0, str(Path(__file__).parent))
    from test_parsers import _build_chrome_db

    db = tmp_path / "History"
    _build_chrome_db(db)
    events = []
    events += parse_evtx_jsonl(FIX / "evtx_sample.jsonl")       # 5
    events += parse_mft_csv(FIX / "mft_sample.csv")              # 2
    events += parse_browser_sqlite(db, user="alice")             # 2
    events += parse_setupapi_log(FIX / "setupapi_sample.log")    # 2
    events += parse_usbstor_json(FIX / "usbstor_sample.json")    # 2
    return events  # 13 total


def test_raw_vocabulary_map_spec_examples():
    from backend.app.models import EventType
    from backend.app.normalize import normalize_event_type

    assert normalize_event_type("4624") is EventType.LOGIN
    assert normalize_event_type("visit") is EventType.PAGE_VISIT
    assert normalize_event_type("download") is EventType.FILE_DOWNLOAD
    assert normalize_event_type("USB insert") is EventType.DEVICE_CONNECTED
    assert normalize_event_type("1102") is EventType.LOG_CLEARED
    assert normalize_event_type("PAGE_VISIT") is EventType.PAGE_VISIT
    try:
        normalize_event_type("not-a-real-type")
    except KeyError:
        pass
    else:
        raise AssertionError("unknown vocabulary must raise KeyError")


def test_normalize_sorts_and_dedups_by_hash(tmp_path):
    from backend.app.normalize import normalize_events

    events = _all_fixture_events(tmp_path)
    assert len(events) == 13
    doubled = events + events  # exact duplicates (same hashes)
    out = normalize_events(doubled)
    assert len(out) == 13
    ts = [e.timestamp for e in out]
    assert ts == sorted(ts), "merged timeline must be chronological"


def test_ingest_idempotent_and_merged(tmp_path):
    from backend.app.normalize import ingest_events
    from backend.app.models import EventRow
    from sqlalchemy import func
    from sqlalchemy.orm import Session
    from backend.app.database import get_engine

    db_url = f"sqlite:///{tmp_path}/norm.db"
    engine = get_engine(db_url)
    events = _all_fixture_events(tmp_path)

    r1 = ingest_events(events, session=Session(engine))
    assert r1 == {"received": 13, "inserted": 13, "skipped_duplicates": 0}

    r2 = ingest_events(events, session=Session(engine))  # re-ingest: no dupes
    assert r2["inserted"] == 0 and r2["skipped_duplicates"] == 13

    with Session(engine) as s:
        assert s.scalar(func.count(EventRow.event_id)) == 13
        # chronological read-back works (what Phase 4 timeline builds on)
        rows = s.query(EventRow).order_by(EventRow.timestamp).all()
        stamps = [r.timestamp for r in rows]
        assert stamps == sorted(stamps)


def test_coerce_dict_with_raw_strings():
    from backend.app.models import EventSource
    from backend.app.normalize import coerce_event

    e = coerce_event({
        "timestamp": "2026-09-01T10:00:00Z",
        "event_type": "4624",  # raw EVTX vocab, not canonical
        "source": EventSource.WINDOWS_EVENTLOG,
        "provenance": {"source_file": "x", "parser_name": "t",
                       "parser_version": "0", "original_record_offset_or_id": "1"},
    })
    assert e.event_type.value == "LOGIN"
    assert len(e.hash) == 64

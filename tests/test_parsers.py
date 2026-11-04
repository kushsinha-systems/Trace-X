"""Parser unit tests — Phase 2. Each parser has a fixture-backed test."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

FIX = Path(__file__).parent / "fixtures"


def test_evtx_parser_priority_ids_and_provenance():
    from backend.app.parsers.evtx import parse_evtx_jsonl

    events = parse_evtx_jsonl(FIX / "evtx_sample.jsonl")
    by_type = {}
    for e in events:
        by_type.setdefault(e.event_type.value, 0)
        by_type[e.event_type.value] += 1
        assert e.provenance.parser_name == "evtx_parser"
        assert e.provenance.source_file.endswith("evtx_sample.jsonl")
        assert e.hash and len(e.hash) == 64
    # 4624 LOGIN, 4688 PROCESS_CREATED, 4663 FILE_ACCESSED, 4634 LOGOFF, 1102 LOG_CLEARED; 9999 skipped
    assert len(events) == 5, events
    assert by_type.get("LOGIN") == 1
    assert by_type.get("LOG_CLEARED") == 1
    assert by_type.get("LOGOFF") == 1


def test_ntfs_parser_preserves_si_and_fn():
    from backend.app.parsers.ntfs import parse_mft_csv

    events = parse_mft_csv(FIX / "mft_sample.csv")
    assert len(events) == 2
    evil = [e for e in events if "secret.txt" in (e.object or "")][0]
    si = evil.raw_metadata["si_timestamps"]
    fn = evil.raw_metadata["fn_timestamps"]
    assert set(si) == {"si_created", "si_modified", "si_mft_modified", "si_accessed"}
    assert set(fn) == {"fn_created", "fn_modified", "fn_mft_modified", "fn_accessed"}
    # second row is the timestomp-like fixture: SI modified older than FN modified
    assert si["si_modified"] < fn["fn_modified"]
    assert evil.provenance.parser_name == "ntfs_mft_parser"


def _build_chrome_db(path: Path):
    epoch_diff = (datetime(2026, 9, 1, tzinfo=timezone.utc) - datetime(1601, 1, 1, tzinfo=timezone.utc))
    base_us = int(epoch_diff.total_seconds() * 1_000_000)
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    con.execute("CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    con.execute("CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, url TEXT, start_time INTEGER)")
    con.execute("INSERT INTO urls VALUES (1, 'https://example.com/report', 'Report')")
    con.execute("INSERT INTO visits VALUES (1, 1, ?)", (base_us,))
    con.execute("INSERT INTO downloads VALUES (1, 'C:\\Users\\alice\\report.pdf', 'https://example.com/report.pdf', ?)", (base_us + 60_000_000,))
    con.commit()
    con.close()


def test_browser_parser_chrome(tmp_path):
    from backend.app.parsers.browser import parse_browser_sqlite

    db = tmp_path / "History"
    _build_chrome_db(db)
    events = parse_browser_sqlite(db, user="alice")
    kinds = sorted(e.event_type.value for e in events)
    assert kinds == ["FILE_DOWNLOAD", "PAGE_VISIT"], kinds
    assert all(e.source.value == "BROWSER" for e in events)
    assert all(e.user == "alice" for e in events)
    assert events[0].object == "https://example.com/report"


def test_usb_parsers_setupapi_and_usbstor():
    from backend.app.parsers.usb import parse_setupapi_log, parse_usbstor_json

    s = parse_setupapi_log(FIX / "setupapi_sample.log")
    assert len(s) == 2
    assert s[0].event_type.value == "DEVICE_CONNECTED"
    assert s[1].event_type.value == "DEVICE_DISCONNECTED"
    assert "USBSTOR" in (s[0].device_id or "")

    u = parse_usbstor_json(FIX / "usbstor_sample.json")
    assert len(u) == 2  # first_install + last_insert
    assert all(e.event_type.value == "DEVICE_CONNECTED" for e in u)
    assert u[0].user == "alice"


def test_schema_roundtrip_sqlite(tmp_path):
    from backend.app.database import get_engine
    from backend.app.models import EventRow
    from backend.app.parsers.evtx import parse_evtx_jsonl
    from sqlalchemy.orm import Session

    engine = get_engine(f"sqlite:///{tmp_path}/t.db")
    events = parse_evtx_jsonl(FIX / "evtx_sample.jsonl")
    with Session(engine) as s:
        for e in events:
            s.add(EventRow.from_event(e))
        s.commit()
        rows = s.query(EventRow).all()
        assert len(rows) == 5
        e2 = rows[0].to_event()
        assert e2.event_id == events[0].event_id

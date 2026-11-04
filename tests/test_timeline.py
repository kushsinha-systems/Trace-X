"""Timeline engine tests — Phase 4. Synthetic/fixture data only."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session


def _seed(session: Session):
    from backend.app.parsers.evtx import parse_evtx_jsonl
    from backend.app.normalize import ingest_events
    from pathlib import Path

    events = parse_evtx_jsonl(Path("tests/fixtures/evtx_sample.jsonl"))
    return ingest_events(events, session=session)


def test_query_filters():
    from backend.app.database import get_engine
    from backend.app.timeline import query_events
    from sqlalchemy.orm import Session

    engine = get_engine("sqlite:///:memory:")
    with Session(engine) as s:
        _seed(s)
        assert len(query_events(s)) == 5
        assert len(query_events(s, user="alice")) == 5
        assert len(query_events(s, user="nobody")) == 0
        assert len(query_events(s, event_type="LOG_CLEARED")) == 1
        assert len(query_events(s, source="WINDOWS_EVENTLOG")) == 5
        # time-range slice: 10:00–10:02 keeps 4624, 4688, 4663
        got = query_events(s, start="2026-09-01T10:00:00Z", end="2026-09-01T10:02:00Z")
        assert len(got) == 3
        assert [e.timestamp for e in got] == sorted(e.timestamp for e in got)
        # object substring ("secret.txt" appears in 4688 command-line + 4663 object)
        assert len(query_events(s, object_substr="secret.txt")) == 2
        # pagination
        assert len(query_events(s, limit=2, offset=0)) == 2
        assert len(query_events(s, limit=2, offset=4)) == 1


def _evt(ts: str, eid: str = "x"):
    from backend.app.models import CanonicalEvent, EventSource, EventType

    return CanonicalEvent(
        timestamp=ts, event_type=EventType.LOGIN, source=EventSource.WINDOWS_EVENTLOG,
        provenance={"source_file": "t", "parser_name": "t",
                    "parser_version": "0", "original_record_offset_or_id": eid},
    )


def test_gap_detector_threshold_and_active_hours():
    from backend.app.timeline import detect_gaps, GAP_FLAG

    base = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
    iso = lambda m: (base.replace(minute=0) + __import__("datetime").timedelta(minutes=m)).isoformat()
    events = [_evt(iso(0), "a"), _evt(iso(10), "b"), _evt(iso(100), "c")]
    gaps = detect_gaps(events)  # default 30 min
    assert len(gaps) == 1
    assert gaps[0].flag == GAP_FLAG
    assert gaps[0].duration_minutes == 90.0
    assert "does NOT establish" in gaps[0].note  # never a conclusion

    # custom threshold: 120 min -> no gaps
    assert detect_gaps(events, threshold_minutes=120) == []

    # overnight silence not flagged under default active hours (06–22 UTC)
    night = [_evt("2026-09-01T22:10:00Z", "n1"), _evt("2026-09-02T06:10:00Z", "n2")]
    assert detect_gaps(night) == []
    assert len(detect_gaps(night, active_hours=None)) == 1  # opt-out flags everything


def test_gaps_in_store_end_to_end():
    from backend.app.database import get_engine
    from backend.app.timeline import detect_gaps_in_store
    from sqlalchemy.orm import Session

    engine = get_engine("sqlite:///:memory:")
    with Session(engine) as s:
        _seed(s)  # 10:00,10:01,10:02,10:12:43,10:30 — max gap ~17min
        assert detect_gaps_in_store(s) == []
        assert len(detect_gaps_in_store(s, threshold_minutes=5)) == 2

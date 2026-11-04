"""Correlation engine tests — Phase 6. Synthetic data only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)


def _mk(ts, user="alice", obj="C:\\f.txt", dev="D1", proc="p.exe", etype="FILE_ACCESSED"):
    from backend.app.models import CanonicalEvent

    return CanonicalEvent(
        timestamp=ts.isoformat(), event_type=etype, source="WINDOWS_EVENTLOG",
        user=user, object=obj, process=proc, device_id=dev,
        provenance={"source_file": "s", "parser_name": "t",
                    "parser_version": "0", "original_record_offset_or_id": "1"},
    )


def test_pair_weights_and_factors():
    from backend.app.correlation import correlate_pair

    a = _mk(T0)
    b = _mk(T0 + timedelta(minutes=2))  # identical fields, 2 min apart
    c = correlate_pair(a, b)
    # temporal 1-2/30=0.933 ×0.3=0.28; +0.2+0.2+0.15+0.15 = 0.98
    assert c.score == 0.98, c
    assert c.factors == ["events within 2 minutes", "same user", "same file",
                         "same device", "same process"]
    assert "Relationship score: 98%" in c.render()

    # beyond window: temporal 0; all-else-different -> 0.0
    d = _mk(T0 + timedelta(hours=2), user="bob", obj="C:\\g.txt", dev="D2", proc="q.exe")
    c2 = correlate_pair(a, d)
    assert c2.score == 0.0 and c2.subscores["temporal_proximity"] == 0.0


def test_boundary_and_threshold():
    from backend.app.correlation import correlate_all

    # same user+object only, 10 min apart: .3×.667+.2+.2 = 0.6 exactly
    a = _mk(T0, dev="D1", proc="p.exe")
    b = _mk(T0 + timedelta(minutes=10), dev="D2", proc="q.exe")
    all0 = correlate_all([a, b], threshold=0.0)
    assert len(all0) == 1 and all0[0].score == 0.6
    assert correlate_all([a, b], threshold=0.61) == []  # chain threshold 0.6 keeps it
    assert len(correlate_all([a, b], threshold=0.6)) == 1


def test_window_pruning_and_order():
    from backend.app.correlation import correlate_all

    ev = [_mk(T0 + timedelta(minutes=m)) for m in (0, 5, 60)]
    out = correlate_all(ev)  # only (0,5) in-window
    assert len(out) == 1
    assert {out[0].event_id_a, out[0].event_id_b} == {ev[0].event_id, ev[1].event_id}

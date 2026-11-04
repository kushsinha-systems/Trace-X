"""Red-team harness — attack our own rules and measure where detection breaks.

For each rule family, one evasion variable is swept over a range while everything
else is held fixed, and the real detector is run on each variant. The result is a
measured boundary ("detected up to X, missed from Y"), not an assumed one.
Run standalone with tools/redteam.py to write docs/redteam_results.md.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .antiforensics import detect_all
from .normalize import coerce_event

T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)
HOST, USER, F = "HOST-RT", "eve", "C:\\Users\\eve\\plan.docx"


def _ev(minutes: float, etype: str, source: str = "WINDOWS_EVENTLOG", obj: str | None = F,
        raw: dict | None = None, tag: str = "rt"):
    ts = T0 + timedelta(minutes=minutes)
    return coerce_event({
        "timestamp": ts.isoformat(), "event_type": etype, "source": source, "user": USER, "object": obj,
        "process": None, "device_id": HOST, "raw_metadata": dict(raw or {}),
        "provenance": {"source_file": "redteam", "parser_name": "redteam", "parser_version": "1.0",
                       "original_record_offset_or_id": f"{tag}-{etype}-{minutes}"}})


def _hit(events, rule: str):
    fs = [f for f in detect_all(events) if f.rule_name == rule]
    best = max(fs, key=lambda f: f.suspicion_score) if fs else None
    return {"detected": best is not None, "score": best.suspicion_score if best else 0.0,
            "level": best.level if best else "—"}


def _boundary(rows, ok=lambda r: r["detected"]):
    last_ok = first_bad = None
    for r in rows:
        if ok(r):
            if first_bad is None:
                last_ok = r["value"]
        elif first_bad is None:
            first_bad = r["value"]
    return last_ok, first_bad


def sweep_evidence_deletion():
    rows = []
    for g in [1, 2, 4, 6, 8, 10, 12, 13, 14, 15, 16, 18, 20]:
        evs = [_ev(0, "FILE_ACCESSED"), _ev(1, "FILE_COPIED"), _ev(1 + g, "FILE_DELETED")]
        rows.append({"value": g, **_hit(evs, "evidence_deletion")})
    ok, bad = _boundary(rows)
    return {"rule": "evidence_deletion", "variable": "minutes between the copy and the delete", "unit": "min",
            "rows": rows, "last_detected": ok, "first_missed": bad,
            "evasion": f"Wait {bad} min or more after copying before deleting (the access must fall inside the 15-min window)."}


def sweep_log_clearing():
    rows = []
    for g in [1, 5, 10, 20, 30, 40, 45, 50, 60, 61, 70, 90]:
        evs = [_ev(0, "LOGIN", obj=None), _ev(1, "FILE_ACCESSED"), _ev(2, "FILE_COPIED"),
               _ev(3, "FILE_DELETED"), _ev(3 + g, "LOG_CLEARED", obj=None)]
        rows.append({"value": g, **_hit(evs, "log_clearing")})
    ok, bad = _boundary(rows, ok=lambda r: r["level"] == "HIGH")
    return {"rule": "log_clearing", "variable": "minutes between the last activity and the clear", "unit": "min",
            "rows": rows, "last_detected": ok, "first_missed": bad, "measure": "rated HIGH",
            "evasion": f"Clearing {bad} min or more after the activity drops it below HIGH; "
                       "every clear is still recorded (an isolated one scores 0.0 LOW)."}


def sweep_mass_deletion():
    count_rows = []
    for n in range(15, 26):
        evs = [_ev(i * 3 / 60, "FILE_DELETED", obj=f"C:\\data\\f{i}.txt") for i in range(n)]
        count_rows.append({"value": n, **_hit(evs, "mass_deletion")})
    span_rows = []
    for span in [30, 60, 100, 119, 120, 121, 150, 180]:
        evs = [_ev(i * span / 19 / 60, "FILE_DELETED", obj=f"C:\\data\\f{i}.txt") for i in range(20)]
        span_rows.append({"value": span, **_hit(evs, "mass_deletion")})
    first_n = next((r["value"] for r in count_rows if r["detected"]), None)
    ok, bad = _boundary(span_rows)
    return {"rule": "mass_deletion", "variable": "files deleted in under a minute", "unit": "files",
            "rows": count_rows, "spread": {"variable": "seconds to delete 20 files", "unit": "s", "rows": span_rows,
                                           "last_detected": ok, "first_missed": bad},
            "first_detected": first_n,
            "evasion": f"Delete {first_n - 1} files or fewer at a time, or spread 20 deletions over more than {ok} s."}


def _mft(skew_h: float, both: bool = False):
    fn_mod = T0
    si_mod = fn_mod if both else fn_mod - timedelta(hours=skew_h)
    iso = lambda d: d.isoformat()  # noqa: E731
    raw = {"si_timestamps": {"si_created": iso(T0), "si_modified": iso(si_mod), "si_mft_modified": iso(T0),
                             "si_accessed": iso(T0)},
           "fn_timestamps": {"fn_created": iso(T0), "fn_modified": iso(fn_mod), "fn_mft_modified": iso(T0),
                             "fn_accessed": iso(T0)}}
    return [_ev(-5, "FILE_ACCESSED"), _ev(0, "FILE_MODIFIED", source="FILESYSTEM_NTFS", raw=raw)]


def sweep_timestamp_anomaly():
    rows = [{"value": h, **_hit(_mft(h), "timestamp_anomaly")} for h in [0, 0.01, 0.1, 1, 6, 12, 16, 24, 48]]
    both = _hit(_mft(48, both=True), "timestamp_anomaly")
    high_from = next((r["value"] for r in rows if r["level"] == "HIGH"), None)
    return {"rule": "timestamp_anomaly", "variable": "hours $SI was set back from $FN", "unit": "h", "rows": rows,
            "both_rewritten": both, "high_from": high_from,
            "evasion": "Rewrite $FN as well as $SI (e.g. SetMACE) and nothing is flagged; "
                       f"a single-field skew is rated HIGH only from about {high_from} h."}


def sweep_metadata_modification():
    def case(content_gap):
        evs = [_ev(0, "FILE_MODIFIED", obj="C:\\Users\\eve\\report.dll",
                   raw={"extension_before": ".docx", "extension_after": ".dll"})]
        if content_gap is not None:
            evs.insert(0, _ev(-content_gap, "FILE_ACCESSED", obj="C:\\Users\\eve\\report.dll"))
        return _hit(evs, "metadata_modification")
    rows = [{"value": "no content activity", **case(None)}]
    rows += [{"value": f"content activity {g} min before", **case(g)} for g in (5, 30, 59, 61, 120)]
    return {"rule": "metadata_modification", "variable": "content activity on the same file", "unit": "",
            "rows": rows,
            "evasion": "Open or copy the file within 60 min of renaming it and the rename is not flagged."}


def run() -> list[dict]:
    return [sweep_evidence_deletion(), sweep_log_clearing(), sweep_mass_deletion(),
            sweep_timestamp_anomaly(), sweep_metadata_modification()]

"""Anti-forensics engine tests — Phase 5. Synthetic/fixture data only."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

T0 = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)


def _mk(ts: datetime, etype: str, obj: str | None = None, user: str = "alice",
        source: str = "WINDOWS_EVENTLOG", raw: dict | None = None, eid: str | None = None):
    from backend.app.models import CanonicalEvent

    return CanonicalEvent(
        timestamp=ts.isoformat(), event_type=etype, source=source, user=user, object=obj,
        raw_metadata=dict(raw or {}),
        provenance={"source_file": "synth", "parser_name": "test",
                    "parser_version": "0", "original_record_offset_or_id": eid or etype},
    )


def test_evidence_deletion_full_chain_high():
    from backend.app.antiforensics import detect_evidence_deletion

    f = "C:\\case\\secret.txt"
    ev = [_mk(T0, "FILE_ACCESSED", f), _mk(T0 + timedelta(minutes=2), "FILE_COPIED", f),
          _mk(T0 + timedelta(minutes=5), "FILE_DELETED", f)]
    out = detect_evidence_deletion(ev)
    assert len(out) == 1
    assert out[0].rule_name == "evidence_deletion"
    assert out[0].level == "HIGH" and out[0].suspicion_score >= 0.8
    assert set(out[0].indicators) == {"relevant_prior_activity", "short_temporal_distance",
                                      "multiple_related_events", "evidence_directly_affected"}
    # delete alone: no precursors -> no finding (scenario-2 must not escalate)
    assert detect_evidence_deletion([_mk(T0, "FILE_DELETED", f)]) == []
    # outside window -> no finding
    ev2 = [_mk(T0, "FILE_ACCESSED", f), _mk(T0 + timedelta(hours=2), "FILE_DELETED", f)]
    assert detect_evidence_deletion(ev2) == []


def test_log_clearing_context_grading():
    from backend.app.antiforensics import detect_log_clearing

    clear = _mk(T0 + timedelta(minutes=30), "LOG_CLEARED")
    busy = [_mk(T0, "LOGIN"), _mk(T0 + timedelta(minutes=25), "FILE_COPIED", "C:\\a.txt"),
            _mk(T0 + timedelta(minutes=27), "FILE_ACCESSED", "C:\\a.txt"), clear]
    hi = detect_log_clearing(busy)
    assert len(hi) == 1 and hi[0].level == "HIGH"
    # isolated clear: recorded but LOW/0.0 — never suppressed, never auto-malicious
    lone = detect_log_clearing([clear])
    assert len(lone) == 1 and lone[0].suspicion_score == 0.0 and lone[0].level == "LOW"


def test_timestamp_anomaly_si_older_than_fn():
    from backend.app.antiforensics import detect_timestamp_anomaly
    from backend.app.parsers.ntfs import parse_mft_csv
    from pathlib import Path

    ev = parse_mft_csv(Path("tests/fixtures/mft_sample.csv"))
    out = detect_timestamp_anomaly(ev)
    assert len(out) == 1  # only secret.txt row (SI-modified < FN-modified)
    assert out[0].rule_name == "timestamp_anomaly"
    assert "si_modified<fn_modified" in out[0].description
    # clean row alone -> nothing
    assert detect_timestamp_anomaly([e for e in ev if "report.docx" in (e.object or "")]) == []


def test_mass_deletion_threshold():
    from backend.app.antiforensics import detect_mass_deletion

    burst = [_mk(T0 + timedelta(seconds=i * 5), "FILE_DELETED", f"C:\\f{i}.txt") for i in range(20)]
    out = detect_mass_deletion(burst)
    assert len(out) == 1 and out[0].level == "HIGH"
    assert len(out[0].event_ids) == 20
    small = [_mk(T0 + timedelta(seconds=i * 5), "FILE_DELETED", f"C:\\f{i}.txt") for i in range(3)]
    assert detect_mass_deletion(small) == []  # scenario-2 scale must not fire


def test_metadata_modification_and_negative():
    from backend.app.antiforensics import detect_metadata_modification

    sneaky = _mk(T0, "FILE_MODIFIED", "C:\\case\\ledger.xlsx",
                 source="FILESYSTEM_NTFS", raw={"metadata_only": True})
    assert len(detect_metadata_modification([sneaky])) == 1
    ext = _mk(T0, "FILE_MODIFIED", "C:\\case\\x", source="FILESYSTEM_NTFS",
              raw={"extension_before": ".txt", "extension_after": ".exe"})
    assert len(detect_metadata_modification([ext])) == 1
    # same change WITH a nearby content event -> explained, not flagged
    explained = [ext, _mk(T0 + timedelta(minutes=5), "FILE_ACCESSED", "C:\\case\\x")]
    assert detect_metadata_modification(explained) == []


def test_normal_usage_near_zero():
    """Scenario-1 analogue: login, browse, open, USB, logout -> no findings."""
    from backend.app.antiforensics import detect_all

    ev = [_mk(T0, "LOGIN"), _mk(T0 + timedelta(minutes=2), "PAGE_VISIT", "https://example.com", source="BROWSER"),
          _mk(T0 + timedelta(minutes=5), "FILE_ACCESSED", "C:\\notes.txt"),
          _mk(T0 + timedelta(minutes=10), "DEVICE_CONNECTED", "USBSTOR\\X", source="USB"),
          _mk(T0 + timedelta(minutes=30), "LOGOFF")]
    assert detect_all(ev) == []

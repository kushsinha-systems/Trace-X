"""Real-corpus wiring test — runs only when data/real/ downloads exist.

Downloads (git-ignored, see DATASETS.md):
- data/real/charlie-work-usb-2009-12-11.E01 (M57, via tools/real_extract.py)
- data/real/DE_104_system_log_cleared.evtx (EVTX-ATTACK-SAMPLES)
"""
from __future__ import annotations

import shutil

import pytest

E01 = "data/real/charlie-work-usb-2009-12-11.E01"
EVTX = "data/real/DE_104_system_log_cleared.evtx"

needs_e01 = pytest.mark.skipif(not shutil.os.path.exists(E01), reason="real E01 not downloaded")
needs_evtx = pytest.mark.skipif(not shutil.os.path.exists(EVTX), reason="real EVTX not downloaded")


@needs_evtx
def test_real_binary_evtx_log_cleared():
    from backend.app.antiforensics import detect_all
    from backend.app.parsers.evtx import parse_evtx

    ev = parse_evtx(EVTX)
    assert len(ev) == 1
    assert ev[0].event_type.value == "LOG_CLEARED"
    assert ev[0].raw_metadata["event_id_raw"] == 104
    assert ev[0].provenance.parser_name == "evtx_parser"
    (f,) = detect_all(ev)
    assert f.rule_name == "log_clearing" and f.level == "LOW"  # isolated: recorded, not malicious


@needs_e01
def test_real_mft_csv_pipeline(tmp_path):
    from backend.app.antiforensics import detect_all
    from backend.app.normalize import normalize_events
    from backend.app.parsers.ntfs import parse_mft_csv
    from tools.real_extract import extract

    out = str(tmp_path / "charlie_mft.csv")
    stats = extract(E01, out)
    assert stats["rows"] == 128, stats
    ev = normalize_events(parse_mft_csv(out))
    assert len(ev) == 128
    rules = {f.rule_name for f in detect_all(ev)}
    assert rules == {"timestamp_anomaly"}  # benign copy pattern only; no chains/escalation

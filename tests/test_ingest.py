"""tools/ingest.py: folder of collected evidence -> event store. Fixtures only, temp store."""
from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

FIX = Path(__file__).parent / "fixtures"


def _evidence_folder(tmp_path: Path) -> Path:
    from test_parsers import _build_chrome_db  # tests/ is on sys.path under pytest

    case = tmp_path / "case"
    (case / "logs").mkdir(parents=True)
    shutil.copy(FIX / "evtx_sample.jsonl", case / "logs" / "security_export.jsonl")
    shutil.copy(FIX / "mft_sample.csv", case / "mft.csv")
    shutil.copy(FIX / "setupapi_sample.log", case / "setupapi.dev.log")
    shutil.copy(FIX / "usbstor_sample.json", case / "usbstor.json")
    _build_chrome_db(case / "History")
    (case / "notes.txt").write_text("investigator notes, not an artefact")
    return case


def _snapshot(folder: Path) -> dict[str, str]:
    return {str(p.relative_to(folder)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(folder.rglob("*")) if p.is_file()}


def _count(db_url: str) -> int:
    from backend.app.database import get_engine
    from backend.app.models import EventRow

    with Session(get_engine(db_url)) as s:
        return s.scalar(func.count(EventRow.event_id))


def test_ingest_recognises_each_artefact_and_replaces_store(tmp_path):
    from tools.ingest import run

    case = _evidence_folder(tmp_path)
    db = f"sqlite:///{(tmp_path / 'store.db').as_posix()}"
    before = _snapshot(case)

    s = run(case, db_url=db, user="alice", out=lambda *_: None)
    kinds = {m["file"].replace("\\", "/"): m["recognised_as"] for m in s["manifest"]}
    assert kinds == {"History": "chrome_history", "logs/security_export.jsonl": "evtx_jsonl",
                     "mft.csv": "mft_csv", "notes.txt": None, "setupapi.dev.log": "setupapi_log",
                     "usbstor.json": "usbstor_json"}
    assert s["errors"] == 0 and s["events"] > 0
    assert s["store"]["mode"] == "replace" and _count(db) == s["store"]["inserted"]
    assert all(len(m["sha256"]) == 64 for m in s["manifest"])

    # evidence folder untouched: same files, same bytes, no SQLite side-files
    assert _snapshot(case) == before

    # re-running replaces rather than piling up
    s2 = run(case, db_url=db, user="alice", out=lambda *_: None)
    assert s2["store"]["removed"] == s["store"]["inserted"] and _count(db) == s["store"]["inserted"]


def test_browser_provenance_names_the_evidence_file_not_a_temp_copy(tmp_path):
    from backend.app.database import get_engine
    from backend.app.models import EventRow
    from tools.ingest import run

    case = _evidence_folder(tmp_path)
    db = f"sqlite:///{(tmp_path / 'store.db').as_posix()}"
    run(case, db_url=db, user="alice", out=lambda *_: None)
    with Session(get_engine(db)) as s:
        browser = [r.to_event() for r in s.query(EventRow).all() if r.source == "BROWSER"]
    assert browser and all(e.provenance.source_file == str((case / "History").resolve()) for e in browser)
    assert all(e.user == "alice" for e in browser)


def test_dry_run_and_empty_folder_never_touch_the_store(tmp_path):
    from tools.ingest import run

    db = f"sqlite:///{(tmp_path / 'store.db').as_posix()}"
    run(_evidence_folder(tmp_path), db_url=db, out=lambda *_: None)
    n = _count(db)

    s = run(tmp_path / "case", db_url=db, dry_run=True, out=lambda *_: None)
    assert s["store"] is None and _count(db) == n

    empty = tmp_path / "empty"
    empty.mkdir()
    s = run(empty, db_url=db, out=lambda *_: None)
    assert s["store"] is None and _count(db) == n  # refuses to wipe the case with nothing


def test_append_keeps_existing_events(tmp_path):
    from tools.ingest import run

    case = _evidence_folder(tmp_path)
    db = f"sqlite:///{(tmp_path / 'store.db').as_posix()}"
    first = run(case, db_url=db, out=lambda *_: None)["store"]["inserted"]
    s = run(case, db_url=db, append=True, out=lambda *_: None)
    assert s["store"]["removed"] == 0 and s["store"]["inserted"] == 0  # same records dedupe by hash
    assert _count(db) == first

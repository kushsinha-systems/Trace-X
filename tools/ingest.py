"""TRACE-X evidence ingest — load a folder of collected artefacts into the store.

Run from anywhere:
    python tools/ingest.py <evidence-folder> [--user NAME] [--append] [--dry-run]
                           [--manifest intake.json] [--db sqlite:///path/to.db]

Walks the folder, recognises each file by content (magic bytes / header) with the
filename as a fallback, runs the matching Phase-2 parser, and REPLACES the event
store with the result (pass --append to add instead). Before parsing, every file
is SHA-256 hashed into an intake manifest, and SQLite databases are parsed from a
temporary copy, so the evidence folder itself is never written to.

Recognised inputs:
  *.evtx (binary, "ElfFile")          -> parsers.evtx.parse_evtx
  *.jsonl EVTX export (EventID lines)  -> parsers.evtx.parse_evtx_jsonl
  *.E01 disk image                     -> tools.real_extract.extract -> parsers.ntfs.parse_mft_csv
  MFT CSV (si_*/fn_* columns)          -> parsers.ntfs.parse_mft_csv
  Chrome History / Firefox places.sqlite -> parsers.browser.parse_browser_sqlite
  setupapi*.log                        -> parsers.usb.parse_setupapi_log
  USBSTOR JSON export ([{"device":..}])  -> parsers.usb.parse_usbstor_json
  Registry hive ("regf", e.g. SYSTEM)  -> parsers.usb.parse_registry_hive (needs python-registry)
Anything else is listed as skipped, never guessed at.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import delete  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from backend.app.database import get_engine  # noqa: E402
from backend.app.models import EventRow  # noqa: E402
from backend.app.normalize import ingest_events  # noqa: E402
from backend.app.parsers.browser import parse_browser_sqlite  # noqa: E402
from backend.app.parsers.evtx import parse_evtx, parse_evtx_jsonl  # noqa: E402
from backend.app.parsers.ntfs import parse_mft_csv  # noqa: E402
from backend.app.parsers.usb import parse_registry_hive, parse_setupapi_log, parse_usbstor_json  # noqa: E402

DEFAULT_DB = f"sqlite:///{(ROOT / 'data' / 'tracex.db').as_posix()}"


@dataclass
class Item:
    path: Path
    sha256: str
    size: int
    kind: str | None = None          # what it was recognised as
    events: int = 0
    note: str = ""                   # skip reason or error
    parsed: list = field(default_factory=list, repr=False)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _head(path: Path, n: int = 16) -> bytes:
    with path.open("rb") as fh:
        return fh.read(n)


def _first_line(path: Path) -> str:
    with path.open(encoding="utf-8", errors="replace") as fh:
        return fh.readline().strip()


def _sqlite_tables(path: Path) -> set[str]:
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro&immutable=1", uri=True)
    try:
        return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        con.close()


def _on_copy(fn: Callable, path: Path, workdir: Path, **kw):
    """Parse a temporary copy so the original evidence file is never opened for writing."""
    copy = workdir / f"{sha256_of(path)[:12]}_{path.name}"
    shutil.copy2(path, copy)
    events = fn(copy, **kw)
    for e in events:  # provenance names the evidence file, not the throwaway copy
        e.provenance.source_file = str(path)
    return events


def detect(path: Path) -> str | None:
    """Recognise an artefact by content first, filename second."""
    head, name, suf = _head(path), path.name.lower(), path.suffix.lower()
    if head.startswith(b"ElfFile\x00"):
        return "evtx"
    if head.startswith(b"regf"):
        return "registry_hive"
    if head.startswith(b"SQLite format 3\x00"):
        tables = _sqlite_tables(path)
        if {"urls", "visits"} <= tables:
            return "chrome_history"
        if {"moz_places", "moz_historyvisits"} <= tables:
            return "firefox_history"
        return None
    if suf == ".e01" or head.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
        return "e01_image"
    if suf == ".jsonl" and '"EventID"' in _first_line(path):
        return "evtx_jsonl"
    if suf == ".csv":
        header = next(csv.reader([_first_line(path)]), [])
        if {"si_modified", "fn_modified"} <= set(header):
            return "mft_csv"
        return None
    if name.startswith("setupapi") and suf == ".log":
        return "setupapi_log"
    if suf == ".json":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if isinstance(data, list) and data and isinstance(data[0], dict) and "device" in data[0]:
            return "usbstor_json"
    return None


def parse(item: Item, workdir: Path, user: str | None) -> list:
    p, k = item.path, item.kind
    if k == "evtx":
        return parse_evtx(p)
    if k == "evtx_jsonl":
        return parse_evtx_jsonl(p)
    if k == "mft_csv":
        return parse_mft_csv(p)
    if k in ("chrome_history", "firefox_history"):
        return _on_copy(parse_browser_sqlite, p, workdir, user=user)
    if k == "setupapi_log":
        return parse_setupapi_log(p)
    if k == "usbstor_json":
        return parse_usbstor_json(p)
    if k == "registry_hive":
        return parse_registry_hive(p) or []
    if k == "e01_image":
        from tools.real_extract import extract

        out = workdir / f"{p.stem}_mft.csv"
        extract(str(p), str(out))
        events = parse_mft_csv(out)
        for e in events:  # provenance points at the image, not the temporary CSV
            e.provenance.source_file = f"{p} (NTFS $MFT via real_extract)"
        return events
    raise ValueError(f"no parser for kind {k!r}")


def run(folder: Path, *, db_url: str = DEFAULT_DB, user: str | None = None, append: bool = False,
        dry_run: bool = False, manifest: Path | None = None, out=print) -> dict:
    folder = folder.resolve()
    if not folder.is_dir():
        raise SystemExit(f"not a folder: {folder}")
    files = sorted(p for p in folder.rglob("*") if p.is_file())
    items = [Item(path=p, sha256=sha256_of(p), size=p.stat().st_size) for p in files]

    with tempfile.TemporaryDirectory(prefix="tracex_ingest_") as tmp:
        workdir = Path(tmp)
        for it in items:
            try:
                it.kind = detect(it.path)
            except Exception as exc:  # unreadable header etc.
                it.note = f"could not inspect: {exc}"
                continue
            if it.kind is None:
                it.note = "not a recognised artefact"
                continue
            if it.kind == "e01_image" and it.path.suffix.lower() not in (".e01", ""):
                it.kind, it.note = None, "E01 continuation segment (read via the .E01)"
                continue
            try:
                it.parsed = parse(it, workdir, user)
                it.events = len(it.parsed)
            except Exception as exc:
                it.note = f"error: {type(exc).__name__}: {exc}"

    # ---- intake table -------------------------------------------------------
    out(f"TRACE-X ingest: {folder}")
    out(f"{'file':<44} {'recognised as':<16} {'events':>7}  sha256 (first 16)  note")
    for it in items:
        rel = str(it.path.relative_to(folder))
        rel = rel if len(rel) <= 44 else "…" + rel[-43:]
        out(f"{rel:<44} {it.kind or '-':<16} {it.events:>7}  {it.sha256[:16]}  {it.note}")
    events = [e for it in items for e in it.parsed]
    errors = [it for it in items if it.note.startswith("error")]
    summary = {"folder": str(folder), "files": len(items),
               "parsed_files": sum(1 for it in items if it.kind and not it.note),
               "events": len(events), "errors": len(errors), "store": None,
               "manifest": [{"file": str(it.path.relative_to(folder)), "sha256": it.sha256,
                             "bytes": it.size, "recognised_as": it.kind, "events": it.events,
                             "note": it.note} for it in items]}
    if manifest:
        manifest.write_text(json.dumps(summary["manifest"], indent=2), encoding="utf-8")
        out(f"intake manifest written: {manifest}")

    if dry_run:
        out(f"dry run: {len(events)} events parsed; store not touched.")
        return summary
    if not events and not append:
        out("no events parsed: refusing to replace the store with an empty case.")
        return summary

    # ---- load the store (replace by default, in one transaction) -----------
    with Session(get_engine(db_url)) as s:
        removed = s.execute(delete(EventRow)).rowcount if not append else 0
        res = ingest_events(events, session=s)
    summary["store"] = {**res, "removed": removed, "mode": "append" if append else "replace"}
    from backend.app.integrity import seal  # seal the loaded case so later edits are detectable
    from backend.app.timeline import query_events

    engine = get_engine(db_url)
    with Session(engine) as s:
        sealed = seal(query_events(s, limit=100_000), engine.url.database, reason=f"ingest: {folder}")
    summary["store"]["case_hash"] = sealed["case_hash"]
    out(f"store {'appended' if append else 'replaced'}: removed {removed}, "
        f"inserted {res['inserted']}, duplicates skipped {res['skipped_duplicates']}.")
    out(f"case sealed: {sealed['case_hash']}  (verify any time from the dashboard's Assurance tab)")
    out("Open the dashboard (or refresh it) to analyse this case.")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Load a folder of collected evidence into the TRACE-X store.")
    ap.add_argument("folder", type=Path, help="folder of collected artefacts (searched recursively)")
    ap.add_argument("--user", help="user name to attach to browser history (browser DBs carry none)")
    ap.add_argument("--append", action="store_true", help="add to the store instead of replacing it")
    ap.add_argument("--dry-run", action="store_true", help="recognise and parse only; don't touch the store")
    ap.add_argument("--manifest", type=Path, help="write the SHA-256 intake manifest to this JSON file")
    ap.add_argument("--db", default=DEFAULT_DB, help=f"store URL (default {DEFAULT_DB})")
    a = ap.parse_args(argv)
    summary = run(a.folder, db_url=a.db, user=a.user, append=a.append, dry_run=a.dry_run,
                  manifest=a.manifest)
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())

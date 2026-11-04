"""TRACE-X live monitor — demo/monitoring mode, NOT forensic acquisition.

Watches this machine as it is used and appends what it sees to a SEPARATE live
store (default data/live.db), so the dashboard can show the timeline growing:

    python tools/live.py --watch C:\\Users\\me\\Documents\\demo

Then run the API on that store and open the dashboard (see README, "Live mode").

Sources (no extra libraries, no admin needed except where noted):
  * files   — polls the watched folder(s): FILE_CREATED / FILE_MODIFIED / FILE_DELETED.
              A new file with byte-identical content to a watched file is a COPY: the
              source is recorded as FILE_ACCESSED + FILE_COPIED (raw_metadata.inferred
              says so), because copying necessarily reads it.
  * USB     — removable volumes appearing / disappearing: DEVICE_CONNECTED / _DISCONNECTED.
              Connected volumes are watched too, so a copy onto the stick is seen.
  * logs    — System log clears (104) always; Security log clears (1102) and interactive
              logons (4624) only when run as administrator.

Limits, by design: Windows does not log file reads unless object-access auditing is
enabled, so "opened" is only ever inferred from a copy; renames and save-by-replace are
inferred from matching size + modified time (one event, not delete + create); app scratch
files (Office ~$ / ~WRL, .tmp, partial downloads) are skipped; $SI/$FN timestamps are not
read live. A live collector changes the system it
observes, which is why TRACE-X's evidential workflow stays post-mortem (tools/ingest.py).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import delete  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from backend.app.database import get_engine  # noqa: E402
from backend.app.models import CanonicalEvent, EventRow, EventSource, EventType  # noqa: E402
from backend.app.normalize import ingest_events  # noqa: E402
from backend.app.parsers.common import make_event  # noqa: E402
from backend.app.parsers.evtx import map_record  # noqa: E402

PARSER = "live_monitor"
VERSION = "0.1.0"
LIVE_DB = f"sqlite:///{(ROOT / 'data' / 'live.db').as_posix()}"
HASH_LIMIT = 50 * 1024 * 1024   # don't hash files above 50 MB for copy detection
MAX_FILES = 5000                # per watched root (protects against huge USB drives)
GONE_GRACE_S = 60               # a deleted file stays a possible copy source this long
# Scratch files apps create and remove on their own (Office ~$ owner files and ~WRL/~WRD temps,
# LibreOffice .~lock, editor .tmp/.swp, partial downloads, shell files): not user activity, and
# reporting them filled the timeline with deletes nobody made.
TRANSIENT = re.compile(r"^~|^\.~lock\.|\.(tmp|temp|crdownload|part|partial|download|swp|swx)\d*$"
                       r"|^(thumbs\.db|desktop\.ini|\.ds_store)$", re.IGNORECASE)
SKIP_DIRS = {"$recycle.bin", "system volume information"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _mtime(ns: int) -> datetime:
    return datetime.fromtimestamp(ns / 1e9, tz=timezone.utc)


# --------------------------------------------------------------------------- files
def _same_volume(a: Path, b: Path) -> bool:
    """Same drive letter on Windows (a rename can't cross drives); elsewhere, same device."""
    da, db = Path(a).drive.lower(), Path(b).drive.lower()
    if da or db:
        return da == db
    try:
        return os.stat(Path(a).parent).st_dev == os.stat(Path(b).parent).st_dev
    except OSError:
        return False


class FolderWatcher:
    """Polling diff of one or more folder trees -> canonical file events."""

    def __init__(self, roots: Iterable[Path], *, user: str, host: str, clock: Callable[[], datetime] = _now):
        self.user, self.host, self.clock = user, host, clock
        self.snap: dict[Path, dict[Path, tuple[int, int]]] = {}
        self._hashes: dict[tuple[Path, int, int], str] = {}
        self._seq = 0
        self._prehashed: set[Path] = set()
        self._pending: dict[Path, tuple[int, int, datetime, Path]] = {}  # new files not yet settled
        self._gone: dict[Path, tuple[int, int, datetime]] = {}  # recently deleted, still valid copy sources
        self._unmatched: dict[Path, datetime] = {}  # new files no copy source matched (yet)
        self._created_as: dict[Path, Path] = {}  # pending file -> the name it first appeared under
        self._truncated: set[Path] = set()  # roots whose last scan stopped at MAX_FILES
        self._since: dict[Path, float] = {}  # root -> wall-clock time watching began
        for r in roots:
            self.add_root(Path(r), prehash=True)

    def add_root(self, root: Path, *, prehash: bool = False) -> None:
        """Start watching; files already there are the baseline, not events.

        prehash: fingerprint the baseline now, so a file that is copied and then
        deleted before the next poll can still be matched as the copy's source.
        """
        root = root.resolve()
        if root not in self.snap:
            self._since[root] = time.time()
            self.snap[root] = self._scan(root)
            if prehash:
                self._prehashed.add(root)
                for p, (size, mt) in self.snap[root].items():
                    self._sha(p, size, mt)

    def drop_root(self, root: Path) -> None:
        """Stop watching (e.g. USB removed) WITHOUT reporting its files as deleted."""
        self.snap.pop(root.resolve(), None)
        self._prehashed.discard(root.resolve())
        self._truncated.discard(root.resolve())
        for p in [q for q, v in self._pending.items() if v[3] == root.resolve()]:
            del self._pending[p]
            self._created_as.pop(p, None)

    def _scan(self, root: Path, prev: dict[Path, tuple[int, int]] | None = None) -> dict[Path, tuple[int, int]]:
        """Size and mtime of every file under root, minus app scratch files (TRANSIENT).
        A file that exists but can't be read this pass keeps its last state: it wasn't deleted."""
        out: dict[Path, tuple[int, int]] = {}
        self._truncated.discard(root)
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
            for f in files:
                if TRANSIENT.search(f):
                    continue
                p = Path(dirpath) / f
                try:
                    st = p.stat()
                except FileNotFoundError:
                    continue
                except OSError:
                    if prev and p in prev:
                        out[p] = prev[p]
                    continue
                out[p] = (st.st_size, st.st_mtime_ns)
                if len(out) >= MAX_FILES:
                    self._truncated.add(root)
                    return out
        return out

    def _predates(self, p: Path, root: Path) -> bool:
        """The file was created before this root was first scanned (Windows st_ctime is creation time)."""
        try:
            st = p.stat()
        except OSError:
            return False
        born = getattr(st, "st_birthtime", st.st_ctime if os.name == "nt" else None)
        return born is not None and born < self._since.get(root, 0)

    def _sha(self, p: Path, size: int, mtime: int) -> str | None:
        if size > HASH_LIMIT:
            return None
        key = (p, size, mtime)
        if key not in self._hashes:
            try:
                self._hashes[key] = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                return None
        return self._hashes[key]

    def _ev(self, ts: datetime, etype: EventType, obj: Path, raw: dict) -> CanonicalEvent:
        self._seq += 1
        return make_event(timestamp=ts, event_type=etype, source=EventSource.FILESYSTEM_NTFS,
                          parser_name=PARSER, parser_version=VERSION, source_file=f"live:{obj.parent}",
                          record_id=f"fs-{self._seq}-{obj.name}", user=self.user, object=str(obj),
                          device_id=self.host, raw_metadata={"path": str(obj), **raw})

    def poll(self) -> list[CanonicalEvent]:
        """One diff pass. A NEW file is reported only once it has settled (same size and
        mtime on two consecutive polls): Windows creates a copy empty and fills it in, so
        judging it on first sight would miss the copy and record a spurious modification."""
        now = self.clock()
        self._gone = {p: v for p, v in self._gone.items() if (now - v[2]).total_seconds() <= GONE_GRACE_S}
        self._unmatched = {p: t for p, t in self._unmatched.items() if (now - t).total_seconds() <= GONE_GRACE_S}
        old_all = {p: v for s in self.snap.values() for p, v in s.items()}
        old_all.update({p: v[:2] for p, v in self._gone.items() if p not in old_all})
        events: list[CanonicalEvent] = []
        new_snaps = {root: self._scan(root, self.snap[root]) for root in self.snap}
        renamed = self._match_renames(new_snaps)  # new path -> old path
        replaced = self._match_replaces(new_snaps, renamed)  # target -> temp file saved over it
        self._carry_pending_renames(new_snaps, renamed, replaced)
        for root, new in new_snaps.items():
            old = self.snap[root]
            committed: dict[Path, tuple[int, int]] = {}
            for p, (size, mt) in new.items():
                if p in renamed:  # one event for a rename / same-drive move, not delete + create
                    was = renamed[p]
                    committed[p] = (size, mt)
                    if root in self._prehashed:
                        self._sha(p, size, mt)
                    raw = {"renamed_from": str(was), "rename": True, "size": size}
                    if was.suffix.lower() != p.suffix.lower():  # what metadata_modification looks for
                        raw.update(extension_before=was.suffix or "(none)", extension_after=p.suffix or "(none)")
                    events.append(self._ev(now, EventType.FILE_MODIFIED, p, raw))
                    continue
                if p not in old:
                    if root in self._truncated and self._predates(p, root):
                        committed[p] = (size, mt)  # was there all along, just beyond the scan cap
                        continue
                    seen = self._pending.get(p)
                    if seen is None or seen[:2] != (size, mt):  # first sight, or still being written
                        self._pending[p] = (size, mt, seen[2] if seen else now, root)
                        continue
                    del self._pending[p]
                    committed[p] = (size, mt)
                    ts = seen[2]  # when it appeared; not mtime, which a Windows copy inherits
                    src = self._copy_source(p, size, mt, old_all)
                    if root in self._prehashed:
                        self._sha(p, size, mt)  # so a later copy of THIS file can be matched too
                    if src is not None:
                        info = {"inferred": "copy detected: identical SHA-256 content", "copied_to": str(p)}
                        # the read necessarily precedes the copy; 1 µs keeps that order on the timeline
                        events.append(self._ev(ts - timedelta(microseconds=1), EventType.FILE_ACCESSED, src, info))
                        events.append(self._ev(ts, EventType.FILE_COPIED, src, info))
                    first_name = self._created_as.pop(p, None)
                    events.append(self._ev(ts, EventType.FILE_CREATED, p,
                                           {"size": size, **({"copied_from": str(src)} if src else {}),
                                            **({"created_as": str(first_name)} if first_name else {})}))
                    if src is None:
                        self._unmatched[p] = ts
                    continue
                committed[p] = (size, mt)
                if p in replaced:
                    # save-by-replace: the app wrote a temp file and renamed it over this one -> one edit
                    self._unmatched.pop(p, None)
                    if root in self._prehashed:
                        self._sha(p, size, mt)
                    events.append(self._ev(min(_mtime(mt), now), EventType.FILE_MODIFIED, p,
                                           {"old_size": old[p][0], "new_size": size, "mtime_ns": mt,
                                            "content_write": True, "saved_via": str(replaced[p])}))
                    continue
                if old[p] != (size, mt) and p in self._unmatched:
                    # a copy that settled before its content arrived (pre-sized or stalled): match it now
                    src = self._copy_source(p, size, mt, old_all)
                    if src is not None:
                        del self._unmatched[p]
                        info = {"inferred": "copy detected: identical SHA-256 content once writing finished",
                                "copied_to": str(p)}
                        events.append(self._ev(now - timedelta(microseconds=1), EventType.FILE_ACCESSED, src, info))
                        events.append(self._ev(now, EventType.FILE_COPIED, src, info))
                        continue  # the write that completed the copy is not a separate edit
                if old[p] != (size, mt):
                    if root in self._prehashed:
                        self._sha(p, size, mt)  # keep the fingerprint current for copy matching
                    events.append(self._ev(min(_mtime(mt), now), EventType.FILE_MODIFIED, p,
                                           {"old_size": old[p][0], "new_size": size, "mtime_ns": mt,
                                            # a write IS a content change: no size_before/size_after keys,
                                            # which metadata_modification reads as "size changed, content not"
                                            "content_write": True}))
            for p in old.keys() - new.keys():
                if p in renamed.values() or p in replaced.values():
                    continue  # it was renamed, moved or saved over another file, not deleted
                if root in self._truncated and p.exists():
                    committed[p] = old[p]  # beyond the scan cap this pass, still on disk
                    continue
                events.append(self._ev(now, EventType.FILE_DELETED, p, {"last_size": old[p][0]}))
                self._gone[p] = (*old[p], now)  # a copy still settling may have come from it (a 'move')
            for p in [q for q, v in self._pending.items() if v[3] == root and q not in new]:
                size, _mt, first, _root = self._pending.pop(p)  # appeared and vanished before settling
                first_name = self._created_as.pop(p, None)
                if p in replaced.values():
                    continue  # a temp file that became another file's new content
                events.append(self._ev(first, EventType.FILE_CREATED, p,
                                       {"size": size, "short_lived": True,
                                        **({"created_as": str(first_name)} if first_name else {})}))
                events.append(self._ev(now, EventType.FILE_DELETED, p, {"last_size": size}))
            self.snap[root] = committed
        return events

    def _match_renames(self, new_snaps: dict[Path, dict[Path, tuple[int, int]]]) -> dict[Path, Path]:
        """A file that vanishes while one with the same size and modified time appears in the SAME
        pass, on the SAME drive, was renamed or moved: a rename keeps both, and a same-drive move
        rewrites no data. A move to another drive (e.g. a USB stick) is a real copy + delete and is
        left to copy detection, so 'move to stick' still raises evidence_deletion."""
        vanished = {p: v for root, new in new_snaps.items() for p, v in self.snap[root].items() if p not in new}
        appeared = {p: v for root, new in new_snaps.items() for p, v in new.items()
                    if p not in self.snap[root] and p not in self._pending}
        out: dict[Path, Path] = {}
        for q, v in appeared.items():
            for p, pv in vanished.items():
                if p in out.values() or pv != v or not _same_volume(p, q):
                    continue
                before = self._hashes.get((p, *pv))  # fingerprint, when we have one, must match too
                if before is not None and self._sha(q, *v) != before:
                    continue
                out[q] = p
                break
        return out

    def _match_replaces(self, new_snaps: dict[Path, dict[Path, tuple[int, int]]],
                        renamed: dict[Path, Path]) -> dict[Path, Path]:
        """Save-by-replace: an app writes its new version to a temp file, then renames it over the
        original. The temp file vanishes in the same pass as an existing file takes on its exact
        size and modified time (a rename keeps both), so that is one edit, not a delete."""
        vanished: dict[Path, tuple[int, int]] = {}
        for root, new in new_snaps.items():
            vanished.update({p: v for p, v in self.snap[root].items() if p not in new and p not in renamed.values()})
            vanished.update({p: v[:2] for p, v in self._pending.items() if v[3] == root and p not in new})
        out: dict[Path, Path] = {}
        for root, new in new_snaps.items():
            old = self.snap[root]
            for q, v in new.items():
                if q not in old or old[q] == v:
                    continue
                p = next((p for p, pv in vanished.items()
                          if pv == v and p not in out.values() and _same_volume(p, q)), None)
                if p is not None:
                    out[q] = p
        return out

    def _carry_pending_renames(self, new_snaps: dict[Path, dict[Path, tuple[int, int]]],
                               renamed: dict[Path, Path], replaced: dict[Path, Path]) -> None:
        """A new file renamed before it settled (Explorer: New > Text Document, then a name typed
        within a second) is one new file: its pending entry moves to the new name, keeping when it
        first appeared, instead of a short-lived create + delete under the first name."""
        appeared = {q: root for root, new in new_snaps.items() for q in new
                    if q not in self.snap[root] and q not in self._pending and q not in renamed}
        for p, (size, mt, first, root) in list(self._pending.items()):
            if root not in new_snaps or p in new_snaps[root] or p in replaced.values():
                continue
            q = next((q for q, qroot in appeared.items()
                      if new_snaps[qroot][q] == (size, mt) and _same_volume(p, q)), None)
            if q is None:
                continue
            del self._pending[p]
            self._pending[q] = (size, mt, first, appeared.pop(q))
            self._created_as[q] = self._created_as.pop(p, p)

    def _copy_source(self, p: Path, size: int, mt: int, known: dict[Path, tuple[int, int]]) -> Path | None:
        candidates = [q for q, (s, m) in known.items() if s == size and q != p and size > 0]
        if not candidates:
            return None
        h = self._sha(p, size, mt)
        for q in candidates:
            if h is not None and self._sha(q, *known[q]) == h:
                return q
        return None


# --------------------------------------------------------------------------- USB
def removable_volumes() -> dict[str, str]:
    """{'E:\\': 'USB volume E: label=KINGSTON serial=1A2B3C4D'} for removable drives (Windows)."""
    if os.name != "nt":
        return {}
    import ctypes

    k32 = ctypes.windll.kernel32
    mask, out = k32.GetLogicalDrives(), {}
    for i in range(26):
        if not mask & (1 << i):
            continue
        root = f"{chr(65 + i)}:\\"
        if k32.GetDriveTypeW(root) != 2:  # DRIVE_REMOVABLE
            continue
        label = ctypes.create_unicode_buffer(256)
        serial = ctypes.c_uint32()
        ok = k32.GetVolumeInformationW(root, label, 256, ctypes.byref(serial), None, None, None, 0)
        if ok:
            out[root] = f"USB volume {root[:2]} label={label.value or '-'} serial={serial.value:08X}"
    return out


class UsbWatcher:
    def __init__(self, *, user: str, host: str, folders: FolderWatcher | None = None,
                 lister: Callable[[], dict[str, str]] = removable_volumes, clock: Callable[[], datetime] = _now):
        self.user, self.host, self.folders, self.lister, self.clock = user, host, folders, lister, clock
        self.present = lister()
        for root in self.present:
            if folders:
                folders.add_root(Path(root))

    def poll(self) -> list[CanonicalEvent]:
        now, cur, events = self.clock(), self.lister(), []
        for root in cur.keys() - self.present.keys():
            events.append(self._ev(now, EventType.DEVICE_CONNECTED, cur[root], root))
            if self.folders:
                self.folders.add_root(Path(root))
        for root in self.present.keys() - cur.keys():
            events.append(self._ev(now, EventType.DEVICE_DISCONNECTED, self.present[root], root))
            if self.folders:
                self.folders.drop_root(Path(root))
        self.present = cur
        return events

    def _ev(self, ts, etype, dev: str, root: str) -> CanonicalEvent:
        return make_event(timestamp=ts, event_type=etype, source=EventSource.USB, parser_name=PARSER,
                          parser_version=VERSION, source_file="live:removable-volumes",
                          record_id=f"usb-{etype.value}-{ts.isoformat()}", user=self.user, object=dev,
                          device_id=self.host, raw_metadata={"mount": root})


# --------------------------------------------------------------------------- event logs
LOG_QUERIES = {"System": "EventID=104", "Security": "EventID=1102 or EventID=4624"}
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def events_from_xml(xml_text: str, log: str, host: str) -> list[CanonicalEvent]:
    """Map `wevtutil qe /f:xml` output (one or more <Event>) to canonical events."""
    out = []
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    for ev in root.findall("e:Event", _NS):
        sysn = ev.find("e:System", _NS)
        eid = int(sysn.findtext("e:EventID", default="0", namespaces=_NS))
        ts = sysn.find("e:TimeCreated", _NS).get("SystemTime")
        ts = re.sub(r"(\.\d{6})\d+", r"\1", ts)  # Windows writes 7 fractional digits; Python 3.10 reads 6
        rid = sysn.findtext("e:EventRecordID", default="?", namespaces=_NS)
        data = {d.get("Name"): (d.text or "") for d in ev.iter() if d.tag.endswith("Data") and d.get("Name")}
        for el in ev.iter():  # 104 / 1102 keep the user under UserData/*/SubjectUserName
            if el.tag.endswith("SubjectUserName") and el.text:
                data.setdefault("SubjectUserName", el.text)
        if eid == 4624:
            if data.get("LogonType") not in ("2", "10", "11") or data.get("TargetUserName", "").endswith("$"):
                continue  # keep interactive human logons only; services log on constantly
        e = map_record({"EventID": eid, "TimeCreated": ts, "EventRecordID": rid,
                        "TargetUser": data.get("TargetUserName"), "SubjectUser": data.get("SubjectUserName"),
                        "Channel": log, "LogonType": data.get("LogonType")},
                       source_file=f"live:{log} event log", record_id=f"{log}-{rid}")
        if e is not None:
            e.device_id = host
            out.append(e)
    return out


class EventLogWatcher:
    def __init__(self, *, host: str, since: datetime, run: Callable[[list[str]], subprocess.CompletedProcess] | None = None):
        self.host, self.since = host, since
        self.run = run or (lambda args: subprocess.run(args, capture_output=True, text=True, timeout=20))
        self.seen: set[tuple[str, str]] = set()
        self.denied: set[str] = set()

    def poll(self) -> list[CanonicalEvent]:
        out = []
        since = (self.since - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        for log, cond in LOG_QUERIES.items():
            if log in self.denied:
                continue
            q = f"*[System[({cond}) and TimeCreated[@SystemTime>='{since}']]]"
            r = self.run(["wevtutil", "qe", log, f"/q:{q}", "/f:xml"])
            if r.returncode != 0:
                if "denied" in (r.stderr + r.stdout).lower():
                    self.denied.add(log)
                continue
            for e in events_from_xml(r.stdout, log, self.host):
                key = (log, e.provenance.original_record_offset_or_id)
                if key not in self.seen:
                    self.seen.add(key)
                    out.append(e)
        return out


# --------------------------------------------------------------------------- loop
def describe(e: CanonicalEvent) -> str:
    extra = (" (inferred from copy)" if e.raw_metadata.get("inferred")
             else f"  (renamed from {Path(e.raw_metadata['renamed_from']).name})" if e.raw_metadata.get("renamed_from") else "")
    return f"{e.timestamp.strftime('%H:%M:%S')} UTC  {e.event_type.value:<20} {e.object or e.user or ''}{extra}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Stream live activity on this PC into a TRACE-X live store.")
    ap.add_argument("--watch", type=Path, action="append", required=True,
                    help="folder to watch (repeatable); removable drives are added automatically")
    ap.add_argument("--db", default=LIVE_DB, help=f"live store URL (default {LIVE_DB})")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between polls (default 2)")
    ap.add_argument("--keep", action="store_true", help="keep events already in the live store")
    ap.add_argument("--no-logs", action="store_true", help="don't read Windows event logs")
    ap.add_argument("--no-usb", action="store_true", help="don't watch removable drives")
    ap.add_argument("--ready-file", type=Path, help="touch this file once the baseline is taken")
    a = ap.parse_args(argv)
    for w in a.watch:
        if not w.is_dir():
            ap.error(f"not a folder: {w}")
    if a.db.rstrip("/").endswith("tracex.db"):
        ap.error("refusing to stream live data into the case store data/tracex.db; use a separate --db")

    user, host = getpass.getuser(), socket.gethostname()
    engine = get_engine(a.db)
    if not a.keep:
        with Session(engine) as s:
            s.execute(delete(EventRow))
            s.commit()
    folders = FolderWatcher(a.watch, user=user, host=host)
    watchers: list = [folders]
    if not a.no_usb:
        watchers.append(UsbWatcher(user=user, host=host, folders=folders))
    if not a.no_logs:
        logs = EventLogWatcher(host=host, since=_now())
        watchers.append(logs)
    print(f"TRACE-X live monitor — user {user} on {host}; store {a.db}")
    print("watching: " + ", ".join(str(r) for r in folders.snap) + "  (existing files are the baseline)")
    print("Ctrl+C to stop.\n")
    if a.ready_file:  # lets a scripted actor wait until the baseline exists
        a.ready_file.write_text("ready", encoding="utf-8")
    total = 0
    try:
        while True:
            batch = [e for w in watchers for e in w.poll()]
            if batch:
                with Session(engine) as s:
                    total += ingest_events(batch, session=s)["inserted"]
                for e in sorted(batch, key=lambda e: e.timestamp):
                    print(describe(e))
            if not a.no_logs and logs.denied and not getattr(logs, "_warned", False):
                print(f"(note: no access to {', '.join(sorted(logs.denied))} log; run as administrator to include it)")
                logs._warned = True
            time.sleep(a.interval)
    except KeyboardInterrupt:
        print(f"\nstopped; {total} events recorded in {a.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

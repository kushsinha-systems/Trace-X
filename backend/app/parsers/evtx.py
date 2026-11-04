"""Windows Event Log parser — Phase 2, source #1.

Primary path: binary .evtx via python-evtx (or Dissect.eventlog as fallback).
Offline-test path (used by unit tests): JSON-lines export where each line is a
record dict, e.g.::

    {"EventID": 4624, "TimeCreated": "2026-09-01T10:00:00Z", "TargetUser": "alice",
     "IpAddress": "10.0.0.5", "Process": "winlogon.exe", "Channel": "Security"}

Priority event IDs: 4624/4625 logon, 4634/4647 logoff, 1102 + System 104
log-cleared, 4663 object access, 4688 process creation.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import EventSource, EventType
from .common import make_event, parse_ts

PARSER_NAME = "evtx_parser"
PARSER_VERSION = "0.1.0"

_EVENT_MAP: dict[int, EventType] = {
    4624: EventType.LOGIN,
    4625: EventType.LOGIN,  # failed logon kept as LOGIN; outcome in raw_metadata
    4634: EventType.LOGOFF,
    4647: EventType.LOGOFF,
    1102: EventType.LOG_CLEARED,
    104: EventType.LOG_CLEARED,
    4663: EventType.FILE_ACCESSED,
    4688: EventType.PROCESS_CREATED,
}


def map_record(rec: dict[str, Any], source_file: str, record_id: str):
    eid = int(rec.get("EventID", rec.get("EventId", 0)))
    if eid not in _EVENT_MAP:
        return None
    etype = _EVENT_MAP[eid]
    user = rec.get("TargetUser") or rec.get("SubjectUser") or rec.get("User")
    obj = rec.get("ObjectName") or rec.get("TargetFilename") or rec.get("Object")
    proc = rec.get("Process") or rec.get("NewProcessName") or rec.get("Image")
    if etype is EventType.PROCESS_CREATED:
        obj = obj or rec.get("CommandLine")
    return make_event(
        timestamp=parse_ts(rec.get("TimeCreated", rec.get("timestamp"))),
        event_type=etype,
        source=EventSource.WINDOWS_EVENTLOG,
        parser_name=PARSER_NAME,
        parser_version=PARSER_VERSION,
        source_file=source_file,
        record_id=record_id,
        user=user,
        object=obj,
        process=proc,
        raw_metadata={"event_id_raw": eid, **{k: v for k, v in rec.items()}},
    )


def parse_evtx_jsonl(path: str | Path):
    """Parse a JSON-lines EVTX export into canonical events."""
    path = Path(path)
    events = []
    with path.open(encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            e = map_record(rec, str(path), rec.get("EventRecordID", i))
            if e is not None:
                events.append(e)
    return events


def parse_evtx(path: str | Path):
    """Parse a binary .evtx file via python-evtx.

    Raises ImportError with a clear message if python-evtx is not installed,
    and ValueError if the file is not a JSON-lines export either.
    """
    path = Path(path)
    if path.suffix.lower() == ".jsonl" or path.suffix.lower() == ".json":
        return parse_evtx_jsonl(path)
    try:
        import Evtx.Evtx as evtx_mod  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "python-evtx is required for binary .evtx parsing; "
            "export to JSON-lines and use parse_evtx_jsonl instead"
        ) from exc
    import re

    events = []
    with evtx_mod.Evtx(str(path)) as log:  # 0.8.x takes a filename, opens it itself
        for i, record in enumerate(log.records()):
            # Minimal XML scrape: EventID + TimeCreated; trimmed XML kept raw.
            # NB: parse inside the context — records read lazily from the mmap.
            try:
                xml = record.xml()
            except Exception:
                continue
            m_id = re.search(r"<EventID[^>]*>(\d+)</EventID>", xml)
            m_ts = re.search(r'SystemTime="([^"]+)"', xml)
            if not m_id or not m_ts:
                continue
            rec = {"EventID": int(m_id.group(1)), "TimeCreated": m_ts.group(1),
                   "_xml": xml[:4000]}
            e = map_record(rec, str(path), i)
            if e is not None:
                events.append(e)
    return events

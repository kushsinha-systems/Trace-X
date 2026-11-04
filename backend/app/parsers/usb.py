"""USB artefact parser — Phase 2, source #4.

Two offline-friendly inputs (both set provenance accurately):

1. ``parse_setupapi_log`` — Windows ``Setupapi.dev.log`` text. Looks for
   USBSTOR / USB device-install lines with ``>>>`` section headers carrying
   ``start <ts>`` stamps, e.g.::

       >>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk...]
       >>>  Section start 2026/09/01 10:05:00.000

   Lines containing USBSTOR/USB\\VID with install/connected language yield
   DEVICE_CONNECTED; lines with remove/disconnect language yield
   DEVICE_DISCONNECTED.

2. ``parse_usbstor_json`` — JSON export of
   ``SYSTEM\\CurrentControlSet\\Enum\\USBSTOR`` (+ Portable Devices) keys,
   as produced by python-registry tooling, e.g.::

       [{"device": "USBSTOR\\\\Disk&Ven_...\\\\012345", "first_install": "...",
         "last_insert": "...", "user": "alice"}]

Direct hive parsing with python-registry is supported where the library is
installed (helper ``parse_registry_hive`` attempts it); the two text/JSON
paths above are what the unit tests exercise so the suite stays offline.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import EventSource, EventType
from .common import make_event, parse_ts

PARSER_NAME = "usb_parser"
PARSER_VERSION = "0.1.0"

_TS = re.compile(r"Section start\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})")
_DEV = re.compile(r"(USBSTOR\\[^\s\]]+|USB\\VID_[0-9A-Fa-f&\\_]+)")
_NEG = re.compile(r"remov|disconnect|uninstall", re.I)
_POS = re.compile(r"install|connect|enumerat", re.I)


def _classify(line: str) -> EventType | None:
    if _NEG.search(line):
        return EventType.DEVICE_DISCONNECTED
    if _POS.search(line):
        return EventType.DEVICE_CONNECTED
    return None


def parse_setupapi_log(path: str | Path):
    path = Path(path)
    events = []
    current_ts: str | None = None
    with path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            m = _TS.search(line)
            if m:
                current_ts = m.group(1).replace("/", "-")
                continue
            if line.lstrip().startswith(">>>"):
                continue  # section header: describes the device, not an action
            d = _DEV.search(line)
            if d and current_ts:
                etype = _classify(line) or EventType.DEVICE_CONNECTED
                dev = d.group(1)
                events.append(
                    make_event(
                        timestamp=current_ts,
                        event_type=etype,
                        source=EventSource.USB,
                        parser_name=PARSER_NAME,
                        parser_version=PARSER_VERSION,
                        source_file=str(path),
                        record_id=f"setupapi-{i}",
                        device_id=dev,
                        object=dev,
                        raw_metadata={"line": line.strip()[:500]},
                    )
                )
    return events


def parse_usbstor_json(path: str | Path):
    path = Path(path)
    events = []
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    for i, rec in enumerate(records):
        dev = rec.get("device", "")
        for key, etype in (("last_insert", EventType.DEVICE_CONNECTED),
                           ("first_install", EventType.DEVICE_CONNECTED),
                           ("last_removal", EventType.DEVICE_DISCONNECTED)):
            if rec.get(key):
                events.append(
                    make_event(
                        timestamp=parse_ts(rec[key]),
                        event_type=etype,
                        source=EventSource.USB,
                        parser_name=PARSER_NAME,
                        parser_version=PARSER_VERSION,
                        source_file=str(path),
                        record_id=f"usbstor-{i}-{key}",
                        user=rec.get("user"),
                        device_id=dev,
                        object=dev,
                        raw_metadata={"registry_key": key, **{k: str(v) for k, v in rec.items()}},
                    )
                )
    return events


def parse_registry_hive(hive_path: str | Path, key_path: str = r"ControlSet001\Enum\USBSTOR"):
    """Attempt direct hive parsing with python-registry (optional)."""
    try:
        from Registry import Registry  # type: ignore
    except ImportError as exc:
        raise ImportError("python-registry is required for direct hive parsing") from exc
    reg = Registry.Registry(str(hive_path))
    events = []
    try:
        key = reg.open(key_path)
    except Exception:
        return []
    for i, sub in enumerate(key.subkeys()):
        events.append(
            make_event(
                timestamp=sub.timestamp(),
                event_type=EventType.DEVICE_CONNECTED,
                source=EventSource.USB,
                parser_name=PARSER_NAME,
                parser_version=PARSER_VERSION,
                source_file=str(hive_path),
                record_id=f"hive-{i}-{sub.name()}",
                device_id=sub.name(),
                object=sub.name(),
                raw_metadata={"hive_key": key_path, "subkey": sub.name()},
            )
        )
    return events

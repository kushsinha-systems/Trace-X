"""Shared parser helpers — Phase 2."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import builtins

from ..models import CanonicalEvent, EventSource, EventType, Provenance


def parse_ts(v: Any) -> datetime:
    if isinstance(v, datetime):
        dt = v
    else:
        s = str(v).strip().replace("Z", "+00:00")
        # tolerate "YYYY-MM-DD HH:MM:SS" (Setupapi / MFT CSV style)
        if "+" not in s and "T" not in s:
            try:
                dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def make_event(
    *,
    timestamp: Any,
    event_type: EventType,
    source: EventSource,
    parser_name: str,
    source_file: str,
    record_id: str,
    user: str | None = None,
    object: str | None = None,
    process: str | None = None,
    device_id: str | None = None,
    raw_metadata: dict | None = None,
    parser_version: str = "0.1.0",
) -> CanonicalEvent:
    e = CanonicalEvent(
        timestamp=parse_ts(timestamp),
        event_type=event_type,
        source=source,
        user=user,
        object=object,
        process=process,
        device_id=device_id,
        raw_metadata=dict(raw_metadata or {}),
        provenance=Provenance(
            source_file=source_file,
            parser_name=parser_name,
            parser_version=parser_version,
            original_record_offset_or_id=str(record_id),
        ),
        hash="",
    )
    # recompute hash now that all fields are final
    # NB: param `object` shadows the builtin, so reach it via builtins.
    builtins.object.__setattr__(e, "hash", e.compute_hash())
    return e

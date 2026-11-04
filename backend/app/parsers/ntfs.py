"""NTFS $MFT parser — Phase 2, source #2.

Input: CSV export in analyzeMFT style, one row per MFT record, with at
minimum a filename + the two timestamp sets this project depends on:

    filename, inode,
    si_created, si_modified, si_mft_modified, si_accessed,
    fn_created, fn_modified, fn_mft_modified, fn_accessed

Both $STANDARD_INFORMATION ($SI) and $FILE_NAME ($FN) sets are preserved
untouched in raw_metadata so Phase 5 can compare $SI vs $FN for the
documented timestomping signature (SI older than FN / inconsistent with
surrounding activity; cf. Chow/Law/Kwan/Lai, Galhuber & Luh).

Each row yields ONE canonical FILE_MODIFIED event anchored on si_modified
(the most forensically useful single timestamp) carrying the full sets.
pytsk3-backed direct $MFT parsing is a future upgrade logged in DECISIONS.md.
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..models import EventSource, EventType
from .common import make_event

PARSER_NAME = "ntfs_mft_parser"
PARSER_VERSION = "0.1.0"

SI_FIELDS = ("si_created", "si_modified", "si_mft_modified", "si_accessed")
FN_FIELDS = ("fn_created", "fn_modified", "fn_mft_modified", "fn_accessed")


def parse_mft_csv(path: str | Path):
    path = Path(path)
    events = []
    with path.open(newline="", encoding="utf-8") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            si = {k: row.get(k) for k in SI_FIELDS}
            fn = {k: row.get(k) for k in FN_FIELDS}
            anchor = row.get("si_modified") or row.get("fn_modified") or row.get("si_created")
            if not anchor:
                continue
            events.append(
                make_event(
                    timestamp=anchor,
                    event_type=EventType.FILE_MODIFIED,
                    source=EventSource.FILESYSTEM_NTFS,
                    parser_name=PARSER_NAME,
                    parser_version=PARSER_VERSION,
                    source_file=str(path),
                    record_id=row.get("inode", i),
                    object=row.get("filename"),
                    raw_metadata={
                        "inode": row.get("inode"),
                        "filename": row.get("filename"),
                        "si_timestamps": si,
                        "fn_timestamps": fn,
                    },
                )
            )
    return events

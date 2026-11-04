"""Browser history parser — Phase 2, source #3.

Reads Chrome `History` SQLite (`urls`, `visits`, `downloads`) and/or
Firefox `places.sqlite` (`moz_places`, `moz_historyvisits`) directly via
sqlite3. Emits PAGE_VISIT / FILE_DOWNLOAD canonical events.

Timestamp notes:
- Chrome visit_time / download start_time: microseconds since 1601-01-01 UTC.
- Firefox visit_date: microseconds since Unix epoch.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from ..models import EventSource, EventType
from .common import make_event

PARSER_NAME = "browser_parser"
PARSER_VERSION = "0.1.0"

_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _chrome_ts(micros: int) -> datetime:
    import datetime as _dt

    return _CHROME_EPOCH + _dt.timedelta(microseconds=int(micros))


def _firefox_ts(micros: int) -> datetime:
    import datetime as _dt

    return datetime(1970, 1, 1, tzinfo=timezone.utc) + _dt.timedelta(microseconds=int(micros))


def _tables(con: sqlite3.Connection) -> set[str]:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def parse_browser_sqlite(path: str | Path, user: str | None = None):
    path = Path(path)
    con = sqlite3.connect(str(path))
    try:
        tables = _tables(con)
        events = []
        if {"urls", "visits"} <= tables:  # Chrome
            for vid, url, title, vt in con.execute(
                "SELECT visits.id, urls.url, urls.title, visits.visit_time "
                "FROM visits JOIN urls ON visits.url = urls.id ORDER BY visits.visit_time"
            ):
                events.append(
                    make_event(
                        timestamp=_chrome_ts(vt),
                        event_type=EventType.PAGE_VISIT,
                        source=EventSource.BROWSER,
                        parser_name=PARSER_NAME,
                        parser_version=PARSER_VERSION,
                        source_file=str(path),
                        record_id=f"chrome-visit-{vid}",
                        user=user,
                        object=url,
                        raw_metadata={"browser": "chrome", "visit_id": vid, "title": title},
                    )
                )
            if "downloads" in tables:
                cols = [r[1] for r in con.execute("PRAGMA table_info(downloads)")]
                for row in con.execute("SELECT * FROM downloads"):
                    d = dict(zip(cols, row))
                    if not d.get("start_time"):
                        continue
                    events.append(
                        make_event(
                            timestamp=_chrome_ts(d["start_time"]),
                            event_type=EventType.FILE_DOWNLOAD,
                            source=EventSource.BROWSER,
                            parser_name=PARSER_NAME,
                            parser_version=PARSER_VERSION,
                            source_file=str(path),
                            record_id=f"chrome-download-{d.get('id')}",
                            user=user,
                            object=d.get("target_path") or d.get("url"),
                            raw_metadata={"browser": "chrome", **{k: str(v) for k, v in d.items()}},
                        )
                    )
        if {"moz_places", "moz_historyvisits"} <= tables:  # Firefox
            for vid, url, title, vd in con.execute(
                "SELECT moz_historyvisits.id, moz_places.url, moz_places.title, "
                "moz_historyvisits.visit_date FROM moz_historyvisits "
                "JOIN moz_places ON moz_historyvisits.place_id = moz_places.id "
                "ORDER BY moz_historyvisits.visit_date"
            ):
                events.append(
                    make_event(
                        timestamp=_firefox_ts(vd),
                        event_type=EventType.PAGE_VISIT,
                        source=EventSource.BROWSER,
                        parser_name=PARSER_NAME,
                        parser_version=PARSER_VERSION,
                        source_file=str(path),
                        record_id=f"firefox-visit-{vid}",
                        user=user,
                        object=url,
                        raw_metadata={"browser": "firefox", "visit_id": vid, "title": title},
                    )
                )
        return events
    finally:
        con.close()

"""Timeline engine — Phase 4.

Chronological event store with query API + gap detector, reading ONLY the
Phase-3 `events` table (never raw sources).

Gap rule (per spec): flag intervals where NO events occur across ANY source
for longer than a configurable threshold (default 30 minutes, measured
during otherwise-active hours) as POTENTIALLY_SIGNIFICANT_GAP — a flag
needing investigation, never an automatic conclusion.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CanonicalEvent, EventRow

GAP_FLAG = "POTENTIALLY_SIGNIFICANT_GAP"


@dataclass(frozen=True)
class TimelineGap:
    gap_start: datetime
    gap_end: datetime
    duration_minutes: float
    flag: str = GAP_FLAG
    note: str = (
        "No events from any source in this interval. Flagged for investigator "
        "review only — this does NOT establish log clearing, deletion, or any "
        "anti-forensic activity."
    )
    within_active_hours: bool = True


def _as_utc(dt: datetime | str) -> datetime:
    if isinstance(dt, str):
        s = dt.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def query_events(
    session: Session,
    *,
    start: datetime | str | None = None,
    end: datetime | str | None = None,
    user: str | None = None,
    device_id: str | None = None,
    object_substr: str | None = None,
    source: str | None = None,
    event_type: str | None = None,
    limit: int = 1000,
    offset: int = 0,
) -> list[CanonicalEvent]:
    """Filter the merged timeline. All filters AND together; always chronological."""
    stmt = select(EventRow)
    if start is not None:
        stmt = stmt.where(EventRow.timestamp >= _as_utc(start).isoformat())
    if end is not None:
        stmt = stmt.where(EventRow.timestamp <= _as_utc(end).isoformat())
    if user is not None:
        stmt = stmt.where(EventRow.user == user)
    if device_id is not None:
        stmt = stmt.where(EventRow.device_id == device_id)
    if object_substr is not None:
        stmt = stmt.where(EventRow.object.like(f"%{object_substr}%"))
    if source is not None:
        stmt = stmt.where(EventRow.source == source)
    if event_type is not None:
        stmt = stmt.where(EventRow.event_type == event_type)
    stmt = stmt.order_by(EventRow.timestamp, EventRow.event_id).limit(limit).offset(offset)
    return [row.to_event() for row in session.scalars(stmt).all()]


def _in_active_hours(dt: datetime, active_hours: tuple[int, int] | None) -> bool:
    if active_hours is None:
        return True
    lo, hi = active_hours
    return lo <= dt.astimezone(timezone.utc).hour < hi


def detect_gaps(
    events: list[CanonicalEvent],
    *,
    threshold_minutes: float = 30.0,
    active_hours: tuple[int, int] | None = (6, 22),
) -> list[TimelineGap]:
    """Flag silent intervals between consecutive events exceeding the threshold.

    `active_hours` (UTC, default 06:00–22:00) implements "otherwise-active
    hours": a gap is only flagged when its midpoint falls inside the window,
    so expected overnight silence is not flagged. Pass None to flag all gaps.
    """
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    gaps: list[TimelineGap] = []
    for prev, nxt in zip(ordered, ordered[1:]):
        delta_min = (nxt.timestamp - prev.timestamp).total_seconds() / 60.0
        if delta_min <= threshold_minutes:
            continue
        mid = prev.timestamp + (nxt.timestamp - prev.timestamp) / 2
        within = _in_active_hours(mid, active_hours)
        if active_hours is not None and not within:
            continue
        gaps.append(TimelineGap(
            gap_start=prev.timestamp,
            gap_end=nxt.timestamp,
            duration_minutes=round(delta_min, 2),
            within_active_hours=within,
        ))
    return gaps


def detect_gaps_in_store(
    session: Session,
    *,
    threshold_minutes: float = 30.0,
    active_hours: tuple[int, int] | None = (6, 22),
    start: datetime | str | None = None,
    end: datetime | str | None = None,
) -> list[TimelineGap]:
    events = query_events(session, start=start, end=end, limit=100_000)
    return detect_gaps(events, threshold_minutes=threshold_minutes, active_hours=active_hours)

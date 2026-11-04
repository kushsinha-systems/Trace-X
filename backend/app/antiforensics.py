"""Anti-forensics detection engine — Phase 5.

Five independent, named, testable rule families. Each produces
SuspiciousEvent records whose suspicion_score (0–1) is built ONLY from
named boolean/graded indicators — never an opaque number. The exact
weight composition lives in docs/scoring_spec.md and is implemented in
`score_indicators` below (defaults per spec: prior 0.30 / temporal 0.30 /
multiple 0.20 / affected 0.20).

Reads CanonicalEvent lists (usually from the Phase-4 timeline query);
never raw sources directly.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from .models import CanonicalEvent, EventType

# Canonical indicator weights (exact values in docs/scoring_spec.md).
W_PRIOR = 0.30
W_TEMPORAL = 0.30
W_MULTIPLE = 0.20
W_AFFECTED = 0.20

LIMITATION_DEFAULT = (
    "This finding describes an observed sequence consistent with potential "
    "evidence concealment. It does NOT establish intent, identity beyond the "
    "logged user field, or that a crime occurred."
)


class SuspiciousEvent(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rule_name: str
    description: str  # Evidence-tier wording: what was observed
    event_ids: list[str] = Field(default_factory=list)
    object: str | None = None
    user: str | None = None
    device_id: str | None = None
    suspicion_score: float = 0.0
    indicators: dict[str, float] = Field(default_factory=dict)  # raw 0–1 per indicator
    level: str = "LOW"  # LOW <0.4 <= MEDIUM <0.7 <= HIGH
    key: str = ""  # stable across re-analysis: rule + trigger event's content hash (finding_id is random)
    limitation: str = LIMITATION_DEFAULT

    def model_post_init(self, _ctx: Any) -> None:
        s = self.suspicion_score
        lvl = "LOW" if s < 0.4 else ("MEDIUM" if s < 0.7 else "HIGH")
        object.__setattr__(self, "level", lvl)


def score_indicators(*, prior: bool, temporal: float, multiple: bool, affected: bool) -> tuple[float, dict[str, float]]:
    """Compose the 0–1 score from the four canonical indicators.

    `temporal` is graded 0–1 (1 = shortest distance / strongest skew).
    Returns (rounded_score, raw_indicators_dict).
    """
    t = max(0.0, min(1.0, float(temporal)))
    indicators = {
        "relevant_prior_activity": 1.0 if prior else 0.0,
        "short_temporal_distance": round(t, 3),
        "multiple_related_events": 1.0 if multiple else 0.0,
        "evidence_directly_affected": 1.0 if affected else 0.0,
    }
    score = W_PRIOR * indicators["relevant_prior_activity"] + W_TEMPORAL * t \
        + W_MULTIPLE * indicators["multiple_related_events"] + W_AFFECTED * indicators["evidence_directly_affected"]
    return round(min(1.0, max(0.0, score)), 3), indicators


def _by_object(events: list[CanonicalEvent]) -> dict[str, list[CanonicalEvent]]:
    groups: dict[str, list[CanonicalEvent]] = {}
    for e in events:
        if e.object:
            groups.setdefault(e.object, []).append(e)
    for g in groups.values():
        g.sort(key=lambda e: (e.timestamp, e.event_id))
    return groups


def detect_evidence_deletion(
    events: list[CanonicalEvent], *, window_minutes: float = 15.0,
) -> list[SuspiciousEvent]:
    """ACCESSED → COPIED/MODIFIED → DELETED on the same object within window."""
    out: list[SuspiciousEvent] = []
    window_s = window_minutes * 60.0
    for obj, grp in _by_object(events).items():
        for d in [e for e in grp if e.event_type is EventType.FILE_DELETED]:
            prior = [e for e in grp if e.timestamp <= d.timestamp
                     and (d.timestamp - e.timestamp).total_seconds() <= window_s
                     and e.event_id != d.event_id]
            accessed = [e for e in prior if e.event_type is EventType.FILE_ACCESSED]
            staged = [e for e in prior if e.event_type in (EventType.FILE_COPIED, EventType.FILE_MODIFIED)]
            if not accessed or not staged:
                continue
            last_pre = max(accessed + staged, key=lambda e: e.timestamp)
            gap_s = (d.timestamp - last_pre.timestamp).total_seconds()
            temporal = 1.0 - min(1.0, gap_s / window_s)
            score, ind = score_indicators(prior=True, temporal=temporal,
                                          multiple=len(accessed + staged) >= 2, affected=True)
            out.append(SuspiciousEvent(
                rule_name="evidence_deletion",
                description=(f"Evidence-tier: file '{obj}' was accessed then "
                             f"copied/modified then deleted within {window_minutes:g} minutes "
                             f"({len(accessed)} access, {len(staged)} stage, delete at {d.timestamp.isoformat()})."),
                event_ids=[e.event_id for e in accessed + staged] + [d.event_id],
                object=obj, user=d.user, device_id=d.device_id,
                suspicion_score=score, indicators=ind,
            ))
    return out


def detect_log_clearing(
    events: list[CanonicalEvent], *, preceding_window_minutes: float = 60.0,
) -> list[SuspiciousEvent]:
    """EVTX 1102 / System 104 with suspicious preceding-window context."""
    out: list[SuspiciousEvent] = []
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    clears = [e for e in ordered if e.event_type is EventType.LOG_CLEARED]
    window_s = preceding_window_minutes * 60.0
    for c in clears:
        prior = [e for e in ordered
                 if e.event_id != c.event_id and e.timestamp <= c.timestamp
                 and (c.timestamp - e.timestamp).total_seconds() <= window_s]
        relevant = [e for e in prior if e.event_type in (
            EventType.LOGIN, EventType.FILE_ACCESSED, EventType.FILE_MODIFIED,
            EventType.FILE_COPIED, EventType.FILE_DELETED, EventType.FILE_CREATED,
            EventType.FILE_DOWNLOAD, EventType.PROCESS_CREATED,
            EventType.DEVICE_CONNECTED, EventType.PAGE_VISIT)]
        files = {e.object for e in relevant
                 if e.event_type in (EventType.FILE_ACCESSED, EventType.FILE_MODIFIED,
                                     EventType.FILE_COPIED, EventType.FILE_DELETED,
                                     EventType.FILE_CREATED, EventType.FILE_DOWNLOAD) and e.object}
        if relevant:
            nearest = max(relevant, key=lambda e: e.timestamp)
            gap_s = (c.timestamp - nearest.timestamp).total_seconds()
            temporal = 1.0 - min(1.0, gap_s / window_s)
        else:
            temporal = 0.0
        score, ind = score_indicators(prior=bool(relevant), temporal=temporal,
                                      multiple=len(relevant) >= 3, affected=bool(files))
        out.append(SuspiciousEvent(
            rule_name="log_clearing",
            description=(f"Evidence-tier: audit/system log clear at {c.timestamp.isoformat()} "
                         f"with {len(relevant)} relevant event(s) in the preceding "
                         f"{preceding_window_minutes:g} minutes"
                         + (f", affecting {len(files)} file(s)" if files else ", no file activity") + "."),
            event_ids=[e.event_id for e in relevant] + [c.event_id],
            object=c.object, user=c.user or (relevant[-1].user if relevant else None),
            device_id=c.device_id,
            suspicion_score=score, indicators=ind,
        ))
    return out


def _parse_ts(v: Any) -> datetime | None:
    if not v:
        return None
    try:
        if isinstance(v, datetime):
            return v
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


def detect_timestamp_anomaly(events: list[CanonicalEvent]) -> list[SuspiciousEvent]:
    """Flag $SI-older-than-$FN (documented timestomp signature) + context deviation.

    Primary signal: any si_* timestamp older than its fn_* counterpart in the
    same MFT row (carried in raw_metadata by the Phase-2 NTFS parser).
    """
    out: list[SuspiciousEvent] = []
    fs = [e for e in events if e.source.value == "FILESYSTEM_NTFS"]
    fs_times = sorted(e.timestamp for e in fs)
    for e in fs:
        si = e.raw_metadata.get("si_timestamps", {}) or {}
        fn = e.raw_metadata.get("fn_timestamps", {}) or {}
        if not si or not fn:
            continue
        anomalous_fields: list[str] = []
        max_skew_s = 0.0
        for stem in ("created", "modified", "mft_modified", "accessed"):
            s, f = _parse_ts(si.get(f"si_{stem}")), _parse_ts(fn.get(f"fn_{stem}"))
            if s and f and s < f:
                anomalous_fields.append(f"si_{stem}<fn_{stem}")
                max_skew_s = max(max_skew_s, (f - s).total_seconds())
        if not anomalous_fields:
            continue
        # Grade skew: full marks at >=24h skew, linear below (cap avoids outliers dominating).
        temporal = min(1.0, max_skew_s / 86_400.0) if max_skew_s > 0 else 0.5
        if len(anomalous_fields) == 1 and max_skew_s <= 0:
            temporal = 0.5
        score, ind = score_indicators(prior=bool(fs_times), temporal=temporal,
                                      multiple=len(anomalous_fields) > 1, affected=True)
        out.append(SuspiciousEvent(
            rule_name="timestamp_anomaly",
            description=(f"Evidence-tier: file '{e.object}' shows {len(anomalous_fields)} "
                         f"$STANDARD_INFORMATION-older-than-$FILE_NAME field(s) "
                         f"({', '.join(anomalous_fields)}; max skew {max_skew_s/3600:.1f}h)."),
            event_ids=[e.event_id], object=e.object, user=e.user, device_id=e.device_id,
            suspicion_score=score, indicators=ind,
        ))
    return out


def detect_mass_deletion(
    events: list[CanonicalEvent], *, threshold_n: int = 20, window_minutes: float = 2.0,
) -> list[SuspiciousEvent]:
    """>=N deletions of distinct files within a short sliding window."""
    out: list[SuspiciousEvent] = []
    dels = sorted([e for e in events if e.event_type is EventType.FILE_DELETED],
                  key=lambda e: (e.timestamp, e.event_id))
    if len(dels) < threshold_n:
        return out
    window_s = window_minutes * 60.0
    i = 0
    while i < len(dels):
        j = i
        while (j + 1 < len(dels)
               and (dels[j + 1].timestamp - dels[i].timestamp).total_seconds() <= window_s):
            j += 1
        cluster = dels[i:j + 1]
        distinct = {e.object for e in cluster if e.object}
        if len(cluster) >= threshold_n and len(distinct) >= threshold_n:
            span_s = (cluster[-1].timestamp - cluster[0].timestamp).total_seconds()
            temporal = 1.0 - min(1.0, span_s / window_s)  # tighter burst = higher
            # prior: the burst corroborates itself — the first N-1 deletes are
            # relevant prior activity for the Nth (plus any outside context).
            score, ind = score_indicators(prior=True, temporal=temporal,
                                          multiple=True, affected=True)
            out.append(SuspiciousEvent(
                rule_name="mass_deletion",
                description=(f"Evidence-tier: {len(cluster)} deletions of {len(distinct)} "
                             f"distinct files within {span_s:.0f}s "
                             f"(threshold {threshold_n} in {window_minutes:g} min)."),
                event_ids=[e.event_id for e in cluster],
                object=None, user=cluster[-1].user, device_id=cluster[-1].device_id,
                suspicion_score=score, indicators=ind,
            ))
            i = j + 1  # non-overlapping clusters
        else:
            i += 1
    return out


def detect_metadata_modification(
    events: list[CanonicalEvent], *, context_window_minutes: float = 60.0,
) -> list[SuspiciousEvent]:
    """Metadata (size/extension/timestamps) changes with no content-modifying event.

    A FILE_MODIFIED counts as metadata-suspicious when raw_metadata carries
    one of: metadata_only=true, extension_before/after differing, or
    size_before/size_after differing — AND no content event
    (ACCESSED/COPIED/CREATED/DOWNLOAD/MODIFIED-with-content) on the same
    object within ±context_window.
    """
    out: list[SuspiciousEvent] = []
    window_s = context_window_minutes * 60.0
    by_obj = _by_object(events)
    for e in events:
        if e.event_type is not EventType.FILE_MODIFIED or not e.object:
            continue
        rm = e.raw_metadata or {}
        ext_changed = rm.get("extension_before") is not None \
            and rm.get("extension_before") != rm.get("extension_after")
        size_changed = rm.get("size_before") is not None \
            and rm.get("size_before") != rm.get("size_after")
        flagged_only = bool(rm.get("metadata_only"))
        if not (flagged_only or ext_changed or size_changed):
            continue
        peers = [p for p in by_obj.get(e.object, [])
                 if p.event_id != e.event_id
                 and abs((p.timestamp - e.timestamp).total_seconds()) <= window_s
                 and p.event_type in (EventType.FILE_ACCESSED, EventType.FILE_COPIED,
                                      EventType.FILE_CREATED, EventType.FILE_DOWNLOAD)]
        if peers:
            continue
        kind = "flagged metadata-only change" if flagged_only else (
            "extension change" if ext_changed else "size change without content event")
        score, ind = score_indicators(prior=bool(by_obj.get(e.object, [])),
                                      temporal=0.5, multiple=False, affected=True)
        out.append(SuspiciousEvent(
            rule_name="metadata_modification",
            description=(f"Evidence-tier: file '{e.object}' shows {kind} at "
                         f"{e.timestamp.isoformat()} with no content-modifying event "
                         f"within ±{context_window_minutes:g} minutes."),
            event_ids=[e.event_id], object=e.object, user=e.user, device_id=e.device_id,
            suspicion_score=score, indicators=ind,
        ))
    return out


def detect_all(events: list[CanonicalEvent], **kwargs: Any) -> list[SuspiciousEvent]:
    """Run all five rule families; sorted by score desc, then rule name."""
    out = [
        *detect_evidence_deletion(events, window_minutes=kwargs.get("deletion_window_minutes", 15.0)),
        *detect_log_clearing(events, preceding_window_minutes=kwargs.get("log_window_minutes", 60.0)),
        *detect_timestamp_anomaly(events),
        *detect_mass_deletion(events, threshold_n=kwargs.get("mass_n", 20),
                              window_minutes=kwargs.get("mass_window_minutes", 2.0)),
        *detect_metadata_modification(events),
    ]
    hashes = {e.event_id: e.hash for e in events}
    for f in out:
        trigger = f.event_ids[-1] if f.event_ids else ""
        f.key = f"{f.rule_name}:{hashes.get(trigger, trigger)[:16]}"
    out.sort(key=lambda f: (-f.suspicion_score, f.rule_name))
    return out

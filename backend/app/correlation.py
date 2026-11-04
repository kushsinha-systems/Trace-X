"""Correlation engine — Phase 6.

Explainable pairwise relationship score (exact weights in docs/scoring_spec.md):

    relationship = 0.30 × temporal_proximity (linear decay, 30-min window → 0)
                 + 0.20 × same_user
                 + 0.20 × same_object
                 + 0.15 × same_device
                 + 0.15 × same_process

Output always lists which factors fired (never just a percentage).
Reads CanonicalEvent lists; never raw sources.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from .models import CanonicalEvent

W_TEMPORAL = 0.30
W_USER = 0.20
W_OBJECT = 0.20
W_DEVICE = 0.15
W_PROCESS = 0.15


class Correlation(BaseModel):
    event_id_a: str
    event_id_b: str
    score: float = Field(ge=0.0, le=1.0)  # 0–1; display as percentage
    subscores: dict[str, float] = Field(default_factory=dict)
    factors: list[str] = Field(default_factory=list)

    def render(self) -> str:
        lines = [f"Relationship score: {self.score * 100:.0f}%", "Supporting factors:"]
        lines += [f"  - {f}" for f in self.factors] or ["  - (none)"]
        return "\n".join(lines)


def _eq(a: str | None, b: str | None) -> bool:
    return bool(a) and a == b


def correlate_pair(
    a: CanonicalEvent, b: CanonicalEvent, *, window_minutes: float = 30.0,
) -> Correlation:
    gap_min = abs((b.timestamp - a.timestamp).total_seconds()) / 60.0
    temporal = max(0.0, 1.0 - gap_min / window_minutes) if window_minutes > 0 else 0.0
    u = 1.0 if _eq(a.user, b.user) else 0.0
    o = 1.0 if _eq(a.object, b.object) else 0.0
    d = 1.0 if _eq(a.device_id, b.device_id) else 0.0
    p = 1.0 if _eq(a.process, b.process) else 0.0
    score = W_TEMPORAL * temporal + W_USER * u + W_OBJECT * o + W_DEVICE * d + W_PROCESS * p

    factors: list[str] = []
    if temporal > 0:
        if gap_min < 1:
            factors.append(f"events within {gap_min * 60:.0f} seconds")
        else:
            factors.append(f"events within {gap_min:.0f} minutes" if gap_min >= 2 else "events within 1 minute")
    if u:
        factors.append("same user")
    if o:
        factors.append("same file")
    if d:
        factors.append("same device")
    if p:
        factors.append("same process")
    return Correlation(
        event_id_a=a.event_id, event_id_b=b.event_id,
        score=round(min(1.0, max(0.0, score)), 3),
        subscores={"temporal_proximity": round(temporal, 3), "same_user": u,
                    "same_object": o, "same_device": d, "same_process": p},
        factors=factors,
    )


def correlate_all(
    events: list[CanonicalEvent],
    *,
    window_minutes: float = 30.0,
    threshold: float = 0.0,
) -> list[Correlation]:
    """All pairs within the temporal window, scored, filtered by threshold, desc."""
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    out: list[Correlation] = []
    window_s = window_minutes * 60.0
    for i in range(len(ordered)):
        for j in range(i + 1, len(ordered)):
            if (ordered[j].timestamp - ordered[i].timestamp).total_seconds() > window_s:
                break  # ordered → no later j can be in-window
            c = correlate_pair(ordered[i], ordered[j], window_minutes=window_minutes)
            if c.score >= threshold:
                out.append(c)
    out.sort(key=lambda c: -c.score)
    return out

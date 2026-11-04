"""Pattern / chain engine — Phase 7.

Sequence detection over the Phase-6 correlation graph: a chain is a
chronological path of correlated events (consecutive pairs each scoring
>= threshold, default 0.6) that also contains at least one
anti-forensics-relevant event type. Matched chains get a human-readable
label plus the mandatory hypothesis/limitation pairing — never an
assertion of malice or intent.
"""
from __future__ import annotations

import uuid

from pydantic import BaseModel, Field

from .correlation import correlate_all, correlate_pair
from .models import CanonicalEvent, EventType

RELEVANT = {EventType.LOG_CLEARED, EventType.FILE_DELETED,
            EventType.TIMESTAMP_ANOMALY, EventType.FILE_COPIED}

# SuspiciousEvent rule -> pseudo-type contribution for labelling/qualification.
# Rationale: some anti-forensic signals (timestomp skew, metadata-only edits)
# live in findings over FILE_MODIFIED events, never as their own event_type.
RULE_AS_RELEVANT = {
    "log_clearing": EventType.LOG_CLEARED,
    "evidence_deletion": EventType.FILE_DELETED,
    "mass_deletion": EventType.FILE_DELETED,
    "timestamp_anomaly": EventType.TIMESTAMP_ANOMALY,
}

HYPOTHESIS_BY_LABEL = {
    "Potential Evidence Concealment Sequence":
        "consistent with a possible attempt to remove evidence",
    "Potential Log Tampering Sequence":
        "consistent with a possible attempt to hide activity by clearing logs",
    "Potential Evidence Deletion Sequence":
        "consistent with removal of a file after access/copy",
    "Potential Timeline Manipulation Sequence":
        "consistent with possible timestamp tampering",
}
LIMITATION = ("does not establish intent, identity beyond the logged fields, "
              "or that wrongdoing occurred; maintenance, tooling, or system "
              "behaviour can produce similar patterns — verify independently.")


class Chain(BaseModel):
    chain_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_ids: list[str] = Field(default_factory=list)
    label: str
    hypothesis: str
    limitation: str = LIMITATION
    mean_score: float = 0.0
    supporting_rules: list[str] = Field(default_factory=list)


def _label_for(types: set[EventType]) -> str | None:
    if EventType.LOG_CLEARED in types and EventType.FILE_DELETED in types:
        return "Potential Evidence Concealment Sequence"
    if EventType.LOG_CLEARED in types:
        return "Potential Log Tampering Sequence"
    if EventType.TIMESTAMP_ANOMALY in types:
        return "Potential Timeline Manipulation Sequence"
    if EventType.FILE_DELETED in types:
        return "Potential Evidence Deletion Sequence"
    return None


def detect_chains(
    events: list[CanonicalEvent], *, threshold: float = 0.6, window_minutes: float = 30.0,
    findings: list | None = None,
) -> list[Chain]:
    """Greedy chronological chaining over correlation edges >= threshold.

    A path qualifies when it holds >=3 events AND matches at least one
    anti-forensics-relevant signal: a RELEVANT event type in-path, or —
    when `findings` are supplied — overlap with a SuspiciousEvent whose rule
    maps to one (RULE_AS_RELEVANT). Labels derive from the union of both.
    Every chain carries hypothesis + limitation, never an assertion of malice.
    """
    if len(events) < 2:
        return []
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    by_id = {e.event_id: e for e in ordered}
    # adjacency: for each event, later events within window scoring >= threshold
    corrs = correlate_all(ordered, window_minutes=window_minutes, threshold=threshold)
    edges: dict[str, list[str]] = {}
    scores: dict[tuple[str, str], float] = {}
    for c in corrs:
        edges.setdefault(c.event_id_a, []).append(c.event_id_b)
        edges.setdefault(c.event_id_b, []).append(c.event_id_a)
        scores[(c.event_id_a, c.event_id_b)] = c.score
        scores[(c.event_id_b, c.event_id_a)] = c.score
    # greedy: extend from each unclaimed start through best next edge (chronological)
    claimed: set[str] = set()
    chains: list[Chain] = []
    order_idx = {e.event_id: i for i, e in enumerate(ordered)}
    for start in ordered:
        if start.event_id in claimed:
            continue
        path = [start.event_id]
        cur = start.event_id
        while True:
            nxt = [n for n in edges.get(cur, [])
                   if order_idx[n] > order_idx[cur] and n not in path and n not in claimed]
            if not nxt:
                break
            # Prefer the temporally nearest candidate among near-best scores:
            # story steps are adjacent in time; raw argmax fragments on noise.
            best = max(scores[(cur, n)] for n in nxt)
            near = [n for n in nxt if scores[(cur, n)] >= best - 0.05]
            near.sort(key=lambda n: ((by_id[n].timestamp - by_id[cur].timestamp).total_seconds(),
                                     order_idx[n]))
            path.append(near[0])
            cur = near[0]
        if len(path) < 3:
            continue
        types = {by_id[e].event_type for e in path}
        if findings:
            # A finding counts toward labelling only if its TRIGGER event
            # (last in the finding's list: the delete / clear / skewed file)
            # is itself in the path — sub-path overlap must not over-label.
            pathset = set(path)
            for f in findings:
                rule = getattr(f, "rule_name", None)
                ids = list(getattr(f, "event_ids", []))
                if rule in RULE_AS_RELEVANT and ids and ids[-1] in pathset:
                    types.add(RULE_AS_RELEVANT[rule])
        label = _label_for(types)
        if label is None:
            continue
        for e in path:
            claimed.add(e)
        pair_scores = [correlate_pair(by_id[a], by_id[b], window_minutes=window_minutes).score
                       for a, b in zip(path, path[1:])]
        chains.append(Chain(
            event_ids=path, label=label,
            hypothesis=HYPOTHESIS_BY_LABEL[label],
            mean_score=round(sum(pair_scores) / len(pair_scores), 3),
        ))
    _merge_chains(chains, by_id, findings, threshold, window_minutes)
    _gap_fill(chains, ordered, by_id, findings, threshold, window_minutes)
    chains.sort(key=lambda c: -c.mean_score)
    return chains


def _relabel(ids: list[str], by_id: dict[str, CanonicalEvent], findings: list | None) -> str | None:
    types = {by_id[i].event_type for i in ids}
    if findings:
        pathset = set(ids)
        for f in findings:
            rule = getattr(f, "rule_name", None)
            fids = list(getattr(f, "event_ids", []))
            if rule in RULE_AS_RELEVANT and fids and fids[-1] in pathset:
                types.add(RULE_AS_RELEVANT[rule])
    return _label_for(types)


def _mean(ids: list[str], by_id: dict[str, CanonicalEvent], window_minutes: float) -> float:
    s = [correlate_pair(by_id[a], by_id[b], window_minutes=window_minutes).score
         for a, b in zip(ids, ids[1:])]
    return round(sum(s) / len(s), 3) if s else 0.0


def _merge_chains(chains: list[Chain], by_id: dict[str, CanonicalEvent],
                  findings: list | None, threshold: float, window_minutes: float) -> None:
    """Union chains linked by any cross edge >= threshold; keep the merge only
    if the merged chronological path verifies (every consecutive pair links).
    Fixes greedy fragmentation of one story into sub-chains. In-place."""
    if len(chains) < 2:
        return
    parent = list(range(len(chains)))
    pos = {e: i for i, c in enumerate(chains) for e in c.event_ids}

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    ids_list = [c.event_ids for c in chains]
    for i in range(len(chains)):
        for j in range(i + 1, len(chains)):
            linked = any(
                correlate_pair(by_id[a], by_id[b], window_minutes=window_minutes).score >= threshold
                for a in ids_list[i] for b in ids_list[j])
            if linked:
                union(i, j)
    groups: dict[int, list[int]] = {}
    for i in range(len(chains)):
        groups.setdefault(find(i), []).append(i)
    if all(len(g) == 1 for g in groups.values()):
        return
    merged: list[Chain] = []
    for g in groups.values():
        if len(g) == 1:
            merged.append(chains[g[0]])
            continue
        ids = sorted({e for i in g for e in chains[i].event_ids},
                     key=lambda e: (by_id[e].timestamp, by_id[e].event_id))
        ok = all(correlate_pair(by_id[a], by_id[b], window_minutes=window_minutes).score >= threshold
                 for a, b in zip(ids, ids[1:]))
        if not ok or len(ids) < 3:
            merged.extend(chains[i] for i in g)  # keep separate, don't fabricate
            continue
        label = _relabel(ids, by_id, findings)
        if label is None:
            merged.extend(chains[i] for i in g)
            continue
        merged.append(Chain(event_ids=ids, label=label,
                            hypothesis=HYPOTHESIS_BY_LABEL[label],
                            mean_score=_mean(ids, by_id, window_minutes)))
    chains[:] = merged


def _gap_fill(chains: list[Chain], ordered: list[CanonicalEvent],
              by_id: dict[str, CanonicalEvent], findings: list | None,
              threshold: float, window_minutes: float) -> None:
    """Insert unclaimed RELEVANT events into chains where both chronological
    neighbours link >= threshold (e.g. a log-clear skipped by greedy argmax).
    Relabels the chain afterwards. In-place."""
    claimed = {e for c in chains for e in c.event_ids}
    relevant_unclaimed = [e for e in ordered
                          if e.event_id not in claimed and e.event_type in RELEVANT]
    for e in relevant_unclaimed:
        best_c, best_i, best_min = None, -1, 0.0
        for c in chains:
            ids = c.event_ids
            # candidate positions keep chronology: find slot by timestamp
            for i in range(len(ids) + 1):
                prev_ok = True
                next_ok = True
                if i > 0:
                    prev_ok = correlate_pair(by_id[ids[i - 1]], e,
                                             window_minutes=window_minutes).score >= threshold
                if i < len(ids):
                    next_ok = correlate_pair(e, by_id[ids[i]],
                                             window_minutes=window_minutes).score >= threshold
                if prev_ok and next_ok and (i == 0 or i == len(ids) or True):
                    # require true chronological fit
                    t = e.timestamp
                    if i > 0 and by_id[ids[i - 1]].timestamp > t:
                        continue
                    if i < len(ids) and by_id[ids[i]].timestamp < t:
                        continue
                    s = min(correlate_pair(by_id[ids[i - 1]], e, window_minutes=window_minutes).score
                            if i > 0 else 1.0,
                            correlate_pair(e, by_id[ids[i]], window_minutes=window_minutes).score
                            if i < len(ids) else 1.0)
                    if s > best_min:
                        best_c, best_i, best_min = c, i, s
        if best_c is not None:
            best_c.event_ids.insert(best_i, e.event_id)
            claimed.add(e.event_id)
            types = {by_id[i].event_type for i in best_c.event_ids}
            if findings:
                pathset = set(best_c.event_ids)
                for f in findings:
                    rule = getattr(f, "rule_name", None)
                    ids = list(getattr(f, "event_ids", []))
                    if rule in RULE_AS_RELEVANT and ids and ids[-1] in pathset:
                        types.add(RULE_AS_RELEVANT[rule])
            label = _label_for(types)
            if label is not None and label != best_c.label:
                best_c.label = label
                best_c.hypothesis = HYPOTHESIS_BY_LABEL[label]
            pair_scores = [correlate_pair(by_id[a], by_id[b], window_minutes=window_minutes).score
                           for a, b in zip(best_c.event_ids, best_c.event_ids[1:])]
            best_c.mean_score = round(sum(pair_scores) / len(pair_scores), 3)


def attach_rules(chains: list[Chain], findings: list) -> list[Chain]:
    """Annotate chains with the rule names of overlapping SuspiciousEvents."""
    for c in chains:
        hit = {f.rule_name for f in findings if set(f.event_ids) & set(c.event_ids)}
        c.supporting_rules = sorted(hit)
    return chains

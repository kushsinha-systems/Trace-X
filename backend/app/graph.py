"""Forensic graph builder — Phase 8.

Nodes = users / files / processes / devices / events.
Edges = accessed / modified / copied / connected / executed / preceded /
correlated-with. Every event node carries its click-through payload: event
detail, directly related evidence ids, why it was flagged (named
indicators), interpretation + explicit limitation.
"""
from __future__ import annotations

from .chains import Chain
from .correlation import Correlation
from .antiforensics import SuspiciousEvent
from .models import CanonicalEvent, EventType

VERB = {
    EventType.FILE_ACCESSED: "accessed",
    EventType.FILE_MODIFIED: "modified",
    EventType.FILE_COPIED: "copied",
    EventType.FILE_DELETED: "deleted",
    EventType.FILE_CREATED: "created",
    EventType.PAGE_VISIT: "visited",
    EventType.FILE_DOWNLOAD: "downloaded",
    EventType.DEVICE_CONNECTED: "connected",
    EventType.DEVICE_DISCONNECTED: "disconnected",
    EventType.LOGIN: "logged-in",
    EventType.LOGOFF: "logged-off",
    EventType.LOG_CLEARED: "cleared",
    EventType.TIMESTAMP_ANOMALY: "anomaly-in",
    EventType.PROCESS_CREATED: "executed",
}


def _entity_id(kind: str, value: str) -> str:
    return f"{kind}:{value}"


def build_graph(
    events: list[CanonicalEvent],
    correlations: list[Correlation] | None = None,
    findings: list[SuspiciousEvent] | None = None,
    chains: list[Chain] | None = None,
) -> dict:
    findings = findings or []
    chains = chains or []
    correlations = correlations or []
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    finding_by_event: dict[str, list[dict]] = {}
    for f in findings:
        for eid in f.event_ids:
            finding_by_event.setdefault(eid, []).append({
                "rule": f.rule_name, "score": f.suspicion_score,
                "level": f.level, "indicators": f.indicators,
                "limitation": f.limitation,
            })
    chain_by_event: dict[str, list[dict]] = {}
    for c in chains:
        for eid in c.event_ids:
            chain_by_event.setdefault(eid, []).append({
                "label": c.label, "hypothesis": c.hypothesis,
                "limitation": c.limitation, "mean_score": c.mean_score,
            })

    def entity(kind: str, value: str | None):
        if not value:
            return
        nid = _entity_id(kind, value)
        if nid not in nodes:
            nodes[nid] = {"id": nid, "kind": kind, "label": value}

    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    for e in ordered:
        nodes[e.event_id] = {
            "id": e.event_id, "kind": "event", "label": e.event_type.value,
            "event_type": e.event_type.value, "timestamp": e.timestamp.isoformat(),
            "user": e.user, "object": e.object, "process": e.process,
            "device_id": e.device_id, "source": e.source.value,
            "provenance": e.provenance.model_dump(), "hash": e.hash,
            "renamed_from": (e.raw_metadata or {}).get("renamed_from"),
            "flagged_by": finding_by_event.get(e.event_id, []),
            "chains": chain_by_event.get(e.event_id, []),
            "related_evidence": [x.event_id for x in ordered
                                 if x.event_id != e.event_id and (
                                     (x.object and x.object == e.object)
                                     or (x.user and x.user == e.user)
                                     or (x.device_id and x.device_id == e.device_id))][:25],
        }
        verb = VERB.get(e.event_type, "related-to")
        if e.user:
            entity("user", e.user)
            edges.append({"from": _entity_id("user", e.user), "to": e.event_id, "verb": verb})
        target_kind = "device" if e.device_id and e.event_type.value.startswith("DEVICE_") else (
            "file" if e.object else None)
        if e.object and target_kind:
            entity(target_kind, e.object)
            edges.append({"from": e.event_id, "to": _entity_id(target_kind, e.object), "verb": verb})
        if e.process and e.event_type is EventType.PROCESS_CREATED:
            entity("process", e.process)
            edges.append({"from": e.event_id, "to": _entity_id("process", e.process), "verb": "executed"})
        elif e.process:
            entity("process", e.process)
            edges.append({"from": _entity_id("process", e.process), "to": e.event_id, "verb": "ran-in"})

    for i in range(len(ordered) - 1):
        edges.append({"from": ordered[i].event_id, "to": ordered[i + 1].event_id, "verb": "preceded"})
    for c in correlations:
        edges.append({"from": c.event_id_a, "to": c.event_id_b,
                      "verb": "correlated-with", "score": c.score, "factors": c.factors})
    return {"nodes": list(nodes.values()), "edges": edges}

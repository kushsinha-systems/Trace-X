"""Case comparison — snapshot the current analysis, diff a later one against it.

Typical use: snapshot a machine's case, load a later collection (or run a live
session), then ask "what is new?". Items are matched by CONTENT, not by ids,
because event and finding ids are regenerated whenever a case is reloaded:
events by content hash, findings by their stable key, chains by label + the
content hashes of their events.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .antiforensics import SuspiciousEvent
from .models import CanonicalEvent

SNAP_ID = re.compile(r"^[0-9A-Za-z_.-]{1,80}$")  # file stems only: no path tricks through the API


def snapshot_dir(db_file: str | Path) -> Path:
    """Snapshots shared by every store in the folder, so a synthetic or ingested case can be
    compared with a live session (and back) — the comparison is across cases, not within one.
    A single snapshot from before this folder existed (case_snapshot.json) is moved in."""
    d = Path(db_file).parent / "snapshots"
    d.mkdir(exist_ok=True)
    legacy = Path(db_file).parent / "case_snapshot.json"
    if legacy.exists():
        legacy.replace(d / "legacy.json")
    return d


def _stamp_id(taken_at: str) -> str:
    return re.sub(r"[^0-9]", "", taken_at)[:20]  # 2026-10-28T07:05:11.001086+00:00 -> 20261028070511001086


def summarise(events: list[CanonicalEvent], findings: list[SuspiciousEvent], chains: list,
              case_name: str = "") -> dict:
    h = {e.event_id: e.hash for e in events}
    return {
        "case_name": case_name,
        "taken_at": datetime.now(timezone.utc).isoformat(),
        "events": {e.hash: f"{e.event_type.value} {e.timestamp.isoformat()} {e.object or e.user or ''}".strip()
                   for e in events},
        "findings": {f.key: {"rule": f.rule_name, "level": f.level, "score": f.suspicion_score,
                             "about": f.object or f.user} for f in findings},
        "chains": {f"{c.label}|{','.join(sorted(h.get(i, i)[:16] for i in c.event_ids))}":
                   {"label": c.label, "events": len(c.event_ids), "mean": c.mean_score} for c in chains},
    }


def _meta(sid: str, s: dict) -> dict:
    return {"id": sid, "taken_at": s.get("taken_at"), "case_name": s.get("case_name", ""),
            "events": len(s.get("events", {})), "findings": len(s.get("findings", {})),
            "chains": len(s.get("chains", {}))}


def take(db_file: str | Path, summary: dict) -> dict:
    d = snapshot_dir(db_file)
    sid = _stamp_id(summary["taken_at"])
    (d / f"{sid}.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return _meta(sid, summary)


def list_snapshots(db_file: str | Path) -> list[dict]:
    """Every saved snapshot, newest first."""
    out = []
    for p in snapshot_dir(db_file).glob("*.json"):
        try:
            out.append(_meta(p.stem, json.loads(p.read_text(encoding="utf-8"))))
        except (OSError, ValueError):
            continue  # a half-written or foreign file is not a snapshot
    return sorted(out, key=lambda m: m["taken_at"] or "", reverse=True)


def delete_all(db_file: str | Path) -> int:
    gone = 0
    for p in snapshot_dir(db_file).glob("*.json"):
        p.unlink(missing_ok=True)
        gone += 1
    return gone


def diff(db_file: str | Path, now: dict, snapshot_id: str | None = None) -> dict:
    """Compare `now` with one snapshot (the newest unless `snapshot_id` names another)."""
    snaps = list_snapshots(db_file)
    if snapshot_id is not None and not SNAP_ID.match(snapshot_id):
        raise ValueError("bad snapshot id")
    sid = snapshot_id if snapshot_id and any(m["id"] == snapshot_id for m in snaps) else (snaps[0]["id"] if snaps else None)
    if sid is None:
        return {"has_snapshot": False}
    then = json.loads((snapshot_dir(db_file) / f"{sid}.json").read_text(encoding="utf-8"))

    def d(kind):
        a, b = then[kind], now[kind]
        return {"new": [b[k] for k in b.keys() - a.keys()], "gone": [a[k] for k in a.keys() - b.keys()],
                "same": len(a.keys() & b.keys())}

    findings = d("findings")
    changed_level = [{"key": k, "before": then["findings"][k]["level"], "after": now["findings"][k]["level"],
                      "rule": now["findings"][k]["rule"]}
                     for k in then["findings"].keys() & now["findings"].keys()
                     if then["findings"][k]["level"] != now["findings"][k]["level"]]
    return {"has_snapshot": True, "snapshot": {"id": sid, "case_name": then.get("case_name"), "taken_at": then.get("taken_at")},
            "events": d("events"), "findings": {**findings, "level_changed": changed_level}, "chains": d("chains")}

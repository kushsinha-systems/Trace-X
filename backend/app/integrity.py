"""Tamper-evident case record — seal the store, verify it later.

Each event gets a digest over ALL its fields (not only the content hash, which by
design excludes provenance/user/device). Digests in timeline order are linked into
a hash chain:  h0 = SHA-256("TRACE-X case seal v1"),  h_i = SHA-256(h_{i-1} || d_i).
The final link is the case hash, printed on the report. Sealing writes the digests
to a sidecar file next to the store; verifying recomputes and names every event
that was changed, added or removed since. Two more checks need no seal at all:
each event's stored content hash must still match its content.

Limitation: someone who can rewrite both the store and the sidecar can re-seal.
The case hash on a printed or submitted report is the external anchor.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from .models import CanonicalEvent

GENESIS = hashlib.sha256(b"TRACE-X case seal v1").hexdigest()


def digest(e: CanonicalEvent) -> str:
    blob = json.dumps(e.model_dump(mode="json"), sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def chain(events: list[CanonicalEvent]) -> tuple[str, list[tuple[str, str]]]:
    """(case hash, [(event_id, digest)] in timeline order)."""
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    h, items = GENESIS, []
    for e in ordered:
        d = digest(e)
        h = hashlib.sha256((h + d).encode()).hexdigest()
        items.append((e.event_id, d))
    return h, items


def seal_path(db_file: str | Path) -> Path:
    return Path(str(db_file) + ".seal.json")


def seal(events: list[CanonicalEvent], db_file: str | Path, *, reason: str = "manual") -> dict:
    case_hash, items = chain(events)
    record = {"case_hash": case_hash, "events": len(items), "sealed_at": datetime.now(timezone.utc).isoformat(),
              "reason": reason, "digests": dict(items)}
    seal_path(db_file).write_text(json.dumps(record, indent=1), encoding="utf-8")
    return {k: v for k, v in record.items() if k != "digests"}


def verify(events: list[CanonicalEvent], db_file: str | Path) -> dict:
    case_hash, items = chain(events)
    content_bad = [e.event_id for e in events if e.hash and e.hash != e.compute_hash()]
    out = {"case_hash": case_hash, "events": len(items), "content_hash_mismatches": content_bad}
    p = seal_path(db_file)
    if not p.exists():
        return {**out, "sealed": False, "verified": None if not content_bad else False,
                "summary": "Not sealed yet." + (" Content hashes already disagree!" if content_bad else "")}
    rec = json.loads(p.read_text(encoding="utf-8"))
    now = dict(items)
    then = rec.get("digests", {})
    changed = sorted(i for i in now.keys() & then.keys() if now[i] != then[i])
    added = sorted(now.keys() - then.keys())
    removed = sorted(then.keys() - now.keys())
    ok = case_hash == rec["case_hash"] and not content_bad
    summary = ("Verified: the store matches its seal." if ok else
               f"Integrity FAILED: {len(changed)} changed, {len(added)} added, {len(removed)} removed"
               + (f", {len(content_bad)} content-hash mismatches" if content_bad else "") + ".")
    return {**out, "sealed": True, "verified": ok, "sealed_case_hash": rec["case_hash"],
            "sealed_at": rec.get("sealed_at"), "seal_reason": rec.get("reason"),
            "changed": changed, "added": added, "removed": removed, "summary": summary}

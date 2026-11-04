"""Investigator review — the human decision on each finding, with an audit log.

TRACE-X flags; a person decides. Each decision (confirmed / false_alarm / unsure,
plus a note and the reviewer's name) is appended to an audit log in a sidecar
file next to the store, keyed by the finding's stable key so it survives
re-analysis. The log is append-only: a changed mind is a new entry, never an edit.

From the decisions, `suggest_thresholds` proposes per-rule cut-offs that would
have kept every confirmed finding while dropping false alarms — a suggestion for
the investigator, never applied automatically.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .antiforensics import SuspiciousEvent

VERDICTS = ("confirmed", "false_alarm", "unsure")


def review_path(db_file: str | Path) -> Path:
    return Path(str(db_file) + ".review.json")


def _log(db_file) -> list[dict]:
    p = review_path(db_file)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def record(db_file, *, key: str, verdict: str, note: str = "", reviewer: str = "",
           finding: SuspiciousEvent | None = None) -> dict:
    if verdict not in VERDICTS:
        raise ValueError(f"verdict must be one of {VERDICTS}")
    entry = {"at": datetime.now(timezone.utc).isoformat(), "key": key, "verdict": verdict,
             "note": note.strip(), "reviewer": reviewer.strip() or "investigator"}
    if finding is not None:
        entry.update(rule=finding.rule_name, score=finding.suspicion_score, level=finding.level,
                     about=finding.object or finding.user)
    log = _log(db_file)
    log.append(entry)
    review_path(db_file).write_text(json.dumps(log, indent=1), encoding="utf-8")
    return entry


def current(db_file) -> dict[str, dict]:
    """Latest decision per finding key."""
    out: dict[str, dict] = {}
    for e in _log(db_file):
        out[e["key"]] = e
    return out


def suggest_thresholds(decisions: dict[str, dict]) -> list[dict]:
    by_rule: dict[str, dict[str, list[float]]] = {}
    for d in decisions.values():
        if "rule" in d and d["verdict"] in ("confirmed", "false_alarm"):
            by_rule.setdefault(d["rule"], {"confirmed": [], "false_alarm": []})[d["verdict"]].append(d["score"])
    out = []
    for rule, s in sorted(by_rule.items()):
        tp, fp = s["confirmed"], s["false_alarm"]
        if not fp:
            continue
        if tp and max(fp) < min(tp):
            cut = round((max(fp) + min(tp)) / 2, 3)
            out.append({"rule": rule, "suggest_min_score": cut,
                        "reason": f"would drop {len(fp)} false alarm(s) (max {max(fp):.2f}) and keep "
                                  f"{len(tp)} confirmed (min {min(tp):.2f})"})
        else:
            out.append({"rule": rule, "suggest_min_score": None,
                        "reason": "false alarms score as high as confirmed findings: a threshold can't separate "
                                  "them; review context instead" if tp else
                                  f"{len(fp)} false alarm(s) and no confirmed finding yet: not enough to suggest a cut-off"})
    return out

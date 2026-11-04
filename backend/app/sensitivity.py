"""Sensitivity analysis — "what would change this conclusion?"

1. Per finding: the smallest change to ONE observed quantity that would drop it a
   severity level, computed from the same weights the score uses (no new model).
2. Threshold sweep: correlation pairs and chains across chain thresholds, and the
   threshold range over which each default chain keeps its label and events.
"""
from __future__ import annotations

from .antiforensics import W_AFFECTED, W_MULTIPLE, W_PRIOR, W_TEMPORAL, SuspiciousEvent
from .chains import detect_chains
from .correlation import correlate_all
from .models import CanonicalEvent

LEVEL_CUTS = (("HIGH", 0.70), ("MEDIUM", 0.40))
# rule -> (window size, unit, what the timing indicator measures)
TIMING = {
    "evidence_deletion": (15.0, "min", "gap between the last access/copy and the delete"),
    "log_clearing": (60.0, "min", "gap between the nearest relevant event and the clear"),
    "mass_deletion": (2.0, "min", "time span of the deletion burst"),
    "timestamp_anomaly": (24.0, "h", "$SI/$FN skew (full marks at 24 h or more)"),
}
WEIGHTS = {"relevant_prior_activity": W_PRIOR, "short_temporal_distance": W_TEMPORAL,
           "multiple_related_events": W_MULTIPLE, "evidence_directly_affected": W_AFFECTED}
PLAIN = {"relevant_prior_activity": "the relevant earlier activity",
         "multiple_related_events": "the corroborating events",
         "evidence_directly_affected": "the affected file"}


def _level(score: float) -> str:
    return "HIGH" if score >= 0.70 else ("MEDIUM" if score >= 0.40 else "LOW")


def counterfactuals(f: SuspiciousEvent) -> dict:
    ind = f.indicators
    score = sum(WEIGHTS[k] * v for k, v in ind.items() if k in WEIGHTS)
    level = _level(score)
    lower_cut = next((c for lv, c in LEVEL_CUTS if lv == level), None)
    lines: list[str] = []
    if lower_cut is None:
        return {"level": level, "lines": ["Already LOW: no single change lowers it further."]}
    target = "MEDIUM" if level == "HIGH" else "LOW"
    # (a) timing: how far the observed quantity must move for the score to fall below the cut
    t = ind.get("short_temporal_distance", 0.0)
    if f.rule_name in TIMING:
        window, unit, what = TIMING[f.rule_name]
        rest = score - W_TEMPORAL * t
        need_t = (lower_cut - rest) / W_TEMPORAL  # timing value at which score == cut
        if f.rule_name == "timestamp_anomaly":  # higher skew = higher t
            observed = t * window
            if need_t <= 0:
                lines.append(f"Timing alone can't lower it: even a negligible skew stays {level} (other indicators carry it).")
            else:
                seen_txt = f"{window:g} {unit} or more" if t >= 1 else f"{observed:.1f} {unit}"
                lines.append(f"Drops to {target} if the {what} were under {need_t * window:.1f} {unit} "
                             f"(observed {seen_txt}).")
        else:  # t = 1 - gap/window: larger gap = lower t
            observed = (1 - t) * window
            if need_t <= 0:
                lines.append(f"Timing alone can't lower it: even at the edge of the {window:g}-{unit} window it stays {level}.")
            elif need_t > 1:
                lines.append(f"Timing can't lift it back: the {what} is already decisive.")
            else:
                lines.append(f"Drops to {target} if the {what} had been over {(1 - need_t) * window:.1f} {unit} "
                             f"(observed {observed:.1f} {unit}).")
    # (b) each boolean indicator removed on its own
    for k, w in WEIGHTS.items():
        if k == "short_temporal_distance" or ind.get(k, 0) <= 0:
            continue
        new = score - w * ind[k]
        if _level(new) != level:
            lines.append(f"Drops to {_level(new)} without {PLAIN[k]} (score {score:.2f} → {new:.2f}).")
        else:
            lines.append(f"Stays {level} without {PLAIN[k]} alone (score {score:.2f} → {new:.2f}).")
    return {"level": level, "lines": lines}


def threshold_sweep(events: list[CanonicalEvent], findings: list[SuspiciousEvent],
                    thresholds: list[float] | None = None, default: float = 0.6) -> dict:
    thresholds = thresholds or [round(0.40 + 0.02 * i, 2) for i in range(26)]  # 0.40 … 0.90
    if default not in thresholds:
        thresholds = sorted({*thresholds, default})
    base = {(c.label, frozenset(c.event_ids)) for c in detect_chains(events, threshold=default, findings=findings)}
    rows, holds = [], {k: [] for k in base}
    for th in thresholds:
        chains = detect_chains(events, threshold=th, findings=findings)
        rows.append({"threshold": th, "pairs": len(correlate_all(events, threshold=th)), "chains": len(chains)})
        present = {(c.label, frozenset(c.event_ids)) for c in chains}
        for k in base:
            holds[k].append(th if k in present else None)
    ranges = []
    for (label, ids), seq in holds.items():
        i = thresholds.index(default)
        lo = hi = default
        for th in reversed(thresholds[:i]):  # walk down from the default while the chain holds
            if seq[thresholds.index(th)] is None:
                break
            lo = th
        for th in thresholds[i + 1:]:
            if seq[thresholds.index(th)] is None:
                break
            hi = th
        nxt = next((th for th in thresholds if th > hi), None)
        ranges.append({"label": label, "events": len(ids), "holds_from": lo, "holds_to": hi,
                       "breaks_at": nxt})
    return {"default": default, "rows": rows, "chains": ranges}


def analyse(events: list[CanonicalEvent], findings: list[SuspiciousEvent]) -> dict:
    return {"findings": {f.key: counterfactuals(f) for f in findings},
            "sweep": threshold_sweep(events, findings)}

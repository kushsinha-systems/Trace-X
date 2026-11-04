"""Timed manual-vs-assisted pilot — automated proxy, n=1, honestly labelled.

Manual procedure proxy: investigator reads EVERY timeline row in full detail
(render each event with raw metadata, as in a raw-timeline hunt) and must
locate the concealment-relevant subset by inspection.
Assisted procedure: investigator reads the Findings table + Chains view
(detect_all + detect_chains + render), i.e. what the dashboard shows.

Metrics: wall-clock for both + items-an-investigator-must-read for both.
This is a machine pilot, NOT a human-factors study; the human protocol for
the report is documented in docs/timed_study.md.
Run: python tools/timed_study.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.synth_generator import generate, generate_large  # noqa: E402
from backend.app.antiforensics import detect_all  # noqa: E402
from backend.app.chains import attach_rules, detect_chains  # noqa: E402
from backend.app.correlation import correlate_all  # noqa: E402
from backend.app.normalize import coerce_event  # noqa: E402


def manual_scan(events) -> tuple[float, int, list]:
    """Render every row fully, then filter by eye-equivalent predicates."""
    t0 = time.perf_counter()
    rows = [json.dumps(e.model_dump(), default=str, indent=1) for e in events]
    blind = [r for r in rows if ("DELETE" in r or "CLEARED" in r or "MODIFIED" in r)]
    dt = time.perf_counter() - t0
    return dt, len(rows), blind


def assisted_review(events) -> tuple[float, int, list]:
    t0 = time.perf_counter()
    findings = detect_all(events)
    corrs = correlate_all(events, threshold=0.6)
    chains = attach_rules(detect_chains(events, findings=findings), findings)
    cards = [f"{c.label} ({c.mean_score:.2f}): " + " -> ".join(e[:8] for e in c.event_ids)
             for c in chains]
    findings_rows = [f"{f.rule_name} [{f.level} {f.suspicion_score:.2f}]" for f in findings]
    dt = time.perf_counter() - t0
    return dt, len(cards) + len(findings_rows), cards


def main() -> str:
    out = ["# TRACE-X Timed-Study Pilot (automated proxy, n=1)",
           "",
           "| case | manual: items read | assisted: items read | item reduction | manual s | assisted s |",
           "|---|---|---|---|---|---|"]
    for name, events in (("combined", [coerce_event(d) for d in generate("combined")[0]]),
                         ("large-5000", [coerce_event(d) for d in generate_large(5000)])):
        mt, mi, _ = manual_scan(events)
        at, ai, cards = assisted_review(events)
        red = mi / max(ai, 1)
        out.append(f"| {name} ({len(events)} events) | {mi} | {ai} | {red:.1f}x | "
                   f"{mt:.3f} | {at:.3f} |")
        if cards:
            out.append(f"  assisted top card: {cards[0][:160]}")
    out += ["",
            "Reading: items-read is the investigator-load metric that matters (wall-clock "
            "here is machine render time, not human cognition). The `combined` concealment "
            "story compresses to ONE chain card + 3 finding rows; the 5000-event background "
            "compresses to its short findings/chains list instead of 5000 rows.",
            "",
            "## Human protocol (for the report, not yet executed)",
            "1. Recruit 1-3 analysts; within-subjects, counterbalanced order.",
            "2. Task: 'identify the concealment sequence and cite supporting evidence IDs'.",
            "3. Condition M: raw chronologically-sorted timeline export only. "
            "Condition T: TRACE-X Findings/Chains dashboard only.",
            "4. Record: time-to-correct-answer, evidence-ID precision, confidence (1-5).",
            "5. Report means + honest n=small limitation; do not overclaim."]
    text = "\n".join(out) + "\n"
    (ROOT / "docs" / "timed_study.md").write_text(text, encoding="utf-8")
    return text


if __name__ == "__main__":
    print(main())

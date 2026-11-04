"""Report generator — Phase 8.

Structured Markdown (PDF export is a UI print-to-PDF step, no extra deps),
ordered answer-first for an investigator reading top-down:

  1 case summary · 2 investigator hypotheses (each chain step by step) ·
  3 suspicious events with score breakdowns · 4 timeline excerpt (gaps inline) ·
  5 correlations (top) · 6 timeline gaps · 7 evidence inventory (provenance) ·
  8 method and scoring · 9 limitations

Every conclusion cites evidence IDs; every hypothesis carries its limitation.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .antiforensics import W_AFFECTED, W_MULTIPLE, W_PRIOR, W_TEMPORAL, SuspiciousEvent
from .chains import Chain
from .correlation import Correlation, W_DEVICE, W_OBJECT, W_PROCESS, W_TEMPORAL as C_TEMPORAL, W_USER
from .models import CanonicalEvent

INDICATOR_WEIGHTS = {
    "relevant_prior_activity": W_PRIOR,
    "short_temporal_distance": W_TEMPORAL,
    "multiple_related_events": W_MULTIPLE,
    "evidence_directly_affected": W_AFFECTED,
}
INDICATOR_MEANING = {
    "relevant_prior_activity": "relevant context before the event",
    "short_temporal_distance": "closeness in time (skew size for timestamps)",
    "multiple_related_events": "enough corroborating events",
    "evidence_directly_affected": "a file was directly affected",
}
RULE_MEANING = {
    "evidence_deletion": "file accessed, copied or modified, then deleted within 15 min",
    "log_clearing": "audit or system log cleared (1102/104), scored on the hour before it",
    "timestamp_anomaly": "$STANDARD_INFORMATION timestamp older than its $FILE_NAME twin",
    "mass_deletion": "20 or more distinct files deleted within 2 min",
    "metadata_modification": "metadata changed with no content activity within ±60 min",
}
LEVELS = ("HIGH", "MEDIUM", "LOW")


def _short(eid: str) -> str:
    return eid[:8]


def _cell(text: object) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ") if text not in (None, "") else "—"


def generate_report(
    *,
    case_name: str,
    events: list[CanonicalEvent],
    findings: list[SuspiciousEvent],
    correlations: list[Correlation],
    chains: list[Chain],
    gaps: list | None = None,
    top_correlations: int = 20,
    timeline_excerpt_n: int = 60,
    extras: dict | None = None,
) -> str:
    """extras (optional) adds sections 10-15: attack, sensitivity, hypotheses, expectations,
    review, integrity, court, each the matching API payload."""
    gaps = gaps or []
    extras = extras or {}
    now = datetime.now(timezone.utc)
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    by_id = {e.event_id: e for e in ordered}
    one_day = len({e.timestamp.date() for e in ordered}) <= 1

    def t(ts: datetime) -> str:
        return ts.strftime("%H:%M:%S") if one_day else ts.strftime("%Y-%m-%d %H:%M:%S")

    def ev(eid: str) -> str:
        e = by_id.get(eid)
        return f"{e.event_type.value} at {t(e.timestamp)} (`{_short(eid)}`)" if e else f"`{_short(eid)}`"

    L: list[str] = []
    A = L.append

    # ---- title + meta -------------------------------------------------------
    A(f"# TRACE-X Forensic Report — {case_name}")
    A("")
    meta = [f"Generated {now.strftime('%Y-%m-%d %H:%M')} UTC"]
    if ordered:
        span = f"{ordered[0].timestamp.strftime('%Y-%m-%d %H:%M')} → {ordered[-1].timestamp.strftime('%H:%M' if one_day else '%Y-%m-%d %H:%M')} UTC"
        meta.append(f"case window {span}")
    meta.append("tiers: **Evidence** (observed) · **Correlation** (measured) · **Hypothesis** (interpreted, with limits)")
    if extras.get("integrity"):
        iv = extras["integrity"]
        state = "verified against seal" if iv.get("verified") else ("NOT sealed" if not iv.get("sealed") else "SEAL MISMATCH")
        meta.append(f"case hash `{iv['case_hash'][:16]}…` ({state})")
    A("_" + " · ".join(meta) + "_")
    A("")

    # ---- 1. case summary ----------------------------------------------------
    A("## 1. Case summary")
    A("")
    by_level = {lv: sum(1 for f in findings if f.level == lv) for lv in LEVELS}
    if chains:
        A(f"**{len(chains)} correlated sequence{'s' if len(chains) != 1 else ''} "
          f"{'were' if len(chains) != 1 else 'was'} found.** {'Each is' if len(chains) != 1 else 'It is'} "
          "presented below as a hypothesis with its stated limitation; this report draws "
          "**no conclusion about intent or guilt**.")
    elif findings:
        A(f"**{len(findings)} anti-forensic indicator{'s' if len(findings) != 1 else ''} fired, "
          "but no correlated sequence met the chain threshold**, so no hypothesis is offered. "
          "The findings are flags for review, not conclusions.")
    else:
        A("**No anti-forensic rule fired and no correlated sequence was found.** "
          "Absence of findings is not proof of absence of activity.")
    A("")
    A("| Measure | Value |")
    A("|---|---|")
    A(f"| Events analysed | {len(events)} |")
    sources = sorted({e.source.value for e in events})
    A(f"| Evidence sources | {_cell(', '.join(sources))} |")
    A(f"| People / hosts | {_cell(', '.join(sorted({e.user for e in events if e.user})))} / "
      f"{_cell(', '.join(sorted({e.device_id for e in events if e.device_id and not e.event_type.value.startswith('DEVICE_')})))} |")
    A(f"| Suspicious events | {len(findings)} (HIGH {by_level['HIGH']} · MEDIUM {by_level['MEDIUM']} · LOW {by_level['LOW']}) |")
    A(f"| Rule families hit | {len({f.rule_name for f in findings})} of 5 |")
    A(f"| Correlated pairs (≥ 0.6) | {len(correlations)} |")
    A(f"| Hypothesis chains | {len(chains)} |")
    A(f"| Potentially significant gaps | {len(gaps)} |")
    A("")
    if chains:
        A("**At a glance**")
        A("")
        for i, c in enumerate(chains, 1):
            people = sorted({by_id[x].user for x in c.event_ids if x in by_id and by_id[x].user})
            first, last = by_id.get(c.event_ids[0]), by_id.get(c.event_ids[-1])
            when = f"{t(first.timestamp)}–{t(last.timestamp)}" if first and last else ""
            A(f"- **H{i} · {c.label}** — {len(c.event_ids)} events, {when}, "
              f"user {_cell(', '.join(people))}; mean link {c.mean_score:.2f}; "
              f"rules: {_cell(', '.join(c.supporting_rules))}.")
        A("")

    # ---- 2. investigator hypotheses ----------------------------------------
    A("## 2. Investigator hypotheses")
    A("")
    if not chains:
        A("No correlated sequence met the chain threshold (every link ≥ 0.6, at least 3 events, "
          "an anti-forensic signal present), so no hypothesis is offered.")
        A("")
    for i, c in enumerate(chains, 1):
        A(f"### H{i}. {c.label}")
        A("")
        A(f"**Interpretation:** {c.hypothesis[0].upper() + c.hypothesis[1:]}.")
        A("")
        A(f"> **Does not establish:** {c.limitation}")
        A("")
        A(f"Mean link score **{c.mean_score:.2f}** · supporting rules: "
          f"{', '.join(f'`{r}`' for r in c.supporting_rules) or 'none'}")
        A("")
        A("| Step | Time | Event | User | Object | Evidence | Link to next |")
        A("|---|---|---|---|---|---|---|")
        corr_by_pair = {frozenset((x.event_id_a, x.event_id_b)): x for x in correlations}
        for n, eid in enumerate(c.event_ids, 1):
            e = by_id.get(eid)
            if e is None:
                continue
            nxt = c.event_ids[n] if n < len(c.event_ids) else None
            link = corr_by_pair.get(frozenset((eid, nxt))) if nxt else None
            link_txt = f"{link.score * 100:.0f}%" if link else ("—" if nxt is None else "below top list")
            A(f"| {n} | {t(e.timestamp)} | {e.event_type.value} | {_cell(e.user)} | {_cell(e.object)} "
              f"| `{_short(eid)}` | {link_txt} |")
        A("")

    # ---- 3. suspicious events ----------------------------------------------
    A("## 3. Suspicious events (anti-forensics findings)")
    A("")
    if not findings:
        A("None. No anti-forensic rule fired on this case.")
        A("")
    else:
        A("| Level | Score | Rule | About | Trigger |")
        A("|---|---|---|---|---|")
        for f in findings:
            trig = by_id.get(f.event_ids[-1]) if f.event_ids else None
            A(f"| **{f.level}** | {f.suspicion_score:.2f} | `{f.rule_name}` | {_cell(f.object or f.user)} "
              f"| {_cell(trig.event_type.value + ' at ' + t(trig.timestamp) if trig else '')} |")
        A("")
        for i, f in enumerate(findings, 1):
            A(f"### F{i}. `{f.rule_name}` — {f.level} {f.suspicion_score:.2f}")
            A("")
            A(f"_Rule: {RULE_MEANING.get(f.rule_name, f.rule_name)}._ {f.description.replace('Evidence-tier: ', 'Observed: ')}")
            A("")
            A("| Indicator | Meaning | Value | × Weight | = Points |")
            A("|---|---|---|---|---|")
            total = 0.0
            for k, v in f.indicators.items():
                w = INDICATOR_WEIGHTS.get(k, 0.0)
                total += w * v
                A(f"| `{k}` | {INDICATOR_MEANING.get(k, '')} | {v:.2f} | {w:.2f} | {w * v:.3f} |")
            A(f"| **Total** | | | | **{total:.3f}** |")
            A("")
            A(f"Evidence: {', '.join(f'`{_short(x)}`' for x in f.event_ids)}")
            A("")

    # ---- 4. timeline excerpt -----------------------------------------------
    A("## 4. Timeline excerpt")
    A("")
    flagged: dict[str, str] = {}
    for f in findings:
        for x in f.event_ids[-1:]:  # the trigger event of each finding
            flagged.setdefault(x, f.level)
    A("| Time | Event | User | Object | Source | Evidence | Flag |")
    A("|---|---|---|---|---|---|---|")
    gap_after = {g.gap_start: g for g in gaps}
    for e in ordered[:timeline_excerpt_n]:
        A(f"| {t(e.timestamp)} | {e.event_type.value} | {_cell(e.user)} | {_cell(e.object)} "
          f"| {e.source.value} | `{_short(e.event_id)}` | {flagged.get(e.event_id, '')} |")
        g = gap_after.get(e.timestamp)
        if g is not None:
            A(f"| ⋯ | _no events for {g.duration_minutes:.0f} min_ | | | | | GAP |")
    A("")
    if len(ordered) > timeline_excerpt_n:
        A(f"_{len(ordered) - timeline_excerpt_n} further events are in the store and the dashboard Timeline tab._")
        A("")

    # ---- 5. correlations ---------------------------------------------------
    A("## 5. Correlations (top)")
    A("")
    if not correlations:
        A("No pair of events reached the 0.6 correlation threshold.")
        A("")
    else:
        shown = correlations[:top_correlations]
        A(f"{len(correlations)} pair{'s' if len(correlations) != 1 else ''} at or above 0.6"
          + (f"; the strongest {len(shown)} are shown." if len(correlations) > len(shown) else "."))
        A("")
        A("| Score | Event A | Event B | Why they relate |")
        A("|---|---|---|---|")
        for c in shown:
            A(f"| **{c.score * 100:.0f}%** | {ev(c.event_id_a)} | {ev(c.event_id_b)} | {_cell('; '.join(c.factors))} |")
        A("")

    # ---- 6. gaps ----------------------------------------------------------
    A("## 6. Timeline gaps")
    A("")
    if not gaps:
        A("No silence over 30 minutes inside 06:00–22:00 UTC, so no part of the timeline relies on "
          "inferring activity across an unobserved interval.")
    else:
        A("| From | To | Silent for |")
        A("|---|---|---|")
        for g in gaps:
            A(f"| {t(g.gap_start)} | {t(g.gap_end)} | {g.duration_minutes:.0f} min |")
        A("")
        A("Gaps are prompts for review only. They do not establish log clearing, deletion or any "
          "anti-forensic activity.")
    A("")

    # ---- 7. evidence inventory --------------------------------------------
    A("## 7. Evidence inventory (provenance)")
    A("")
    A("| Evidence | Type | Source file | Parser | Original record | SHA-256 (first 16) |")
    A("|---|---|---|---|---|---|")
    for e in ordered:
        p = e.provenance
        A(f"| `{_short(e.event_id)}` | {e.event_type.value} | {_cell(p.source_file)} "
          f"| {_cell(p.parser_name)} {_cell(p.parser_version)} | {_cell(p.original_record_offset_or_id)} "
          f"| `{e.hash[:16]}` |")
    A("")

    # ---- 8. method -------------------------------------------------------
    A("## 8. Method and scoring")
    A("")
    A(f"- **Suspicion score** = {W_PRIOR:.2f} × prior activity + {W_TEMPORAL:.2f} × timing "
      f"+ {W_MULTIPLE:.2f} × multiple events + {W_AFFECTED:.2f} × file affected. "
      "LOW < 0.40 ≤ MEDIUM < 0.70 ≤ HIGH.")
    A(f"- **Correlation score** = {C_TEMPORAL:.2f} × time proximity (linear decay to 0 at 30 min) "
      f"+ {W_USER:.2f} same user + {W_OBJECT:.2f} same object + {W_DEVICE:.2f} same device "
      f"+ {W_PROCESS:.2f} same process.")
    A("- **Chain** = 3 or more events in time order, every consecutive link ≥ 0.6, containing a "
      "delete, log clear, copy or rule trigger. Labels follow what the chain contains.")
    A("- Full specification: `docs/scoring_spec.md`. Detection is rule-based and deterministic; "
      "no machine-learning model scores evidence.")
    A("")

    # ---- 9. limitations --------------------------------------------------
    A("## 9. Limitations (must read)")
    A("")
    shared = sorted({c.limitation for c in chains})
    for lim in shared:
        A(f"- **Every hypothesis above** {lim[0].lower() + lim[1:]}")
    for lim in sorted({f.limitation for f in findings}):
        A(f"- **Every finding above:** {lim}")
    A("- Scores are measured indicators, not verdicts; weights are set by design, not calibrated on labelled data.")
    A("- Coverage is 4 evidence sources (Windows event logs, NTFS $MFT, Chrome/Firefox history, USB "
      "records). Absence of findings is not proof of absence of activity.")
    A("- Timeline gaps are review prompts, not conclusions.")
    A("")
    _extra_sections(A, extras, findings)
    return "\n".join(L) + "\n"


def _bullets(items: list[dict]) -> str:
    return " · ".join(f"{i['text']} ({', '.join(i['events'])})" for i in items) or "—"


def _extra_sections(A, x: dict, findings: list[SuspiciousEvent]) -> None:
    fkey = {f.key: f for f in findings}
    if "attack" in x:
        at = x["attack"]
        obs = set(at.get("observed", []))
        A("## 10. MITRE ATT&CK mapping")
        A("")
        A(f"Techniques this case shows evidence of: {', '.join(f'**{t}**' for t in sorted(obs)) or 'none'}. "
          "Coverage states what TRACE-X can and cannot see, case or no case.")
        A("")
        A("| Technique | Name | Tactic | Coverage | In this case | How |")
        A("|---|---|---|---|---|---|")
        for r in at.get("coverage", []):
            A(f"| [{r['id']}]({r['url']}) | {_cell(r['name'])} | {r['tactic']} | {r['coverage'].replace('_', ' ')} "
              f"| {'yes' if r['id'] in obs else ''} | {_cell(r['how'])} |")
        A("")
    if "sensitivity" in x:
        sv = x["sensitivity"]
        sw = sv.get("sweep", {})
        A("## 11. What would change these conclusions")
        A("")
        for i, f in enumerate(findings, 1):
            A(f"- **F{i} `{f.rule_name}` ({f.level} {f.suspicion_score:.2f})**")
            for ln in sv["findings"].get(f.key, {}).get("lines", []):
                A(f"    - {ln}")
        for c in sw.get("chains", []):
            brk = f"; it breaks at {c['breaks_at']:.2f}" if c.get("breaks_at") else ""
            A(f"- **Chain \u201c{c['label']}\u201d** ({c['events']} events) holds for chain thresholds "
              f"{c['holds_from']:.2f}-{c['holds_to']:.2f}{brk} (default {sw.get('default', 0.6):.2f}).")
        if not findings and not sw.get("chains"):
            A("No findings or chains to test.")
        A("")
    if "hypotheses" in x:
        A("## 12. Competing hypotheses")
        A("")
        if not x["hypotheses"]:
            A("No chain or finding to weigh.")
            A("")
        else:
            A("_" + x["hypotheses"][0]["note"] + "_")
            A("")
        for st in x["hypotheses"]:
            A(f"### {st['label']}")
            A("")
            A("| Explanation | Status | Supported by | Contradicted by |")
            A("|---|---|---|---|")
            for h in st["hypotheses"]:
                A(f"| {h['hypothesis']} | **{h['status']}** | {_cell(_bullets(h['supporting']))} "
                  f"| {_cell(_bullets(h['contradicting']))} |")
            A("")
    if "expectations" in x:
        A("## 13. Missing evidence")
        A("")
        if not x["expectations"]:
            A("Every expectation checked is met by the evidence.")
        else:
            A("Artefacts the evidence implies but does not contain: leads to follow up, not findings.")
            A("")
            A("| Gap | Why it matters | Collect next | Evidence |")
            A("|---|---|---|---|")
            for g in x["expectations"]:
                A(f"| {_cell(g['title'])} | {_cell(g['why_it_matters'])} | {_cell(g['collect'])} "
                  f"| {', '.join(f'`{e}`' for e in g['events'])} |")
        A("")
    if "review" in x:
        rv = x["review"]
        dec = rv.get("decisions", {})
        A("## 14. Investigator review")
        A("")
        if not dec:
            A("No finding has been reviewed yet. TRACE-X flags; the investigator decides.")
        else:
            A("| Finding | Decision | Reviewer | Note | When (UTC) |")
            A("|---|---|---|---|---|")
            for k, d in dec.items():
                f = fkey.get(k)
                name = f"`{f.rule_name}` {f.level} {f.suspicion_score:.2f}" if f else f"`{k}` (not in current case)"
                A(f"| {name} | **{d['verdict'].replace('_', ' ')}** | {_cell(d['reviewer'])} | {_cell(d['note'])} "
                  f"| {d['at'][:16].replace('T', ' ')} |")
            A("")
            for sg in rv.get("suggestions", []):
                cut = f"min score {sg['suggest_min_score']}" if sg["suggest_min_score"] is not None else "no cut-off"
                A(f"- Suggestion for `{sg['rule']}`: {cut}: {sg['reason']} (not applied automatically).")
            A(f"- Audit log: {len(rv.get('log', []))} decision(s) recorded, append-only.")
        A("")
    if "integrity" in x or "court" in x:
        A("## 15. Integrity and court readiness")
        A("")
        iv = x.get("integrity")
        if iv:
            A(f"- **Case hash:** `{iv['case_hash']}` over {iv['events']} events (SHA-256 hash chain of full event records).")
            sealed = (f" Sealed {str(iv.get('sealed_at', ''))[:16].replace('T', ' ')} UTC ({iv.get('seal_reason')})."
                      if iv.get("sealed") else "")
            A(f"- **Seal:** {iv['summary']}{sealed}")
            A("")
        if x.get("court"):
            A("Self-assessment against the Daubert factors courts use for scientific evidence:")
            A("")
            A("| Factor | Status | Evidence |")
            A("|---|---|---|")
            for c in x["court"]:
                A(f"| {c['factor']} | **{c['status'].replace('_', ' ')}** | {_cell(c['evidence'])} |")
            A("")

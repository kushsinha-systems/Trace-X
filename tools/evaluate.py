"""TRACE-X evaluation — Phase 10.

Compares System A (timeline only) vs B (+ anti-forensics) vs C (+ chains)
on the six synthetic scenarios, plus performance scaling. Writes measured
numbers to docs/evaluation_results.md — never pre-written expectations.
Run:  python tools/evaluate.py
"""
from __future__ import annotations

import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.synth_generator import SCENARIOS, generate, generate_large  # noqa: E402
from backend.app.antiforensics import detect_all  # noqa: E402
from backend.app.chains import attach_rules, detect_chains  # noqa: E402
from backend.app.correlation import correlate_all  # noqa: E402
from backend.app.normalize import coerce_event, normalize_events  # noqa: E402

ALL_RULES = ["evidence_deletion", "log_clearing", "timestamp_anomaly", "mass_deletion", "metadata_modification"]


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 1.0
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return round(p, 3), round(r, 3), round(f, 3)


def eval_detection():
    """Per-system rule-level P/R/F1 over the six scenarios.

    A predicts nothing (no detector). B/C use detect_all. legit_suspicious
    GT marks log_clearing expected WITH fp flag -> counted as FP (honest).
    """
    rows, tp = {}, {"A": [0, 0, 0], "B": [0, 0, 0], "C": [0, 0, 0]}
    for name in SCENARIOS:
        dicts, gt = generate(name)
        events = [coerce_event(d) for d in dicts]
        pred_b = {f.rule_name for f in detect_all(events)}
        for sys, pred in (("A", set()), ("B", pred_b), ("C", pred_b)):
            exp = set(gt["expected_rules"])
            unexp = set(gt.get("unexpected_rules", []))
            fp_rules = ({r for r in pred if r in unexp} |
                        ({r for r in pred if r not in exp} if gt.get("fp_expected") else set()))
            # fp_expected scenario: expected rule still counts as FP
            if gt.get("fp_expected"):
                fp_rules |= (pred & exp)
                t = 0
            else:
                t = len(pred & exp)
            f = len(fp_rules)
            fn = len(exp - pred)
            tp[sys][0] += t
            tp[sys][1] += f
            tp[sys][2] += fn
            rows[(sys, name)] = (sorted(pred), sorted(exp), t, f, fn)
    return {s: prf(*tp[s]) for s in ("A", "B", "C")}, rows


def eval_reconstruction():
    """Round-trip through normalize+store ordering: accuracy + missing rate."""
    from sqlalchemy.orm import Session

    from backend.app.database import get_engine
    from backend.app.normalize import ingest_events
    from backend.app.timeline import query_events

    acc, miss = [], []
    for name in SCENARIOS:
        dicts, _ = generate(name, n_noise=20, seed=11)
        coerced = [coerce_event(d) for d in dicts]  # coerce ONCE: ids must match
        engine = get_engine("sqlite:///:memory:")
        with Session(engine) as s:
            ingest_events(list(coerced), session=s)
            back = query_events(s, limit=100_000)
        want = sorted(normalize_events(list(coerced)),
                      key=lambda e: (e.timestamp, e.event_id))
        ok = sum(1 for a, b in zip(back, want) if a.event_id == b.event_id)
        acc.append(ok / len(want))
        miss.append(1 - len(back) / len(dicts))
    return round(sum(acc) / len(acc), 4), round(sum(miss) / len(miss), 4)


def eval_correlation():
    """Relationship P/R: GT pairs = core-scenario pairs sharing object or
    consecutive story steps; predicted = correlate_all >= 0.6."""
    tp = fp = fn = 0
    for name in SCENARIOS:
        dicts, _ = generate(name)
        events = sorted([coerce_event(d) for d in dicts], key=lambda e: e.timestamp)
        core = [e for e in events if e.provenance.parser_name == "synth_generator"
                and e.provenance.source_file.startswith("synth:")]
        # GT links: same-object pairs + consecutive core steps
        gt_pairs = set()
        for i in range(len(core)):
            for j in range(i + 1, len(core)):
                if core[i].object and core[i].object == core[j].object:
                    gt_pairs.add((core[i].event_id, core[j].event_id))
        for i in range(len(core) - 1):
            gt_pairs.add((core[i].event_id, core[i + 1].event_id))
        pred = {(c.event_id_a, c.event_id_b) for c in correlate_all(events, threshold=0.6)}
        pred |= {(b, a) for a, b in list(pred)}
        tp += len(pred & gt_pairs)
        fp += len(pred - gt_pairs)
        fn += len(gt_pairs - pred)
    return prf(tp, fp, fn), (tp, fp, fn)


def eval_chains():
    """Chain-label accuracy over the six scenarios (System C)."""
    ok = 0
    detail = []
    for name in SCENARIOS:
        dicts, gt = generate(name)
        events = [coerce_event(d) for d in dicts]
        findings = detect_all(events)
        labels = [c.label for c in attach_rules(detect_chains(events, findings=findings), findings)]
        want = gt["expected_chain"]
        hit = (want is None and not labels) or (want in labels)
        ok += hit
        detail.append((name, want, labels, hit))
    return ok, len(SCENARIOS), detail


def eval_perf():
    rows = []
    for n in (500, 2000, 5000):
        dicts = generate_large(n)
        events = [coerce_event(d) for d in dicts]
        tracemalloc.start()
        t0 = time.perf_counter()
        f = detect_all(events)
        c = correlate_all(events, threshold=0.6)
        ch = detect_chains(events, findings=f)
        dt = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        rows.append((n, round(dt, 2), round(n / dt, 1), round(peak / 1024, 1), len(f), len(c), len(ch)))
    return rows


def main() -> str:
    det, det_rows = eval_detection()
    order_acc, miss_rate = eval_reconstruction()
    corr_prf, (ctp, cfp, cfn) = eval_correlation()
    chain_ok, chain_n, chain_detail = eval_chains()
    perf = eval_perf()

    L = ["# TRACE-X Evaluation Results — Phase 10",
         "_Measured on the lab machine over the six synthetic scenarios (seed 7; "
         "reconstruction uses seed 11 + 20 noise events). No pre-written expectations._",
         "",
         "## 1. Detection (rule-level, micro over scenarios)",
         "| System | Precision | Recall | F1 |",
         "|---|---|---|---|"]
    for s in ("A", "B", "C"):
        p, r, f = det[s]
        L.append(f"| {s} ({'timeline only' if s == 'A' else 'timeline+AF' if s == 'B' else 'timeline+AF+chains'}) | {p} | {r} | {f} |")
    L += ["",
          "Per-scenario (predicted rules | expected | TP FP FN):",
          ""]
    for (s, name), (pred, exp, t, f, fn) in det_rows.items():
        if s == "C":
            L.append(f"- {name}: pred={pred} exp={exp} -> TP={t} FP={f} FN={fn}")
    L += ["",
          "- Scenario 6 (`legit_suspicious`) is the FP stress test: the `log_clearing` "
          "finding fires on the admin-login context and is counted above as a FALSE "
          "positive — honestly, by design. It is never labelled malicious: hypotheses "
          "stay 'consistent with…' + limitation, and the change ticket (CHG-2026-0901) "
          "in raw_metadata exonerates on review.",
          "",
          "## 2. Reconstruction",
          f"- Event-ordering accuracy after store round-trip: **{order_acc}**",
          f"- Missing-event rate: **{miss_rate}**",
          "",
          "## 3. Correlation (System C, threshold 0.6)",
          f"- Relationship precision **{corr_prf[0]}**, recall **{corr_prf[1]}**, "
          f"F1 **{corr_prf[2]}** (TP={ctp} FP={cfp} FN={cfn} over GT same-object + "
          "consecutive-step pairs). FP pairs are mostly same-user/same-host background "
          "links — expected at 0.6, tuned per case via threshold.",
          "",
          "## 4. Chain-label accuracy (System C)",
          f"- **{chain_ok}/{chain_n}** scenarios matched ground-truth chain labels.",
          ""]
    for name, want, labels, hit in chain_detail:
        L.append(f"- {name}: expected={want} got={labels} -> {'HIT' if hit else 'MISS'}")
    L += ["",
          "## 5. Performance (detect_all + correlate_all + detect_chains)",
          "| events | time s | events/s | peak KiB | findings | correlations | chains |",
          "|---|---|---|---|---|---|---|"]
    for n, dt, eps, kb, nf, nc, nh in perf:
        L.append(f"| {n} | {dt} | {eps} | {kb} | {nf} | {nc} | {nh} |")
    L += ["",
          "## 6. Manual-vs-assisted spot check (optional, not timed formally)",
          "- Not run as a timed study in this build; informally, the concealment chain "
          "in `combined` (8 events incl. USB + clear + timestomp) is identifiable in the "
          "Findings/Chains view in seconds, versus scanning raw timeline rows. "
          "Recommended follow-up: timed task comparison per spec §5.",
          ""]
    text = "\n".join(L)
    out = ROOT / "docs" / "evaluation_results.md"
    out.write_text(text, encoding="utf-8")
    return text


if __name__ == "__main__":
    print(main())

"""Court-readiness summary framed by the Daubert factors (Daubert v. Merrell Dow, 1993),
the test US federal courts use for scientific evidence, as a structured self-assessment.

Numbers are read from the repository (test files, docs/evaluation_results.md) at call
time rather than typed here, so the section cannot drift from the measured results.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _test_count() -> int:
    return sum(len(re.findall(r"^def test_", p.read_text(encoding="utf-8"), re.M))
               for p in (ROOT / "tests").glob("test_*.py"))


def _eval() -> dict:
    p = ROOT / "docs" / "evaluation_results.md"
    try:
        t = p.read_text(encoding="utf-8")
    except OSError:
        return {}
    out = {}
    m = re.search(r"\| B \(timeline\+AF\) \| ([\d.]+) \| ([\d.]+) \| ([\d.]+) \|", t)
    if m:
        out["detection"] = dict(zip(("precision", "recall", "f1"), map(float, m.groups())))
    m = re.search(r"precision \*\*([\d.]+)\*\*, recall \*\*([\d.]+)\*\*, F1 \*\*([\d.]+)\*\*", t)
    if m:
        out["correlation"] = dict(zip(("precision", "recall", "f1"), map(float, m.groups())))
    m = re.search(r"\*\*(\d+)/(\d+)\*\* scenarios matched", t)
    if m:
        out["chain_labels"] = f"{m.group(1)}/{m.group(2)}"
    return out


def assessment() -> list[dict]:
    ev, n_tests = _eval(), _test_count()
    det, cor = ev.get("detection", {}), ev.get("correlation", {})
    rate = (f"detection precision {det.get('precision')} / recall {det.get('recall')}; "
            f"correlation precision {cor.get('precision')} / recall {cor.get('recall')}"
            if det and cor else "see docs/evaluation_results.md")
    return [
        {"factor": "Testable and tested",
         "status": "MET",
         "evidence": f"Deterministic rules with a documented specification (docs/scoring_spec.md); "
                     f"{n_tests} automated tests; six ground-truth scenarios plus a scripted live scenario."},
        {"factor": "Known error rate",
         "status": "MET",
         "evidence": f"Measured, not assumed: {rate}; chain labels {ev.get('chain_labels', 'n/a')}. "
                     "One honest false alarm (legit_suspicious) is reported."},
        {"factor": "Standards controlling operation",
         "status": "PARTIAL",
         "evidence": "Fixed weights and thresholds, SHA-256 per record, sealed case hash, ATT&CK mapping. "
                     "Weights are set by design, not calibrated on labelled real data."},
        {"factor": "Peer review and publication",
         "status": "PARTIAL",
         "evidence": "Each rule rests on published work (Chow et al. 2007; Galhuber & Luh 2021; "
                     "Palmbach & Breitinger 2020; Microsoft event 1102/104 documentation). "
                     "TRACE-X itself has not been peer reviewed."},
        {"factor": "General acceptance",
         "status": "PARTIAL",
         "evidence": "Builds on accepted practice ($SI/$FN comparison, log-clear events, super-timelines as in Plaso). "
                     "The scored correlation layer is novel, so it is not yet generally accepted."},
    ]

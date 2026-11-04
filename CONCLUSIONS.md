# TRACE-X — Build Summary and Conclusions

**Research question:** Can contextual and temporal correlation of heterogeneous digital
evidence improve detection and interpretation of potential anti-forensic activity, while
keeping evidence, correlation, and hypothesis distinct?

**Answer: yes — with measured support and stated limits.**

## Status

All 10 phases complete. 33/33 tests pass. Real-corpus wiring done (M57 NTFS image,
EVTX-ATTACK-SAMPLES log-clear). Smoke test done (API + frontend E2E). Timed-study pilot done
(human protocol documented for report authors to run).

## 1. Layered design — measured detection results

| System | Detection P / R / F1 |
|---|---|
| A — timeline only | 1.00 / 0.00 / 0.00 (finds nothing, by construction) |
| B — + anti-forensics | 0.857 / 1.00 / 0.923 |
| C — + correlation/chains | 0.857 / 1.00 / 0.923, plus 6/6 chain labels, relationship recall 0.75 |

Reconstruction is lossless (ordering 1.0, missing 0.0). Each layer adds something the previous
cannot: timeline orders, detectors flag, chains interpret (one concealment card instead of 8
scattered rows).

## 2. Epistemic discipline held under real and synthetic adversarial cases

- Scenario 6 (admin log-clear during maintenance) fires as a flag, counted as an FP, never
  labelled malicious.
- Isolated real log-clear (DE_104, System 104) scores 0.0 LOW — recorded, not suppressed, not
  accused.
- Real M57 NTFS data: 10 timestamp flags from a benign copy pattern, zero chains — system
  raised a flag without accusing. This restraint is the core finding.

## 3. Honest caveats for the report

- Validation is synthetic-primary; real-data precision needs labelled ground truth (M57 answer
  keys are instructor-encrypted).
- Correlation precision 0.404 at threshold 0.6 — same-user/same-host background links;
  threshold is a per-case tuning knob, not universal.
- Coverage: 4 sources, Vista+ EVTX only (M57 is XP/.evt — queued), one small real image wired;
  workstation E01s and the full human timed study are pending/deferred.

## 4. Engineering verdict

All 10 phases + real-corpus wiring + smoke test + pilot study done. Offline laptop performance
2.2k–18k events/s. Full provenance per conclusion. API v1.0.0 with working 5-tab dashboard.
Phase-0 novelty gap still holds: none of Plaso, Timesketch, Autopsy, or Volatility does scored,
explainable correlation with enforced Evidence/Correlation/Hypothesis separation.

**One-line conclusion for the report:** TRACE-X detects anti-forensic sequences with high
recall, interprets them as traceable hypotheses rather than verdicts, and degrades gracefully
— flagging for review where it cannot corroborate — on both synthetic and first real evidence.

## Reference docs in the repo

`PROGRESS.md` (per-phase log), `DECISIONS.md` (18 entries), `DATASETS.md` (corpora + citations),
`SUMMARY.md` (build log), `docs/landscape_comparison.md`, `docs/scoring_spec.md`,
`docs/evaluation_results.md`, `docs/timed_study.md`.

# TRACE-X Evaluation Results — Phase 10
_Measured on the lab machine over the six synthetic scenarios (seed 7; reconstruction uses seed 11 + 20 noise events). No pre-written expectations._

## 1. Detection (rule-level, micro over scenarios)
| System | Precision | Recall | F1 |
|---|---|---|---|
| A (timeline only) | 1.0 | 0.0 | 0.0 |
| B (timeline+AF) | 0.857 | 1.0 | 0.923 |
| C (timeline+AF+chains) | 0.857 | 1.0 | 0.923 |

Per-scenario (predicted rules | expected | TP FP FN):

- normal: pred=[] exp=[] -> TP=0 FP=0 FN=0
- deletion: pred=['evidence_deletion'] exp=['evidence_deletion'] -> TP=1 FP=0 FN=0
- log_clearing: pred=['log_clearing'] exp=['log_clearing'] -> TP=1 FP=0 FN=0
- timestamp_manipulation: pred=['timestamp_anomaly'] exp=['timestamp_anomaly'] -> TP=1 FP=0 FN=0
- combined: pred=['evidence_deletion', 'log_clearing', 'timestamp_anomaly'] exp=['evidence_deletion', 'log_clearing', 'timestamp_anomaly'] -> TP=3 FP=0 FN=0
- legit_suspicious: pred=['log_clearing'] exp=['log_clearing'] -> TP=0 FP=1 FN=0

- Scenario 6 (`legit_suspicious`) is the FP stress test: the `log_clearing` finding fires on the admin-login context and is counted above as a FALSE positive — honestly, by design. It is never labelled malicious: hypotheses stay 'consistent with…' + limitation, and the change ticket (CHG-2026-0901) in raw_metadata exonerates on review.

## 2. Reconstruction
- Event-ordering accuracy after store round-trip: **1.0**
- Missing-event rate: **0.0**

## 3. Correlation (System C, threshold 0.6)
- Relationship precision **0.404**, recall **0.75**, F1 **0.525** (TP=21 FP=31 FN=7 over GT same-object + consecutive-step pairs). FP pairs are mostly same-user/same-host background links — expected at 0.6, tuned per case via threshold.

## 4. Chain-label accuracy (System C)
- **6/6** scenarios matched ground-truth chain labels.

- normal: expected=None got=[] -> HIT
- deletion: expected=Potential Evidence Deletion Sequence got=['Potential Evidence Deletion Sequence'] -> HIT
- log_clearing: expected=Potential Log Tampering Sequence got=['Potential Log Tampering Sequence'] -> HIT
- timestamp_manipulation: expected=Potential Timeline Manipulation Sequence got=['Potential Timeline Manipulation Sequence'] -> HIT
- combined: expected=Potential Evidence Concealment Sequence got=['Potential Evidence Concealment Sequence'] -> HIT
- legit_suspicious: expected=None got=[] -> HIT

## 5. Performance (detect_all + correlate_all + detect_chains)
| events | time s | events/s | peak KiB | findings | correlations | chains |
|---|---|---|---|---|---|---|
| 500 | 0.04 | 13071.1 | 74.2 | 0 | 2 | 0 |
| 2000 | 0.48 | 4189.8 | 324.6 | 0 | 8 | 0 |
| 5000 | 3.23 | 1547.5 | 685.3 | 0 | 41 | 0 |

## 6. Manual-vs-assisted spot check (optional, not timed formally)
- Not run as a timed study in this build; informally, the concealment chain in `combined` (8 events incl. USB + clear + timestomp) is identifiable in the Findings/Chains view in seconds, versus scanning raw timeline rows. Recommended follow-up: timed task comparison per spec §5.

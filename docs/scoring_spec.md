# TRACE-X Scoring Specification — Phase 5

All suspicion and correlation scores are explainable: every number is a
weighted sum of **named indicators**, each listed in the output alongside
the final score. Opaque scores are forbidden.

## 1. Suspicion score (anti-forensics engine)

```
score = 0.30 × relevant_prior_activity (0/1)
      + 0.30 × short_temporal_distance  (graded 0–1)
      + 0.20 × multiple_related_events  (0/1)
      + 0.20 × evidence_directly_affected (0/1)
```

Maximum 1.0. Levels: LOW < 0.40 ≤ MEDIUM < 0.70 ≤ HIGH.

| Indicator | Meaning | Boolean or graded? |
|---|---|---|
| `relevant_prior_activity` | Context that makes the event worth flagging exists (precursor access/stage, activity before a log clear, surrounding filesystem events, any non-delete context before a burst) | boolean |
| `short_temporal_distance` | Closer = stronger. Graded per rule (see §2); always `1 − gap/window` style or skew-magnitude style, capped at 1 | graded |
| `multiple_related_events` | Corroboration count threshold met (≥2 precursors, ≥3 events before a clear, >1 anomalous timestamp field, burst by definition) | boolean |
| `evidence_directly_affected` | A file was deleted/modified/affected, or file activity preceded a clear | boolean |

### 2. Per-rule indicator definitions

- **evidence_deletion** (default window 15 min): prior = ACCESSED found in window;
  temporal = `1 − (delete − last_precursor)/window`; multiple = ≥2 precursor
  events; affected = true (the delete). Full chain (access+stage+delete tightly
  packed) scores ≈ 1.0 HIGH; missing access or stage → no finding at all.
- **log_clearing** (default preceding window 60 min): prior = any relevant
  activity (login/file/process/device/browser) in window; temporal =
  `1 − (clear − nearest_relevant)/window`; multiple = ≥3 relevant events;
  affected = file activity present in window. A clear minutes after file
  activity scores HIGH (~0.8–1.0); an isolated clear with no context scores
  0.0 LOW — still recorded, never suppressed.
- **timestamp_anomaly**: prior = surrounding filesystem events exist;
  temporal = `$SI`–`$FN` skew magnitude graded (`skew/24h`, capped 1; tiny
  skews score low); multiple = >1 anomalous field; affected = true. Flags
  only the documented signature: `$SI` older than `$FN` (cf. Chow et al.,
  Galhuber & Luh — see `docs/landscape_comparison.md` §3).
- **mass_deletion** (defaults ≥20 distinct files in 2 min): prior = true by
  construction (the burst corroborates itself — the first N−1 deletes are
  prior activity for the Nth); temporal = burst tightness
  (`1 − span/window`); multiple = true by definition; affected = true.
  Non-overlapping clusters reported separately.
- **metadata_modification** (±60 min context): fires on FILE_MODIFIED
  carrying `metadata_only=true`, an `extension_before≠extension_after`, or a
  `size_before≠size_after`, with no content event (ACCESSED/COPIED/CREATED/
  DOWNLOAD) on the same object in window. prior = any same-object history;
  temporal = fixed 0.5 (ordering uninformative here); multiple = false;
  affected = true → typical score 0.50 MEDIUM by construction.

## 3. Correlation score (Phase 6 — recorded here for completeness)

```
relationship = 0.30 × temporal_proximity (graded decay, 30-min window → 0)
             + 0.20 × same_user
             + 0.20 × same_object
             + 0.15 × same_device
             + 0.15 × same_process
```

Output lists fired factors ("events within 2 minutes, same user, …"), not
just the percentage. Chain threshold default 0.6 (Phase 7).

## 4. Worked example

Log clear 3 min after a file copy, with 4 relevant events incl. file
activity, in a 60-min window:
prior=1 → 0.30; temporal=1−3/60=0.95 → 0.285;
multiple=1 → 0.20; affected=1 → 0.20. **Total 0.985 → HIGH.**

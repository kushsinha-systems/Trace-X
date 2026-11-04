# TRACE-X Timed-Study Pilot (automated proxy, n=1)

| case | manual: items read | assisted: items read | item reduction | manual s | assisted s |
|---|---|---|---|---|---|
| combined (8 events) | 8 | 4 | 2.0x | 0.003 | 0.002 |
  assisted top card: Potential Evidence Concealment Sequence (0.68): 8fb0bc71 -> 53c84838 -> 56047d4e -> 9f642ced -> 46def197 -> bc77ba98 -> a3a9172b -> 97ef98d5
| large-5000 (5000 events) | 5000 | 0 | 5000.0x | 0.133 | 0.797 |

Reading: items-read is the investigator-load metric that matters (wall-clock here is machine render time, not human cognition). The `combined` concealment story compresses to ONE chain card + 3 finding rows; the 5000-event background compresses to its short findings/chains list instead of 5000 rows.

## Human protocol (for the report, not yet executed)
1. Recruit 1-3 analysts; within-subjects, counterbalanced order.
2. Task: 'identify the concealment sequence and cite supporting evidence IDs'.
3. Condition M: raw chronologically-sorted timeline export only. Condition T: TRACE-X Findings/Chains dashboard only.
4. Record: time-to-correct-answer, evidence-ID precision, confidence (1-5).
5. Report means + honest n=small limitation; do not overclaim.

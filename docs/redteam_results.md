# TRACE-X Red-team Results
_Measured by tools/redteam.py: one evasion variable swept per rule, the real detector run on each variant. Boundaries below are observed, not assumed._

## `evidence_deletion`

**Evasion:** Wait 15 min or more after copying before deleting (the access must fall inside the 15-min window).

| minutes between the copy and the delete | detected | level | score |
|---|---|---|---|
| 1 | yes | HIGH | 0.980 |
| 2 | yes | HIGH | 0.960 |
| 4 | yes | HIGH | 0.920 |
| 6 | yes | HIGH | 0.880 |
| 8 | yes | HIGH | 0.840 |
| 10 | yes | HIGH | 0.800 |
| 12 | yes | HIGH | 0.760 |
| 13 | yes | HIGH | 0.740 |
| 14 | yes | HIGH | 0.720 |
| 15 | no | — | 0.000 |
| 16 | no | — | 0.000 |
| 18 | no | — | 0.000 |
| 20 | no | — | 0.000 |

## `log_clearing`

**Evasion:** Clearing 60 min or more after the activity drops it below HIGH; every clear is still recorded (an isolated one scores 0.0 LOW).

| minutes between the last activity and the clear | detected | level | score |
|---|---|---|---|
| 1 | yes | HIGH | 0.995 |
| 5 | yes | HIGH | 0.975 |
| 10 | yes | HIGH | 0.950 |
| 20 | yes | HIGH | 0.900 |
| 30 | yes | HIGH | 0.850 |
| 40 | yes | HIGH | 0.800 |
| 45 | yes | HIGH | 0.775 |
| 50 | yes | HIGH | 0.750 |
| 60 | yes | MEDIUM | 0.500 |
| 61 | yes | LOW | 0.000 |
| 70 | yes | LOW | 0.000 |
| 90 | yes | LOW | 0.000 |

## `mass_deletion`

**Evasion:** Delete 19 files or fewer at a time, or spread 20 deletions over more than 120 s.

| files deleted in under a minute | detected | level | score |
|---|---|---|---|
| 15 | no | — | 0.000 |
| 16 | no | — | 0.000 |
| 17 | no | — | 0.000 |
| 18 | no | — | 0.000 |
| 19 | no | — | 0.000 |
| 20 | yes | HIGH | 0.857 |
| 21 | yes | HIGH | 0.850 |
| 22 | yes | HIGH | 0.843 |
| 23 | yes | HIGH | 0.835 |
| 24 | yes | HIGH | 0.827 |
| 25 | yes | HIGH | 0.820 |

| seconds to delete 20 files | detected | level | score |
|---|---|---|---|
| 30 | yes | HIGH | 0.925 |
| 60 | yes | HIGH | 0.850 |
| 100 | yes | HIGH | 0.750 |
| 119 | yes | HIGH | 0.702 |
| 120 | yes | HIGH | 0.700 |
| 121 | no | — | 0.000 |
| 150 | no | — | 0.000 |
| 180 | no | — | 0.000 |

## `timestamp_anomaly`

**Evasion:** Rewrite $FN as well as $SI (e.g. SetMACE) and nothing is flagged; a single-field skew is rated HIGH only from about 16 h.

| hours $SI was set back from $FN | detected | level | score |
|---|---|---|---|
| 0 | no | — | 0.000 |
| 0.01 | yes | MEDIUM | 0.500 |
| 0.1 | yes | MEDIUM | 0.501 |
| 1 | yes | MEDIUM | 0.512 |
| 6 | yes | MEDIUM | 0.575 |
| 12 | yes | MEDIUM | 0.650 |
| 16 | yes | HIGH | 0.700 |
| 24 | yes | HIGH | 0.800 |
| 48 | yes | HIGH | 0.800 |

Both $SI and $FN rewritten (48 h): detected = False.

## `metadata_modification`

**Evasion:** Open or copy the file within 60 min of renaming it and the rename is not flagged.

| content activity on the same file | detected | level | score |
|---|---|---|---|
| no content activity | yes | MEDIUM | 0.650 |
| content activity 5 min before | no | — | 0.000 |
| content activity 30 min before | no | — | 0.000 |
| content activity 59 min before | no | — | 0.000 |
| content activity 61 min before | yes | MEDIUM | 0.650 |
| content activity 120 min before | yes | MEDIUM | 0.650 |

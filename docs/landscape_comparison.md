# TRACE-X Landscape Comparison — Phase 0

**Date:** 2026-09-26
**Purpose:** Prove due diligence for the capstone report and fix exactly where TRACE-X's novelty lives: a scored, explainable correlation + chain-detection layer above a normalised timeline, with a strict Evidence / Correlation / Hypothesis separation.
**Method:** Web research on the four reference tools (Plaso/log2timeline, Timesketch, Autopsy, Volatility). Every factual claim cites a source below.

---

## 1. Feature matrix

| Capability | Plaso / log2timeline | Timesketch | Autopsy | Volatility 3 | TRACE-X (planned) |
|---|---|---|---|---|---|
| **Artefact sources supported** | Very broad: dozens of parsers (EVTX, MFT/NTFS, Chrome/Firefox history, USB/registry, etc.) via parser plug-ins; framework explicitly supports "adding new parsers or parsing plug-ins" [1][2] | Ingests Plaso output / CSV / JSON timelines for collaborative analysis; does not parse disk images itself — it is a consumer of timelines [7][8] | Disk images + ingest modules: filesystem, web artefacts, registry, email, hash sets, keyword search; dedicated **Plaso ingest module** that "runs Plaso to generate events displayed in the Autopsy Timeline" [11][12]; timeline pulls file-system times, web history, registry etc. [13][14] | Memory images only (Windows/Linux/macOS RAM: raw, crash dump, hibernation, VM snapshots, EWF, LiME, QEMU, etc.) [19][20]; plugins extract processes, network, kernel modules | Narrow-by-design prototype scope: **4 sources only** — Windows EVTX, NTFS $MFT ($SI+$FN), Chrome/Firefox SQLite history, USB registry + Setupapi log. Depth over breadth. |
| **Timeline reconstruction** | Core function: "collect all timestamped events … aggregated in a single place (aka Super Timeline)" [1]; `psort` exports/slices timelines [5]; supported-formats + analysis plug-ins docs [3] | Core function: collaborative timeline analysis via "sketches … organize timelines and analyze them at the same time" [7][8]; search, tagging, notebooks, import from JSON/CSV | Timeline feature: bar-chart/drill-down over file-system times, later extended to web/registry; Plaso events shown in Timeline [13][14][11] | Since Volatility 3: "automatic timeline integration of all plugins that produce timestamps" [21]; per-plugin timestamps, not a cross-source super-timeline | Canonical event schema (Pydantic + SQLite), merged/sorted/deduped `events` table + gap detector (30-min default). Deliberately Plaso-like normalisation, smaller parser set. |
| **Cross-source correlation** | Aggregation + tagging/analysis plug-ins, but no scored causality/relationship graph; correlation = co-location on one timeline [1][3] | Search/collaboration/tagging; **Sigma-rule detection** (alpha, OpenSearch backend, no aggregations) [9][10]; no pairwise relationship scoring or chain scoring | Clustering/similar-item grouping in timeline view; no pairwise scored correlation or chain detection (see Plaso-module docs — Plaso only feeds the timeline) [11] | None across disk/log/browser sources — memory-only [19][20] | **Novelty core:** pairwise explainable score `temporal 30 / user 20 / object 20 / device 15 / process 15` with fired-factor listing; chain = path of edges >0.6 containing an anti-forensics-relevant type. |
| **Anti-forensics detection** | Tagging/analysis plug-ins exist, but no built-in timestomp/log-clear/mass-delete sequence-chain detector [1][3] | Sigma rules *can* detect single events (e.g. Splunk-style rule: Security 1102 or System 104 = log cleared [17]); Sigma-in-Timesketch is alpha with "performance and functionality issues", field-mapping gaps, no aggregation support [9][10]; no $SI/$FN comparison | Hash/keyword/carving; no native $SI-vs-$FN timestomp or log-clear-sequence detector documented [11][13] | Tamper-adjacent plugins exist (e.g. contest plugin "Windows Defender Tampering" [22]) but no generic log-clear/timestomp sequence engine | **5 named rule families**, each independently testable with named-indicator scores: evidence deletion, log clearing (1102/104), $SI-vs-$FN anomaly, mass deletion (≥20/2min), suspicious metadata modification. Weights documented in `docs/scoring_spec.md`. |
| **Explainable scoring** | No — output is an event stream, not a score with reasons | No — hits are rule matches + tags (`ts_sigma_rule`, `ts_ttp`) [9], not decomposed scores | No scored suspicion output | No | Mandatory: every score lists its fired sub-scores/indicators (e.g. "events within 2 min, same user…"). Opaque numbers forbidden. |
| **Hypothesis / evidence separation** | No epistemic model — one flat event stream | No — tags/comments/notebooks are free-form collaboration | No — artefacts + tags, no formal tiers | No | **Three-tier model enforced in schema, UI and report:** Evidence (observed) / Correlation (measured) / Hypothesis (interpretation + explicit limitation, e.g. "consistent with possible concealment; does not establish intent"). |
| **Provenance traceability** | Source parser recorded per event (framework design), but downstream conclusions are analyst-made | Provenance = which timeline/upload + analyzer run; Sigma hits carry rule title (`ts_sigma_rule`) [9] | Case DB + ingest-module lineage; Plaso events traceable to parser run [11] | Plugin + memory offset provenance per result | Per-event `provenance{source_file, parser_name, parser_version, original_record_offset_or_id}` + `hash` (sha256 of raw record); every report conclusion cites evidence IDs; click-through from graph to raw metadata. |
| **Graph visualisation** | No native graph — CSV/timeline output [5] | No forensic entity graph — search views, aggregations, notebooks | Link/attachment views exist, but no scored entity-relationship (user/file/process/device/event) graph with correlation edges | No | React Flow/Cytoscape.js entity graph: nodes = users/files/processes/devices/events; edges = accessed/modified/copied/connected/executed/preceded/correlated-with. Clicking a node shows evidence, indicators, interpretation + limitation. |

---

## 2. Tool-by-tool notes

### 2.1 Plaso / log2timeline
- Python engine; "automatic creation of timelines … aggregate large amount of info found in logs and other files" [1][2]; PyPI shows active releases into 2026 (e.g. `plaso-20260720`) [4].
- Framework for "adding new parsers or parsing plug-ins; adding new analysis plug-ins; tagging events" [1]; docs cover parsers, analysis plug-ins, output modules, collection/event filters [3].
- Typical workflow: `log2timeline` → `.plaso` store → `psort` export/slice (e.g. CSV, time-slice ±30 min) [5].
- Gap confirmed: builds the super-timeline TRACE-X sits on top of; does not reason about anti-forensic sequences or produce a scored relationship graph.

### 2.2 Timesketch
- "Open-source tool for collaborative forensic timeline analysis … sketches … organize and work together" [7]; listed by CISA in the same terms [8].
- Sigma support since early 2020, still "Alpha … known performance and functionality issues" [9]; Sigma analyzer runs one celery job per rule, only `stable` rules considered, aggregations unsupported [10].
- LLM features (summarisation, NL2Q) are experimental/opt-in [23].
- Gap confirmed: search/visualisation/collaboration + single-event Sigma hits; not a causality/correlation-scoring or hypothesis engine.

### 2.3 Autopsy
- "Premier open source digital forensics platform" with hash analysis, keyword search, registry analysis, enhanced timeline analysis, multi-user cases, Python modules [15][16].
- Timeline originated as Sleuth Kit body-file/`mactime` graphs (beta in 3.0.5, memory-scaling caveats) [13], now a documented Timeline feature answering "when did web activity / device plugs / EXIF events occur" [14].
- Plaso integration: ingest module "runs Plaso to generate events displayed in the Autopsy Timeline"; Plaso runs dozens of parsers, slow — slowest parsers dominate [11][12]; Plaso history entry: "New Plaso ingest module … generates events for the timeline" (4.14.0 notes) [6].
- Gap confirmed: GUI disk analysis + timeline clustering, Plaso as a feeder — no anti-forensic chain detection with explainable scoring.

### 2.4 Volatility
- "Open-source memory forensics framework for incident response and malware analysis … Windows, Mac OS X, Linux" (Wikipedia) [20]; classic scope: processes, memory structures, network connections, kernel modules [24][25].
- Supported inputs: raw/dd, hibernation, crash dump, VirtualBox/VMware/QEMU dumps, EWF, LiME, Mach-O, Firewire [19].
- Volatility 3 (parity release v2.26.0, May 2025; Volatility 2 deprecated): removed `--profile`, added "automatic timeline integration of all plugins that produce timestamps", generic/aligned structured outputs [21]; current release line v2.27.0 (Jan 2026) [22].
- Gap confirmed: memory-only; complementary to TRACE-X's disk/log/browser/USB scope. No cross-source correlation or hypothesis layer.

---

## 3. Anti-forensics literature anchors (for Phase 5 + report)

- **NTFS $SI vs $FN:** every MFT entry stores MACB timestamps in `$STANDARD_INFORMATION` (SI) and a second MACE set in `$FILE_NAME` (FN); FN only updates when name/parent changes — hence SI-older-than-FN or SI/FN inconsistency is a documented tampering indicator [26][27][28][29].
- **Time rules:** Chow et al. (2007) "The Rules of Time on NTFS" first systematised file-operation → timestamp effects (cited in Palmbach & Breitinger 2020 [29] and Galhuber et al. [27]).
- **Tool limits as detectors:** Timestomp/SetMACE/nTimestomp leave tells (e.g. zeroed nanoseconds, full-second rounding); Galhuber & Luh ("Time for Truth", 2021) map Windows 10 2004 time rules and app-specific deviations [27][30]; Palmbach & Breitinger (2020) rate `$MFT`, `$LogFile`, `$USNjrnl`, LNK, Prefetch reliability for manipulation detection [29]; Cho (2013) pioneered `$LogFile` cross-checking; Minnaard (2014, UvA) tested single-source anomaly detection [26].
- **Log clearing:** Windows Security **1102(S) "The audit log was cleared"** fires on every Security-log clear regardless of audit policy; Account/Domain/Logon-ID identify who and allow backward correlation to 4624 [31][32][33]; System log **104** is the parallel clearing signal — Splunk's `windows_event_log_cleared` analytic keys on "1102 or 104" [17]; multiple 1102s on one host is itself anomalous, and clearing rewrites the EVTX file leaving recoverable chunks [34].

---

## 4. Novelty statement (verify, don't assert blindly — status: HOLDS)

Existing open-source tools solve pieces separately: Plaso builds the super-timeline [1]; Timesketch searches/tags it with Sigma help [9][10]; Autopsy gives GUI disk analysis + timeline fed partly by Plaso [11][13]; Volatility covers memory [20][21]. **None** provides a scored, explainable correlation + chain-detection layer over a normalised timeline that (a) detects the five anti-forensic families with named-indicator scores, (b) separates Evidence/Correlation/Hypothesis everywhere, and (c) exposes full per-conclusion provenance in a forensic graph. That is the gap TRACE-X occupies. If later testing contradicts any cell above, update this file and log it in `DECISIONS.md`.

---

## 5. Sources

[1] log2timeline/plaso README — "Super timeline all the things … adding new parsers … analysis plug-ins … tagging events" — https://github.com/log2timeline/plaso
[2] Plaso raw README mirror — same — https://raw.githubusercontent.com/log2timeline/plaso/4ea03ef9a48dad5284c371ac9b537a184b3eea9c/README.md
[3] Plaso documentation index (parsers, analysis plugins, filters, output modules) — https://plaso.readthedocs.io/en/latest/index.html
[4] PyPI plaso (releases incl. 20260720) — https://pypi.org/project/plaso
[5] PSU course notes: `psort` export/slice workflow (docker log2timeline/plaso) — https://web.cecs.pdx.edu/~dmcgrath/courses/Su26/forensics/plaso.html
[6] Autopsy history (4.14.0: "New Plaso ingest module … generates events for the timeline") — https://www.sleuthkit.org/autopsy/history.php
[7] Timesketch home — "Collaborative timeline analysis … sketches" — https://timesketch.org/
[8] CISA Timesketch listing — same description — https://www.cisa.gov/resources-tools/services/timesketch
[9] Timesketch "Use Sigma" (alpha, limitations, `ts_sigma_rule`/`ts_ttp`) — https://timesketch.org/guides/user/sigma
[10] Timesketch Sigma analyzer (multi-analyzer, stable-only, no aggregations) — https://timesketch.org/guides/analyzers/sigma_analyzer
[11] Autopsy docs: Plaso ingest module — https://www.sleuthkit.org/autopsy/docs/user-docs/4.22.0//plaso_page.html
[12] Autopsy docs mirror (Plaso page) — https://www.sleuthkit.org/autopsy/docs/user-docs/4.19.3/plaso_page.html
[13] Autopsy timeline feature announcement (3.0.5, body-file/mactime graphs) — https://www.autopsy.com/autopsy-feature-graphical-timeline-analysis-for-cyber-forensics
[14] Autopsy Timeline user docs — https://www.sleuthkit.org/autopsy/docs/user-docs/4.19.3/timeline_page.html
[15] Autopsy 4.0 feature PDF (Basis Technology) — http://www.autopsy.com/wp-content/uploads/sites/8/2016/02/Autopsy-4.0-EN-optimized.pdf
[16] Tracxn Autopsy company summary (module list) — https://platform.tracxn.com/a/d/company/587710b2e4b0f7e1661aa275/autopsy
[17] Splunk security_content `windows_event_log_cleared.yml` (1102 or 104) — https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_event_log_cleared.yml
[18] Ubuntu manpage: volatility(1) (memory formats, profiles) — https://manpages.ubuntu.com/manpages/xenial/man1/volatility.1.html
[19] Wikipedia: Volatility (software) — OS/format support — https://en.wikipedia.org/wiki/Volatility_(software)
[20] Volatility Foundation: framework page — https://volatilityfoundation.org/the-volatility-framework
[21] Volatility Foundation: parity release (no `--profile`, timeline integration, structured output) — https://volatilityfoundation.org/announcing-the-official-parity-release-of-volatility-3
[22] Volatility timeline (releases incl. v2.27.0 Jan 2026; contest plugins) — https://volatilityfoundation.org/volatility-timeline
[23] Timesketch LLM features (experimental summarisation/NL2Q) — https://timesketch.org/guides/user/llm-features-user
[24] OSTI: Evolution of Volatile Memory Forensics (Volatility/Rekall comparison) — https://www.osti.gov/servlets/purl/1885656
[25] OSTI mirror — https://www.osti.gov/servlets/purl/1884642
[26] Minnaard (2014, UvA): Timestomping NTFS (SI/FN/IXFN, detection methods) — https://rp.os3.nl/2013-2014/p48/report.pdf
[27] ACM: Reconstructing Timelines — NTFS SI/FN, Chow et al. [8], Galhuber & Luh [10] — https://dl.acm.org/doi/fullHtml/10.1145/3600160.3605027
[28] InverseCos: Timestomping Detection — $SI/$FN MAC(b) — https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html
[29] Palmbach & Breitinger (2020): Artifacts for Detecting Timestamp Manipulation in NTFS (SIA/FNA, Chow/Cho rules, $LogFile/$USNjrnl) — https://www.sciencedirect.com/science/article/pii/S2666281720300159 (full text mirror: https://opus.bibliothek.uni-augsburg.de/opus4/frontdoor/deliver/index/docId/117569/file/117569.pdf)
[30] Galhuber (2021): Time for Truth — Forensic Analysis of NTFS Timestamps — https://eprints.cs.univie.ac.at/7091/1/3465481.3470016.pdf
[31] Microsoft Learn: 1102(S) The audit log was cleared — https://learn.microsoft.com/it-it/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102
[32] Ultimate Windows Security: Event 1102 detail (fields, 4624 backward correlation) — https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=1102
[33] LogRhythm EVID 1102 mapping — https://docs.logrhythm.com/devices/docs/evid-1102-log-file-cleared-security
[34] EVTX parser blog: clearing leaves 1102 + EVTX rewrite gaps — https://www.evtxparser.com/en/blog/event-log-clearing-evidence

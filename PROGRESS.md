# TRACE-X PROGRESS log

Append after every phase: what was built, decisions + why, what is left, open questions.
New sessions resume from the bottom entry.

## 2026-09-26 — Phase 0 COMPLETE (landscape study)

- Built: `docs/landscape_comparison.md` — feature matrix TRACE-X(planned) vs Plaso/log2timeline vs Timesketch vs Autopsy vs Volatility across 8 capabilities (sources, timeline, cross-source correlation, anti-forensics, explainable scoring, hypothesis separation, provenance, graph), with tool notes + anti-forensics literature anchors + 34 cited sources.
- Decisions: novelty fixed as scored explainable correlation + chain-detection layer above a normalised timeline with Evidence/Correlation/Hypothesis separation (see DECISIONS.md #1).
- Left: Phases 1–9 per MASTER BUILD PROMPT.
- Open: none blocking; gap statement marked VERIFY-don't-assert — re-check if tool releases change matrix.

## 2026-09-26 — Phase 1 COMPLETE (repo, env, schema)

- Built: monorepo `backend/app(+parsers) frontend tools docs tests/fixtures data`; `backend/requirements.txt` (FastAPI/SQLAlchemy/Pydantic/pytest/python-evtx/python-registry); `backend/app/models.py` canonical schema (exact spec fields: event_id/timestamp/event_type/source/user/object/process/device_id/raw_metadata/provenance/hash + EventRow SQLite mirror); `database.py` (SQLite+create_all); `main.py` (FastAPI /health + /events/validate); `pytest.ini`, `README.md`, `frontend/package.json` (React+Vite+ReactFlow+Recharts+Tailwind), `tools/synth_generator.py` stub with fixed Phase-7 import path.
- Decisions: Python 3.10 accepted for prototype (3.11+ recommended); SQLite file `data/tracex.db`; synth stub now, full generator Phase 7.
- Left: Phase 2 parsers (next).
- Open: none.

## 2026-09-26 — Phase 2 COMPLETE (artefact parsers)

- Built: 4 parsers in dependency order — `parsers/evtx.py` (4624/4625→LOGIN, 4634/4647→LOGOFF, 1102/104→LOG_CLEARED, 4663→FILE_ACCESSED, 4688→PROCESS_CREATED; JSONL test path + binary .evtx via python-evtx with XML scrape), `parsers/ntfs.py` (analyzeMFT-style CSV, preserves full $SI+$FN sets in raw_metadata, anchored on si_modified), `parsers/browser.py` (Chrome urls/visits/downloads + Firefox moz_places/moz_historyvisits via sqlite3, correct 1601 vs epoch microsecond handling), `parsers/usb.py` (Setupapi.dev.log + USBSTOR JSON + optional direct hive via python-registry); fixtures `evtx_sample.jsonl mft_sample.csv setupapi_sample.log usbstor_sample.json` (+ Chrome SQLite built in-test); `tests/test_parsers.py` (5 tests: EVTX mapping/provenance/hash, SI/FN preservation + SI<FN fixture, Chrome visit+download, Setupapi connect/disconnect + USBSTOR, SQLite round-trip dedup shape).
- Decisions: fixture-first offline testing (binary EVTX/hives supported but not required for suite); NTFS emits one FILE_MODIFIED per row (detection, not classification, lives in Phase 5); unknown EVTX IDs skipped, not errored.
- Left: PAUSE for review before Phase 3 (normalisation) per FIRST ACTIONS instruction. Do NOT start Phase 3+ without owner sign-off.
- Open: Q1 — confirm pausing here as instructed vs proceeding to Phase 3; Q2 — real .evtx/SYSTEM-hive samples wanted for integration tests, or synthetic-only until Phase 7?

## 2026-09-26 — Phase 3 COMPLETE (normalisation layer)

- Built: `backend/app/normalize.py` — `RAW_EVENT_MAP` (EVTX IDs 4624/25→LOGIN, 4634/47→LOGOFF, 1102/104→LOG_CLEARED, 4663→FILE_ACCESSED, 4688→PROCESS_CREATED; browser `visit`→PAGE_VISIT, `download`→FILE_DOWNLOAD; USB `usb insert`→DEVICE_CONNECTED etc.; canonical names map to themselves), `normalize_event_type` (KeyError on unknown vocab), `coerce_event` (CanonicalEvent|dict → CanonicalEvent, raw strings coerced), `normalize_events` (sort by timestamp + dedup by hash, keep first), `ingest_events` (idempotent bulk merge into `events`, returns received/inserted/skipped_duplicates); `main.py` gained `POST /events/bulk` + `GET /events/count` (v0.2.0-phase3); `tests/test_normalize.py` (4 tests: spec vocab examples, 13-event cross-parser sort+dedup, ingest idempotency + chronological read-back, dict coercion). Suite: 9/9 pass.
- Decisions: synthetic/fixture-only through Phase 6, real corpora at Phase 7 (DECISIONS.md #12, owner sign-off); re-ingest is a no-op on hash, never a duplicate row; unknown vocab raises loudly.
- Left: Phase 4 timeline engine (query API + gap detector) — the chronological read-back tested here is its foundation.
- Open: none blocking.

## 2026-09-26 — Phase 4 COMPLETE (timeline engine)

- Built: `backend/app/timeline.py` — `query_events` (filters: start/end, user, device_id, object_substr, source, event_type; AND-combined, always chronological, limit/offset) + `detect_gaps`/`detect_gaps_in_store` (flags silent intervals > threshold, default 30 min, as POTENTIALLY_SIGNIFICANT_GAP with investigator-only note; active-hours gate 06–22 UTC, None disables); `main.py` v0.3.0-phase4 gained `GET /events` + `GET /timeline/gaps`; `tests/test_timeline.py` (3 tests: filters/pagination, threshold + active-hours + never-a-conclusion note, store end-to-end). Suite: 12/12 pass.
- Decisions: active-hours = gap midpoint in 06–22 UTC (DECISIONS.md #13).
- Left: Phase 5 anti-forensics detection engine (five rule families + `docs/scoring_spec.md`).
- Open: none blocking.

## 2026-09-26 — Phase 5 COMPLETE (anti-forensics detection engine)

- Built: `backend/app/antiforensics.py` — five named/testable rules returning `SuspiciousEvent` (finding_id, rule_name, Evidence-tier description, event_ids, object/user/device, suspicion_score, named `indicators`, level LOW/MED/HIGH, limitation disclaimer): `detect_evidence_deletion` (15-min ACCESS→COPY/MODIFY→DELETE, HIGH ≈1.0 on full chain, silent without precursors), `detect_log_clearing` (60-min preceding window, graded by recency, isolated clear recorded at 0.0 LOW), `detect_timestamp_anomaly` ($SI<$FN per-field flags + skew-graded score), `detect_mass_deletion` (≥20 distinct/2 min sliding non-overlapping clusters, burst self-corroborates → HIGH), `detect_metadata_modification` (metadata_only/extension/size with no content event ±60 min → 0.50 MEDIUM), plus `detect_all` (score-desc); `docs/scoring_spec.md` (exact 0.30/0.30/0.20/0.20 weights, per-rule indicator defs, worked example); `tests/test_antiforensics.py` (6 tests incl. normal-usage near-zero); `GET /analysis/suspicious` (rule + min_score filters). Suite: 18/18 pass.
- Decisions: mass-deletion prior-true-by-construction; isolated clears recorded-not-suppressed (DECISIONS.md #14).
- Left: Phase 6 correlation engine (pairwise explainable score + fired-factor listing).
- Open: none blocking.

## 2026-09-26 — Phase 6 COMPLETE (correlation engine)

- Built: `backend/app/correlation.py` (`correlate_pair` with graded temporal + 4 boolean
  factors, `render()` in spec's exact block format, window-pruned `correlate_all`);
  `GET /analysis/correlations` (threshold/window/limit); `tests/test_correlation.py`
  (3 tests: 0.98 worked pair + factor order + render, 0.60 boundary vs 0.6 chain
  threshold, window pruning).
- Left: Phase 7 pattern/chain engine + `synth_generator.py` six scenarios.
- Open: none blocking.

## 2026-09-26 — Phase 7 COMPLETE (chain engine + synthetic scenarios)

- Built: `tools/synth_generator.py` full (6 scenarios, noise, `generate_large`,
  GT with expected/unexpected rules + fp flag); `backend/app/chains.py`
  (greedy ≥0.6 chaining, findings-aware RULE_AS_RELEVANT labels, hypothesis +
  limitation, `attach_rules`); `GET /analysis/chains`; `tests/test_chains.py`
  (3 tests incl. full GT matrix + wording hygiene). Suite: 24/24 pass.
- Decisions: findings-aware chains; HOST-01 device linkage; legit FP recorded (DECISIONS.md #15).
- Left: Phase 8 graph API + dashboard UI + report generator.
- Open: none blocking.

## 2026-09-26 — Phase 8 COMPLETE (graph, dashboard, report)

- Built: `graph.py` + `GET /graph` (counts included); `report.py` + `GET /report`
  (Markdown, print-to-PDF via UI); `POST /cases/load-scenario`; `frontend/src/`
  dashboard (5 tabs, React Flow graph, Recharts timeline, provenance panel,
  tier badges); `tests/test_graph_report.py` (3 tests incl. live API round-trip).
  Suite: 27/27 pass.
- Left: Phase 9 AI narrative layer (LAST, local-first) then Phase 10 evaluation.
- Open: none blocking.

## 2026-09-26 — Phase 9 COMPLETE (AI narrative layer, built last)

- Built: `backend/app/narrative.py` (`template_narrative` + `validate_narrative` +
  `ollama_polish` with graceful offline fallback + `narrate_chain`);
  `GET /analysis/narratives`; `tests/test_narrative.py` (3 tests: per-claim cites,
  forbidden-pattern rejection incl. the spec's two banned examples, offline fallback).
  Suite: 30/30 pass. AI never detects — input is always computed chains.
- Left: Phase 10 evaluation (A/B/C + `docs/evaluation_results.md`).
- Open: none blocking.

## 2026-09-26 — Phase 10 COMPLETE (evaluation)

- Built: `tools/evaluate.py` (A/B/C detection P/R/F1, reconstruction ordering +
  missing rate, correlation P/R, chain-label accuracy, perf scaling with
  tracemalloc) writing measured `docs/evaluation_results.md`;
  `tests/test_evaluate.py`. Results: B/C 0.857/1.0/0.923 (sole FP honest S6);
  recon 1.0/0.0; correlation 0.404/0.750/0.525; chains 6/6. Suite: 31/31 pass.
- Decisions: chain merge/trigger-gating (DECISIONS.md #16); eval bugfixes
  (single-coercion recon, ASCII-safe console output).
- Left: nothing in build scope. Follow-ups for the report: real-corpus wiring
  (DATASETS.md), frontend `npm install && npm run dev`, timed manual-vs-assisted study.
- Open: none blocking.

## 2026-09-27 — Real-corpus wiring DONE (first image end-to-end)

- Wired: M57 `charlie-work-usb-2009-12-11.E01` (9,265,553 bytes, sha256 recorded)
  via new `tools/real_extract.py` (Dissect → SI/FN CSV) → 128 real events →
  10 timestamp_anomaly flags with 0 chains (benign copy pattern, reported honestly);
  real `DE_104_system_log_cleared.evtx` → binary-EVTX path → 1 LOG_CLEARED, 0.0 LOW.
  Fixed 2 latent parser bugs (context-manager, lazy mmap). `tests/test_real_corpus.py`.
  Suite: 33/33 pass. Queued: workstation E01s (GBs), XP/EVT support.
- Left: smoke test (uvicorn + npm dev E2E), optional timed study.
- Open: none blocking.

## 2026-09-27 — Smoke test + timed-study pilot DONE (report-ready)

- Smoke: API v1.0.0 E2E green (combined → 8 events / 3 HIGH / 15 correlations /
  1 concealment chain / graph / narrative / report); `npm install` + `vite build`
  green (965 modules); dev server + proxy E2E verified (browser → vite → API).
  Servers stopped, box clean. Suite: 33/33 pass.
- Timed pilot: `tools/timed_study.py` → `docs/timed_study.md` (items-read 2.0x on
  combined, 5000→0 on background; human protocol documented, unexecuted).
  `docs/evaluation_results.md` §6 now points at the pilot.
- Left: report writing itself (outside build scope). Queued follow-ups: workstation
  E01s, EVT support, human timed study, recharts v3 + chunk-splitting nits.
- Open: none blocking.

## 2026-09-27 — UI/UX redesign DONE (frontend-only, backend untouched)

- Redesigned `frontend/`: dark SIEM theme (`#0b0e14`/`#12151c`), mono for all
  IDs/hashes/timestamps/paths, severity chips + rings + glows, stat tiles +
  severity bars + findings preview (Overview), custom SVG lane timeline with
  gap bands + hover detail (Recharts retired from views), hypothesis/limitation
  split cards (Findings), type-colored graph + tinted MiniMap + real empty
  state (Graph), react-markdown report + Print/PDF (Report), pill tab bar.
- `frontend/DESIGN_NOTES.md` (tokens, type scale, 8 layout rationales).
- Smoke: `vite build` clean (467 KB, down from 664 KB) + dev-proxy E2E — all
  5 tabs' data verified live (8 events, 3 findings, 1 chain, 11 nodes/36 edges).
  Suite: 33/33 pass. Servers stopped.
- Left: report writing itself (outside build scope).
- Open: none blocking.

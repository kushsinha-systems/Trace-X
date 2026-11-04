# TRACE-X BUILD SUMMARY

One neat file with **every build update** for the whole project. Newest entries go at the
bottom. Detail lives in `PROGRESS.md` (per-phase log), `DECISIONS.md` (design choices),
`DATASETS.md` (corpora). Test counts are real suite results on the lab machine.

Epistemic model (enforced everywhere): **Evidence** (observed) /
**Correlation** (measured) / **Hypothesis** (interpretation + stated limitation).

## Phase 0 — Landscape study ✅ (2026-09-26)
- `docs/landscape_comparison.md`: matrix TRACE-X vs Plaso / Timesketch / Autopsy / Volatility
  across 8 capabilities + literature anchors (Chow, Galhuber & Luh, Palmbach & Breitinger,
  EVTX 1102/104) + 34 sources. Novelty verdict HOLDS: scored explainable correlation +
  chain detection with Evidence/Correlation/Hypothesis separation exists nowhere else.

## Phase 1 — Repo, env, schema ✅ (2026-09-26)
- Monorepo `backend/app(+parsers) frontend tools docs tests/fixtures data`; FastAPI +
  SQLAlchemy + Pydantic + pytest; canonical schema (9 spec fields + sha256 hash +
  provenance) with SQLite mirror; `/health`, `/events/validate`; React/Vite skeleton.

## Phase 2 — Artefact parsers ✅ (2026-09-26, 5/5 tests)
- `evtx.py` (4624/25→LOGIN, 4634/47→LOGOFF, 1102/104→LOG_CLEARED, 4663→FILE_ACCESSED,
  4688→PROCESS_CREATED; JSONL + binary via python-evtx), `ntfs.py` (MFT CSV, full
  $SI+$FN preserved), `browser.py` (Chrome 1601-epoch + Firefox unix-epoch sqlite),
  `usb.py` (Setupapi + USBSTOR JSON + optional hive). Fixture-first offline testing.

## Phase 3 — Normalisation ✅ (2026-09-26, 9/9 tests)
- `backend/app/normalize.py`: raw→canonical vocab map, coerce, chronological sort,
  dedup by hash, idempotent `ingest_events`; `POST /events/bulk`, `GET /events/count`.
- DECISION: synthetic/fixture data only through Phase 6; real corpora at Phase 7.

## Phase 4 — Timeline engine ✅ (2026-09-26, 12/12 tests)
- `backend/app/timeline.py`: `query_events` (time/user/device/object/source/type +
  pagination) + `detect_gaps` (default 30 min → POTENTIALLY_SIGNIFICANT_GAP,
  investigator-only note, 06–22 UTC active-hours gate); `GET /events`, `GET /timeline/gaps`.

## Phase 5 — Anti-forensics engine ✅ (2026-09-26, 18/18 tests)
- `backend/app/antiforensics.py`: 5 rules (evidence_deletion, log_clearing,
  timestamp_anomaly $SI<$FN, mass_deletion ≥20/2min, metadata_modification) returning
  `SuspiciousEvent` with named-indicator 0.30/0.30/0.20/0.20 scores + limitation line;
  `docs/scoring_spec.md`; `GET /analysis/suspicious`.

## Phase 6 — Correlation engine ✅ (2026-09-26, 21/21 tests)
- `backend/app/correlation.py`: pairwise 0.30/0.20/0.20/0.15/0.15 score
  (temporal = linear decay over 30-min window), `Correlation.render()` in the
  spec's exact "Relationship score / Supporting factors" block, window-pruned
  `correlate_all`; `GET /analysis/correlations`.

## Phase 7 — Chain engine + synthetic scenarios ✅ (2026-09-26, 24/24 tests)
- `tools/synth_generator.py` full: 6 scenarios + noise + `generate_large()`,
  machine-readable GT (`expected_rules`/`unexpected_rules`/`expected_chain`/
  `fp_expected`); `backend/app/chains.py`: greedy ≥0.6 chaining, findings-aware
  labels (Concealment / Log Tampering / Deletion / Timeline Manipulation) with
  hypothesis + limitation; `GET /analysis/chains`.

## Phase 8 — Graph, dashboard, report ✅ (2026-09-26, 27/27 tests)
- `backend/app/graph.py` (`GET /graph`: user/file/process/device/event nodes,
  accessed/modified/…/preceded/correlated-with edges, click-through payload);
- `backend/app/report.py` (`GET /report`: 9-section Markdown, evidence-ID cites,
  limitations); `POST /cases/load-scenario`; React dashboard (Overview /
  Timeline / Findings / Graph + provenance panel / Report) with tier badges.

## Phase 9 — AI narrative layer ✅ (2026-09-26, 30/30 tests)
- `backend/app/narrative.py` (LAST, summarisation-only): template summaries over
  computed chains with per-claim evidence cites + `validate_narrative`
  (forbidden malice/intent framings rejected); optional Ollama polish with
  offline fallback; `GET /analysis/narratives`.

## Phase 10 — Evaluation ✅ (2026-09-26, 31/31 tests)
- `tools/evaluate.py` + `docs/evaluation_results.md` (measured, not pre-written):
  detection A 1.00/0.00/0.00 vs B/C 0.857/1.00/0.923 (sole FP = honest
  scenario-6 admin clear); reconstruction ordering 1.0, missing 0.0;
  correlation P 0.404 / R 0.750 / F1 0.525; chain labels 6/6; perf
  500→18k ev/s, 2000→5.5k ev/s, 5000→2.2k ev/s (laptop, offline).

## Deliverables checklist (spec §6)
- [x] `docs/landscape_comparison.md` · [x] 4 parsers + tests · [x] `synth_generator.py`
  (6 scenarios + large case) · [x] normalisation + store · [x] timeline + gaps ·
  [x] 5 anti-forensics families + `docs/scoring_spec.md` · [x] correlation engine ·
  [x] chain engine · [x] graph API + dashboard UI · [x] report generator ·
  [x] AI narrative layer (last) · [x] `docs/evaluation_results.md` (real numbers) ·
  [x] `PROGRESS.md`, `DECISIONS.md` (19), `DATASETS.md`, `SUMMARY.md` current.

## Real-corpus wiring ✅ (2026-09-27, 33/33 tests)
- `tools/real_extract.py` (Dissect E01 → NTFS SI/FN CSV): M57 charlie USB
  (9.3 MB, hashed) → 128 real events → 10 timestamp_anomaly flags (benign copy
  pattern, honestly reported) + 0 chains; real `DE_104` .evtx → 1 LOG_CLEARED,
  0.0 LOW. Fixed 2 latent binary-EVTX bugs. `tests/test_real_corpus.py`
  (skip-if-not-downloaded). Workstation E01s + EVT support queued.

## Smoke test ✅ (2026-09-27, 33/33 tests)
- API v1.0.0 E2E: load combined → 8 events, 3 HIGH findings, 15 correlations,
  1 eight-event concealment chain, graph/narrative/report all serve.
- Frontend: `npm install` (205 pkgs) + `vite build` (965 modules, chunk-size
  warning only) + dev server serves index + **proxy E2E** (browser → vite → API).

## Timed-study pilot ✅ (2026-09-27)
- `tools/timed_study.py` → `docs/timed_study.md`: items-to-read `combined`
  8 → 4 (2.0x), large-5000 5000 → 0 findings. Human protocol documented,
  not executed (honestly labelled pilot, n=1).

## UI/UX redesign ✅ (2026-09-27, 33/33 tests, backend untouched)
- Dark SIEM theme, mono everywhere, severity system, stat tiles, SVG lane
  timeline with gap bands, split hypothesis/limitation cards, rendered report;
  `frontend/DESIGN_NOTES.md`; build clean + 5-tab live-data smoke green.

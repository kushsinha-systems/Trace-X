# TRACE-X — Temporal Relationship Analysis & Correlation Engine for Digital Forensics

University cyber-forensics capstone prototype (team of two). Open-source/free tooling only, offline-runnable on a normal laptop.

## Layout

- `backend/` — Python 3.11+, FastAPI, SQLite via SQLAlchemy, Pydantic schema, pytest
- `frontend/` — React (Vite) + React Flow + Recharts + TailwindCSS
- `tools/` — generators/scripts (`synth_generator.py` is the primary day-to-day dataset)
- `docs/` — `landscape_comparison.md` (Phase 0), scoring spec, evaluation results
- `tests/` — unit tests + fixtures (mirrors backend parser tests)
- `data/` — local case data (git-ignored artefacts, never committed images)

## Epistemic model (enforced everywhere)

- **Evidence** — directly observed fact from a single artefact source, with provenance.
- **Correlation** — measured relationship between evidence items, with transparent score.
- **Hypothesis** — human-readable interpretation, always paired with what it does NOT establish.

## Current state

See `PROGRESS.md` (what was built per phase), `DECISIONS.md` (design choices), `DATASETS.md` (corpora used).

## Assurance: how TRACE-X challenges its own conclusions

The **Assurance** tab (and report sections 10–15) adds analysis on top of detection:

| Feature | What it answers | Where |
|---|---|---|
| MITRE ATT&CK mapping | Which adversary techniques does each finding speak to, and what can't we see? | `backend/app/attack.py` |
| What would change this | The smallest change that drops each finding a level; the threshold range a chain survives | `backend/app/sensitivity.py` |
| Competing hypotheses | Five rival explanations per story, with the evidence for and against each | `backend/app/hypotheses.py` |
| Missing evidence | Artefacts the evidence implies but doesn't contain, and what to collect next | `backend/app/expectations.py` |
| Integrity seal | SHA-256 hash chain over every event record; sealed on load/ingest, verify any time | `backend/app/integrity.py` |
| Case comparison | Snapshot a case, load another, see what's new / gone / changed (matched by content) | `backend/app/compare.py` |
| Investigator review | Confirm / false alarm / unsure per finding, append-only audit log, threshold suggestions | `backend/app/review.py` |
| Red team | Where each rule stops detecting, measured on synthetic evasions (`python tools/redteam.py`) | `backend/app/redteam.py`, `docs/redteam_results.md` |
| Court readiness | Self-assessment against the Daubert factors, using the measured numbers | `backend/app/court.py` |

## Analysing real collected evidence

Put the collected artefacts (copies, never originals) in one folder: `.evtx` logs, `.E01` disk
images, Chrome `History` / Firefox `places.sqlite`, `setupapi.dev.log`, USBSTOR JSON exports,
MFT CSVs. Then load them as the current case:

```powershell
python tools\ingest.py path\to\case-folder --user alice --manifest intake.json
```

Each file is recognised by its content, SHA-256 hashed into the intake manifest, and parsed with
the matching parser; the store is **replaced** with the result (`--append` adds instead,
`--dry-run` only reports). SQLite databases are parsed from a temporary copy, so the evidence
folder is never written to. Refresh the dashboard to analyse the case.

## Live mode (monitoring demo, not acquisition)

From the dashboard: **Load scenario** has two live sections beside the synthetic ones.

- **Dynamic ground-truth scenarios** — `live_copy_to_usb` acts out a known story for real
  (edit, create, copy to a stand-in USB folder, delete) in `data/live_sandbox` while the collector
  watches. Because the script is fixed, the expected result is known: `evidence_deletion` HIGH and
  one "Potential Evidence Deletion Sequence" chain.
- **Live monitor · no ground truth** — type a folder path and Start; your own activity there (and
  on any USB stick) is analysed as it happens.

The API runs the collector itself (`POST /live/start`, `/live/stop`, `GET /live/status`) and points
every view at `data/live.db`; the status pill reads **Engine online · Online mode** and the
dashboard refreshes every 3 seconds. Loading any synthetic scenario stops the session and returns
to the case store.

Standalone, `tools/live.py` watches this PC and streams what it sees into a **separate** store,
`data/live.db` (it refuses to write into the case store). Three terminals, from the repo root:

```powershell
python tools\live.py --watch C:\path\to\demo-folder
$env:TRACEX_DB='sqlite:///./data/live.db'; python -m uvicorn backend.app.main:app --port 8020
$env:TRACEX_API='http://127.0.0.1:8020'; npm --prefix frontend run dev -- --port 5174
```

Open http://localhost:5174: it starts in **Live** mode and re-runs the analysis every 3 seconds.
Seen live: file create / modify / delete in watched folders (files present at start are the
baseline); USB volumes plugged or unplugged, which are then watched too; System-log clears (104),
plus Security-log clears (1102) and interactive logons (4624) when run as administrator.
A new file whose content is byte-identical to a watched file is a **copy**: the source is
recorded as accessed + copied, marked `inferred`. Copying a watched file to a USB stick and
deleting the original therefore raises `evidence_deletion`.

Renames, quick renames of a brand-new file, and save-by-replace (an app writing a temp file
and renaming it over the original) are each recorded as one event, not delete + create; app
scratch files (Office `~$` / `~WRL`, `.tmp`, partial downloads) are skipped.

Not seen live: file reads (Windows doesn't log them without object-access auditing) and
`$SI`/`$FN` timestamps. A live collector changes the system
it observes, so evidential analysis stays post-mortem via `tools/ingest.py`.

## Quickstart (backend)

```powershell
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
pytest -q
uvicorn backend.app.main:app --reload
```

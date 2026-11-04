# TRACE-X DATASETS

Real evidence policy: use public, legally redistributable corpora — never fabricate case studies. Record exact image + citation here when downloaded.

## Wired real data (2026-09-27 — downloader: tools/real_extract.py, git-ignored under data/real/)

| Corpus | Exact artefact | Size / SHA-256 | Result through TRACE-X |
|--------|---------------|----------------|------------------------|
| Digital Corpora — M57-Patents, `usb/charlie-work-usb-2009-12-11.E01` (https://downloads.digitalcorpora.org/corpora/scenarios/2009-m57-patents/usb/) | NTFS USB stick, 128 files, 2009-11-19 → 2009-12-10 | 9,265,553 bytes / `7A998C55…FB40A` (full: `7A998C556B22F5DC9426A33DCACEADD21A14C9CFB22957EDCE461D58A14FB40A`) | NTFS parser → 128 events; **10 timestamp_anomaly flags** (all `modified`-field SI<FN, top 1.0 on `/Nitroba work.odt`), **0 correlations ≥0.6, 0 chains**. Verdict: benign cross-volume copy pattern (SI keeps source mtime, FN reset at copy) — flagged for review, correctly un-escalated. Honest precision caveat for the report. |
| sbousseaden/EVTX-ATTACK-SAMPLES (GPL-3.0, https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), `Defense Evasion/DE_104_system_log_cleared.evtx` | Real System log-clear (ID 104), 2019-03-19 | 69,632 bytes / `5579CDCA…C558C2AF` | Binary-EVTX parser path → 1 LOG_CLEARED event; log_clearing finding **0.0 LOW** (isolated, recorded-not-malicious). Also fixed two latent parser bugs (context-manager + lazy mmap). |

Terms: Digital Corpora data is free for forensics education/research without prior authorisation; EVTX-ATTACK-SAMPLES is GPL-3.0 (data file read at runtime, not incorporated into code).

## Planned corpora (status)

| Corpus | URL | Intended use | Status |
|--------|-----|--------------|--------|
| NIST CFReDS Portal | https://cfreds.nist.gov/ | Tool testing/validation with known ground truth | Not downloaded |
| Digital Corpora — M57-Patents workstations (2–10 GB E01 each, `drives-redacted/`) | https://digitalcorpora.org/corpora/disk-images/ | Multi-user/device timeline realism; registry + browser hives | Queued — GB-scale downloads; needs `tools/real_extract.py` run per image |
| Digital Corpora — Nitroba University Harassment Scenario | https://digitalcorpora.org/corpora/disk-images/ | Browser+network storyline | Not downloaded |
| Digital Corpora — NPS test images (nps-2009-canon2, nps-2009-casper-rw) | https://digitalcorpora.org/corpora/disk-images/ | Filesystem/carving validation | Not downloaded |
| DFRWS Forensic Challenges | https://dfrws.org/dfrws-forensic-challenge | Artefact-combination scoping + citations | Not downloaded |

Notes: M57 workstations run Windows XP (`.evt`, not `.evtx`) — the EVTX parser covers Vista+; EVT support is queued future work (DECISIONS.md #17). E01 access is via `dissect.target` (pure Python); `pyewf` has no PyPI distribution and `pytsk3` cannot open E01, both verified.

## Planned corpora (not yet downloaded — Phase 2 uses synthetic fixtures)

| Corpus | URL | Intended use | Status |
|--------|-----|--------------|--------|
| NIST CFReDS Portal | https://cfreds.nist.gov/ | Tool testing/validation with known ground truth | Not downloaded |
| Digital Corpora — M57-Patents (multi-actor, multi-drive, weeks-long) | https://digitalcorpora.org/corpora/disk-images/ | Multi-user/device timeline realism | Not downloaded |
| Digital Corpora — Nitroba University Harassment Scenario | https://digitalcorpora.org/corpora/disk-images/ | Browser+network storyline | Not downloaded |
| Digital Corpora — NPS test images (nps-2009-canon2, nps-2009-casper-rw) | https://digitalcorpora.org/corpora/disk-images/ | Filesystem/carving validation | Not downloaded |
| DFRWS Forensic Challenges | https://dfrws.org/dfrws-forensic-challenge | Artefact-combination scoping + citations | Not downloaded |

## Synthetic data (current)

- `tests/fixtures/evtx_sample.jsonl` — 6 Security-log records incl. 1102 + unknown-ID skip case
- `tests/fixtures/mft_sample.csv` — 2 MFT rows; row 2 has SI-modified older than FN-modified (timestomp-like)
- `tests/fixtures/setupapi_sample.log` — USBSTOR connect + USB VID disconnect
- `tests/fixtures/usbstor_sample.json` — USBSTOR first_install + last_insert
- Browser fixture: Chrome History SQLite built programmatically in `tests/test_parsers.py`
- Full `tools/synth_generator.py` (six scenarios + noise + large case): Phase 7 deliverable

Usage terms: respect each corpus's stated terms on download; document exact image hashes here at that time.

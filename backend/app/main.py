"""TRACE-X FastAPI entrypoint — Phases 1+3+4.

Timeline query routes (Phase 4) included; graph/report land in Phase 8.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import delete, func
from sqlalchemy.orm import Session

from .database import get_engine
from .live_session import LiveSession, pick_folder
from .models import CanonicalEvent, EventRow
from .normalize import ingest_events
from .timeline import detect_gaps, detect_gaps_in_store, query_events
from .antiforensics import SuspiciousEvent, detect_all
from .correlation import Correlation, correlate_all
from .chains import Chain, attach_rules, detect_chains
from .graph import build_graph
from .report import generate_report
from .normalize import coerce_event, ingest_events
from .narrative import Narrative, narrate_chain
from . import attack, compare, court, expectations, hypotheses, integrity, redteam, review, sensitivity

app = FastAPI(title="TRACE-X", version="1.0.0")
_case_engine = get_engine()  # creates tables on import
_live_engine = None          # opened on first use of a live scenario
_active = {"store": "case"}  # which store every endpoint reads: "case" or "live"
_live = LiveSession()


def _db_file() -> str:
    """Path of the active store's SQLite file (sidecar files sit next to it)."""
    return str(_db().url.database)


def _snapshot_anchor() -> str:
    """Snapshots always sit beside the CASE store, so one taken of a synthetic or ingested case
    can be compared with a live session (and the other way round)."""
    return str(_case_engine.url.database)


def _db():
    """Engine of the active store: the case store, or the live store during a live scenario."""
    global _live_engine
    if _active["store"] == "live":
        if _live_engine is None:
            _live_engine = get_engine(_live.db_url)
        return _live_engine
    return _case_engine


class Health(BaseModel):
    status: str
    version: str
    store: str = ""  # file name of the event store this API serves (e.g. tracex.db, live.db)
    mode: str = "case"  # "case" (synthetic / ingested evidence) or "live"
    live_running: bool = False


@app.get("/health", response_model=Health)
def health() -> Health:
    store = Path(str(_db().url.database or "")).name
    return Health(status="ok", version="1.0.0", store=store,
                  mode="live" if _active["store"] == "live" or store.startswith("live") else "case",
                  live_running=_live.status()["running"])


@app.post("/events/validate", response_model=CanonicalEvent)
def validate_event(e: CanonicalEvent) -> CanonicalEvent:
    """Validate a canonical event against the Phase 1 schema (echo)."""
    return e


class BulkIngest(BaseModel):
    events: list[CanonicalEvent]


@app.post("/events/bulk")
def bulk_ingest(payload: BulkIngest) -> dict:
    """Phase-3 merge path: normalise + sort + dedup-by-hash into `events`."""
    with Session(_db()) as s:
        return ingest_events(payload.events, session=s)


@app.get("/events/count")
def event_count() -> dict:
    with Session(_db()) as s:
        return {"events": s.scalar(func.count(EventRow.event_id))}


@app.get("/events", response_model=list[CanonicalEvent])
def list_events(
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    user: str | None = Query(default=None),
    device_id: str | None = Query(default=None),
    object_substr: str | None = Query(default=None),
    source: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=1000, le=100_000),
    offset: int = Query(default=0, ge=0),
) -> list[CanonicalEvent]:
    """Phase-4 chronological query API over the merged `events` table."""
    with Session(_db()) as s:
        return query_events(
            s, start=start, end=end, user=user, device_id=device_id,
            object_substr=object_substr, source=source, event_type=event_type,
            limit=limit, offset=offset,
        )


@app.get("/timeline/gaps")
def timeline_gaps(
    threshold_minutes: float = Query(default=30.0, gt=0),
    active_hours_off: bool = Query(default=False),
) -> dict:
    """Phase-4 gap detector. Flags POTENTIALLY_SIGNIFICANT_GAP intervals."""
    with Session(_db()) as s:
        gaps = detect_gaps_in_store(
            s, threshold_minutes=threshold_minutes,
            active_hours=None if active_hours_off else (6, 22),
        )
    return {"threshold_minutes": threshold_minutes, "gaps": [g.__dict__ for g in gaps]}


@app.get("/analysis/suspicious", response_model=list[SuspiciousEvent])
def suspicious(
    rule: str | None = Query(default=None),
    min_score: float = Query(default=0.0, ge=0.0, le=1.0),
) -> list[SuspiciousEvent]:
    """Phase-5 anti-forensics findings over the merged store (score-sorted)."""
    with Session(_db()) as s:
        events = query_events(s, limit=100_000)
    findings = detect_all(events)
    if rule is not None:
        findings = [f for f in findings if f.rule_name == rule]
    return [f for f in findings if f.suspicion_score >= min_score]


@app.get("/analysis/correlations", response_model=list[Correlation])
def correlations(
    threshold: float = Query(default=0.6, ge=0.0, le=1.0),
    window_minutes: float = Query(default=30.0, gt=0),
    limit: int = Query(default=500, ge=1, le=10_000),
) -> list[Correlation]:
    """Phase-6 pairwise correlations over the merged store (score-desc)."""
    with Session(_db()) as s:
        events = query_events(s, limit=100_000)
    return correlate_all(events, window_minutes=window_minutes, threshold=threshold)[:limit]


@app.get("/analysis/chains", response_model=list[Chain])
def chains(
    threshold: float = Query(default=0.6, ge=0.0, le=1.0),
    window_minutes: float = Query(default=30.0, gt=0),
) -> list[Chain]:
    """Phase-7 concealment-sequence chains over the merged store."""
    with Session(_db()) as s:
        events = query_events(s, limit=100_000)
    findings = detect_all(events)
    return attach_rules(
        detect_chains(events, threshold=threshold, window_minutes=window_minutes, findings=findings),
        findings,
    )


def _full_case(threshold: float = 0.6, window_minutes: float = 30.0):
    with Session(_db()) as s:
        events = query_events(s, limit=100_000)
    findings = detect_all(events)
    correlations = correlate_all(events, window_minutes=window_minutes, threshold=threshold)
    chains_out = attach_rules(
        detect_chains(events, threshold=threshold, window_minutes=window_minutes, findings=findings),
        findings,
    )
    return events, findings, correlations, chains_out


@app.get("/graph")
def graph(
    threshold: float = Query(default=0.6, ge=0.0, le=1.0),
    window_minutes: float = Query(default=30.0, gt=0),
) -> dict:
    """Phase-8 forensic entity graph (nodes + verb edges)."""
    events, findings, correlations, chains_out = _full_case(threshold, window_minutes)
    g = build_graph(events, correlations, findings, chains_out)
    return {**g, "counts": {"events": len(events), "suspicious": len(findings),
                            "chains": len(chains_out), "correlations": len(correlations)}}


@app.get("/report", response_class=PlainTextResponse)
def report(case_name: str = Query(default="case")) -> str:
    """Phase-8 structured Markdown report; every conclusion cites evidence IDs."""
    events, findings, correlations, chains_out = _full_case()
    decisions = review.current(_db_file())
    extras = {
        "attack": attack.map_findings(findings, chains_out, {e.event_id: e for e in events}),
        "sensitivity": sensitivity.analyse(events, findings),
        "hypotheses": hypotheses.analyse(events, findings, chains_out),
        "expectations": expectations.check(events, findings),
        "review": {"decisions": decisions, "log": review._log(_db_file()),
                   "suggestions": review.suggest_thresholds(decisions)},
        "integrity": integrity.verify(events, _db_file()),
        "court": court.assessment(),
    }
    return generate_report(case_name=case_name, events=events, findings=findings,
                           correlations=correlations, chains=chains_out,
                           gaps=detect_gaps(sorted(events, key=lambda e: e.timestamp)), extras=extras)


class LoadScenario(BaseModel):
    scenario: str = "combined"
    n_noise: int = 0
    seed: int = 7
    replace: bool = True  # clear the store first so scenarios never mix into one timeline


@app.post("/cases/load-scenario")
def load_scenario(payload: LoadScenario) -> dict:
    """Load one synthetic scenario into the store (dashboard demo / validation).

    Replaces the stored case by default: scenarios share one date and host, so
    appending them would cross-correlate unrelated stories. `replace=false` appends.
    """
    import sys
    from pathlib import Path as _P

    if str(_P.cwd()) not in sys.path:
        sys.path.insert(0, str(_P.cwd()))
    from tools.synth_generator import generate

    dicts, gt = generate(payload.scenario, n_noise=payload.n_noise, seed=payload.seed)
    _live.stop()                # a synthetic scenario ends any live session
    _active["store"] = "case"   # and switches the dashboard back to the case store
    with Session(_db()) as s:
        removed = s.execute(delete(EventRow)).rowcount if payload.replace else 0
        res = ingest_events([coerce_event(d) for d in dicts], session=s)
    with Session(_db()) as s:  # seal the freshly loaded case so later edits are detectable
        integrity.seal(query_events(s, limit=100_000), _db_file(), reason=f"load-scenario: {payload.scenario}")
    return {**res, "removed": removed, "scenario": payload.scenario, "ground_truth": gt}


@app.get("/analysis/narratives", response_model=list[Narrative])
def narratives(
    threshold: float = Query(default=0.6, ge=0.0, le=1.0),
    use_llm: bool = Query(default=False),
) -> list[Narrative]:
    """Phase-9 narrative summaries over computed chains (summarisation only)."""
    events, findings, _, chains_out = _full_case(threshold)
    return [narrate_chain(c, events, findings, use_llm=use_llm) for c in chains_out]


# ---- live scenarios (dynamic ground truth / live monitor) -----------------------
class LiveStart(BaseModel):
    mode: str = "scripted"      # "scripted" = dynamic ground-truth scenario, "monitor" = watch folders
    watch: list[str] = []       # folders to watch (monitor mode)
    step_delay: float = 3.0     # seconds between the scripted actor's actions
    interval: float = 1.0       # collector polling interval, seconds


@app.post("/live/start")
def live_start(payload: LiveStart) -> dict:
    """Start a live session and point every endpoint at the live store."""
    try:
        st = _live.start(payload.mode, payload.watch, step_delay=payload.step_delay,
                         interval=payload.interval)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _active["store"] = "live"
    with Session(_db()) as s:  # start from zero: no flash of the previous session's events
        s.execute(delete(EventRow))
        s.commit()
    integrity.seal_path(_db_file()).unlink(missing_ok=True)  # the old session's seal no longer applies
    return st


@app.post("/live/stop")
def live_stop() -> dict:
    """Stop collecting and seal what was recorded; the dashboard keeps showing it until a scenario is loaded."""
    was_running = _live.status()["running"]
    st = _live.stop()
    if was_running and _active["store"] == "live":
        with Session(_db()) as s:
            st["seal"] = integrity.seal(query_events(s, limit=100_000), _db_file(), reason="live session ended")
    return st


@app.get("/live/status")
def live_status() -> dict:
    return {**_live.status(), "active_store": _active["store"]}


class PickFolder(BaseModel):
    initial: str | None = None  # folder the dialog opens in


@app.post("/live/pick-folder")
def live_pick_folder(payload: PickFolder) -> dict:
    """Open the native folder picker on this PC (the API is local) and return the chosen path."""
    return {"path": pick_folder(payload.initial)}


# ---- assurance: ATT&CK, sensitivity, hypotheses, missing evidence, red team, court, integrity,
#      comparison, review --------------------------------------------------------------------
def _by_id(events):
    return {e.event_id: e for e in events}


@app.get("/analysis/attack")
def analysis_attack() -> dict:
    """MITRE ATT&CK techniques per finding, techniques observed in this case, and coverage."""
    events, findings, _c, chains_out = _full_case()
    return attack.map_findings(findings, chains_out, _by_id(events))


@app.get("/analysis/sensitivity")
def analysis_sensitivity() -> dict:
    """What would change each conclusion: per-finding counterfactuals and a chain-threshold sweep."""
    events, findings, _c, _ch = _full_case()
    return sensitivity.analyse(events, findings)


@app.get("/analysis/hypotheses")
def analysis_hypotheses() -> list[dict]:
    """Competing explanations per chain / unchained finding, with evidence for and against."""
    events, findings, _c, chains_out = _full_case()
    return hypotheses.analyse(events, findings, chains_out)


@app.get("/analysis/expectations")
def analysis_expectations() -> list[dict]:
    """Artefacts the evidence implies but does not contain."""
    events, findings, _c, _ch = _full_case()
    return expectations.check(events, findings)


@app.get("/analysis/redteam")
def analysis_redteam() -> list[dict]:
    """Measured detection limits per rule (synthetic evasion sweeps; independent of the case)."""
    return redteam.run()


@app.get("/assurance/court")
def assurance_court() -> list[dict]:
    return court.assessment()


@app.get("/integrity/verify")
def integrity_verify() -> dict:
    with Session(_db()) as s:
        events = query_events(s, limit=100_000)
    out = integrity.verify(events, _db_file())
    out["live_running"] = _active["store"] == "live" and _live.status()["running"]
    if out["live_running"]:  # still growing: a seal now would be stale by the next event
        out["summary"] = "Live session in progress: the case is still growing and will be sealed when it stops."
        out["verified"] = None
    return out


@app.post("/integrity/seal")
def integrity_seal() -> dict:
    if _active["store"] == "live" and _live.status()["running"]:
        raise HTTPException(status_code=409, detail="stop the live session first; it is sealed automatically when it stops")
    with Session(_db()) as s:
        events = query_events(s, limit=100_000)
    return integrity.seal(events, _db_file(), reason="manual")


class Snapshot(BaseModel):
    case_name: str = ""


@app.post("/compare/snapshot")
def compare_snapshot(payload: Snapshot) -> dict:
    events, findings, _c, chains_out = _full_case()
    return compare.take(_snapshot_anchor(), compare.summarise(events, findings, chains_out, payload.case_name))


@app.get("/compare/snapshots")
def compare_snapshots() -> list[dict]:
    """Every saved snapshot, newest first (for the Assurance page's picker)."""
    return compare.list_snapshots(_snapshot_anchor())


@app.delete("/compare/snapshots")
def compare_delete_snapshots() -> dict:
    return {"deleted": compare.delete_all(_snapshot_anchor())}


@app.get("/compare")
def compare_diff(snapshot: str | None = Query(default=None)) -> dict:
    """Diff the current case against a snapshot: the one named, else the newest."""
    events, findings, _c, chains_out = _full_case()
    try:
        return compare.diff(_snapshot_anchor(), compare.summarise(events, findings, chains_out), snapshot)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


class Review(BaseModel):
    key: str
    verdict: str
    note: str = ""
    reviewer: str = ""


@app.get("/review")
def review_get() -> dict:
    decisions = review.current(_db_file())
    return {"decisions": decisions, "log": review._log(_db_file()),
            "suggestions": review.suggest_thresholds(decisions)}


@app.post("/review")
def review_post(payload: Review) -> dict:
    events, findings, _c, _ch = _full_case()
    f = next((x for x in findings if x.key == payload.key), None)
    if f is None:
        raise HTTPException(status_code=404, detail="no finding with that key in the current case")
    try:
        return review.record(_db_file(), key=payload.key, verdict=payload.verdict, note=payload.note,
                             reviewer=payload.reviewer, finding=f)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

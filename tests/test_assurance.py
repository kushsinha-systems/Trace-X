"""Assurance layer: ATT&CK, court readiness, sensitivity, integrity, comparison, review,
red team, competing hypotheses, missing evidence, and their report sections."""
from __future__ import annotations

import re

import pytest


def _case(name):
    from tools.synth_generator import generate
    from backend.app.normalize import coerce_event
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains

    events = [coerce_event(d) for d in generate(name)[0]]
    findings = detect_all(events)
    return events, findings, attach_rules(detect_chains(events, findings=findings), findings)


def test_findings_have_stable_keys_across_reanalysis():
    e1, f1, _ = _case("combined")
    _, f2, _ = _case("combined")  # fresh ids, same content
    assert sorted(f.key for f in f1) == sorted(f.key for f in f2)
    assert {f.finding_id for f in f1}.isdisjoint({f.finding_id for f in f2})


def test_attack_mapping_and_coverage():
    from backend.app.attack import coverage, map_findings

    events, findings, chains = _case("combined")
    m = map_findings(findings, chains, {e.event_id: e for e in events})
    assert set(m["observed"]) == {"T1070.001", "T1070.004", "T1070.006", "T1052.001"}  # copy + USB in the chain
    assert all(re.fullmatch(r"T\d{4}(\.\d{3})?", r["id"]) for r in coverage())
    assert {r["coverage"] for r in coverage()} == {"DETECTED", "PARTIAL", "NOT_COVERED"}
    _, f_legit, c_legit = _case("legit_suspicious")
    assert map_findings(f_legit, c_legit, {})["observed"] == ["T1070.001"]


def test_court_assessment_reads_measured_numbers():
    from backend.app.court import assessment

    a = {x["factor"]: x for x in assessment()}
    assert "0.857" in a["Known error rate"]["evidence"] and "0.404" in a["Known error rate"]["evidence"]
    assert re.search(r"\d+ automated tests", a["Testable and tested"]["evidence"])


def test_sensitivity_counterfactuals_and_chain_range():
    from backend.app.sensitivity import analyse

    events, findings, _ = _case("legit_suspicious")
    lines = analyse(events, findings)["findings"][findings[0].key]["lines"]
    assert any("over 40.0 min (observed 30.0 min)" in ln for ln in lines)
    events, findings, _ = _case("combined")
    (rng,) = analyse(events, findings)["sweep"]["chains"]
    assert (rng["holds_from"], rng["holds_to"], rng["breaks_at"]) == (0.4, 0.6, 0.62)


def test_integrity_seal_detects_each_kind_of_tampering(tmp_path):
    from backend.app.integrity import seal, verify

    db = tmp_path / "case.db"
    events, _, _ = _case("combined")
    assert verify(events, db)["sealed"] is False
    sealed = seal(events, db)
    ok = verify(events, db)
    assert ok["verified"] and ok["case_hash"] == sealed["case_hash"]
    events[2].user = "mallory"  # a field the content hash does not cover
    bad = verify(events, db)
    assert bad["verified"] is False and bad["changed"] == [events[2].event_id]
    assert verify(events[:-1], db)["removed"]


def test_compare_finds_new_and_gone_by_content(tmp_path):
    from backend.app.compare import diff, summarise, take

    db = tmp_path / "case.db"
    e1, f1, c1 = _case("deletion")
    take(db, summarise(e1, f1, c1, "before"))
    e2, f2, c2 = _case("combined")
    d = diff(db, summarise(e2, f2, c2))
    assert d["has_snapshot"] and d["snapshot"]["case_name"] == "before"
    # combined's deletion is a different event (09:12 vs 09:06), so it is new and the old one is gone
    assert {x["rule"] for x in d["findings"]["new"]} == {"log_clearing", "timestamp_anomaly", "evidence_deletion"}
    assert [x["rule"] for x in d["findings"]["gone"]] == ["evidence_deletion"]
    e3, f3, c3 = _case("deletion")  # the same case reloaded (new ids) is not "new"
    same = diff(db, summarise(e3, f3, c3))
    assert not same["findings"]["new"] and not same["events"]["new"]


def test_several_snapshots_are_listed_picked_and_deleted(tmp_path):
    import json
    from backend.app.compare import delete_all, diff, list_snapshots, summarise, take

    db = tmp_path / "case.db"
    (tmp_path / "case_snapshot.json").write_text(json.dumps(  # a single snapshot from the old layout
        {**summarise(*_case("deletion"), "old"), "taken_at": "2026-10-01T00:00:00+00:00"}))
    e1, f1, c1 = _case("deletion")
    first = take(db, summarise(e1, f1, c1, "baseline"))
    e2, f2, c2 = _case("combined")
    second = take(db, summarise(e2, f2, c2, "after"))
    snaps = list_snapshots(db)
    assert [s["case_name"] for s in snaps] == ["after", "baseline", "old"]  # newest first, old one kept
    assert snaps[0]["findings"] == 3 and not (tmp_path / "case_snapshot.json").exists()

    now = summarise(e2, f2, c2)
    assert diff(db, now)["snapshot"]["id"] == second["id"]          # default: the newest
    picked = diff(db, now, first["id"])                            # or the one chosen in the picker
    assert picked["snapshot"]["case_name"] == "baseline" and picked["findings"]["new"]
    with pytest.raises(ValueError):
        diff(db, now, "../../etc/passwd")
    assert delete_all(db) == 3 and list_snapshots(db) == [] and diff(db, now) == {"has_snapshot": False}


def test_review_log_and_threshold_suggestion(tmp_path):
    from backend.app.review import current, record, suggest_thresholds

    db = tmp_path / "case.db"
    _, fl, _ = _case("legit_suspicious")
    _, fc, _ = _case("combined")
    record(db, key=fl[0].key, verdict="false_alarm", note="CHG-2026-0901", reviewer="kushagra", finding=fl[0])
    for f in fc:
        if f.rule_name == "log_clearing":
            record(db, key=f.key, verdict="confirmed", finding=f)
    with pytest.raises(ValueError):
        record(db, key="x", verdict="guilty")
    (s,) = suggest_thresholds(current(db))
    assert s["rule"] == "log_clearing" and 0.45 < s["suggest_min_score"] < 0.985


def test_red_team_measures_the_documented_boundaries():
    from backend.app.redteam import run

    r = {x["rule"]: x for x in run()}
    assert r["evidence_deletion"]["first_missed"] == 15
    assert r["mass_deletion"]["first_detected"] == 20 and r["mass_deletion"]["spread"]["first_missed"] == 121
    assert r["timestamp_anomaly"]["both_rewritten"]["detected"] is False
    assert r["log_clearing"]["first_missed"] == 60


def test_competing_hypotheses_follow_the_evidence():
    from backend.app.hypotheses import analyse

    def top(name, kind):
        ev, fs, ch = _case(name)
        story = [s for s in analyse(ev, fs, ch) if s["kind"] == kind][0]
        return [(h["hypothesis"], h["status"]) for h in story["hypotheses"]]

    assert top("combined", "chain")[0] == ("Deliberate concealment of evidence", "best supported")
    assert top("legit_suspicious", "finding")[0] == ("Planned maintenance or administration", "best supported")
    ev, fs, ch = _case("deletion")
    statuses = [h["status"] for h in analyse(ev, fs, ch)[0]["hypotheses"]]
    assert "tied" in statuses or "best supported" in statuses


def test_missing_evidence_leads():
    from backend.app.expectations import check

    ev, fs, _ = _case("combined")
    kinds = {g["check"] for g in check(ev, fs)}
    assert {"copy_destination", "copy_before_device", "session_open"} <= kinds
    ev, fs, _ = _case("legit_suspicious")
    assert check(ev, fs) == []


def test_report_appends_sections_10_to_15_without_renumbering():
    from backend.app import attack, court, expectations, hypotheses, sensitivity
    from backend.app.correlation import correlate_all
    from backend.app.report import generate_report

    ev, fs, ch = _case("combined")
    extras = {"attack": attack.map_findings(fs, ch, {e.event_id: e for e in ev}),
              "sensitivity": sensitivity.analyse(ev, fs), "hypotheses": hypotheses.analyse(ev, fs, ch),
              "expectations": expectations.check(ev, fs), "review": {"decisions": {}, "log": [], "suggestions": []},
              "court": court.assessment()}
    md = generate_report(case_name="t", events=ev, findings=fs, correlations=correlate_all(ev, threshold=0.6),
                         chains=ch, extras=extras)
    heads = [l for l in md.splitlines() if l.startswith("## ")]
    assert heads[4] == "## 5. Correlations (top)" and heads[8].startswith("## 9. Limitations")
    assert [h.split(".")[0] for h in heads[9:]] == ["## 10", "## 11", "## 12", "## 13", "## 14", "## 15"]
    assert "<br>" not in md


def test_api_assurance_endpoints_and_auto_seal():
    from fastapi.testclient import TestClient

    import backend.app.main as main

    c = TestClient(main.app)
    c.post("/cases/load-scenario", json={"scenario": "combined"})
    v = c.get("/integrity/verify").json()
    assert v["sealed"] and v["verified"] and v["seal_reason"] == "load-scenario: combined"
    for path in ["/analysis/attack", "/analysis/sensitivity", "/analysis/hypotheses", "/analysis/expectations",
                 "/analysis/redteam", "/assurance/court", "/compare", "/review"]:
        assert c.get(path).status_code == 200, path
    assert c.post("/review", json={"key": "nope:0", "verdict": "confirmed"}).status_code == 404
    md = c.get("/report", params={"case_name": "api"}).text
    assert "## 15. Integrity and court readiness" in md and "verified against seal" in md

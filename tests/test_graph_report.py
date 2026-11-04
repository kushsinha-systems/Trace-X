"""Phase 8 tests: graph builder + report generator. Synthetic data only."""
from __future__ import annotations


def _combined():
    from tools.synth_generator import generate
    from backend.app.normalize import coerce_event

    dicts, gt = generate("combined")
    return [coerce_event(d) for d in dicts], gt


def test_graph_nodes_edges_and_click_payload():
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains
    from backend.app.correlation import correlate_all
    from backend.app.graph import build_graph

    events, _ = _combined()
    findings = detect_all(events)
    corrs = correlate_all(events, threshold=0.6)
    chains = attach_rules(detect_chains(events, findings=findings), findings)
    g = build_graph(events, corrs, findings, chains)

    kinds = {n["kind"] for n in g["nodes"]}
    assert {"event", "user", "file"} <= kinds
    verbs = {e["verb"] for e in g["edges"]}
    assert "correlated-with" in verbs and "preceded" in verbs
    # click-through payload on an event node: detail + related + why + interpretation + limitation
    flagged = [n for n in g["nodes"] if n["kind"] == "event" and n["flagged_by"]]
    assert flagged
    n = flagged[0]
    assert {"event_type", "timestamp", "provenance", "hash", "related_evidence", "chains"} <= set(n)
    assert set(n["flagged_by"][0]) >= {"rule", "score", "indicators", "limitation"}
    assert all("hypothesis" in c and "limitation" in c for c in n["chains"])


def test_report_sections_cite_evidence_and_limitations():
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains
    from backend.app.correlation import correlate_all
    from backend.app.report import generate_report

    events, _ = _combined()
    findings = detect_all(events)
    corrs = correlate_all(events, threshold=0.6)
    chains = attach_rules(detect_chains(events, findings=findings), findings)
    md = generate_report(case_name="demo", events=events, findings=findings,
                         correlations=corrs, chains=chains)
    for section in ["Case summary", "Evidence inventory", "Timeline excerpt",
                    "Suspicious events", "Correlations", "Anti-forensics findings",
                    "hypotheses", "Limitations"]:
        assert section.lower() in md.lower(), section
    # every finding's evidence cited; every chain's limitation present
    for f in findings:
        assert f.event_ids[0][:8] in md
    for c in chains:
        assert c.limitation in md
    assert "Potential Evidence Concealment Sequence" in md
    # section numbers the case report and study guide refer to stay stable
    assert "## 5. Correlations (top)" in md and "## 9. Limitations" in md
    # every finding shows its score breakdown, and the points add up to the score
    for f in findings:
        assert f"| **Total** | | | | **{f.suspicion_score:.3f}** |" in md, f.rule_name
    # the shared limitation is stated once per kind, not once per item
    assert md.count(chains[0].limitation) <= 2


def test_report_lists_gaps_inline_and_in_their_section():
    from tools.synth_generator import generate
    from backend.app.normalize import coerce_event
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains
    from backend.app.correlation import correlate_all
    from backend.app.report import generate_report
    from backend.app.timeline import detect_gaps

    events = sorted((coerce_event(d) for d in generate("multi_story")[0]), key=lambda e: e.timestamp)
    findings = detect_all(events)
    chains = attach_rules(detect_chains(events, findings=findings), findings)
    md = generate_report(case_name="multi", events=events, findings=findings,
                         correlations=correlate_all(events, threshold=0.6), chains=chains,
                         gaps=detect_gaps(events))
    assert md.count("### H") == 3
    assert "_no events for 102 min_" in md and "_no events for 114 min_" in md
    assert "| 09:18:00 | 11:00:00 | 102 min |" in md


def test_api_graph_and_report_endpoints():
    from fastapi.testclient import TestClient

    import backend.app.main as main

    c = TestClient(main.app)
    assert c.get("/health").json()["status"] == "ok"
    r = c.post("/cases/load-scenario", json={"scenario": "combined"})
    body = r.json()
    assert r.status_code == 200 and body["received"] >= 8
    assert body["inserted"] + body["skipped_duplicates"] == body["received"]
    again = c.post("/cases/load-scenario", json={"scenario": "combined"}).json()
    assert again["removed"] == body["received"] and again["inserted"] == body["received"]
    assert c.get("/events/count").json()["events"] == body["received"]  # replaced, not appended
    g = c.get("/graph").json()
    assert g["counts"]["events"] >= 8 and g["counts"]["chains"] >= 1
    md = c.get("/report", params={"case_name": "api-case"}).text
    assert "api-case" in md and "Limitations" in md

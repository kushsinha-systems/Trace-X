"""Phase 7 tests: generator scenarios + chain engine. Synthetic data only."""
from __future__ import annotations


def _to_events(dicts):
    from backend.app.normalize import coerce_event

    return [coerce_event(d) for d in dicts]


def test_all_six_scenarios_ground_truth():
    from tools.synth_generator import SCENARIOS, generate
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains

    assert len(SCENARIOS) == 6
    for name in SCENARIOS:
        dicts, gt = generate(name)
        events = _to_events(dicts)
        findings = detect_all(events)
        rules = {f.rule_name for f in findings}
        chains = attach_rules(detect_chains(events, findings=findings), findings)

        for r in gt["expected_rules"]:
            assert r in rules, (name, r, rules)
        for r in gt.get("unexpected_rules", []):
            assert r not in rules, (name, r, rules)
        if gt["expected_chain"] is None:
            assert chains == [], (name, chains)
        else:
            assert any(c.label == gt["expected_chain"] for c in chains), (name, chains)

        # Epistemic hygiene holds in EVERY scenario, including legit_suspicious:
        for c in chains:
            assert "malicious" not in c.hypothesis.lower()
            assert "intent" in c.limitation
        for f in findings:
            assert "malicious" not in f.description.lower()

        if name == "combined":
            full = [c for c in chains if c.label == "Potential Evidence Concealment Sequence"][0]
            assert len(full.event_ids) >= 4
            assert set(full.supporting_rules) >= {"evidence_deletion", "log_clearing", "timestamp_anomaly"}


def test_multi_story_yields_three_separate_chains():
    from tools.synth_generator import DEMO_SCENARIOS, SCENARIOS, generate
    from backend.app.antiforensics import detect_all
    from backend.app.chains import attach_rules, detect_chains

    assert "multi_story" in DEMO_SCENARIOS and "multi_story" not in SCENARIOS  # eval set unchanged
    dicts, gt = generate("multi_story")
    events = _to_events(dicts)
    findings = detect_all(events)
    assert set(gt["expected_rules"]) <= {f.rule_name for f in findings}
    chains = attach_rules(detect_chains(events, findings=findings), findings)

    assert sorted(c.label for c in chains) == sorted(gt["expected_chains"])
    users = [{e.user for e in events if e.event_id in c.event_ids} for c in chains]
    assert sorted(u.pop() for u in users if len(u) == 1) == ["alice", "bob", "carol"]  # one actor each
    all_ids = [i for c in chains for i in c.event_ids]
    assert len(all_ids) == len(set(all_ids))  # no event shared between stories
    for c in chains:
        assert "intent" in c.limitation

    from backend.app.timeline import detect_gaps

    gaps = detect_gaps(sorted(events, key=lambda e: e.timestamp))
    assert len(gaps) == gt["expected_gaps"]
    assert sorted(g.duration_minutes for g in gaps) == [102.0, 114.0]


def test_noise_keeps_pipeline_stable():
    from tools.synth_generator import generate
    from backend.app.antiforensics import detect_all

    dicts, _ = generate("combined", n_noise=50, seed=42)
    findings = detect_all(_to_events(dicts))
    assert {"evidence_deletion", "log_clearing", "timestamp_anomaly"} <= {f.rule_name for f in findings}


def test_chain_threshold_filters_weak_links():
    from tools.synth_generator import generate
    from backend.app.antiforensics import detect_all
    from backend.app.chains import detect_chains

    dicts, _ = generate("combined")
    events = _to_events(dicts)
    findings = detect_all(events)
    assert detect_chains(events, findings=findings, threshold=0.99) == []
    assert detect_chains(events, findings=findings)

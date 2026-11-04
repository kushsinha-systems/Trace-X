"""Live scenarios through the API: the scripted dynamic ground-truth run, store switching."""
from __future__ import annotations

import time


def _wait(predicate, timeout=40.0, step=0.5):
    end = time.time() + timeout
    while time.time() < end:
        v = predicate()
        if v:
            return v
        time.sleep(step)
    return None


def _isolated_live(monkeypatch, tmp_path):
    """Point the API's live session at a temp sandbox + store, away from any real session."""
    import backend.app.main as main
    from backend.app.live_session import LiveSession

    monkeypatch.setattr(main, "_live", LiveSession(base=tmp_path / "live"))
    monkeypatch.setattr(main, "_live_engine", None)
    return main


def test_scripted_live_scenario_meets_its_ground_truth_then_switches_back(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    main = _isolated_live(monkeypatch, tmp_path)
    c = TestClient(main.app)
    try:
        st = c.post("/live/start", json={"mode": "scripted", "step_delay": 0.6, "interval": 0.3}).json()
        assert st["running"] and st["mode"] == "scripted"
        gt = st["ground_truth"]
        h = c.get("/health").json()
        assert h["mode"] == "live" and h["store"] == "live.db" and h["live_running"]

        # wait for the actor to finish its real file operations and the collector to record them
        assert _wait(lambda: c.get("/live/status").json()["script_done"]), "script never finished"
        assert _wait(lambda: c.get("/events/count").json()["events"] >= gt["expected_events"])
        time.sleep(1.0)  # one more poll so nothing is still in flight

        assert c.get("/events/count").json()["events"] == gt["expected_events"]
        rules = {f["rule_name"]: f for f in c.get("/analysis/suspicious").json()}
        for r in gt["expected_rules"]:
            assert r in rules and rules[r]["level"] == "HIGH", rules
        for r in gt["unexpected_rules"]:
            assert r not in rules, r
        assert [ch["label"] for ch in c.get("/analysis/chains").json()] == [gt["expected_chain"]]
    finally:
        # a synthetic scenario ends the live session and returns to the case store
        r = c.post("/cases/load-scenario", json={"scenario": "combined"}).json()
    assert r["inserted"] == 8
    h = c.get("/health").json()
    assert h["mode"] == "case" and h["store"] == "tracex.db" and not h["live_running"]
    assert c.get("/events/count").json()["events"] == 8


def test_monitor_mode_needs_an_existing_folder(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    main = _isolated_live(monkeypatch, tmp_path)
    c = TestClient(main.app)
    r = c.post("/live/start", json={"mode": "monitor", "watch": ["C:/definitely/not/here"]})
    assert r.status_code == 400 and "folder" in r.json()["detail"]
    assert c.get("/health").json()["mode"] == "case"


def test_second_process_cannot_start_a_parallel_session(tmp_path):
    """A live collector owned by another process blocks a new session on the same store."""
    import subprocess
    import sys
    from backend.app.live_session import LiveSession

    other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        s = LiveSession(base=tmp_path)
        tmp_path.mkdir(exist_ok=True)
        s.lock.write_text(str(other.pid))
        try:
            s.start("scripted")
            raise AssertionError("expected refusal")
        except ValueError as exc:
            assert "already running" in str(exc)
    finally:
        other.kill()
    s.start("scripted", step_delay=0.2, interval=0.3)  # stale lock (process gone) no longer blocks
    s.stop()
    assert not s.lock.exists()


def test_pick_folder_returns_the_chosen_path_or_none_when_cancelled():
    import subprocess
    from backend.app.live_session import pick_folder

    seen = {}

    def fake(args, **kw):
        seen["initial"] = args[-1]
        return subprocess.CompletedProcess(args, 0, "C:/Users/vikas/Documents/demo", "")

    assert pick_folder("C:/start", run=fake).replace("\\", "/") == "C:/Users/vikas/Documents/demo"
    assert seen["initial"] == "C:/start"
    cancelled = lambda args, **kw: subprocess.CompletedProcess(args, 0, "", "")  # noqa: E731
    assert pick_folder(run=cancelled) is None


def test_pick_folder_endpoint(monkeypatch):
    from fastapi.testclient import TestClient

    import backend.app.main as main

    monkeypatch.setattr(main, "pick_folder", lambda initial=None: "C:/chosen" if initial != "cancel" else None)
    c = TestClient(main.app)
    assert c.post("/live/pick-folder", json={}).json() == {"path": "C:/chosen"}
    assert c.post("/live/pick-folder", json={"initial": "cancel"}).json() == {"path": None}


def test_assurance_follows_a_live_session_and_seals_it(monkeypatch, tmp_path):
    """Every Assurance view reads the live store; the snapshot spans case <-> live; the session is sealed on stop."""
    from fastapi.testclient import TestClient

    main = _isolated_live(monkeypatch, tmp_path)
    c = TestClient(main.app)
    try:
        c.post("/cases/load-scenario", json={"scenario": "deletion"})
        assert c.post("/compare/snapshot", json={"case_name": "synthetic"}).json()["findings"] == 1
        c.post("/live/start", json={"mode": "scripted", "step_delay": 0.5, "interval": 0.3})
        v = c.get("/integrity/verify").json()
        assert v["live_running"] and "in progress" in v["summary"]
        assert c.post("/integrity/seal").status_code == 409  # can't seal a case that is still growing
        assert _wait(lambda: c.get("/live/status").json()["script_done"])
        assert _wait(lambda: c.get("/events/count").json()["events"] >= 6)
        time.sleep(1.0)

        assert "T1070.004" in c.get("/analysis/attack").json()["observed"]
        assert c.get("/analysis/hypotheses").json()[0]["label"] == "Potential Evidence Deletion Sequence"
        assert c.get("/analysis/sensitivity").json()["sweep"]["chains"]
        assert isinstance(c.get("/analysis/expectations").json(), list)
        d = c.get("/compare").json()  # live session vs the synthetic snapshot
        assert d["has_snapshot"] and d["snapshot"]["case_name"] == "synthetic" and d["findings"]["new"]

        stop = c.post("/live/stop").json()
        assert stop["seal"]["reason"] == "live session ended"
        after = c.get("/integrity/verify").json()
        assert after["verified"] and not after["live_running"]
        c.post("/live/start", json={"mode": "scripted", "step_delay": 5, "interval": 0.3})
        assert c.get("/integrity/verify").json()["sealed"] is False  # a new session drops the old seal
    finally:
        c.post("/cases/load-scenario", json={"scenario": "combined"})

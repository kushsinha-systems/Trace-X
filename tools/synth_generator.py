"""TRACE-X synthetic event generator — Phase 7 (full implementation).

Primary day-to-day dataset: emits realistic, internally consistent records in
the SAME field shapes the real parsers emit (CanonicalEvent dicts), so the
rest of the pipeline cannot tell synthetic from real input.

Six scenarios (spec §Phase 7), each returning (events, ground_truth):
  normal / deletion / log_clearing / timestamp_manipulation / combined / legit_suspicious
plus a demo-only multi_story scenario (three independent stories → three chains).

Plus: configurable users/timestamps/devices/files, injectable benign noise,
and generate_large() for performance testing.

Real CFReDS/Digital Corpora wiring is deliberately separate (DATASETS.md);
this module is the principled, inspectable ground truth for validation.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

SCENARIOS = ["normal", "deletion", "log_clearing", "timestamp_manipulation",
             "combined", "legit_suspicious"]
# Demo-only scenarios: loadable and tested, but kept OUT of SCENARIOS so the
# Phase-10 evaluation (tools/evaluate.py) stays over the original six.
DEMO_SCENARIOS = ["multi_story"]

T0 = datetime(2026, 9, 1, 9, 0, tzinfo=timezone.utc)

_NOISE_URLS = ["https://news.example.com/", "https://docs.example.com/help",
               "https://intranet.example.com/wiki"]
_NOISE_FILES = ["C:\\Users\\{u}\\notes.txt", "C:\\Users\\{u}\\todo.md",
                "C:\\Users\\{u}\\photo.jpg"]


def _ev(ts: datetime, etype: str, source: str, user: str | None = None,
        obj: str | None = None, proc: str | None = None,
        dev: str | None = None, raw: dict | None = None, tag: str = "synth") -> dict[str, Any]:
    return {
        "timestamp": ts.isoformat(), "event_type": etype, "source": source,
        "user": user, "object": obj, "process": proc, "device_id": dev,
        "raw_metadata": dict(raw or {}),
        "provenance": {"source_file": f"synth:{tag}", "parser_name": "synth_generator",
                       "parser_version": "1.0.0",
                       "original_record_offset_or_id": f"{tag}-{etype}-{ts.isoformat()}"},
    }


def _noise(rng: random.Random, start: datetime, n: int, user: str) -> list[dict]:
    out = []
    for i in range(n):
        ts = start + timedelta(minutes=rng.randint(1, 240))
        kind = rng.choice(["browse", "open", "login"])
        if kind == "browse":
            out.append(_ev(ts, "PAGE_VISIT", "BROWSER", user, rng.choice(_NOISE_URLS), tag="noise"))
        elif kind == "open":
            out.append(_ev(ts, "FILE_ACCESSED", "WINDOWS_EVENTLOG", user,
                           rng.choice(_NOISE_FILES).format(u=user), tag="noise"))
        else:
            out.append(_ev(ts, "LOGIN", "WINDOWS_EVENTLOG", "bob" if rng.random() < 0.3 else user, tag="noise"))
    return out


def generate(scenario: str, n_noise: int = 0, seed: int = 7,
             user: str = "alice") -> tuple[list[dict], dict[str, Any]]:
    """Generate (events, ground_truth) for one scenario.

    ground_truth: {"malicious": bool, "expected_rules": [...],
                   "expected_chain": label|None, "story": str}
    (multi_story also carries "expected_chains": [label, ...], one per story)
    """
    if scenario not in SCENARIOS + DEMO_SCENARIOS:
        raise ValueError(f"unknown scenario {scenario!r}; choose from {SCENARIOS + DEMO_SCENARIOS}")
    rng = random.Random(seed)
    t = T0
    ev: list[dict] = []
    dev = "USBSTOR\\Disk&Ven_SanDisk&Prod_Ultra\\4C5300123456789&0"
    host = "HOST-01"  # shared workstation id; lets correlation link same-host events
    f = "C:\\Users\\alice\\secret.txt"

    if scenario == "normal":
        ev += [_ev(t, "LOGIN", "WINDOWS_EVENTLOG", user),
               _ev(t + timedelta(minutes=2), "PAGE_VISIT", "BROWSER", user, "https://example.com/report"),
               _ev(t + timedelta(minutes=10), "FILE_ACCESSED", "WINDOWS_EVENTLOG", user, f),
               _ev(t + timedelta(minutes=15), "DEVICE_CONNECTED", "USB", user, dev, dev=dev),
               _ev(t + timedelta(minutes=25), "DEVICE_DISCONNECTED", "USB", user, dev, dev=dev),
               _ev(t + timedelta(minutes=40), "LOGOFF", "WINDOWS_EVENTLOG", user)]
        gt = {"malicious": False, "expected_rules": [], "unexpected_rules": ["log_clearing", "evidence_deletion", "timestamp_anomaly", "mass_deletion", "metadata_modification"], "expected_chain": None,
              "story": "Benign work session; false-positive check."}

    elif scenario == "deletion":
        ev += [_ev(t, "LOGIN", "WINDOWS_EVENTLOG", user),
               _ev(t + timedelta(minutes=2), "FILE_ACCESSED", "WINDOWS_EVENTLOG", user, f),
               _ev(t + timedelta(minutes=4), "FILE_COPIED", "WINDOWS_EVENTLOG", user, f),
               _ev(t + timedelta(minutes=6), "FILE_DELETED", "WINDOWS_EVENTLOG", user, f)]
        gt = {"malicious": False, "expected_rules": ["evidence_deletion"],
              "unexpected_rules": ["log_clearing", "timestamp_anomaly", "mass_deletion"],
              "expected_chain": "Potential Evidence Deletion Sequence",
              "story": "Open→copy→delete: deletion detected and chained, no log/timestomp escalation."}

    elif scenario == "log_clearing":
        ev += [_ev(t, "LOGIN", "WINDOWS_EVENTLOG", user, dev=host),
               _ev(t + timedelta(minutes=5), "FILE_ACCESSED", "WINDOWS_EVENTLOG", user, f, dev=host),
               _ev(t + timedelta(minutes=6), "FILE_COPIED", "WINDOWS_EVENTLOG", user, f, dev=host),
               _ev(t + timedelta(minutes=9), "LOG_CLEARED", "WINDOWS_EVENTLOG", user, dev=host)]
        gt = {"malicious": True, "expected_rules": ["log_clearing"],
              "unexpected_rules": ["timestamp_anomaly", "mass_deletion", "evidence_deletion"],
              "expected_chain": "Potential Log Tampering Sequence",
              "story": "Suspicious activity then audit-log clear; expect HIGH."}

    elif scenario == "timestamp_manipulation":
        ev += [_ev(t, "LOGIN", "WINDOWS_EVENTLOG", user, dev=host),
               _ev(t + timedelta(minutes=2), "FILE_ACCESSED", "WINDOWS_EVENTLOG", user, f, dev=host),
               _ev(t + timedelta(minutes=5), "FILE_MODIFIED", "FILESYSTEM_NTFS", user, f, dev=host,
                    raw={"inode": "1002",
                         "si_timestamps": {"si_created": "2026-09-01T09:00:00+00:00",
                                           "si_modified": "2026-08-01T08:00:00+00:00",
                                           "si_mft_modified": "2026-09-01T09:05:00+00:00",
                                           "si_accessed": "2026-09-01T09:05:00+00:00"},
                         "fn_timestamps": {"fn_created": "2026-09-01T09:00:00+00:00",
                                           "fn_modified": "2026-09-01T09:04:00+00:00",
                                           "fn_mft_modified": "2026-09-01T09:04:00+00:00",
                                           "fn_accessed": "2026-09-01T09:04:00+00:00"}})]
        gt = {"malicious": True, "expected_rules": ["timestamp_anomaly"],
              "unexpected_rules": ["log_clearing", "mass_deletion", "evidence_deletion"],
              "expected_chain": "Potential Timeline Manipulation Sequence",
              "story": "$SI older than $FN after file activity."}

    elif scenario == "combined":
        ev += [_ev(t, "LOGIN", "WINDOWS_EVENTLOG", user, dev=host),
               _ev(t + timedelta(minutes=2), "FILE_ACCESSED", "WINDOWS_EVENTLOG", user, f, dev=host),
               _ev(t + timedelta(minutes=4), "FILE_COPIED", "WINDOWS_EVENTLOG", user, f, dev=host),
               _ev(t + timedelta(minutes=8), "DEVICE_CONNECTED", "USB", user, dev, dev=host),
               _ev(t + timedelta(minutes=10), "DEVICE_DISCONNECTED", "USB", user, dev, dev=host),
               _ev(t + timedelta(minutes=12), "FILE_DELETED", "WINDOWS_EVENTLOG", user, f, dev=host),
               _ev(t + timedelta(minutes=15), "LOG_CLEARED", "WINDOWS_EVENTLOG", user, dev=host),
               _ev(t + timedelta(minutes=18), "FILE_MODIFIED", "FILESYSTEM_NTFS", user, f, dev=host,
                    raw={"inode": "1002",
                         "si_timestamps": {"si_created": "2026-09-01T09:00:00+00:00",
                                           "si_modified": "2026-08-01T08:00:00+00:00",
                                           "si_mft_modified": "2026-09-01T09:05:00+00:00",
                                           "si_accessed": "2026-09-01T09:05:00+00:00"},
                         "fn_timestamps": {"fn_created": "2026-09-01T09:00:00+00:00",
                                           "fn_modified": "2026-09-01T09:04:00+00:00",
                                           "fn_mft_modified": "2026-09-01T09:04:00+00:00",
                                           "fn_accessed": "2026-09-01T09:04:00+00:00"}})]
        gt = {"malicious": True, "expected_rules": ["evidence_deletion", "log_clearing", "timestamp_anomaly"],
              "unexpected_rules": ["mass_deletion"],
              "expected_chain": "Potential Evidence Concealment Sequence",
              "story": "Full access→copy→USB→delete→clear→timestomp chain."}

    elif scenario == "multi_story":
        # Three unrelated stories on one day. Different user + host + a 2-hour
        # separation keep every cross-story pair below the 0.6 chain threshold
        # (pairs >30 min apart are not even scored), so each forms its own chain.
        ev += generate("combined", seed=seed, user=user)[0]  # alice, 09:00–09:18, HOST-01
        t2, bob, h2, f2 = t + timedelta(hours=2), "bob", "HOST-02", "C:\\Users\\bob\\payroll.xlsx"
        ev += [_ev(t2, "LOGIN", "WINDOWS_EVENTLOG", bob, dev=h2),
               _ev(t2 + timedelta(minutes=2), "FILE_ACCESSED", "WINDOWS_EVENTLOG", bob, f2, dev=h2),
               _ev(t2 + timedelta(minutes=4), "FILE_COPIED", "WINDOWS_EVENTLOG", bob, f2, dev=h2),
               _ev(t2 + timedelta(minutes=6), "FILE_DELETED", "WINDOWS_EVENTLOG", bob, f2, dev=h2)]
        t3, carol, h3, f3 = t + timedelta(hours=4), "carol", "HOST-03", "C:\\Users\\carol\\contracts.pdf"
        ev += [_ev(t3, "LOGIN", "WINDOWS_EVENTLOG", carol, dev=h3),
               _ev(t3 + timedelta(minutes=5), "FILE_ACCESSED", "WINDOWS_EVENTLOG", carol, f3, dev=h3),
               _ev(t3 + timedelta(minutes=6), "FILE_COPIED", "WINDOWS_EVENTLOG", carol, f3, dev=h3),
               _ev(t3 + timedelta(minutes=9), "LOG_CLEARED", "WINDOWS_EVENTLOG", carol, dev=h3)]
        gt = {"malicious": True,
              "expected_rules": ["evidence_deletion", "log_clearing", "timestamp_anomaly"],
              "unexpected_rules": ["mass_deletion"],
              "expected_chain": "Potential Evidence Concealment Sequence",
              "expected_chains": ["Potential Evidence Concealment Sequence",
                                  "Potential Evidence Deletion Sequence",
                                  "Potential Log Tampering Sequence"],
              # silences between stories: 09:18→11:00 and 11:06→13:00, both inside 06–22 UTC
              "expected_gaps": 2,
              "story": ("Three separate stories: alice's full concealment sequence (09:00, HOST-01), "
                        "bob's open→copy→delete (11:00, HOST-02), carol's activity then log clear "
                        "(13:00, HOST-03). Expect exactly three chains, none sharing an event, and "
                        "two potentially significant gaps (102 and 114 min) between the stories.")}

    else:  # legit_suspicious — admin clear inside a documented maintenance window
        admin = "admin"
        ev += [_ev(t, "LOGIN", "WINDOWS_EVENTLOG", admin),
               _ev(t + timedelta(minutes=30), "LOG_CLEARED", "WINDOWS_EVENTLOG", admin,
                    raw={"maintenance_window": True,
                         "change_ticket": "CHG-2026-0901",
                         "note": "Documented maintenance window 09:00–10:00 UTC"}),
               _ev(t + timedelta(minutes=45), "LOGOFF", "WINDOWS_EVENTLOG", admin)]
        gt = {"malicious": False, "expected_rules": ["log_clearing"],
              "fp_expected": True,  # honest FP: clear fires on the login context;
              "unexpected_rules": ["evidence_deletion", "timestamp_anomaly", "mass_deletion"],
              "expected_chain": None,
              "story": ("Admin log clear inside a documented window (ticket CHG-2026-0901). "
                        "The log_clearing finding may fire on the login context — that is "
                        "the expected false positive. It must NOT be auto-classified as "
                        "malicious: hypotheses stay 'consistent with…' + limitation "
                        "by construction, and the ticket in raw_metadata exonerates.")}

    if n_noise:
        ev += _noise(rng, T0, n_noise, user)
    ev.sort(key=lambda e: e["timestamp"])
    return ev, gt


def generate_large(n_events: int = 5000, seed: int = 7) -> list[dict]:
    """Configurable-scale background case for performance testing."""
    rng = random.Random(seed)
    users = ["alice", "bob", "carol"]
    types = ["LOGIN", "FILE_ACCESSED", "PAGE_VISIT", "FILE_MODIFIED", "LOGOFF"]
    src = {"LOGIN": "WINDOWS_EVENTLOG", "LOGOFF": "WINDOWS_EVENTLOG",
           "FILE_ACCESSED": "WINDOWS_EVENTLOG", "FILE_MODIFIED": "FILESYSTEM_NTFS",
           "PAGE_VISIT": "BROWSER"}
    out = []
    for i in range(n_events):
        ts = T0 + timedelta(seconds=rng.randint(0, 7 * 24 * 3600))
        et = rng.choice(types)
        u = rng.choice(users)
        out.append(_ev(ts, et, src[et], u, f"C:\\Users\\{u}\\file{rng.randint(1, 200)}.txt", tag="large"))
    out.sort(key=lambda e: e["timestamp"])
    return out


if __name__ == "__main__":  # pragma: no cover
    import json
    import sys

    name = sys.argv[1] if len(sys.argv) > 1 else "combined"
    events, gt = generate(name, n_noise=int(sys.argv[2]) if len(sys.argv) > 2 else 0)
    print(json.dumps({"ground_truth": gt, "n_events": len(events), "events": events}, indent=1)[:2000])

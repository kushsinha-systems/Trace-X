"""Scripted live scenario — a dynamic ground-truth case acted out for real.

While tools/live.py watches a sandbox, this script performs a known sequence of
real file operations in it, in real time. Because the script is fixed, the
expected outcome is known in advance (GROUND_TRUTH), unlike live monitoring of
a person, where there is no answer key.

    python tools/live_demo.py <sandbox> [--step-delay 3] [--ready-file f]

The sandbox holds Documents/ (the user's files) and USB_STICK/ (a folder that
stands in for a removable drive, so the demo needs no hardware).
"""
from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

SCENARIO = "live_copy_to_usb"
GROUND_TRUTH = {
    "scenario": SCENARIO,
    "story": ("Acted out in real time: edit notes.txt, create draft.docx, copy salaries.xlsx "
              "to the USB_STICK folder, then delete the original."),
    "expected_events": 6,  # MODIFIED, CREATED, ACCESSED*, COPIED*, CREATED (stick), DELETED  (*inferred)
    "expected_rules": ["evidence_deletion"],
    "unexpected_rules": ["log_clearing", "timestamp_anomaly", "mass_deletion", "metadata_modification"],
    "expected_chain": "Potential Evidence Deletion Sequence",
}


def prepare(sandbox: Path) -> list[Path]:
    """Fresh sandbox with the baseline files; returns the folders to watch."""
    if sandbox.exists():
        shutil.rmtree(sandbox)
    docs, stick = sandbox / "Documents", sandbox / "USB_STICK"
    docs.mkdir(parents=True)
    stick.mkdir()
    (docs / "salaries.xlsx").write_text("Q3 salary bands - CONFIDENTIAL\n", encoding="utf-8")
    (docs / "notes.txt").write_text("meeting notes\n", encoding="utf-8")
    return [docs, stick]


def steps(sandbox: Path):
    docs, stick = sandbox / "Documents", sandbox / "USB_STICK"
    return [
        ("edit notes.txt", lambda: (docs / "notes.txt").write_text("meeting notes\nadded action items\n", encoding="utf-8")),
        ("create draft.docx", lambda: (docs / "draft.docx").write_text("draft v1", encoding="utf-8")),
        ("copy salaries.xlsx to USB_STICK", lambda: shutil.copy2(docs / "salaries.xlsx", stick / "salaries.xlsx")),
        ("delete the original salaries.xlsx", lambda: (docs / "salaries.xlsx").unlink()),
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("sandbox", type=Path)
    ap.add_argument("--step-delay", type=float, default=3.0, help="seconds between actions (default 3)")
    ap.add_argument("--ready-file", type=Path, help="wait for the collector to create this file first")
    a = ap.parse_args(argv)
    if a.ready_file:
        deadline = time.time() + 60
        while not a.ready_file.exists():
            if time.time() > deadline:
                print("collector never became ready; aborting", flush=True)
                return 1
            time.sleep(0.2)
    for name, act in steps(a.sandbox):
        time.sleep(a.step_delay)
        act()
        print(f"{time.strftime('%H:%M:%S')}  {name}", flush=True)
    print("script complete", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

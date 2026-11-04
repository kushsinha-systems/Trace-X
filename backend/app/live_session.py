"""Live sessions started from the dashboard — the collector (and, for a scripted
dynamic ground-truth scenario, the actor) run as child processes of the API.

  scripted : tools/live_demo.py acts out a known story in <base>/live_sandbox while
             tools/live.py watches it; the expected outcome is tools.live_demo.GROUND_TRUTH.
  monitor  : tools/live.py watches folders the user chose; no ground truth exists.

Both write to the live store only (<base>/live.db), never to the case store. A lock
file names the running collector, so a second TRACE-X process cannot start another
session on the same sandbox and store (two collectors would double-record events).
"""
from __future__ import annotations

import atexit
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _alive(pid: int) -> bool:
    """True when a process with this id is still running (no signal is sent)."""
    if os.name == "nt":
        import ctypes

        k32 = ctypes.windll.kernel32
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ok = k32.GetExitCodeProcess(h, ctypes.byref(code))
        k32.CloseHandle(h)
        return bool(ok) and code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


_PICKER = (
    "import sys, tkinter as tk\n"
    "from tkinter import filedialog\n"
    "root = tk.Tk(); root.withdraw(); root.attributes('-topmost', True)\n"
    "p = filedialog.askdirectory(title='TRACE-X: choose a folder to monitor', initialdir=sys.argv[1] or None, mustexist=True)\n"
    "root.destroy(); sys.stdout.write(p or '')\n"
)


def pick_folder(initial: str | None = None, *, timeout: float = 600,
                run=subprocess.run) -> str | None:
    """Open the native folder picker on this PC; returns the chosen path, or None if cancelled.

    The dialog runs in its own short-lived process so a GUI event loop never lives
    inside the API's worker threads. A browser cannot do this itself: pages are not
    allowed to learn real folder paths.
    """
    r = run([sys.executable, "-c", _PICKER, initial or ""], capture_output=True, text=True, timeout=timeout)
    path = (r.stdout or "").strip()
    return str(Path(path)) if path else None


class LiveSession:
    def __init__(self, base: Path | None = None) -> None:
        self.base = Path(base or ROOT / "data")
        self.db_url = f"sqlite:///{(self.base / 'live.db').as_posix()}"
        self.sandbox = self.base / "live_sandbox"
        self.log = self.base / "live_session.log"
        self.ready = self.base / "live_ready.flag"
        self.lock = self.base / "live_session.lock"
        self.collector: subprocess.Popen | None = None
        self.actor: subprocess.Popen | None = None
        self.mode: str | None = None
        self.watch: list[str] = []
        self.started_at: float | None = None
        self.ground_truth: dict | None = None
        atexit.register(self.stop)

    def _foreign_session(self) -> int | None:
        """PID of a collector started by ANOTHER process that is still running, if any."""
        try:
            pid = int(self.lock.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return None
        mine = self.collector.pid if self.collector else None
        return pid if pid != mine and _alive(pid) else None

    def start(self, mode: str, watch: list[str] | None = None, *, step_delay: float = 3.0,
              interval: float = 1.0) -> dict:
        if mode not in ("scripted", "monitor"):
            raise ValueError("mode must be 'scripted' or 'monitor'")
        self.stop()
        other = self._foreign_session()
        if other:
            raise ValueError(f"a live session is already running in another TRACE-X process "
                             f"(collector pid {other}); stop it first")
        sys.path.insert(0, str(ROOT))
        from tools.live_demo import GROUND_TRUTH, prepare

        self.base.mkdir(parents=True, exist_ok=True)
        extra: list[str] = []
        if mode == "scripted":
            folders = prepare(self.sandbox)
            extra = ["--no-usb", "--no-logs"]  # only the scripted story, so the answer key holds
            self.ground_truth = GROUND_TRUTH
        else:
            folders = [Path(w).expanduser() for w in (watch or [])]
            if not folders or not all(f.is_dir() for f in folders):
                raise ValueError("monitor mode needs at least one existing folder to watch")
            self.ground_truth = None
        self.ready.unlink(missing_ok=True)
        log = self.log.open("w", encoding="utf-8")
        args = [sys.executable, "-u", str(ROOT / "tools" / "live.py"), "--db", self.db_url,
                "--interval", str(interval), "--ready-file", str(self.ready), *extra]
        for f in folders:
            args += ["--watch", str(f)]
        self.collector = subprocess.Popen(args, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        self.lock.write_text(str(self.collector.pid), encoding="utf-8")
        if mode == "scripted":
            self.actor = subprocess.Popen(
                [sys.executable, "-u", str(ROOT / "tools" / "live_demo.py"), str(self.sandbox),
                 "--step-delay", str(step_delay), "--ready-file", str(self.ready)],
                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        self.mode, self.watch, self.started_at = mode, [str(f) for f in folders], time.time()
        return self.status()

    def stop(self) -> dict:
        ours = self.collector is not None
        for p in (self.actor, self.collector):
            if p is not None and p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        self.actor = self.collector = None
        if ours:
            self.lock.unlink(missing_ok=True)
        return self.status()

    def status(self) -> dict:
        running = self.collector is not None and self.collector.poll() is None
        return {
            "running": running,
            "mode": self.mode,
            "watch": self.watch,
            "started_at": self.started_at,
            "script_done": None if self.actor is None and self.mode != "scripted" else (
                self.actor is None or self.actor.poll() is not None),
            "ground_truth": self.ground_truth,
        }

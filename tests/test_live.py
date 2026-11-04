"""tools/live.py: watcher logic on temp folders, fake USB lister and canned event-log XML."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


class _Clock:
    def __init__(self):
        self.t = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def tick(self, minutes: float = 1):
        self.t += timedelta(minutes=minutes)


def _types(events):
    return [(e.event_type.value, e.object.rsplit("\\", 1)[-1].rsplit("/", 1)[-1] if e.object else None) for e in events]


def test_folder_watcher_create_modify_delete_and_baseline(tmp_path):
    from tools.live import FolderWatcher

    (tmp_path / "already_there.txt").write_text("baseline")
    clock = _Clock()
    w = FolderWatcher([tmp_path], user="alice", host="PC-1", clock=clock)
    assert w.poll() == []  # existing files are the baseline, not events

    f = tmp_path / "plan.docx"
    f.write_text("v1")
    assert w.poll() == []  # first sight: wait until it settles
    assert _types(w.poll()) == [("FILE_CREATED", "plan.docx")]
    f.write_text("version two")
    assert _types(w.poll()) == [("FILE_MODIFIED", "plan.docx")]
    f.unlink()
    evs = w.poll()
    assert _types(evs) == [("FILE_DELETED", "plan.docx")]
    assert all(e.user == "alice" and e.device_id == "PC-1" and e.provenance.parser_name == "live_monitor" for e in evs)


def test_ordinary_edit_is_not_flagged_as_metadata_tampering(tmp_path):
    from tools.live import FolderWatcher
    from backend.app.antiforensics import detect_all

    f = tmp_path / "notes.txt"
    f.write_text("short")
    w = FolderWatcher([tmp_path], user="alice", host="PC-1", clock=_Clock())
    f.write_text("a much longer version of the notes")
    evs = w.poll()
    assert _types(evs) == [("FILE_MODIFIED", "notes.txt")]
    assert detect_all(evs) == []


def test_copy_then_delete_is_seen_as_evidence_deletion_and_chained(tmp_path):
    """Copy a watched file to a 'USB stick', delete the original: the real rules fire."""
    from tools.live import FolderWatcher, UsbWatcher
    from backend.app.antiforensics import detect_all
    from backend.app.chains import detect_chains

    docs, stick = tmp_path / "docs", tmp_path / "E"
    docs.mkdir(), stick.mkdir()
    secret = docs / "secret.txt"
    secret.write_text("salary data")
    clock = _Clock()
    drives: dict[str, str] = {}
    folders = FolderWatcher([docs], user="alice", host="PC-1", clock=clock)
    usb = UsbWatcher(user="alice", host="PC-1", folders=folders, lister=lambda: dict(drives), clock=clock)
    timeline = []

    def settle():  # one poll to see a new file, one more to confirm it has settled
        return usb.poll() + folders.poll() + folders.poll()

    clock.tick(1); drives[str(stick)] = "USB volume E: label=STICK serial=1234ABCD"
    timeline += settle()
    clock.tick(1); (stick / "secret.txt").write_bytes(secret.read_bytes())          # copy to stick
    timeline += settle()
    clock.tick(1); secret.unlink()                                                   # delete original
    timeline += settle()
    clock.tick(1); drives.clear()                                                    # unplug
    timeline += settle()

    assert _types(timeline) == [
        ("DEVICE_CONNECTED", "USB volume E: label=STICK serial=1234ABCD"),
        ("FILE_ACCESSED", "secret.txt"), ("FILE_COPIED", "secret.txt"), ("FILE_CREATED", "secret.txt"),
        ("FILE_DELETED", "secret.txt"),
        ("DEVICE_DISCONNECTED", "USB volume E: label=STICK serial=1234ABCD"),
    ]
    inferred = [e for e in timeline if e.raw_metadata.get("inferred")]
    assert {e.event_type.value for e in inferred} == {"FILE_ACCESSED", "FILE_COPIED"}
    assert all(e.object == str(secret.resolve()) for e in inferred)  # recorded on the SOURCE file

    findings = detect_all(timeline)
    assert [f.rule_name for f in findings] == ["evidence_deletion"] and findings[0].level == "HIGH"
    assert detect_chains(timeline, findings=findings)  # the story links into a chain


def test_unplugging_a_drive_does_not_report_its_files_deleted(tmp_path):
    from tools.live import FolderWatcher, UsbWatcher

    stick = tmp_path / "E"
    stick.mkdir()
    (stick / "photo.jpg").write_bytes(b"x" * 10)
    drives = {str(stick): "USB volume E: label=CAM serial=00000001"}
    folders = FolderWatcher([], user="u", host="h")
    usb = UsbWatcher(user="u", host="h", folders=folders, lister=lambda: dict(drives))
    drives.clear()
    evs = usb.poll() + folders.poll()
    assert _types(evs) == [("DEVICE_DISCONNECTED", "USB volume E: label=CAM serial=00000001")]


SYSTEM_104 = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID><TimeCreated SystemTime='2026-10-27T10:05:00.1234567Z'/><EventRecordID>9001</EventRecordID><Channel>System</Channel><Computer>PC-1</Computer></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>alice</SubjectUserName><Channel>Application</Channel></LogFileCleared></UserData></Event>"""
LOGONS = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4624</EventID><TimeCreated SystemTime='2026-10-27T10:00:00Z'/><EventRecordID>1</EventRecordID></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>2</Data></EventData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4624</EventID><TimeCreated SystemTime='2026-10-27T10:00:01Z'/><EventRecordID>2</EventRecordID></System><EventData><Data Name='TargetUserName'>SYSTEM</Data><Data Name='LogonType'>5</Data></EventData></Event>"""


def test_event_log_xml_maps_clears_and_human_logons_only():
    from tools.live import events_from_xml

    (clear,) = events_from_xml(SYSTEM_104, "System", "PC-1")
    assert clear.event_type.value == "LOG_CLEARED" and clear.user == "alice" and clear.device_id == "PC-1"
    assert clear.timestamp.microsecond == 123456  # 7-digit Windows time trimmed, not truncated to seconds
    logons = events_from_xml(LOGONS, "Security", "PC-1")
    assert [(e.event_type.value, e.user) for e in logons] == [("LOGIN", "alice")]  # service logon dropped


def test_event_log_watcher_dedupes_and_remembers_denied_logs():
    import subprocess
    from tools.live import EventLogWatcher

    calls = []

    def fake(args):
        calls.append(args[2])
        if args[2] == "Security":
            return subprocess.CompletedProcess(args, 5, "", "Access is denied.")
        return subprocess.CompletedProcess(args, 0, SYSTEM_104, "")

    w = EventLogWatcher(host="PC-1", since=datetime(2026, 10, 27, tzinfo=timezone.utc), run=fake)
    assert len(w.poll()) == 1 and w.poll() == []      # same record never reported twice
    assert w.denied == {"Security"} and calls.count("Security") == 1  # not retried every poll


def test_live_refuses_the_case_store():
    import pytest
    from tools.live import main

    with pytest.raises(SystemExit):
        main(["--watch", ".", "--db", "sqlite:///./data/tracex.db"])


def test_a_copy_caught_mid_write_is_still_recognised(tmp_path):
    """Windows creates a copy empty, then fills it: the half-written file must not be judged."""
    from tools.live import FolderWatcher

    docs, stick = tmp_path / "docs", tmp_path / "E"
    docs.mkdir(), stick.mkdir()
    (docs / "secret.txt").write_text("salary data")
    w = FolderWatcher([docs, stick], user="alice", host="PC-1", clock=_Clock())
    dst = stick / "secret.txt"
    dst.write_bytes(b"")                       # poll lands while the copy is still empty
    assert w.poll() == []
    dst.write_bytes((docs / "secret.txt").read_bytes())  # copy finishes
    assert w.poll() == []                      # changed since last look: not settled yet
    assert _types(w.poll()) == [("FILE_ACCESSED", "secret.txt"), ("FILE_COPIED", "secret.txt"),
                                ("FILE_CREATED", "secret.txt")]


def test_a_file_that_vanishes_before_settling_is_still_reported(tmp_path):
    from tools.live import FolderWatcher

    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    t = tmp_path / "tmp.lock"
    t.write_text("x")
    assert w.poll() == []
    t.unlink()
    assert _types(w.poll()) == [("FILE_CREATED", "tmp.lock"), ("FILE_DELETED", "tmp.lock")]


def test_move_to_stick_is_recognised_even_if_the_original_goes_first(tmp_path):
    """Copy then delete straight away (a 'move'): the source is gone before the copy settles."""
    from tools.live import FolderWatcher
    from backend.app.antiforensics import detect_all

    docs, stick = tmp_path / "docs", tmp_path / "E"
    docs.mkdir(), stick.mkdir()
    src = docs / "secret.txt"
    src.write_text("salary data")
    clock = _Clock()
    w = FolderWatcher([docs, stick], user="alice", host="PC-1", clock=clock)
    (stick / "secret.txt").write_bytes(src.read_bytes())
    clock.tick(0.01); first = w.poll()      # copy first seen (not settled)
    src.unlink()
    clock.tick(0.01); second = w.poll()     # original deleted, copy settles in the same pass
    evs = first + second + w.poll()
    assert sorted(t for t, _ in _types(evs)) == sorted(
        ["FILE_ACCESSED", "FILE_COPIED", "FILE_CREATED", "FILE_DELETED"])
    assert [f.rule_name for f in detect_all(evs)] == ["evidence_deletion"]


def test_move_where_delete_is_seen_a_poll_before_the_copy_settles(tmp_path):
    from tools.live import FolderWatcher

    docs, stick = tmp_path / "docs", tmp_path / "E"
    docs.mkdir(), stick.mkdir()
    src = docs / "secret.txt"
    src.write_text("salary data")
    w = FolderWatcher([docs, stick], user="alice", host="PC-1", clock=_Clock())
    dst = stick / "secret.txt"
    dst.write_bytes(b"")                     # copy started (empty)
    src_bytes = src.read_bytes()
    assert w.poll() == []
    src.unlink()                             # original deleted while copy is still empty
    second = _types(w.poll())                # the empty file has "settled": reported as created
    assert sorted(second) == [("FILE_CREATED", "secret.txt"), ("FILE_DELETED", "secret.txt")]
    dst.write_bytes(src_bytes)               # copy content lands after the delete was seen
    third = w.poll()
    assert _types(third) == [("FILE_ACCESSED", "secret.txt"), ("FILE_COPIED", "secret.txt")]
    assert all(e.object == str(src.resolve()) for e in third)  # recorded on the original


def test_explorer_new_file_then_rename_is_one_rename_not_a_delete(tmp_path):
    """Right-click > New > Text Document, then type a name: created once, then renamed."""
    from tools.live import FolderWatcher
    from backend.app.antiforensics import detect_all

    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    (tmp_path / "New Text Document.txt").write_text("")
    w.poll()
    created = w.poll()
    (tmp_path / "New Text Document.txt").rename(tmp_path / "Fun.txt")
    evs = w.poll()
    assert _types(created) == [("FILE_CREATED", "New Text Document.txt")]
    assert _types(evs) == [("FILE_MODIFIED", "Fun.txt")]
    assert evs[0].raw_metadata["renamed_from"].endswith("New Text Document.txt")
    assert detect_all(created + evs) == []  # same extension: an ordinary rename, nothing flagged


def test_rename_that_changes_the_extension_is_flagged_as_disguise(tmp_path):
    from tools.live import FolderWatcher
    from backend.app.antiforensics import detect_all

    (tmp_path / "report.docx").write_text("quarterly figures")
    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    (tmp_path / "report.docx").rename(tmp_path / "report.dll")
    evs = w.poll()
    assert _types(evs) == [("FILE_MODIFIED", "report.dll")]
    assert evs[0].raw_metadata["extension_before"] == ".docx"
    assert [f.rule_name for f in detect_all(evs)] == ["metadata_modification"]


def test_move_between_watched_folders_on_one_drive_is_a_move(tmp_path):
    from tools.live import FolderWatcher

    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    (a / "plan.txt").write_text("plan")
    w = FolderWatcher([a, b], user="u", host="h", clock=_Clock())
    (a / "plan.txt").rename(b / "plan.txt")
    assert _types(w.poll()) == [("FILE_MODIFIED", "plan.txt")]


def test_new_file_renamed_before_it_settles_is_one_created_file(tmp_path):
    """The poll lands between Explorer's 'New Text Document.txt' and the typed name: no phantom delete."""
    from tools.live import FolderWatcher

    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    (tmp_path / "New Text Document.txt").write_text("")
    assert w.poll() == []                                   # first sight, not settled yet
    (tmp_path / "New Text Document.txt").rename(tmp_path / "Wow.txt")
    evs = w.poll() + w.poll()
    assert _types(evs) == [("FILE_CREATED", "Wow.txt")]
    assert evs[0].raw_metadata["created_as"].endswith("New Text Document.txt")


def test_save_by_replace_is_one_edit_not_a_delete(tmp_path):
    """An app writes the new version to a side file and renames it over the original."""
    import os
    from tools.live import FolderWatcher
    from backend.app.antiforensics import detect_all

    notes = tmp_path / "notes.txt"
    notes.write_text("v1")
    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    side = tmp_path / "notes.txt.new"
    side.write_text("version two")
    assert w.poll() == []                                   # side file seen, not settled
    os.replace(side, notes)
    evs = w.poll() + w.poll()
    assert _types(evs) == [("FILE_MODIFIED", "notes.txt")]
    assert evs[0].raw_metadata["saved_via"].endswith("notes.txt.new")

    side.write_text("version three, longer")                # slower save: the side file settles first
    created = w.poll() + w.poll()
    os.replace(side, notes)
    evs = w.poll() + w.poll()
    assert _types(created) == [("FILE_CREATED", "notes.txt.new")]
    assert _types(evs) == [("FILE_MODIFIED", "notes.txt")]  # no delete of the side file, no 'copy'
    assert detect_all(created + evs) == []


def test_office_and_editor_scratch_files_are_ignored(tmp_path):
    from tools.live import FolderWatcher

    (tmp_path / "report.docx").write_text("report v1")
    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    scratch = ["~$report.docx", "~WRL0002.tmp", "Wow.txt.tmp8812", ".~lock.sheet.ods#", "big.iso.crdownload"]
    for name in scratch:
        (tmp_path / name).write_text("scratch")
    assert w.poll() + w.poll() == []
    for name in scratch:
        (tmp_path / name).unlink()
    assert w.poll() + w.poll() == []


def test_files_beyond_the_scan_cap_are_not_reported_deleted_or_created(tmp_path, monkeypatch):
    import tools.live as live

    monkeypatch.setattr(live, "MAX_FILES", 3)
    for i in range(6):
        (tmp_path / f"f{i}.txt").write_text(str(i))
    w = live.FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    (tmp_path / "a_new.txt").write_text("new")              # sorts first: pushes f2 out of the capped scan
    evs = w.poll() + w.poll()
    assert _types(evs) == [("FILE_CREATED", "a_new.txt")]  # f2 is still on disk: not 'deleted'
    (tmp_path / "a_new.txt").unlink()                      # f2 comes back into the scan: not 'created'
    assert _types(w.poll() + w.poll()) == [("FILE_DELETED", "a_new.txt")]


def test_a_file_that_cannot_be_read_for_a_moment_is_not_deleted(tmp_path, monkeypatch):
    from pathlib import Path
    from tools.live import FolderWatcher

    locked = tmp_path / "busy.xlsx"
    locked.write_text("numbers")
    w = FolderWatcher([tmp_path], user="u", host="h", clock=_Clock())
    real_stat = Path.stat

    def flaky(self, *a, **kw):
        if self.name == "busy.xlsx":
            raise PermissionError("in use")
        return real_stat(self, *a, **kw)

    monkeypatch.setattr(Path, "stat", flaky)
    assert w.poll() == []
    monkeypatch.setattr(Path, "stat", real_stat)
    assert w.poll() == []


def test_move_to_another_drive_is_still_copy_plus_delete(tmp_path, monkeypatch):
    """Cut/paste onto a USB stick (another drive) must keep raising evidence_deletion."""
    import tools.live as live
    from backend.app.antiforensics import detect_all

    monkeypatch.setattr(live, "_same_volume", lambda a, b: False)  # the stick is a different drive
    docs, stick = tmp_path / "docs", tmp_path / "E"
    docs.mkdir(), stick.mkdir()
    (docs / "secret.txt").write_text("salary data")
    w = live.FolderWatcher([docs, stick], user="alice", host="PC-1", clock=_Clock())
    (docs / "secret.txt").rename(stick / "secret.txt")  # same size + mtime, but a different drive
    evs = w.poll() + w.poll()
    assert sorted(t for t, _ in _types(evs)) == ["FILE_ACCESSED", "FILE_COPIED", "FILE_CREATED", "FILE_DELETED"]
    assert [f.rule_name for f in detect_all(evs)] == ["evidence_deletion"]

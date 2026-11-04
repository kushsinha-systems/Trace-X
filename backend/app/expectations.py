"""Missing-evidence reasoning — artefacts the evidence implies but does not contain.

Each check states an expectation that follows from an observed event ("a copy has a
destination", "a logon session ends with a logoff") and reports where it is not met.
An absence is a lead for the investigator — collect another source, or explain it —
never a finding of wrongdoing: evidence can be missing for innocent reasons too.
"""
from __future__ import annotations

from datetime import timedelta

from .antiforensics import SuspiciousEvent
from .models import CanonicalEvent, EventType as T

ACTIVITY = {T.FILE_ACCESSED, T.FILE_MODIFIED, T.FILE_COPIED, T.FILE_DELETED, T.FILE_CREATED,
            T.FILE_DOWNLOAD, T.PROCESS_CREATED, T.PAGE_VISIT}


def _gap(kind, title, why, ids, collect):
    return {"check": kind, "title": title, "why_it_matters": why, "events": [i[:8] for i in ids], "collect": collect}


def check(events: list[CanonicalEvent], findings: list[SuspiciousEvent] | None = None) -> list[dict]:
    ev = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    out: list[dict] = []
    by_type: dict[T, list[CanonicalEvent]] = {}
    for e in ev:
        by_type.setdefault(e.event_type, []).append(e)

    # 1. a copy has a destination
    created_from = {(e.raw_metadata or {}).get("copied_from") for e in by_type.get(T.FILE_CREATED, [])}
    for c in by_type.get(T.FILE_COPIED, []):
        if c.object not in created_from and not (c.raw_metadata or {}).get("copied_to"):
            out.append(_gap("copy_destination", f"Copy of {c.object} has no recorded destination",
                            "The evidence shows the file was copied but not where to; the copy may still exist elsewhere.",
                            [c.event_id], "the destination volume (e.g. the USB device), or $MFT / LNK files on likely targets"))

    # 2. a copy to removable media needs the device present at the time
    usb_on = [e.timestamp for e in by_type.get(T.DEVICE_CONNECTED, [])]
    for c in by_type.get(T.FILE_COPIED, []):
        later = [t for t in usb_on if t > c.timestamp]
        if usb_on and later and not [t for t in usb_on if t <= c.timestamp]:
            mins = (min(later) - c.timestamp).total_seconds() / 60
            out.append(_gap("copy_before_device", f"Copy happened {mins:.0f} min before any USB device was connected",
                            "So the copy did not go straight to that device; an intermediate location is not in the evidence.",
                            [c.event_id], "staging folders, temp directories, cloud-sync folders"))

    # 3. devices connect and disconnect in pairs
    on = {e.object: e for e in by_type.get(T.DEVICE_CONNECTED, [])}
    off = {e.object: e for e in by_type.get(T.DEVICE_DISCONNECTED, [])}
    for dev in on.keys() - off.keys():
        out.append(_gap("device_unpaired", f"{dev} connected with no disconnection recorded",
                        "Either it was still attached when evidence was collected, or the removal record is missing.",
                        [on[dev].event_id], "the device itself; SYSTEM hive / Setupapi log for removal times"))
    for dev in off.keys() - on.keys():
        out.append(_gap("device_unpaired", f"{dev} disconnected with no connection recorded",
                        "It was attached before the evidence window began.", [off[dev].event_id],
                        "earlier Setupapi / registry data"))

    # 4. a logon session ends with a logoff
    logoffs = {e.user for e in by_type.get(T.LOGOFF, [])}
    for lg in by_type.get(T.LOGIN, []):
        if lg.user and lg.user not in logoffs:
            out.append(_gap("session_open", f"Logon by {lg.user} has no matching logoff",
                            "The session was still open at collection time, or the logoff record is missing or was cleared.",
                            [lg.event_id], "Security log 4634/4647 from a backup or forwarded copy"))

    # 5. user activity is preceded by that user's logon
    logged = {}
    for lg in by_type.get(T.LOGIN, []):
        logged.setdefault(lg.user, lg.timestamp)
    seen_users = set()
    for e in ev:
        if e.event_type in ACTIVITY and e.user and e.user not in seen_users:
            seen_users.add(e.user)
            if e.user not in logged or logged[e.user] > e.timestamp:
                out.append(_gap("activity_without_logon", f"Activity by {e.user} with no earlier logon recorded",
                                "The logon may predate the evidence or sit in a log that was not collected — or was cleared.",
                                [e.event_id], "Security log 4624 covering the period before this event"))

    # 6. a log clear explains missing records only for what came before it
    for c in by_type.get(T.LOG_CLEARED, []):
        before = [e for e in ev if e.source == c.source and e.timestamp < c.timestamp
                  and e.timestamp >= c.timestamp - timedelta(hours=24) and e.event_id != c.event_id]
        if not before:
            out.append(_gap("cleared_log_empty", "Nothing from the cleared log survives from the 24 h before the clear",
                            "Consistent with the clear removing those records; other sources must cover that period.",
                            [c.event_id], "forwarded logs (SIEM/WEF), backups, VSS snapshots of the .evtx"))

    # 7. a timestamp anomaly should be corroborated by other activity on the file
    for f in findings or []:
        if f.rule_name != "timestamp_anomaly" or not f.object:
            continue
        others = [e for e in ev if e.object == f.object and e.event_id not in f.event_ids]
        if not others:
            out.append(_gap("uncorroborated_timestamp", f"Timestamp anomaly on {f.object} has no other activity on that file",
                            "Without surrounding activity it can't be tied to a user action; a copy or restore can cause it.",
                            f.event_ids[-1:], "$UsnJrnl / $LogFile entries for the file"))
    return out

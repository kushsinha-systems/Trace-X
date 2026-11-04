"""Competing hypotheses — weigh rival explanations against the evidence.

After Heuer's Analysis of Competing Hypotheses: for each story (a chain, or a
finding outside any chain), five explanations are listed with the observed
evidence that SUPPORTS and CONTRADICTS each one, every item citing event ids.
Ranking is by (supporting − contradicting) items. It is a structured weighing to
guide the investigator, never a verdict: "best supported" is not "true".
"""
from __future__ import annotations

import re

from .antiforensics import SuspiciousEvent
from .models import CanonicalEvent

ADMIN = re.compile(r"admin|administrator|^svc|service|backup", re.I)
TOOLS = re.compile(r"backup|sync|robocopy|onedrive|dropbox|veeam|rsync|vss", re.I)
NOTE = "A structured weighing of explanations from the logged evidence, not proof of any of them."


def _short(ids):
    return [i[:8] for i in ids]


def _signals(evs: list[CanonicalEvent], fs: list[SuspiciousEvent]) -> dict:
    types = {}
    for e in evs:
        types.setdefault(e.event_type.value, []).append(e.event_id)
    rules = {}
    for f in fs:
        rules.setdefault(f.rule_name, []).append(f)
    users = {e.user for e in evs if e.user}
    s = {
        "deletion_finding": [i for f in rules.get("evidence_deletion", []) for i in f.event_ids[-1:]],
        "log_clear": types.get("LOG_CLEARED", []),
        "timestomp": [i for f in rules.get("timestamp_anomaly", []) for i in f.event_ids[-1:]],
        "copy_signature": [i for f in rules.get("timestamp_anomaly", [])
                           if all("modified" in part for part in re.findall(r"si_\w+<fn_\w+", f.description))
                           for i in f.event_ids[-1:]],
        "usb": types.get("DEVICE_CONNECTED", []),
        "copied": types.get("FILE_COPIED", []),
        "deleted": types.get("FILE_DELETED", []),
        "login": types.get("LOGIN", []),
        "ticket": [e.event_id for e in evs if (e.raw_metadata or {}).get("change_ticket")
                   or (e.raw_metadata or {}).get("maintenance_window")],
        "admin_user": [e.event_id for e in evs if e.user and ADMIN.search(e.user)],
        "tool_process": [e.event_id for e in evs if e.process and TOOLS.search(e.process)],
        "any_process": [e.event_id for e in evs if e.process],
        "own_files": [e.event_id for e in evs if e.object and e.user
                      and f"\\users\\{e.user.lower()}\\" in e.object.lower()],
        "objects": {e.object for e in evs if e.object and e.event_type.value.startswith("FILE_")},
        "users": users,
    }
    tickets = {str((e.raw_metadata or {}).get("change_ticket")) for e in evs if (e.raw_metadata or {}).get("change_ticket")}
    s["ticket_ids"] = sorted(tickets)
    return s


def _item(text, ids):
    return {"text": text, "events": _short(ids)}


def weigh(evs: list[CanonicalEvent], fs: list[SuspiciousEvent]) -> list[dict]:
    s = _signals(evs, fs)
    H = []

    sup, con = [], []
    if s["deletion_finding"]: sup.append(_item("a file was deleted shortly after being accessed and copied", s["deletion_finding"]))
    if s["log_clear"]: sup.append(_item("an event log was cleared", s["log_clear"]))
    if s["timestomp"]: sup.append(_item("file timestamps are inconsistent ($SI older than $FN)", s["timestomp"]))
    if s["usb"]: sup.append(_item("a removable device was connected during the activity", s["usb"]))
    if s["ticket"]: con.append(_item(f"a change ticket / maintenance window is recorded ({', '.join(s['ticket_ids']) or 'flag'})", s["ticket"]))
    if s["tool_process"]: con.append(_item("the activity came from a backup or sync tool", s["tool_process"]))
    H.append(("Deliberate concealment of evidence", sup, con))

    sup, con = [], []
    if s["ticket"]: sup.append(_item(f"a change ticket / maintenance window is recorded ({', '.join(s['ticket_ids']) or 'flag'})", s["ticket"]))
    if s["admin_user"]: sup.append(_item("the account is an administrative or service account", s["admin_user"]))
    if (s["log_clear"] or s["deleted"]) and not s["ticket"]:
        con.append(_item("no change ticket or maintenance window is recorded", s["log_clear"] or s["deleted"]))
    if s["own_files"]: con.append(_item("it touched a user's own files, not system files", s["own_files"]))
    H.append(("Planned maintenance or administration", sup, con))

    sup, con = [], []
    if s["tool_process"]: sup.append(_item("a backup or sync process is recorded", s["tool_process"]))
    if len(s["objects"]) >= 20: sup.append(_item(f"{len(s['objects'])} different files were touched in bulk", [e.event_id for e in evs][:3]))
    if not s["any_process"]: con.append(_item("no process is recorded for any of the events", [e.event_id for e in evs][:1]))
    if s["login"] and not s["admin_user"]: con.append(_item("an interactive user logon precedes the activity", s["login"]))
    if 0 < len(s["objects"]) <= 2: con.append(_item("the activity centres on one or two files, not a bulk job", [e.event_id for e in evs if e.object][:2]))
    H.append(("Backup, sync or housekeeping software", sup, con))

    sup, con = [], []
    if s["copied"]: sup.append(_item("a file copy is recorded", s["copied"]))
    if s["copy_signature"]: sup.append(_item("$SI older than $FN only on 'modified' fields, which an ordinary copy also leaves", s["copy_signature"]))
    if s["usb"] and s["copied"]: sup.append(_item("a removable device was present to copy to", s["usb"]))
    if s["log_clear"]: con.append(_item("copying files does not clear event logs", s["log_clear"]))
    if s["timestomp"] and not s["copy_signature"]: con.append(_item("timestamp fields beyond 'modified' disagree, which a copy does not explain", s["timestomp"]))
    H.append(("Ordinary file copy or move", sup, con))

    sup, con = [], []
    if s["deleted"] and s["own_files"]: sup.append(_item("the user deleted files in their own folders", s["deleted"]))
    if s["log_clear"]: con.append(_item("tidying up does not need an event-log clear", s["log_clear"]))
    if s["usb"]: con.append(_item("a removable device was involved", s["usb"]))
    if s["timestomp"] and not s["copy_signature"]: con.append(_item("timestamps were altered", s["timestomp"]))
    H.append(("User tidying up their own files", sup, con))

    rows = [{"hypothesis": h, "supporting": sup, "contradicting": con, "balance": len(sup) - len(con)}
            for h, sup, con in H if sup or con]
    rows.sort(key=lambda r: (-r["balance"], -len(r["supporting"])))
    top = rows[0]["balance"] if rows and rows[0]["supporting"] else None
    leaders = sum(1 for r in rows if top is not None and r["balance"] == top and r["supporting"])
    for r in rows:
        if top is not None and r["balance"] == top and r["supporting"]:
            # a tie means the evidence cannot separate these explanations: say so
            r["status"] = "best supported" if leaders == 1 else "tied"
        elif r["balance"] < 0 or not r["supporting"]:
            r["status"] = "weakened"
        else:
            r["status"] = "possible"
    return rows


def analyse(events: list[CanonicalEvent], findings: list[SuspiciousEvent], chains: list) -> list[dict]:
    """One weighing per story: each chain, then each finding whose trigger is in no chain."""
    by_id = {e.event_id: e for e in events}
    in_chain = {i for c in chains for i in c.event_ids}
    stories = []
    for c in chains:
        ids = set(c.event_ids)
        fs = [f for f in findings if f.event_ids and f.event_ids[-1] in ids]
        stories.append({"kind": "chain", "id": c.chain_id, "label": c.label, "event_ids": list(c.event_ids),
                        "hypotheses": weigh([by_id[i] for i in c.event_ids if i in by_id], fs), "note": NOTE})
    for f in findings:
        if f.event_ids and f.event_ids[-1] not in in_chain:
            stories.append({"kind": "finding", "id": f.key, "label": f"{f.rule_name} ({f.level})",
                            "hypotheses": weigh([by_id[i] for i in f.event_ids if i in by_id], [f]), "note": NOTE})
    return stories

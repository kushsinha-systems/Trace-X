"""MITRE ATT&CK mapping — which adversary techniques each rule family speaks to.

Technique IDs and names follow the ATT&CK Enterprise matrix
(https://attack.mitre.org/techniques/enterprise/). `coverage` is an honest
statement of scope: DETECTED (a rule targets it), PARTIAL (only a slice of the
technique is visible to TRACE-X), NOT_COVERED (related, but out of scope).
"""
from __future__ import annotations

from .antiforensics import SuspiciousEvent

_URL = "https://attack.mitre.org/techniques/{}/"

TECHNIQUES: dict[str, dict] = {
    "T1070.001": {"name": "Indicator Removal: Clear Windows Event Logs", "tactic": "Defense Evasion",
                  "coverage": "DETECTED", "rules": ["log_clearing"],
                  "how": "Security 1102 / System 104 log-clear events, scored on the hour before them."},
    "T1070.004": {"name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion",
                  "coverage": "DETECTED", "rules": ["evidence_deletion", "mass_deletion"],
                  "how": "Deletes preceded by access and staging, or bursts of 20+ deletions."},
    "T1070.006": {"name": "Indicator Removal: Timestomp", "tactic": "Defense Evasion",
                  "coverage": "PARTIAL", "rules": ["timestamp_anomaly"],
                  "how": "$SI older than $FN only; tools that rewrite $FN too are not detected."},
    "T1036.008": {"name": "Masquerading: Masquerade File Type", "tactic": "Defense Evasion",
                  "coverage": "PARTIAL", "rules": ["metadata_modification"],
                  "how": "Extension or size changed with no content activity; content signatures not checked."},
    "T1485": {"name": "Data Destruction", "tactic": "Impact",
              "coverage": "PARTIAL", "rules": ["mass_deletion"],
              "how": "Bulk deletion is visible; overwriting or wiping in place is not."},
    "T1052.001": {"name": "Exfiltration Over Physical Medium: Exfiltration over USB", "tactic": "Exfiltration",
                  "coverage": "PARTIAL", "rules": [],
                  "how": "USB connects/disconnects and copy-then-delete chains are shown; the data transfer itself is not observed."},
    "T1070.003": {"name": "Indicator Removal: Clear Command History", "tactic": "Defense Evasion",
                  "coverage": "NOT_COVERED", "rules": [],
                  "how": "Shell history artefacts are not parsed."},
    "T1562.002": {"name": "Impair Defenses: Disable Windows Event Logging", "tactic": "Defense Evasion",
                  "coverage": "NOT_COVERED", "rules": [],
                  "how": "Audit-policy changes (e.g. event 4719) are not mapped."},
}

RULE_TECHNIQUES: dict[str, list[str]] = {}
for _tid, _t in TECHNIQUES.items():
    for _r in _t["rules"]:
        RULE_TECHNIQUES.setdefault(_r, []).append(_tid)


def technique(tid: str) -> dict:
    t = TECHNIQUES[tid]
    return {"id": tid, "name": t["name"], "tactic": t["tactic"], "url": _URL.format(tid.replace(".", "/"))}


def coverage() -> list[dict]:
    order = {"DETECTED": 0, "PARTIAL": 1, "NOT_COVERED": 2}
    rows = [{**technique(tid), "coverage": t["coverage"], "rules": t["rules"], "how": t["how"]}
            for tid, t in TECHNIQUES.items()]
    return sorted(rows, key=lambda r: (order[r["coverage"]], r["id"]))


def map_findings(findings: list[SuspiciousEvent], chains: list | None = None,
                 by_id: dict | None = None) -> dict:
    """Techniques per finding (by stable key), plus which techniques this case actually shows."""
    per = {f.key: [technique(t) for t in RULE_TECHNIQUES.get(f.rule_name, [])] for f in findings}
    seen = {t["id"] for ts in per.values() for t in ts}
    usb_chains = []
    # A chain holding both a file copy and a USB connection speaks to exfiltration over USB.
    for c in chains or []:
        types = {by_id[e].event_type.value for e in c.event_ids if by_id and e in by_id}
        if {"FILE_COPIED", "DEVICE_CONNECTED"} <= types:
            seen.add("T1052.001")
            usb_chains.append(c.chain_id)
    return {"per_finding": per, "observed": sorted(seen), "usb_chains": usb_chains, "coverage": coverage()}

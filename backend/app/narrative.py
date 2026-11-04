"""AI narrative layer — Phase 9 (built LAST, summarisation only).

Hard rule: this module NEVER detects anything. Input = an already-computed
chain of evidence/correlations/hypotheses (Phases 5–7); output = a
plain-language summary where every factual claim cites a specific evidence
ID the UI can highlight. Forbidden framings (assertions of malice/intent)
are rejected by `validate_narrative`, tested below.

Backend: deterministic offline template by default (no external dependency).
Optional Ollama polish (`use_llm=True`, local model, e.g. llama3) degrades
gracefully to the template when Ollama is unreachable. An API-based model
may be swapped in only as configuration, never a requirement.
"""
from __future__ import annotations

import json
import urllib.request

from pydantic import BaseModel, Field

from .chains import Chain
from .antiforensics import SuspiciousEvent
from .models import CanonicalEvent

FORBIDDEN = [
    "malicious", "attacker", "guilty", "culprit", "perpetrator",
    "determined the user", "concluded the user", "proved the user",
    "ai determined", "ai concluded",
]


def validate_narrative(text: str) -> None:
    low = text.lower()
    for pat in FORBIDDEN:
        if pat in low:
            raise ValueError(f"forbidden narrative framing: {pat!r}")


class Narrative(BaseModel):
    chain_id: str
    text: str
    evidence_refs: list[str] = Field(default_factory=list)


def _describe(e: CanonicalEvent) -> str:
    who = f" by {e.user}" if e.user else ""
    obj = f" {e.object}" if e.object else ""
    return f"{e.event_type.value}{obj}{who} at {e.timestamp.isoformat()}"


def template_narrative(
    chain: Chain, by_id: dict[str, CanonicalEvent], findings: list[SuspiciousEvent] | None = None,
) -> Narrative:
    findings = findings or []
    evs = [by_id[i] for i in chain.event_ids if i in by_id]
    lines = [
        f"The system identified a sequence consistent with {chain.hypothesis.lower()} "
        f"(label: {chain.label}, mean edge score {chain.mean_score:.2f}).",
        "Observed steps in order:",
    ]
    for e in evs:
        lines.append(f"- {_describe(e)} [evidence `{e.event_id[:8]}`].")
    for f in findings:
        if set(f.event_ids) & set(chain.event_ids):
            lines.append(f"- Related indicator: {f.rule_name} (score {f.suspicion_score:.2f}, "
                         f"level {f.level}) [evidence {', '.join(f'`{i[:8]}`' for i in f.event_ids)}].")
    lines.append(f"Limitation: {chain.limitation}")
    text = "\n".join(lines)
    validate_narrative(text)
    return Narrative(chain_id=chain.chain_id, text=text,
                     evidence_refs=[e.event_id for e in evs])


def ollama_polish(text: str, model: str = "llama3", timeout_s: int = 20) -> str:
    """Optional local-LLM polish. Falls back to `text` when unreachable."""
    prompt = ("Rewrite the following forensic summary in clear investigator-facing prose. "
              "RULES: keep every [evidence `xxxxxxxx`] citation verbatim; never assert malice, "
              "intent, or guilt; keep the Limitation sentence verbatim.\n\n" + text)
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:11434/api/generate",
            data=json.dumps({"model": model, "prompt": prompt, "stream": False}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            out = json.loads(r.read().decode()).get("response", "").strip()
        if not out:
            return text
        validate_narrative(out)  # reject polish that smuggles forbidden framing
        return out
    except Exception:
        return text


def narrate_chain(
    chain: Chain, events: list[CanonicalEvent],
    findings: list[SuspiciousEvent] | None = None, *, use_llm: bool = False,
) -> Narrative:
    by_id = {e.event_id: e for e in events}
    n = template_narrative(chain, by_id, findings)
    if use_llm:
        polished = ollama_polish(n.text)
        n = Narrative(chain_id=n.chain_id, text=polished, evidence_refs=n.evidence_refs)
    return n

"""TRACE-X red-team run — measure where each rule stops detecting, write docs/redteam_results.md.
Run:  python tools/redteam.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app.redteam import run  # noqa: E402


def main() -> str:
    L = ["# TRACE-X Red-team Results",
         "_Measured by tools/redteam.py: one evasion variable swept per rule, the real detector run on each "
         "variant. Boundaries below are observed, not assumed._", ""]
    for r in run():
        L += [f"## `{r['rule']}`", "", f"**Evasion:** {r['evasion']}", "",
              f"| {r['variable']} | detected | level | score |", "|---|---|---|---|"]
        L += [f"| {x['value']} | {'yes' if x['detected'] else 'no'} | {x['level']} | {x['score']:.3f} |" for x in r["rows"]]
        if "spread" in r:
            s = r["spread"]
            L += ["", f"| {s['variable']} | detected | level | score |", "|---|---|---|---|"]
            L += [f"| {x['value']} | {'yes' if x['detected'] else 'no'} | {x['level']} | {x['score']:.3f} |" for x in s["rows"]]
        if "both_rewritten" in r:
            L += ["", f"Both $SI and $FN rewritten (48 h): detected = {r['both_rewritten']['detected']}."]
        L.append("")
    text = "\n".join(L)
    out = ROOT / "docs" / "redteam_results.md"
    out.write_text(text, encoding="utf-8")
    return str(out)


if __name__ == "__main__":
    print("wrote", main())

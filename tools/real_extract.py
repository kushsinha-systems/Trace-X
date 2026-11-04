"""Real-corpus extractor — M57 images via Dissect -> TRACE-X NTFS CSV shape.

Usage: python tools/real_extract.py data/real/charlie-work-usb-2009-12-11.E01

Walks the NTFS volume, reads per-file $STANDARD_INFORMATION (0x10) and
$FILE_NAME (0x30) timestamp sets, and writes an analyzeMFT-style CSV that
backend/app/parsers/ntfs.py consumes directly. Prints an artefact inventory
(EVTX / registry hives / browser DBs, if present on the volume).
"""
from __future__ import annotations

import csv
import sys
from datetime import timezone
from pathlib import Path


def _iso(dt) -> str:
    if dt is None:
        return ""
    try:
        if getattr(dt, "tzinfo", None) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return str(dt)


def extract(image: str, out_csv: str) -> dict:
    from dissect.target import Target

    t = Target.open(image)
    fs = [f for f in t.filesystems if type(f).__name__ == "NtfsFilesystem"][0]
    rows = []
    interesting: list[str] = []
    n_walked = 0
    for root, _dirs, files in fs.walk("/"):
        for name in files:
            n_walked += 1
            path = root.rstrip("/") + "/" + name if root != "/" else "/" + name
            low = path.lower()
            if low.endswith((".evtx", ".evt")) or "winevt" in low or low.endswith((".dat", ".hive")) \
                    or "history" in low or "places.sqlite" in low:
                interesting.append(path)
            try:
                entry = fs.get(path).entry
                attrs = getattr(entry, "attributes", {})
                si_list = list(attrs.get(0x10, []))
                fn_list = list(attrs.get(0x30, []))
                if not si_list or not fn_list:
                    continue
                si = si_list[0].attribute
                # prefer a Win32/long namespace FILE_NAME when several exist
                fn = fn_list[0].attribute
                for cand in fn_list:
                    nm = str(getattr(cand.attribute, "name", ""))
                    if nm and "~" not in nm:
                        fn = cand.attribute
                        break
                rows.append({
                    "filename": path,
                    "inode": str(getattr(entry, "index", "")),
                    "si_created": _iso(getattr(si, "creation_time", None)),
                    "si_modified": _iso(getattr(si, "last_modification_time", None)),
                    "si_mft_modified": _iso(getattr(si, "last_change_time", None)),
                    "si_accessed": _iso(getattr(si, "last_access_time", None)),
                    "fn_created": _iso(getattr(fn, "creation_time", None)),
                    "fn_modified": _iso(getattr(fn, "last_modification_time", None)),
                    "fn_mft_modified": _iso(getattr(fn, "last_change_time", None)),
                    "fn_accessed": _iso(getattr(fn, "last_access_time", None)),
                })
            except Exception:
                continue
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["filename", "inode", "si_created", "si_modified",
                                           "si_mft_modified", "si_accessed", "fn_created",
                                           "fn_modified", "fn_mft_modified", "fn_accessed"])
        w.writeheader()
        w.writerows(rows)
    return {"walked": n_walked, "rows": len(rows), "interesting": interesting}


if __name__ == "__main__":
    image = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else str(Path(image).with_suffix("")) + "_mft.csv"
    stats = extract(image, out)
    print(f"walked={stats['walked']} rows={stats['rows']} csv={out}")
    print(f"interesting ({len(stats['interesting'])}):")
    for p in stats["interesting"][:40]:
        print("  ", p)

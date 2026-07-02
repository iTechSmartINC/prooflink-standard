#!/usr/bin/env python3
"""Pull a fresh slice of REAL receipts from the live ProofLink ledger and run
the conformance validator against them (with consecutive chain-link checks).

    python3 fetch_live.py            # validate the newest ~16 ledger entries
    python3 fetch_live.py 200        # validate the newest ~200 entries

Because /api/export is oldest-first and entry[i].prev_hash == entry[i-1].hash,
each fetched receipt is chain-checked against its predecessor in the slice.
Only v3 receipts (schema_version "3.0") are asserted conformant; older v1/v2
entries in the slice are reported as SKIP (legacy, not recomputable).
"""
from __future__ import annotations

import json
import sys
import urllib.request

from conformance import validate, GREEN, RED, DIM, RESET

BASE = "https://verify.itechsmart.dev"


def _get(path: str) -> dict:
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "prooflink-conformance/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def main(argv: list[str]) -> int:
    n = int(argv[0]) if argv else 16
    total = _get("/api/export?from=0&to=1")["total"]
    hi = total
    lo = max(0, hi - n)
    receipts = _get(f"/api/export?from={lo}&to={hi}")["receipts"]  # oldest-first
    print(f"Live ledger total={total}; validating entries [{lo}..{hi}) "
          f"({len(receipts)} receipts) from {BASE}\n")

    v3 = skipped = conformant = 0
    for i, r in enumerate(receipts):
        prev = receipts[i - 1]["hash_sha256"] if i > 0 else None
        if str(r.get("schema_version")) != "3.0":
            skipped += 1
            print(f"{DIM}SKIP{RESET} {r.get('id')} (legacy v{r.get('schema_version','1')})")
            continue
        v3 += 1
        res = validate(r, prev_hash=prev if i > 0 else None)
        ok = res["valid"]
        if ok:
            conformant += 1
        tag = f" {DIM}[compliance_tags]{RESET}" if "compliance_tags" in r else ""
        color = GREEN if ok else RED
        print(f"{color}{'PASS' if ok else 'FAIL'}{RESET} {r.get('id')} "
              f"cat={r.get('category','?')}{tag}")
        if not ok:
            for name, p, detail in res["checks"]:
                if not p:
                    print(f"     {RED}✗{RESET} {name}: {detail}")

    print(f"\nSummary: {len(receipts)} fetched · {v3} v3 · {conformant}/{v3} v3 conformant "
          f"· {skipped} legacy skipped")
    return 0 if conformant == v3 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""ProofLink Receipt Standard v3.0 — Conformance Test Suite.

Validates any receipt JSON against Standard v3.0: schema shape + cryptographic
integrity + hash-chain linkage. Emits PASS/FAIL per receipt with reasons.

This is a STANDALONE reference checker (stdlib + `cryptography` only): it does
not import the SDK, so it independently exercises the same normative algorithm
the SDK and the live verifier implement.

Usage:
    python3 conformance.py <file.json> [<file.json> ...]
    python3 conformance.py --chain <file.json>   # also check consecutive prev_hash links
    cat receipt.json | python3 conformance.py -

Input forms accepted per file:
    - a single receipt object
    - a JSON array of receipt objects
    - {"receipts": [...]}  (the /api/export shape; array is oldest-first / chain order)
    - a conformance-fixture array of {"receipt": {...}, "prev_hash_expected": "..."}

Exit code 0 iff every receipt is conformant (a fixture explicitly marked
"expect": "FAIL" is treated as conformant when it correctly FAILS).
"""
from __future__ import annotations

import hashlib
import json
import sys
from typing import Any, Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False

EXCLUDE = ("canonical_bytes", "signature", "hash_sha256")
SCHEMA_V3 = "3.0"
REQUIRED_FIELDS = ("id", "timestamp", "category", "subject", "action", "actor",
                   "outcome", "schema_version", "prev_hash", "chain_position",
                   "canonical_bytes", "hash_sha256", "signature")

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def canonicalize(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def validate(receipt: dict, prev_hash: Optional[str] = None) -> dict:
    """Return {'valid': bool, 'checks': [(name, passed, detail)], 'errors': [...]}"""
    checks: list[tuple[str, bool, str]] = []
    errors: list[str] = []

    # --- Schema shape ---------------------------------------------------
    missing = [f for f in REQUIRED_FIELDS if f not in receipt]
    checks.append(("schema_fields", not missing,
                  "all required fields present" if not missing
                  else f"missing required fields: {missing}"))
    schema = str(receipt.get("schema_version", ""))
    checks.append(("schema_version", schema == SCHEMA_V3,
                  f'schema_version == "3.0"' if schema == SCHEMA_V3
                  else f'schema_version is {schema!r}; Standard v3.0 covers "3.0" '
                       f"(v1/v2 are legacy, not recomputable)"))
    sig = receipt.get("signature")
    sig_ok = isinstance(sig, dict) and {"algorithm", "public_key", "value"} <= set(sig)
    checks.append(("signature_shape", bool(sig_ok),
                  "signature object well-formed" if sig_ok
                  else "signature missing/!malformed (need algorithm, public_key, value)"))

    if missing or schema != SCHEMA_V3 or not sig_ok:
        return {"valid": False, "checks": checks, "errors": errors}

    # --- Check 1: hash integrity ---------------------------------------
    try:
        canon = bytes.fromhex(receipt["canonical_bytes"])
    except Exception as e:
        checks.append(("hash_integrity", False, f"canonical_bytes not valid hex: {e}"))
        return {"valid": False, "checks": checks, "errors": errors}
    got = hashlib.sha256(canon).hexdigest()
    h_ok = got == receipt.get("hash_sha256")
    checks.append(("hash_integrity", h_ok,
                  "SHA256(canonical_bytes) == hash_sha256" if h_ok
                  else f"hash mismatch: computed {got[:16]}… stored {str(receipt.get('hash_sha256'))[:16]}…"))

    # --- Check 2: canonical re-derivation ------------------------------
    payload = {k: v for k, v in receipt.items() if k not in EXCLUDE}
    rederived = canonicalize(payload)
    c_ok = rederived == canon
    checks.append(("canonical_rederivation", c_ok,
                  "re-derived canonical bytes match stored canonical_bytes" if c_ok
                  else "canonical re-derivation MISMATCH — a signed field was tampered"))

    # --- Check 3: Ed25519 signature ------------------------------------
    if not _HAVE_CRYPTO:
        errors.append("cryptography not installed — cannot verify Ed25519")
        checks.append(("ed25519_signature", False, "cryptography unavailable"))
    else:
        try:
            pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
            pub.verify(bytes.fromhex(sig["value"]), canon)
            checks.append(("ed25519_signature", True, f"Ed25519 OK (key {sig['public_key'][:16]}…)"))
        except InvalidSignature:
            checks.append(("ed25519_signature", False, "Ed25519 signature INVALID"))
        except Exception as e:
            checks.append(("ed25519_signature", False, f"signature error: {e}"))

    # --- Check 4: chain link (optional) --------------------------------
    if prev_hash is not None:
        l_ok = receipt.get("prev_hash") == prev_hash
        checks.append(("chain_link", l_ok,
                      "prev_hash links to previous entry" if l_ok
                      else f"chain BROKEN: prev_hash {str(receipt.get('prev_hash'))[:16]}… != expected {prev_hash[:16]}…"))

    valid = all(p for _, p, _ in checks) and not errors
    return {"valid": valid, "checks": checks, "errors": errors}


def _load(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with open(path) as f:
        return json.load(f)


def _iter_cases(data: Any):
    """Yield (receipt, prev_hash_or_None, expect) tuples."""
    if isinstance(data, dict) and "receipts" in data:
        receipts = data["receipts"]
        for i, r in enumerate(receipts):
            prev = receipts[i - 1].get("hash_sha256") if i > 0 else None
            yield r, prev, "PASS"
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and "receipt" in item:
                yield item["receipt"], item.get("prev_hash_expected"), item.get("expect", "PASS")
            else:
                yield item, None, "PASS"
    elif isinstance(data, dict):
        yield data, None, "PASS"


def main(argv: list[str]) -> int:
    chain_mode = "--chain" in argv
    paths = [a for a in argv if a != "--chain"] or ["-"]

    total = passed = conformant = 0
    for path in paths:
        data = _load(path)
        for receipt, prev, expect in _iter_cases(data):
            total += 1
            res = validate(receipt, prev_hash=prev if (prev and (chain_mode or True)) else None)
            rid = receipt.get("id", "<no-id>")
            got = "PASS" if res["valid"] else "FAIL"
            # A fixture that is EXPECTED to fail is conformant iff it FAILs.
            is_conformant = (got == expect)
            if res["valid"]:
                passed += 1
            if is_conformant:
                conformant += 1
            tag = ""
            if "compliance_tags" in receipt:
                tag = f" {DIM}[compliance_tags]{RESET}"
            verdict_color = GREEN if is_conformant else RED
            expect_note = "" if expect == "PASS" else f" (expected {expect})"
            print(f"{verdict_color}{got}{RESET} {rid} "
                  f"cat={receipt.get('category','?')}{tag}{expect_note}")
            for name, ok, detail in res["checks"]:
                mark = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
                print(f"     {mark} {name}: {detail}")
            for e in res["errors"]:
                print(f"     {RED}!{RESET} {e}")

    print()
    print(f"Summary: {total} receipt(s) checked · {passed} valid · "
          f"{conformant}/{total} conformant with expectation")
    return 0 if conformant == total else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

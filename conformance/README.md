# ProofLink Receipt Standard v3.0 — Conformance Test Suite

A standalone reference checker that validates any receipt JSON against
[ProofLink Receipt Standard v3.0](../ProofLink-Receipt-Standard-v3.md):
**schema shape + cryptographic integrity + hash-chain linkage**, emitting
PASS/FAIL per receipt with reasons.

It is intentionally **self-contained** (stdlib + `cryptography` only) — it does
not import the SDK, so it independently exercises the same normative algorithm
the SDK and the live verifier implement.

## Requirements

```bash
pip install cryptography
```

## Usage

```bash
# Validate any receipt file (single object, array, or /api/export shape)
python3 conformance.py fixtures/real_receipts.json

# Also check consecutive prev_hash chain links
python3 conformance.py --chain fixtures/real_receipts.json

# From stdin
curl -s "https://verify.itechsmart.dev/api/export?from=0&to=20" | python3 conformance.py -

# Pull a FRESH slice from the live ledger and validate it (with chain links)
python3 fetch_live.py 20
```

Exit code is `0` iff every receipt is conformant with its expectation
(a fixture marked `"expect": "FAIL"` is conformant when it correctly FAILs).

## The four normative checks (Standard v3.0 §9)

1. **hash_integrity** — `SHA256(canonical_bytes) == hash_sha256`
2. **canonical_rederivation** — `json.dumps(payload, sort_keys=True, separators=(",",":"), ensure_ascii=False)` re-derives the stored `canonical_bytes` exactly (catches any tampered signed field)
3. **ed25519_signature** — `signature.value` verifies over the raw `canonical_bytes` under the embedded `public_key`
4. **chain_link** — `prev_hash` equals the previous ledger entry's `hash_sha256` (checked when a predecessor is available)

Plus schema-shape gates: required fields present, `schema_version == "3.0"`,
well-formed `signature` object.

## Fixtures

| File | What | Expected |
|---|---|---|
| `fixtures/real_receipts.json` | 4 real live v3 receipts pulled from `/api/export` (one carries `compliance_tags`), each with its expected predecessor hash | all **PASS** (incl. chain link) |
| `fixtures/tampered_receipt.json` | 3 tamper vectors of one real receipt: **A** mutated signed field, **B** corrupted signature, **C** altered `canonical_bytes` | all **FAIL** — each on the check that catches it |

## Proven results (real live data, 2026-07-02)

`python3 conformance.py --chain fixtures/real_receipts.json` → **4/4 PASS**, exit 0
(all four checks green on every receipt, including the compliance-tagged one).

`python3 conformance.py fixtures/tampered_receipt.json` → **3/3 correctly FAIL**:

- **A** mutated `outcome`: `hash_integrity ✓`, `ed25519_signature ✓`, but
  `canonical_rederivation ✗` — the re-derivation check is what catches a
  display-field tamper (the stored `canonical_bytes` still hashes and verifies,
  but no longer matches the receipt's fields).
- **B** corrupted `signature.value`: `ed25519_signature ✗`.
- **C** altered `canonical_bytes`: `hash_integrity ✗` + `canonical_rederivation ✗` + `ed25519_signature ✗`.

`python3 fetch_live.py 20` → **20/20 v3 conformant** against a fresh slice of the
live ledger (total ≈ 79,458 entries), every consecutive `prev_hash` link intact.

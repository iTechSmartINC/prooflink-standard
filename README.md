# ProofLink Receipt Standard

> **Every other AI-accountability standard is a PDF. ProofLink is a running ledger of
> 79,000+ cryptographically-sealed AI actions you can verify right now — not a spec, a
> live chain.** → **[verify.itechsmart.dev](https://verify.itechsmart.dev)**

The open standard for cryptographically verifiable AI-action receipts — **and its live
reference implementation.** Every autonomous or semi-autonomous action taken by the
iTechSmart platform is sealed as a **ProofLink receipt**: a canonicalized JSON object bound
by a SHA-256 hash chain, signed with Ed25519, and anchored into the Bitcoin blockchain via
OpenTimestamps. *Don't trust the AI — trust the math.*

This repository contains the **normative standard**
([`ProofLink-Receipt-Standard-v3.md`](ProofLink-Receipt-Standard-v3.md)) and a **standalone
[conformance suite](conformance/)** that runs the four normative checks against live and
tampered receipts.

- **Standard edition:** **v3.0** — specifies receipt format **v3** (`schema_version "3.0"`),
  the current live format. The edition number tracks the format generation (see §14).
- **Published by:** iTechSmart Inc. This is an **open standard**, not an official/ratified
  standards-body document.

---

## Not a spec — a running chain

As of a live snapshot (2026-07-02), the public ledger reports (`/api/chain`, `/api/stats`):

| Metric | Value |
|---|---|
| Total receipts | **79,000+** and growing |
| Chain integrity | **`chain_intact: true`, 0 breaks** |
| Strict cryptographically-verifiable **v3** receipts | **2,100+** (hash + canonical re-derivation + Ed25519 + chain link) — **and every new action is sealed as v3** |
| Bitcoin-anchored (OpenTimestamps → real block inclusion) | **13,700+** (~17%, growing as the backlog is upgraded daily) |

Verify it yourself — no iTechSmart account, no trust required:

```bash
curl -s "https://verify.itechsmart.dev/api/export?from=0&to=20" \
  | python3 conformance/conformance.py -
```

### Honest two-era note

The chain spans two eras, disclosed openly at `/api/stats`:

- **v3 (`schema_version "3.0"`) — strict, cryptographically verifiable.** Full-payload
  canonicalization, SHA-256 hash recompute, Ed25519 signature over the raw canonical bytes,
  and hash-chain linkage. This is the current format; every new action is v3.
- **Legacy v1/v2 — pointer-linked, preserved unmodified.** Earlier receipts predate the v3
  hardening; their hashes are not recomputable from stored data and `prev_hash` is a pointer
  only. They are **never rewritten** (no history rewrite) and are reported honestly. The
  overall chain remains intact; `strict_full_chain_linked: false` is simply the disclosed
  count of legacy pointer links, **not a chain break** (`breaks: 0`).

We do **not** claim all 79k receipts are strict-verifiable — 2,100+ v3 receipts are, and the
count grows with every new action.

---

## Verify in 5 lines

The four normative checks (§9), reproduced with only `hashlib` (stdlib) + `cryptography`:

```python
import json, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
EXCLUDE = ("canonical_bytes", "signature", "hash_sha256")

def verify_v3(r, prev_hash=None):
    canon = bytes.fromhex(r["canonical_bytes"])
    assert hashlib.sha256(canon).hexdigest() == r["hash_sha256"]                    # 1 hash
    payload = {k: v for k, v in r.items() if k not in EXCLUDE}
    assert json.dumps(payload, sort_keys=True, separators=(",",":"),
                      ensure_ascii=False).encode() == canon                          # 2 re-derive
    sig = r["signature"]
    ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"])) \
        .verify(bytes.fromhex(sig["value"]), canon)                                  # 3 signature
    assert prev_hash is None or r["prev_hash"] == prev_hash                          # 4 chain link
    return True
```

---

## Built for the regulations

ProofLink markets directly to the controls auditors actually cite. Each row names the
receipt field/mechanism that satisfies it (full mapping in §10 of the standard):

| Regulation / framework | Requirement | ProofLink field / mechanism |
|---|---|---|
| **EU AI Act (Reg. 2024/1689) Article 12** | Automatic, tamper-evident event logging over the lifetime of a high-risk AI system | Append-only, hash-chained ledger (§4); every action seals `timestamp`, `actor`, `action`, `subject`, `outcome`, `details` |
| **NIST AI RMF 1.0 — MEASURE 2.7 / MANAGE 4.1** | Security/resilience evaluated & documented; post-deployment monitoring implemented | `security` / `platform_fix` / `platform_health_check` receipts, signed & immutable; `actor` distinguishes system vs. agent vs. operator |
| **CMMC Level 2 — AU.L2-3.3.1 / AU.L2-3.3.8** | Create, retain, and protect audit logs from modification/deletion | SHA-256 hash chain + Ed25519 signatures make any edit, deletion, or reorder detectable; Bitcoin anchoring adds external existence proof |
| **SOC 2 — CC7.2 / CC7.3 / CC8.1** | Anomaly monitoring, security-event evaluation, change management | `signal_classified` / `security` monitoring receipts; `config_change` records `{before_hash, after_hash, diff_summary}` — all signed |
| **ISO/IEC 42001:2023 — Clause 9.1** | Retain documented information as evidence of monitoring/evaluation | The receipt ledger *is* the retained evidence; integrity is cryptographically provable (`iso_42001` mappings emitted live) |

A receipt can also self-declare the controls it attests to via `compliance_tags` — and
because that list is inside `canonical_bytes`, the compliance claim is itself sealed.

---

## Connect anything

Every call seals a receipt into the chain:

- **MCP server** — verify and search receipts from any MCP client (Claude, Cursor, Copilot,
  LangGraph, CrewAI): `prooflink_verify_receipt`, `prooflink_search_receipts`,
  `prooflink_verify_chain`.
- **FastAPI / REST** — `verify.itechsmart.dev` exposes `/api/export`, `/api/verify/<id>`,
  `/api/chain`, `/api/stats`, `/api/anchors`, and `/api/how-to-verify` for backends and
  auditors.
- **SDKs** — [`prooflink-sdk`](https://github.com/Iteksmart/prooflink-sdk) (Python + TypeScript)
  wraps seal + verify; [`prooflink-verifier`](https://github.com/Iteksmart/prooflink-verifier)
  is the zero-dependency reference verifier.

---

## Relationship to `draft-sharif-agent-audit-trail`

ProofLink aligns conceptually with the IETF Internet-Draft
[`draft-sharif-agent-audit-trail-00`](https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00)
(*Agent Audit Trail (AAT)*) — same problem (tamper-evident audit trails for autonomous AI),
same core (per-action JSON records, SHA-256 hash chaining, optional signatures, EU AI Act /
SOC 2 / ISO 42001 alignment). It **differs deliberately** in canonicalization (Python
`json.dumps` profile, not RFC 8785 JCS), signature algorithm (Ed25519, not ECDSA P-256), and
adds Bitcoin/OpenTimestamps anchoring, sealed compliance tags, supersession, and learning
receipts. See §11 of the standard for the clause-level comparison. (The draft is a work in
progress; re-confirm details against the current datatracker version.)

---

## Repository layout

```
ProofLink-Receipt-Standard-v3.md   # the normative standard (edition v3.0, format v3)
conformance/
  conformance.py                   # standalone reference checker (stdlib + cryptography)
  fetch_live.py                    # pull a fresh slice from the live ledger and validate
  fixtures/real_receipts.json      # real live v3 receipts (all PASS incl. chain link)
  fixtures/tampered_receipt.json   # tamper vectors (all correctly FAIL)
```

## License

[MIT](LICENSE) — © iTechSmart Inc. Use freely, audit openly, verify everything.

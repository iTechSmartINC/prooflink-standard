# ProofLink Receipt Standard v3.0

**Status:** Open Standard — Receipt Format v3 (Standard Edition v3.0)
**Date:** 2026-07-02
**Publisher:** iTechSmart Inc.
**Abstract:** The ProofLink Receipt Standard defines a cryptographically verifiable,
append-only audit-record format for autonomous and semi-autonomous AI actions. Every
action taken by the iTechSmart platform — self-heals, platform fixes, configuration
changes, learning updates, telemetry heartbeats, and other operational events — is
sealed as a **ProofLink receipt**: a canonicalized JSON object bound by a SHA-256 hash
chain, signed with an Ed25519 key, and additionally anchored to the Bitcoin blockchain
through OpenTimestamps. The core principle is *don't trust the AI, trust the math*: any
third party can independently re-derive the canonical bytes, recompute the hash, verify
the signature against a published public key, and confirm chain linkage — without trusting
iTechSmart, and without access to any private key.

This document normatively specifies the **v3 receipt format** (`schema_version` `"3.0"`).
Legacy v1/v2 formats are documented as preserved-but-non-conformant. The **edition
number of this Standard tracks the receipt-format generation it specifies**: this is
edition **v3.0** because it specifies format **v3**, which is also the current live format.
v3.0 is the first *published* edition of the Standard (the earlier v1/v2 formats were never
published as a standalone standard). See §14.

---

## Conventions and Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**,
**SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be
interpreted as described in [RFC 2119] and [RFC 8174] when, and only when, they appear
in all capitals, as shown here.

- **Receipt** — a single sealed audit record conforming to this standard.
- **Ledger** — the append-only ordered array of receipts.
- **Canonical bytes** — the deterministic byte encoding of a receipt's payload that is
  hashed and signed.
- **Producer** — any component that seals a receipt.
- **Verifier** — any party that independently checks a receipt.

---

## Table of Contents

1. [Introduction & Motivation](#1-introduction--motivation)
2. [The Canonical Receipt Object](#2-the-canonical-receipt-object)
3. [Canonicalization Rules](#3-canonicalization-rules)
4. [SHA-256 Hash-Chain Linkage](#4-sha-256-hash-chain-linkage)
5. [Ed25519 Signing](#5-ed25519-signing)
6. [OpenTimestamps → Bitcoin Anchoring](#6-opentimestamps--bitcoin-anchoring)
7. [Optional Fields](#7-optional-fields)
8. [Receipt Categories](#8-receipt-categories)
9. [Verification Algorithm](#9-verification-algorithm)
10. [Regulatory Mapping](#10-regulatory-mapping)
11. [Relationship to draft-sharif-agent-audit-trail](#11-relationship-to-draft-sharif-agent-audit-trail)
12. [Legacy Eras (v1 / v2)](#12-legacy-eras-v1--v2)
13. [Conformance Requirements](#13-conformance-requirements)
14. [Versioning & Change Policy](#14-versioning--change-policy)
15. [Appendix A: Worked Example](#15-appendix-a-worked-example)
16. [References](#16-references)

---

## 1. Introduction & Motivation

Autonomous AI systems increasingly take real actions on production infrastructure:
restarting containers, rewriting network configurations, rotating credentials, and
updating their own policies. Traditional application logs are trivially editable and
carry no cryptographic proof of integrity, ordering, or authorship. For regulated
environments — and for any environment where an operator must later prove *what the AI
did, when, and that the record was not altered afterward* — plain logs are insufficient.

ProofLink provides a **verifiable audit trail** for autonomous AI actions. Each action
produces a receipt whose integrity, authorship, and position in history are provable by
mathematics alone:

- **Integrity** — the receipt hashes to a value stored in the receipt (recomputable).
- **Non-repudiation** — the receipt is signed by an Ed25519 key whose public half is
  published and embedded in every receipt.
- **Tamper-evident ordering** — each receipt embeds the hash of its predecessor inside
  the signed payload, so reordering or deleting history breaks the chain.
- **Independent timestamping** — receipt hashes are anchored into the Bitcoin blockchain
  via OpenTimestamps, giving a trust-minimized proof that a receipt existed by a given
  time.

The design goal is that a skeptical third party can verify any receipt **without trusting
iTechSmart at all**. This is what "don't trust the AI, trust the math" means in practice.

The live public verification service is at `https://verify.itechsmart.dev`. The
authoritative human-readable verification spec is served at
`GET https://verify.itechsmart.dev/api/how-to-verify`, and this standard is consistent
with it.

---

## 2. The Canonical Receipt Object

A conformant v3 receipt is a JSON object. The following top-level fields are **REQUIRED**
on every v3 receipt:

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | MUST | Stable receipt identifier. Caller-supplied stable id, or a `uuid4().hex[:16]`. Covered by the signature. |
| `timestamp` | string | MUST | Event time, ISO-8601 / RFC 3339 with UTC offset (e.g. `2026-07-02T03:47:47.509484+00:00`). |
| `category` | string | MUST | Free-form receipt category (see §8). Every category is hash-chained identically. |
| `subject` | string | MUST | The entity the action was performed on / about (e.g. a service or device name). |
| `action` | string | MUST | Human-readable description of the action taken. |
| `actor` | string | MUST | The identity that performed the action (e.g. `hermes-agent:security-remediation`, `system:cmdb-discovery`, `ops-api:itsm`). |
| `outcome` | string | MUST | Result of the action (e.g. `success`, `P0`, `INFO — auto-receipted`, or a descriptive outcome string). |
| `schema_version` | string | MUST | `"3.0"` for receipts conforming to this standard. |
| `prev_hash` | string | MUST | `hash_sha256` of the previous (next-older) ledger entry; `""` for the genesis entry. Inside the signed payload (see §4). |
| `chain_position` | integer | MUST | Zero-based (monotonic) index of this receipt in the ledger. Inside the signed payload. |
| `canonical_bytes` | string (hex) | MUST | Hex-encoded canonical JSON of the full payload (all stored fields **except** the three computed fields `canonical_bytes`, `signature`, `hash_sha256`). See §3. **Computed field — excluded from itself.** |
| `hash_sha256` | string (hex) | MUST | `SHA256(canonical_bytes)` as lowercase hex. **Computed field.** |
| `signature` | object | MUST | Ed25519 signature object (below). **Computed field.** |

### 2.1 The `signature` sub-object

| Field | Type | Required | Description |
|---|---|---|---|
| `algorithm` | string | MUST | `"Ed25519"`. |
| `public_key` | string (hex) | MUST | 32-byte Ed25519 public key, hex-encoded. Identical on every receipt sealed with the production key (see §5). |
| `value` | string (hex) | MUST | 64-byte Ed25519 signature over the **raw** `canonical_bytes` (not the hex string, not the hash). |
| `signs` | string | SHOULD | `"canonical_bytes"` — declares what the signature covers. |

### 2.2 Optional additive fields (normative when present)

| Field | Type | Required | Description |
|---|---|---|---|
| `compliance_tags` | list[string] | MAY | Control IDs this receipt attests to (see §7.1). |
| `supersedes` | string | MAY | Receipt `id` this receipt corrects/replaces (see §7.2). |
| `learned_from` | list[string] | MAY | Prior receipt ids that informed this receipt (see §7.3). |

### 2.3 Additional data fields

Receipts **MAY** carry arbitrary additional top-level or nested data fields. These are not
constrained by this standard, but — with the sole exception of the three computed fields —
**every stored field is inside `canonical_bytes` and is therefore covered by both the hash
and the signature** with no special handling. Fields observed on live v3 receipts include,
among others: `details` (a category-specific object), `human_input` (bool),
`auto_resolved` (bool), `tamper_detected` (bool), `verify_url` (string), and platform
interoperability fields such as `vc_context`, `vc_type`, `compliance_mappings`,
`scitt_compatible`, `transparency_log`, `receiver_attestation`, and internal
`_asqav_*` markers. A conformant verifier treats all of these uniformly: they are just
payload, and they are all protected by the canonical re-derivation check (§9, step 2).

> **Note on `receiver_attestation`:** In v3 this field, when present, is a normal payload
> field and is therefore *inside* `canonical_bytes` and covered by the signature. (This is
> a deliberate change from v2, where `receiver_attestation` was excluded from the canonical
> bytes — see §12.)

---

## 3. Canonicalization Rules

Deterministic canonicalization is the foundation of verifiability: producer and verifier
must derive **byte-identical** encodings from the same payload.

The canonical bytes of a receipt are defined as:

```python
payload = {k: v for k, v in receipt.items()
           if k not in ("canonical_bytes", "signature", "hash_sha256")}

canonical_bytes = json.dumps(
    payload,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
).encode("utf-8")
```

The resulting bytes are stored **hex-encoded** in the receipt's `canonical_bytes` field.

Producers **MUST** apply exactly these rules; verifiers **MUST** re-derive using exactly
these rules:

1. **Field set.** The canonical payload is the full receipt object minus exactly the three
   computed fields (`canonical_bytes`, `signature`, `hash_sha256`). Every other stored
   field — including `prev_hash`, `chain_position`, `id`, `timestamp`, and any optional or
   arbitrary data fields — **MUST** be included.
2. **`sort_keys=True`.** Object keys are sorted lexicographically (by Unicode code point),
   recursively at every nesting level.
3. **`separators=(",", ":")`.** No insignificant whitespace: item separator is a single
   comma, key/value separator is a single colon.
4. **`ensure_ascii=False`.** Non-ASCII characters are emitted as literal UTF-8, **not** as
   `\uXXXX` escapes. The em dash `—` (U+2014), for example, is encoded as its 3-byte UTF-8
   sequence `e2 80 94`.
5. **UTF-8.** The canonical JSON string is encoded to bytes as UTF-8.

Because the encoding is fully deterministic, any two correct implementations produce the
same bytes, and any single-bit change to any covered field changes the canonical bytes
(and therefore the hash and the signature).

> **Interoperability note.** This canonicalization is the Python-standard-library
> `json.dumps` canonical form. It is **not** RFC 8785 JSON Canonicalization Scheme (JCS);
> in particular RFC 8785 mandates specific number serialization and other rules that this
> profile does not adopt. Verifiers **MUST** re-derive using the rules above, not a generic
> JCS library. See §11 for the relationship to standards that use JCS.

---

## 4. SHA-256 Hash-Chain Linkage

Receipts form an append-only hash chain.

- `hash_sha256` = `SHA256(canonical_bytes)`, lowercase hex. It is recomputable by any
  verifier from the stored `canonical_bytes` (§9, step 1).
- `prev_hash` = the `hash_sha256` of the previous (next-older) ledger entry. The genesis
  entry uses `prev_hash = ""`.
- `chain_position` = the integer index of the receipt within the ledger.

Critically, **`prev_hash` and `chain_position` are ordinary payload fields**: they are
inside `canonical_bytes`, and therefore covered by both `hash_sha256` and the Ed25519
signature. Consequences:

- Altering any field of a receipt changes its `canonical_bytes`, breaking both the hash
  recompute and the signature.
- Altering the `prev_hash` pointer (to try to splice history) breaks the hash and
  signature of the receipt that carries it.
- Reordering or deleting entries breaks the `prev_hash == previous.hash_sha256` linkage.

Thus the chain is **tamper-evident end to end**: to forge a consistent alternative history
an attacker would need the Ed25519 private key (§5) *and* would still leave any
Bitcoin-anchored hashes (§6) unmatchable.

**Ledger order.** The raw ledger array is stored **newest-first**, and that array order is
the true chain order. The public export endpoint,
`GET /api/export?from=<i>&to=<j>` (paginated, max page size 1000), returns receipts
**oldest-first** so that, in the export, `entry[i].prev_hash == entry[i-1].hash_sha256`.

---

## 5. Ed25519 Signing

Each receipt is signed with Ed25519 (EdDSA over Curve25519).

- **What is signed.** `signature.value` is the Ed25519 signature over the **raw
  `canonical_bytes`** — the decoded bytes (`bytes.fromhex(receipt["canonical_bytes"])`),
  **not** the hex string, and **not** the `hash_sha256`.
- **Key format.** The public key is a 32-byte Ed25519 public key, hex-encoded (64 hex
  chars). The signature value is 64 bytes, hex-encoded (128 hex chars).
- **Key storage.** The production signing (private) key resides at
  `~/.secrets/prooflink_ed25519.key` on the sealing host and is never exported.
- **Embedded public key.** The public key is embedded in every v3 receipt at
  `signature.public_key`, and independently published at
  `GET /api/how-to-verify`. Verifiers **SHOULD** cross-check the embedded key against the
  published key.

**Published production public key (Ed25519):**

```
public_key (hex):        21102eaa68ea9ed42c05a2253aa953d33c59b5348ff8659018146e59fb061b97
fingerprint (SHA-256):   54a2116e9cea5f51d6db61c4701d62fd3a0cf670b3004c89a5278eeb5507643f
```

The fingerprint is the SHA-256 of the 32-byte public key. Verifiers **MAY** pin this
fingerprint.

---

## 6. OpenTimestamps → Bitcoin Anchoring

Beyond the hash chain and Ed25519 signatures, each receipt hash is submitted to the
**OpenTimestamps** protocol, which aggregates submissions across four public calendar
servers and periodically commits the aggregate into a **Bitcoin** transaction. Once that
transaction is mined and the OTS proof is upgraded with the confirmed block header, the
receipt gains a trust-minimized, independently verifiable proof that it existed no later
than that block's time.

Honest properties of the anchoring layer:

- **Non-blocking.** Anchoring is asynchronous and **never** blocks or prevents the ledger
  write. A receipt is fully sealed (hashed + signed + chained) regardless of anchoring
  status.
- **A growing share, never overclaimed.** At any moment only a subset of receipts are
  confirmed on Bitcoin; the rest are `pending_confirmation`. A receipt is **NEVER** marked
  `bitcoin_anchored` without real block inclusion. Confirmations continue over time as a
  daily batch upgrades the backlog.
- **Live reporting.** `GET /api/anchors` reports the live totals — total receipts, OTS
  submissions, confirmed `bitcoin_anchored` count, pending count, and the anchored share —
  plus a sample of anchored receipts with their `bitcoin_block` heights. As one live
  snapshot (2026-07-02), roughly 17% of receipts were confirmed on-chain with the
  remainder pending; these figures grow monotonically over time.
- **Independently verifiable.** Any anchored sample can be checked without trusting
  iTechSmart: look up its `bitcoin_block` on any block explorer
  (e.g. `https://mempool.space/block/<height>`), or validate the `.ots` proof at
  `https://opentimestamps.org`.

Anchoring **complements** but does not replace the hash chain and signature: integrity and
authorship are provable offline from a single receipt; anchoring adds trust-minimized
*existence-by-time*.

---

## 7. Optional Fields

The following optional fields were introduced 2026-07-02 as **additive, forward-only**
extensions. They are present **only** on receipts that set them and are absent by default.
Each is an ordinary top-level payload field: it is inside `canonical_bytes` and covered by
`hash_sha256` and the Ed25519 signature with **no special handling** — the reference
verifier (§9) already validates them. Receipts without these fields are unchanged and
verify exactly as before.

### 7.1 `compliance_tags`

`list[str]` of control identifiers the receipt attests to, e.g.
`["NIST 800-53 AU-2", "EU AI Act Article 12", "CMMC AC.L2-3.1.1", "HIPAA 164.312(b)"]`.
The strings are free-form; **no fixed vocabulary is enforced**. Because the list is inside
`canonical_bytes`, a compliance tag **cannot** be altered, added, or removed without
breaking the hash and the signature — the compliance claim is itself cryptographically
sealed.

### 7.2 `supersedes`

A `str` receipt `id` that **this** receipt corrects or replaces. Supersession is
**forward-only**:

- The newer receipt points **backward** at the older receipt's `id`.
- The older receipt is **NEVER** mutated: its `hash_sha256` and `signature` remain valid
  and its chain position is preserved. History is never rewritten.
- The reverse link (`superseded_by`) is **NOT** stored in history. `GET /api/verify/<id>`
  **derives** it at read time by scanning for receipts whose `supersedes == <id>`, and
  returns it as a top-level **response** field that is **outside** the signed receipt
  payload, so re-derivation and signature verification of the underlying receipt are
  unaffected.

This gives a provable correction trail without ever invalidating or altering the record
being corrected.

### 7.3 `learned_from`

`list[str]` of prior receipt ids this receipt learned from. Used by the
`learning_receipt` category (§8) to close the **LEARN** loop provably: a model/policy
update is cryptographically bound to the ids of the receipts that informed the change, so
the provenance of a learned change is itself in the tamper-evident chain.

---

## 8. Receipt Categories

The `category` field is **free-form**, and every category is hash-chained, signed, and
anchored identically; categories require **no special verification**. The entries below
are documented conventions so producers and consumers agree on payload shape.

| Category | Meaning | Typical `details` / extras |
|---|---|---|
| `config_change` | Infrastructure config mutation (sealed by the netmiko connector). | `details`: `{device, change_type, before_hash, after_hash, diff_summary}`. May carry `compliance_tags` and/or `supersedes`. |
| `learning_receipt` | A model/policy update; closes the LEARN loop. | `learned_from` (prior receipt ids) plus `details` describing what changed. |
| `platform_fix` | An autonomous or operator platform change / remediation. | Remediation `details`. |

Additional categories observed live (all hash-chained identically):
`platform_health_check`, `graph_poll_complete`, `signal_classified`, `security`,
`cmdb_discovery_complete`, `container_restart`, and others. The ledger deliberately mixes
autonomous remediations, platform scans, telemetry heartbeats, and other operational
receipts; `GET /api/stats → provenance_summary` reports each category honestly.

---

## 9. Verification Algorithm

A conformant verifier **MUST** perform the following four checks. **All four MUST pass**
for a v3 receipt to be considered verified. (If a previous-entry hash is available, the
chain-link check is also mandatory.)

**Step 1 — Hash integrity.**
```
canon = bytes.fromhex(receipt["canonical_bytes"])
assert sha256(canon).hexdigest() == receipt["hash_sha256"]
```

**Step 2 — Canonical re-derivation (detects any field tamper).**
```
payload = {k: v for k, v in receipt.items()
           if k not in ("canonical_bytes", "signature", "hash_sha256")}
rederived = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
assert rederived == canon
```

**Step 3 — Ed25519 signature.**
```
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
pub.verify(bytes.fromhex(sig["value"]), canon)   # raises on bad signature
```

**Step 4 — Chain link (when a previous entry hash is provided).**
```
assert receipt["prev_hash"] == prev_entry_hash
```

### 9.1 Normative reference implementation

The following Python verifier is the normative reference implementation, reproduced from
`GET /api/how-to-verify`:

```python
import json, hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519

EXCLUDE = ("canonical_bytes", "signature", "hash_sha256")

def verify_v3(receipt, prev_entry_hash=None):
    canon = bytes.fromhex(receipt["canonical_bytes"])
    assert hashlib.sha256(canon).hexdigest() == receipt["hash_sha256"], "hash mismatch"
    payload = {k: v for k, v in receipt.items() if k not in EXCLUDE}
    rederived = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    assert rederived == canon, "canonical re-derivation mismatch (field tampered)"
    sig = receipt["signature"]
    pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"]))
    pub.verify(bytes.fromhex(sig["value"]), canon)  # raises on bad signature
    if prev_entry_hash is not None:
        assert receipt["prev_hash"] == prev_entry_hash, "chain link broken"
    return True

# usage: receipts = GET /api/export?from=N&to=N+1000 (oldest-first)
# for i, r in enumerate(receipts[1:], 1): verify_v3(r, receipts[i-1]["hash_sha256"])
```

This reference verifier requires only `hashlib` (stdlib) and the `cryptography` package's
Ed25519 primitive. It has no dependency on iTechSmart infrastructure.

---

## 10. Regulatory Mapping

This section maps ProofLink mechanisms and fields to specific regulatory and framework
controls. The mapping is intended to be accurate; where an exact clause number is version-
dependent it is phrased carefully. A receipt **MAY** additionally self-declare the controls
it attests to via `compliance_tags` (§7.1), and the live platform also emits a structured
`compliance_mappings` object on many receipts (e.g. `nist_ai_rmf`, `eu_ai_act`,
`iso_42001`, `soc2`) — both are covered by the signature.

| Control (ID + name) | What it requires | ProofLink field / mechanism that satisfies it |
|---|---|---|
| **EU AI Act (Reg. 2024/1689) Article 12(1)–(3) — Record-keeping / logging** | High-risk AI systems must technically allow **automatic recording of events (logs) over the lifetime** of the system, appropriate to the intended purpose, ensuring a level of traceability of functioning. | Every AI action seals a receipt with `timestamp`, `actor`, `action`, `subject`, `outcome` and category-specific `details`; the append-only, hash-chained ledger (§4) provides lifetime, ordered, tamper-evident event recording and traceability. |
| **EU AI Act Article 12 — traceability of functioning** | Logging must enable tracing the system's operation and identifying risk situations. | `prev_hash`/`chain_position` provide ordered traceability; `category` + `outcome` (e.g. `P0`, anomaly detections) capture risk situations; `learned_from`/`supersedes` trace policy evolution and corrections. |
| **NIST AI RMF 1.0 — MEASURE 2.7 (AI system security and resilience evaluated & documented)** | Security/resilience properties of the AI system are evaluated and **documented**. | Security and remediation actions (e.g. `security`, `platform_fix` categories) are documented as signed, immutable receipts; integrity is provable, so the documentation itself is trustworthy. |
| **NIST AI RMF 1.0 — MEASURE 4.x (feedback / tracking of measured risk over time)** | Measurement approaches track existing and emergent risks and are informed by deployment monitoring. | Continuous telemetry/health/anomaly receipts (`platform_health_check`, `signal_classified`, `telemetry_anomaly`) create a durable, ordered record of measured risk over time. |
| **NIST AI RMF 1.0 — MANAGE 4.1 (post-deployment monitoring implemented)** | Post-deployment AI system monitoring plans are implemented, including capturing input from relevant AI actors. | The autonomous remediation loop seals a receipt for every detection and every action; `actor` distinguishes system vs. agent vs. operator; `human_input` flags human involvement. |
| **NIST AI RMF 1.0 — MANAGE 4.3 / incident communication & correction** | Incidents/errors are communicated and corrections are managed. | `supersedes` (§7.2) provides a provable, forward-only correction trail; incident receipts link detection → action → outcome. |
| **CMMC Level 2 — AU.L2-3.3.1 (System auditing)** | Create and retain audit logs sufficient to monitor, analyze, investigate, and report unauthorized activity (time stamps, identities, event descriptions, success/failure). | Each receipt carries `timestamp`, `actor`, `subject`, `action`, `outcome`, and `details`, retained append-only in the ledger. |
| **CMMC Level 2 — AU.L2-3.3.8 (Protect audit information from modification/deletion)** | Protect audit information and audit tools from unauthorized access, modification, and deletion. | The SHA-256 hash chain (§4) makes any modification, deletion, or reordering detectable; Ed25519 signatures (§5) prevent forgery; Bitcoin anchoring (§6) provides external, immutable existence proof. This is cryptographic tamper-evidence, exceeding write-once storage expectations. |
| **CMMC Level 2 — AU.L2-3.3.2 (Traceability to individual actors)** | Ensure actions can be uniquely traced to responsible users/processes. | The `actor` field records the responsible identity; it is inside the signed canonical bytes. |
| **SOC 2 CC7.2 (Monitoring of system components / anomaly detection)** | Monitor system components and the operation for anomalies indicative of malicious acts or errors. | Telemetry/anomaly/health receipts continuously record monitoring events in the tamper-evident ledger. |
| **SOC 2 CC7.3 (Evaluate security events)** | Evaluate security events to determine whether they represent incidents. | `signal_classified` and `security` receipts capture classification/evaluation with confidence and outcome, immutably. |
| **SOC 2 CC4.x (Monitoring of controls)** | Ongoing evaluation and communication of control operation. | The ledger provides continuous, verifiable evidence that controls (self-heals, scans) executed. |
| **SOC 2 CC8.1 (Change management)** | Authorize, design, develop, document, approve, and implement changes to meet objectives. | `config_change` receipts record `{device, change_type, before_hash, after_hash, diff_summary}`; `human_input`/`actor` capture authorization; `supersedes` records superseding changes — all signed and immutable. |
| **ISO/IEC 42001:2023 — Clause 9.1 (Monitoring, measurement, analysis and evaluation)** | Determine what is monitored/measured and retain documented information as evidence of results. | The receipt ledger is the retained documented evidence of monitoring and evaluation results; integrity is cryptographically provable. |
| **ISO/IEC 42001:2023 — Clause 8 / Annex A operation-logging controls (AI system operation & event recording)** | Operate the AI management system with control, including recording of AI system operation events. *(Exact Annex A control number is version-dependent — verify against the published standard.)* | Autonomous AI actions are recorded as signed receipts during operation; `details` capture operation specifics. The live platform emits `iso_42001` mappings such as `8.4` and `9.1` on receipts. |

> Framework subcategory statements are summarized. Verifiers/assessors **SHOULD** confirm
> exact clause wording against the authoritative source documents (see §16).

---

## 11. Relationship to draft-sharif-agent-audit-trail

**Referenced draft:** *Agent Audit Trail (AAT): A Standard Logging Format for Autonomous
AI Systems*, `draft-sharif-agent-audit-trail-00` (IETF Internet-Draft). Per its datatracker
record it **expires 2026-09-29**; as an Internet-Draft it is a work in progress and may be
revised, replaced, or allowed to lapse. The comparison below is based on the published
`-00` version and this standard's own live behavior.

### 11.1 Where ProofLink ALIGNS with the draft

Both specifications target the same problem — a **standard, tamper-evident audit trail for
autonomous AI agent actions** — and share the core architecture:

- **JSON records per action.** AAT (Section 3.1) defines mandatory per-action fields
  (`record_id`, `timestamp`, `agent_id`, `agent_version`, `session_id`, `action_type`,
  `action_detail`, `outcome`, `trust_level`, `parent_record_id`, `prev_hash`). ProofLink's
  required fields (§2) cover the same concepts: `id` ↔ `record_id`, `timestamp` ↔
  `timestamp` (both RFC 3339 UTC), `actor` ↔ `agent_id`, `action`/`category` ↔
  `action_type`, `details` ↔ `action_detail`, `outcome` ↔ `outcome`.
- **SHA-256 hash chaining.** Both link each record to its predecessor via a SHA-256 hash
  of the previous record, with the genesis record using a null/empty `prev_hash`
  (AAT Section 4.1 / 6.1; ProofLink §4). Both treat the chain as tamper-evident.
- **Optional cryptographic signatures for non-repudiation** (AAT Section 4.2; ProofLink
  §5 — mandatory in ProofLink v3).
- **Regulatory alignment.** Both map to EU AI Act Article 12, SOC 2, and ISO/IEC 42001
  (AAT Section 9; ProofLink §10).

### 11.2 Where ProofLink EXTENDS / DIFFERS from the draft

- **Canonicalization.** AAT (Section 4.1) mandates **RFC 8785 JCS** for canonicalization.
  ProofLink uses the deterministic Python `json.dumps(sort_keys, separators, ensure_ascii=
  False)` profile (§3), **not** JCS. This is a concrete, deployed profile but is *not*
  wire-compatible with an AAT/JCS verifier; a bridge would need to re-canonicalize.
- **Signature algorithm.** AAT specifies **ECDSA P-256** (FIPS 186-5), IEEE P1363 r||s,
  Base64url. ProofLink uses **Ed25519**, hex-encoded, signing the raw canonical bytes.
  These are not interchangeable.
- **Bitcoin / OpenTimestamps anchoring.** ProofLink adds an external, trust-minimized
  timestamping layer (§6) anchoring receipt hashes into Bitcoin block headers via OTS —
  a mechanism not present in the AAT draft. This provides existence-by-time provable
  without trusting either the agent or iTechSmart.
- **Compliance tagging inside the signed payload.** ProofLink's `compliance_tags` (§7.1)
  and structured `compliance_mappings` bind control claims *cryptographically* to the
  action, so the compliance assertion cannot be altered after the fact.
- **Supersession semantics.** ProofLink's forward-only `supersedes` with read-time reverse
  linkage (§7.2) provides a provable correction trail without history rewrite — a concrete
  mechanism beyond the draft's record model.
- **Learning receipts.** ProofLink's `learned_from` (§7.3) cryptographically binds a
  model/policy change to the receipts that informed it, closing an auditable LEARN loop.
- **Public real-time transparency service.** ProofLink exposes a live public verification
  and export API (`verify.itechsmart.dev`) with an embedded public key on every receipt.

### 11.3 Honesty note

This cross-reference reflects the `-00` draft as retrieved from the IETF datatracker and
summarized at the field/section level. Exact draft field semantics and section numbering
**should be re-confirmed against the current datatracker version** before relying on this
comparison, since Internet-Drafts change and this one may be superseded before its
2026-09-29 expiry. Where the draft's precise wording could not be independently reproduced
here, the alignment is described at the conceptual level (agent-action audit trails) rather
than asserted as an exact clause-by-clause equivalence.

---

## 12. Legacy Eras (v1 / v2)

Earlier receipts are preserved **unmodified** in the ledger (no history rewrite). They
predate the v3 hardening and are documented as legacy / non-conformant-but-preserved. This
Standard (edition v3.0) normatively specifies the **v3** format only.

- **v2 (`schema_version` `"2.0"`).** `canonical_bytes` = hex canonical JSON of all fields
  **except** `canonical_bytes`, `signature`, **and `receiver_attestation`**. The
  `hash_sha256` was computed over a pre-signing snapshot and is **NOT** recomputable from
  the stored receipt (so §9 step 1 does not hold for v2). `prev_hash` was **NOT** covered
  by the signature. Treat v2 signatures as authenticity of the signed payload only; chain
  linkage is not cryptographically bound.
- **v1 (`schema_version` absent).** Unsigned. `hash_sha256` was computed over a pre-storage
  snapshot and is not recomputable from stored data. `prev_hash` is a pointer only.

Verifiers **MUST NOT** apply the v3 algorithm (§9) to v1/v2 receipts as a conformance test;
these are outside the normative scope of this standard.

---

## 13. Conformance Requirements

### 13.1 Conformant Producer

A conformant producer **MUST**:

1. Emit all REQUIRED fields of §2 with `schema_version` `"3.0"`.
2. Compute `canonical_bytes` exactly per §3 (full payload minus the three computed fields;
   `sort_keys=True`, `separators=(",",":")`, `ensure_ascii=False`, UTF-8) and store it hex.
3. Set `hash_sha256 = SHA256(canonical_bytes)` (lowercase hex).
4. Sign the **raw** `canonical_bytes` with Ed25519 and populate the `signature` object,
   embedding the 32-byte public key.
5. Set `prev_hash` to the previous entry's `hash_sha256` (`""` for genesis) and a monotonic
   `chain_position`, both inside the payload.
6. Treat any optional/arbitrary fields as ordinary payload (no exclusion from
   `canonical_bytes` other than the three computed fields).

A conformant producer **SHOULD** submit the receipt hash to OpenTimestamps (non-blocking)
and **MUST NOT** mark a receipt `bitcoin_anchored` without confirmed block inclusion.
Producers **MUST NOT** mutate previously sealed receipts (forward-only corrections via
`supersedes`).

### 13.2 Conformant Verifier

A conformant verifier **MUST** perform the four checks of §9:

1. **Hash integrity** — `SHA256(canonical_bytes) == hash_sha256`.
2. **Canonical re-derivation** — re-derived canonical bytes equal the stored bytes.
3. **Ed25519 signature** — signature verifies over the raw canonical bytes with the
   embedded public key (which it **SHOULD** cross-check against the published key/fingerprint
   of §5).
4. **Chain link** — when a previous entry hash is available, `prev_hash` equals it.

A verifier **MAY** additionally validate OTS/Bitcoin anchoring via `/api/anchors`, a block
explorer, or opentimestamps.org.

---

## 14. Versioning & Change Policy

- **Standard edition tracks the receipt-format generation.** The version number of *this
  Standard document* is deliberately aligned with the receipt `schema_version` generation it
  normatively specifies. This is edition **v3.0** because it specifies receipt format **v3**
  (`schema_version` `"3.0"`), which is also the current live format. Edition v3.0 is the
  **first published edition** of the Standard: formats v1 and v2 existed as deployed receipt
  eras (§12) but were never published as a standalone standard, so there is no published
  "Standard v1" or "Standard v2" document — the edition numbering starts at the generation
  it first documents. A future receipt-format generation (a `schema_version` `"4.0"`) would
  be specified by a **Standard edition v4.0**; the edition minor version (e.g. v3.1) is used
  for editorial or additive clarifications that do not change the signed field set,
  canonicalization, hash construction, or signature algorithm.
- **Additive and forward-only.** New fields are introduced as optional additive fields
  (present only when set, absent by default), each an ordinary payload field covered by the
  hash and signature with no special verifier handling. Existing receipts remain valid and
  verify unchanged.
- **No history rewrite.** Sealed receipts are never mutated. Corrections are expressed by a
  *new* receipt that `supersedes` the old one; the old receipt's hash, signature, and chain
  position are preserved.
- **Schema version bumps.** A change that alters canonicalization, the signed field set,
  the hash construction, or the signature algorithm **MUST** bump `schema_version` and be
  documented as a new era (as formats v1→v2→v3 were). Such a bump **MUST** be accompanied by
  a new **Standard edition** at the matching major version (a `schema_version` `"4.0"` format
  is specified by Standard edition v4.0). Verifiers select the algorithm by `schema_version`.
- **Reverse/derived links** (e.g. `superseded_by`) are computed at read time and returned
  **outside** the signed payload, so they never affect re-derivation.

---

## 15. Appendix A: Worked Example

The following is a **real, live v3 receipt** exported from the public ledger via
`GET https://verify.itechsmart.dev/api/export?from=79430&to=79436`. It is a `security`
category receipt (chain position 79435) that carries `compliance_tags`. The
`canonical_bytes` hex is truncated with `…` for readability — the full value is available
from the export endpoint.

```json
{
  "id": "0752fedd1ba00df7",
  "timestamp": "2026-07-02T03:47:47.509484+00:00",
  "category": "security",
  "subject": "Iteksmart/itechsmart-ag2 ag2 agent Ed25519 keypairs",
  "action": "rotate_leaked_keys",
  "actor": "hermes-agent:security-remediation",
  "outcome": "rotated 7 ag2 keypairs; removed private keys from repo; sign/verify roundtrip PASS; container healthy; scrubbed studio+suite working trees (local-only)",
  "details": {
    "rotated_agents": ["IncidentDetector", "DigitalTwinAnalyst", "RemediationPlanner",
                       "SecurityGatekeeper", "ExecutionAgent", "ProofLinkNotary", "HumanArbiter"],
    "roundtrip": "PASS (7/7, fingerprint==manifest, tamper rejected)",
    "container": "itechsmart-ag2 restarted -> healthy",
    "ledger_key_untouched": true
  },
  "compliance_tags": ["NIST 800-53 IA-5", "NIST 800-53 SA-15", "OWASP A07:2021"],
  "human_input": false,
  "auto_resolved": true,
  "tamper_detected": false,
  "schema_version": "3.0",
  "prev_hash": "4f6a0d5aed5b0f283eb989178b1d216816735917f6a02e702412d2f4ea368ae6",
  "chain_position": 79435,
  "canonical_bytes": "7b225f61737161765f6d6f6465223a22636c6f7564222c…227665726966795f75726c223a22227d",
  "hash_sha256": "39a712cf57e9707984c366e88fe5d66afcf20039f316bf0d61139d2aaaa837c1",
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "21102eaa68ea9ed42c05a2253aa953d33c59b5348ff8659018146e59fb061b97",
    "value": "6ffe23b960844b3ab321a181a9bca39c80f4af06fc4c6967eb9d4e64b0dce50c4f1f166b4c39ba234ca3ff98f800758e11d0558e35758c5c92b75d1d7fca7707",
    "signs": "canonical_bytes"
  }
}
```

*(The live receipt also carries additional platform fields — `verify_url`, `vc_context`,
`vc_type`, `compliance_mappings`, `scitt_compatible`, `transparency_log`,
`receiver_attestation`, and internal `_asqav_*` markers — omitted above for brevity. Per
§2.3 they are all inside `canonical_bytes` and covered by the hash and signature.)*

### Walking the four verification steps

This receipt was verified end-to-end with the reference verifier of §9.1 (all four checks
pass):

1. **Hash integrity.** Decode `canonical_bytes` from hex to raw bytes, compute
   `SHA256(...)`, and confirm it equals
   `hash_sha256 = 39a712cf57e9707984c366e88fe5d66afcf20039f316bf0d61139d2aaaa837c1`. ✅
   (The decoded bytes begin `{"_asqav_mode":"cloud","_asqav_sig":"sig_1DxDhfBP-_LOODp6LcS…`,
   confirming keys are sorted lexicographically and `_asqav_*` fields sort first.)
2. **Canonical re-derivation.** Strip the three computed fields
   (`canonical_bytes`, `signature`, `hash_sha256`) from the receipt, re-encode the
   remaining payload with `json.dumps(payload, sort_keys=True, separators=(",",":"),
   ensure_ascii=False).encode("utf-8")`, and confirm the result is byte-identical to the
   decoded `canonical_bytes`. Because `compliance_tags`, `prev_hash`, `chain_position`,
   `details`, etc. are all in the payload, any tampering with them (including altering a
   compliance tag) fails this step. ✅
3. **Ed25519 signature.** Load the public key
   `21102eaa…fb061b97` and verify `signature.value`
   (`6ffe23b9…fca7707`) over the raw canonical bytes. Verification succeeds. ✅
   (The embedded public key matches the published key and fingerprint of §5.)
4. **Chain link.** The immediately preceding export entry (chain position 79434) has
   `hash_sha256 = 4f6a0d5aed5b0f283eb989178b1d216816735917f6a02e702412d2f4ea368ae6`, which
   equals this receipt's `prev_hash`. ✅

All four checks pass → the receipt is verified: its content is intact, it was signed by the
ProofLink key, and it is correctly linked into the chain. Optionally, its hash can be
checked against OpenTimestamps / Bitcoin via `/api/anchors` once anchored.

---

## 16. References

- **[RFC 2119]** Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, 1997.
- **[RFC 8174]** Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, 2017.
- **[RFC 3339]** Klyne, G., Newman, C., "Date and Time on the Internet: Timestamps", RFC 3339, 2002.
- **[RFC 8785]** Rundgren, A., et al., "JSON Canonicalization Scheme (JCS)", RFC 8785, 2020.
- **draft-sharif-agent-audit-trail-00** — "Agent Audit Trail (AAT): A Standard Logging Format for Autonomous AI Systems", IETF Internet-Draft (expires 2026-09-29). https://datatracker.ietf.org/doc/html/draft-sharif-agent-audit-trail-00
- **EU AI Act** — Regulation (EU) 2024/1689, Article 12 (Record-keeping).
- **NIST AI RMF 1.0** — NIST AI 100-1, Artificial Intelligence Risk Management Framework, and the AI RMF Playbook (Measure / Manage functions).
- **CMMC Level 2** — CMMC Assessment Guide Level 2 (v2.0), Audit & Accountability (AU) practices AU.L2-3.3.1, AU.L2-3.3.2, AU.L2-3.3.8.
- **SOC 2** — AICPA Trust Services Criteria (Common Criteria CC4.x, CC7.2, CC7.3, CC8.1).
- **ISO/IEC 42001:2023** — Information technology — Artificial intelligence — Management system (Clause 8 Operation, Clause 9.1 Monitoring/measurement, Annex A controls).
- **OpenTimestamps** — https://opentimestamps.org
- **Live ProofLink verification spec** — https://verify.itechsmart.dev/api/how-to-verify

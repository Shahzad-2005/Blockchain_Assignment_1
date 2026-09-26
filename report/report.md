# Single-Zone IIoT Decentralized Identity Management Framework

**Course:** Blockchain & Cryptography — Assignment 1
**Team:** Muhammad Shahzaib, Lutfan Shahzad
**Date:** September 2026

---

## 1. System Architecture

### 1.1 Overview

We implement a single-zone IIoT identity-management framework consisting of
one fog node and multiple simulated IIoT devices. The fog node handles all
computationally intensive cryptographic operations — DID resolution, batch
aggregation, Merkle tree construction, proof generation, token issuance,
and verification — while devices only perform lightweight hashing and
signing. This mirrors the fog-assisted model from Asim et al. (2026),
where heavy coordination is kept off resource-constrained devices.

### 1.2 Components

| Component | Role |
|---|---|
| **IIoT device (simulated)** | Generates DID + ECC keypair, signs PoP challenges, requests tokens, submits proofs |
| **Fog node (Flask)** | Authenticates devices, forms batches, builds Merkle trees, anchors roots, issues tokens, verifies requests, enforces policy, manages revocation |
| **Root registry (hash-chain)** | Append-only local ledger simulating blockchain anchoring of epoch roots |
| **Policy module** | Role → resource → allowed-operations map |
| **Attack suite** | Four scripts demonstrating replay, tampering, theft, and revocation checks |
| **Benchmark + plotter** | Measures scalability and produces three required graphs |

### 1.3 Data Flow

```
   Device                    Fog Node                  Root Registry
   (P-256)                   (Flask)                   (hash chain)
      |                         |                            |
      |--- PSK auth ----------->|                            |
      |--- PoP signature ------>|                            |
      |--- DID + PK + metadata->|                            |
      |                         |                            |
      |                         |--- sort + build tree       |
      |                         |--- anchor root ----------->|
      |<-- token + proof path --|                            |
      |                         |                            |
      |--- resource request --->|                            |
      |    (proof + token       |--- verify proof            |
      |     + fresh signature)  |--- check token/revocation  |
      |                         |--- apply policy            |
      |<-- ALLOW / DENY --------|                            |
```

Flow summary:
1. Device authenticates via PSK, proves key ownership via PoP.
2. Fog collects leaves into a batch, builds one Merkle tree, anchors the root.
3. Fog issues a temporary token and (later) a Merkle inclusion proof.
4. Device sends a resource request with proof + token + fresh signature.
5. Fog verifies membership, token validity, revocation status, and policy → ALLOW/DENY.

### 1.4 Trust model

- **Devices** are untrusted until they complete PSK bootstrap + proof-of-possession.
- **Fog node** is trusted for this assignment (single zone). Multi-fog trust is deferred to Assignment 2.
- **Root registry** is append-only and provides the same integrity guarantee as a permissioned blockchain: the anchored root cannot be retroactively altered.
- **Private keys never leave devices.** The fog only ever sees public keys and signatures.

### 1.5 Design choices and rationale

| Choice | Why |
|---|---|
| ECDSA P-256 | 256-bit security with compact keys, widely supported on ESP32-class hardware |
| SHA-256 for leaves and node hashes | Standard, fast, collision-resistant |
| Regular Merkle tree (not SMT) | Sufficient for membership proofs in a single zone; SMT deferred to Assignment 2 |
| Batch registration per epoch | Amortizes tree construction and anchoring cost across many devices |
| Temporary tokens | Bridges devices that join mid-epoch, before their permanent proof exists |
| Self-signed TLS (demo) | Protects the device↔fog channel in the assignment's scope |
| In-memory state + hash-chain registry | Simple, transparent, and easily auditable during the demo |

---

## 2. Technologies and Cryptographic Primitives

### 2.1 Stack

| Layer | Technology |
|---|---|
| Language | Python 3.14 |
| Fog server | Flask 2.3.3 |
| Transport | HTTPS via self-signed certificate (TLS 1.3) |
| Crypto library | `cryptography` (ECDSA, RSA, X.509) |
| Hashing | `hashlib` (SHA-256) |
| State | In-memory dicts + append-only JSON-style hash chain |
| Graphs | `matplotlib` |
| HTTP client | `requests` + `urllib3` |

### 2.2 Cryptographic primitives

| Primitive | Where used | Why |
|---|---|---|
| **ECDSA P-256 (secp256r1)** | Device identity keys, fog signing key | 128-bit security with compact 64-byte signatures; widely supported on constrained hardware |
| **SHA-256** | Leaf hash `Ld = H(DID‖PK)`, internal Merkle nodes, anchor hash | Collision-resistant, fast, standard |
| **Canonical serialization** | `DID || "|" || PK` before hashing | Prevents same input producing different leaves across implementations |
| **Fresh nonces** | PoP challenge, resource request | Replay protection |
| **Nonce blacklist** | `USED_NONCES`, `USED_REQUEST_NONCES` | Detects reused nonces |
| **Fog-signed tokens** | Temporary tokens (Phase 2) | Binds identity + expiry to fog's authority |
| **Hash-chained root registry** | Epoch anchor records | Simulates blockchain immutability: each anchor links to the previous |

### 2.3 Why these choices

- **ECDSA over RSA:** smaller keys, faster signing, better for IIoT hardware (ESP32, Raspberry Pi).
- **SHA-256 over SHA-3:** universally supported, faster on most platforms, still collision-resistant.
- **Regular Merkle tree over SMT:** single-zone membership proofs are sufficient here; SMT adds non-membership support we don't need yet.
- **Hash-chain over real blockchain:** demonstrates the anchoring + immutability property without the operational overhead; full blockchain integration is out of scope for Assignment 1.
- **Self-signed TLS:** satisfies the "protected connection" requirement without needing a CA; production deployment would use a managed certificate.

---

## 3. Phase 1 — Registration and Batch Formation

### 3.1 Device onboarding sequence

Each device follows this sequence:

1. **PSK authentication** — device POSTs `/register/start` with a shared key. Fog returns a `session_id`.
2. **DID + keypair generation** — device creates `did:iiot:<name>` and an ECDSA P-256 keypair locally. Private key never leaves the device.
3. **Public key submission** — device POSTs `/register/challenge` with `session_id` + `pk_hex`. Fog validates the key format and returns a fresh 32-byte nonce.
4. **Proof-of-possession** — device signs the nonce with its private key and POSTs `/register/complete` with `did`, `pk_hex`, `nonce_hex`, `signature_hex`, and metadata.
5. **Fog verification** — fog checks: session valid, nonce not expired (60 s TTL), nonce matches issued value, nonce unused, public key matches session, ECDSA signature valid.
6. **Leaf creation** — `Ld = SHA256(DID || "|" || PK_hex)` with canonical serialization.
7. **Batch append** — leaf added to `CURRENT_BATCH`. No tree rebuild yet.

### 3.2 Why proof-of-possession matters

Copying a DID and public key is trivial. Without PoP, an attacker could register any device's claimed identity. PoP forces the requester to sign a **fresh, fog-generated nonce** with the private key matching the claimed public key. Fresh nonces also block replay of an old valid signature.

### 3.3 Batch finalization (`/batch/finalize`)

At the end of a registration window:

1. Collect all leaves from `CURRENT_BATCH`.
2. Sort deterministically (bytewise) — every honest verifier must arrive at the same tree.
3. Build the Merkle tree once → single root.
4. Anchor root in an append-only hash chain:
   ```
   anchor_hash = SHA256(epoch || root || timestamp || prev_hash)
   ```
5. Generate an inclusion proof for every registered device.
6. Sign each proof package: `Sign_Fog(leaf || root || epoch)`.
7. Increment epoch, clear batch.

### 3.4 Proof package structure

```
{
  "did": "did:iiot:temp-101",
  "leaf_hex": "...",
  "epoch": 27,
  "root_hex": "...",
  "proof": [ ["L"|"R", sibling_hex], ... ],
  "fog_signature_hex": "..."
}
```

The device stores this locally and reuses it indefinitely — the epoch root is frozen.

### 3.5 Why batching

Without batching, every new device forces a tree rebuild and a new root. Existing proofs become stale because their sibling hashes change. With batching, one root is anchored per epoch and all proofs remain valid for that epoch. Section 9 quantifies the savings.

---

## 4. Phase 2 — Temporary Token Bridging

### 4.1 The problem

A device that registers mid-epoch has no Merkle proof yet — the batch isn't finalized. Without any credential, it can't operate for the remainder of the epoch (up to hours in production). Blocking it defeats the purpose of "connect and work."

### 4.2 Solution: short-lived signed token

After PoP succeeds, the fog issues a token signed with the fog's private key:

```
Issue(d) = DID || PK || scope || issued_at || expires_at || token_id
τ_d = Sign_Fog( Issue(d) )
```

For the demo, TTL is 300 seconds. In production, tokens would live until the epoch closes.

The device receives the token and can now request **limited/provisional** access while waiting for permanent inclusion.

### 4.3 Token validation on every request

The fog rejects a request unless **all** of these pass:

| Check | Detects |
|---|---|
| Token exists in `TOKENS` | Forged or unknown token |
| Token signature valid | Tampering with DID, PK, or expiry |
| `now < expires_at` | Expired token |
| `token_id ∉ REVOCATIONS` | Explicitly revoked token |
| `token.did == request.did` and `token.pk == request.pk` | Token used on wrong device |

### 4.4 Fresh proof-of-possession per request

A stolen token is still not enough. Every resource request includes:

- A **fresh nonce** generated by the device (not the fog).
- A **signature** over `nonce || resource || operation` using the device's private key.

The fog verifies this signature against the registered public key. Replay is blocked by a `USED_REQUEST_NONCES` set. Changing the resource, operation, or nonce invalidates the signature.

This converts the token from a **bearer credential** ("whoever has it can use it") into a **proof-of-possession credential** ("whoever holds the private key can use it").

### 4.5 Transition to permanent state

Once the epoch closes and the batch is finalized:

1. The device's leaf is in the anchored root.
2. The fog issues the device its proof package.
3. Subsequent requests use the proof (Phase 3) instead of the temporary token.
4. The temporary token remains valid until its expiry but is no longer the primary credential.

---

## 5. Phase 3 — Verification and Resource Authorization

### 5.1 The distinction that matters

- **Verification** answers: *was this DID + PK registered in a trusted epoch?*
- **Authorization** answers: *may this device perform this operation right now?*

A device can pass verification but fail authorization. The assignment's minimum example — a temperature sensor that may WRITE readings but must not STOP a production line — is exactly this case.

### 5.2 Verification pipeline

For each resource request the fog performs:

| Step | Action | Failure reason |
|---|---|---|
| 1 | Resolve root from `ANCHORED_ROOTS[epoch]` | unknown epoch |
| 2 | Recompute leaf `Ld = SHA256(DID‖PK)` | — |
| 3 | Verify Merkle proof: rebuilt root == anchored root | proof invalid |
| 4 | Validate token (signature, expiry, revocation, DID/PK match) | token errors |
| 5 | Check request nonce not in `USED_REQUEST_NONCES` | nonce reused |
| 6 | Verify request signature `Sign_SKd(nonce‖resource‖operation)` | request signature invalid |
| 7 | Apply role policy | policy denial |

Every check must pass for **ALLOW**.

### 5.3 Access-control policy

Policy is a two-level map, `role → resource → [allowed operations]`:

```python
POLICY = {
    "temperature-sensor": {"temperature":      ["WRITE", "READ"]},
    "pressure-sensor":    {"pressure":         ["WRITE", "READ"]},
    "valve-controller":   {"valve":            ["WRITE", "READ"],
                            "production-line": ["STOP"]},
    "camera":             {"stream":           ["READ"]},
}
```

A camera attempting `WRITE stream` is rejected even though its identity is valid. This is the identity ≠ authorization demonstration.

### 5.4 Request payload

```json
{
  "did": "did:iiot:temp-101",
  "pk_hex": "...",
  "epoch": 27,
  "proof": [["L","..."], ["R","..."]],
  "token_id": "...",
  "resource": "temperature",
  "operation": "WRITE",
  "nonce": "<fresh>",
  "request_sig": "<Sign_SKd(nonce || resource || operation)>"
}
```

---

## 6. Revocation

### 6.1 Two-layer model

| Layer | Latency | Scope |
|---|---|---|
| **Local block** | Immediate | `REVOCATIONS` set on fog; token rejected on next request |
| **Epoch exclusion** | Next epoch | Device skipped from future batch and root |

The old anchored root is **never modified** — historic proofs remain mathematically verifiable. Access is controlled by the current revocation state, not by rewriting history.

### 6.2 Why two layers

Immediate access must not wait for the next epoch boundary (which could be hours). Conversely, an old proof will always be valid against its historic root — so exclusion from future roots alone isn't enough for immediate response. Both layers are needed.

### 6.3 Demonstration

```
before revoke  -> ALLOW
revoke called  -> OK
after revoke   -> DENY  (reason: token revoked)
```

Any device that appears in `REVOKED_DEVICES` is skipped when the next `/batch/finalize` builds the tree.

---

## 7. Security Attacks

Four attacks implemented in `attacks/attacks.py`. Each demonstrates the setup, detection point, and rejection reason.

### 7.1 Replay of exact request

- **Setup:** capture a valid request (same nonce, same signature) and resend verbatim.
- **Detection:** fog's nonce validator (`USED_REQUEST_NONCES`).
- **Result:** `DENY — nonce reused`.
- **Why:** fresh nonces are single-use and cannot be reused even within the token's validity window.

### 7.2 Tampered Merkle proof

- **Setup:** flip one bit in a sibling hash inside the proof path.
- **Detection:** Merkle proof verifier — recomputed root ≠ anchored root.
- **Result:** `DENY — proof invalid`.
- **Why:** SHA-256 collision resistance means a single bit change alters the entire path to the root.

### 7.3 Stolen valid token

- **Setup:** attacker obtains `token_id`, `did`, `pk_hex`, and a valid proof — but not the private key.
- **Detection:** request proof-of-possession signature check.
- **Result:** `DENY — request signature invalid`.
- **Why:** the token is device-bound and nonce-protected. Without the private key, the attacker cannot sign the fresh challenge.

### 7.4 Revoked token reuse

- **Setup:** legitimate token used after explicit revocation.
- **Detection:** `REVOCATIONS` check.
- **Result:** `DENY — token revoked`.
- **Why:** revocation overrides valid signatures and unexpired tokens.

### 7.5 Summary table

| Attack | Detected by | Result |
|---|---|---|
| Replay | Nonce blacklist | DENY |
| Tampered proof | Merkle verification | DENY |
| Stolen token | Proof-of-possession | DENY |
| Revoked token | Revocation list | DENY |

---

## 8. Performance Evaluation

### 8.1 Methodology

- Device counts: **5, 10, 25, 50, 100**
- Runs per count: **5**
- Fog state reset (`/reset`) between runs to eliminate warm-cache bias
- Timings captured client-side with `time.perf_counter()` (microsecond precision)
- Metrics: registration latency, batch processing time, proof generation, verification latency, throughput

### 8.2 Results

| Metric | n=5 | n=100 | Trend |
|---|---|---|---|
| Avg registration (ms) | ~20 | ~16 | Flat |
| Batch processing (ms) | ~7 | ~15 | Rises with n |
| Verification (ms) | ~7 | ~5 | Flat |
| Throughput (reg/s) | ~48 | ~62 | Slight rise then plateau |

### 8.3 Interpretation

- **Registration is per-device constant** — each device's onboarding cost is independent of total population.
- **Batch time grows with n** — expected: tree construction is O(n) node hashes for a balanced tree, with sorting O(n log n). n=100 stays under 20 ms.
- **Verification stays flat** — proof path length is O(log n), so verification cost barely changes from n=5 to n=100.
- **Throughput plateaus** — after initial warm-up, the fog processes ~60 registrations/second.

### 8.4 Required graphs

Three graphs are produced by `perf/plot.py` from `data/perf_results.csv`:

1. Number of devices vs batch registration time — monotonic rise
2. Number of devices vs verification latency — flat
3. Number of devices vs registration throughput — rise then plateau

*(Graphs embedded in Section 10.)*

---

## 9. Batch vs Individual Registration

### 9.1 The problem with per-device updates

If each new device triggers a tree rebuild:

- **N root updates** per batch (one per device arrival).
- Every arrival can invalidate existing sibling hashes on other devices' proof paths.
- Over N devices, up to **N(N−1)/2 stale proofs** require redistribution.
- Each root update implies a new blockchain/registry anchor.

### 9.2 Measured comparison

`perf/batch_vs_individual.py` builds the tree **twice** for each n: once incrementally (rebuild after each device), once as a single batch.

| n | Individual (ms) | Batch (ms) | Speedup | Root updates (indiv) | Stale proofs (indiv) |
|---|---|---|---|---|---|
| 5 | 0.0 | 0.0 | 1.6× | 5 | 10 |
| 10 | 0.2 | 0.1 | 3.3× | 10 | 45 |
| 25 | 1.0 | 0.1 | 9.4× | 25 | 300 |
| 50 | 2.1 | 0.2 | 11.6× | 50 | 1,225 |
| 100 | 5.7 | 0.3 | 19.6× | 100 | 4,950 |
| 200 | 24.4 | 0.7 | 34.3× | 200 | 19,900 |

### 9.3 Conclusion

Batch registration delivers:

- **Sub-linear cost growth** in tree construction.
- **One root per epoch** instead of N.
- **Zero proof churn** within a batch — every device shares the same epoch snapshot.

The saving grows with N — exactly the property a scalable IIoT identity system requires.

---

## 10. Demo Screenshots and Logs

### 10.1 Fog node startup (HTTPS)

![Fog startup](screenshots/01_fog_https.png)

The fog node runs on `https://127.0.0.1:5000` with a self-signed TLS certificate. All device↔fog traffic is encrypted in transit.

### 10.2 Device registration

![Registration](screenshots/02_registration.png)

Five simulated devices with mixed roles (temperature sensor, pressure sensor, valve controller, camera) register sequentially. Each device proves PSK authentication, generates a DID + ECC keypair, and completes a PoP challenge.

### 10.3 Batch finalization and proof verification

![Batch and proof](screenshots/03_batch_proof.png)

Four devices registered; batch finalized; one root anchored in the hash chain. A proof path of length 2 was generated for `dev-001` and verified locally — the recomputed root matched the anchored root.

### 10.4 Verification: ALLOW and DENY

![Verify](screenshots/04_verify_allow_deny.png)

- `WRITE temperature` → **ALLOW** (policy permits temperature-sensors to write temperature).
- `STOP production-line` → **DENY** (policy forbids the operation even though identity is valid).

This screenshot shows the core identity ≠ authorization distinction.

### 10.5 Revocation

![Revoke](screenshots/05_revoke.png)

Before revocation: ALLOW. After `/revoke`: same token produces **DENY — token revoked**. Historical proofs remain valid; current access state changes immediately.

### 10.6 Security attacks

![Attacks](screenshots/06_attacks.png)

All four attacks blocked:
- Replay → DENY (nonce reused)
- Tampered proof → DENY (proof invalid)
- Stolen token → DENY (request signature invalid)
- Revoked token → DENY (token revoked)

### 10.7 Performance benchmark

![Benchmark](screenshots/07_benchmark.png)

Benchmark across 5, 10, 25, 50, 100 devices with 5 runs each. Registration stays flat; batch time rises; verification stays flat.

### 10.8 Scalability graph

![Batch graph](screenshots/08_graph_batch.png)

Batch time rises monotonically with N (expected), while verification latency remains flat (Section 8). Full graphs and raw data are in `data/`.

---

## 11. Problems Encountered and Design Decisions

### 11.1 Problems

| Problem | Resolution |
|---|---|
| Self-signed TLS cert caused `CERTIFICATE_VERIFY_FAILED` in clients | Added a `Session.request` monkey-patch in each client to disable cert verification (demo only; production uses proper CA-signed certs) |
| Flask CLI (`flask run`) ignores `ssl_context` | Switched to `python -m fog.server` to trigger the `__main__` block that configures TLS |
| Benchmark runs accumulated fog state → wrong trends | Added `/reset` endpoint; benchmark resets state before each run |
| Tampered-proof attack crashed on single-device trees (empty proof path) | Register 4 filler devices in the attack setup so the victim has a real proof path |
| Odd number of leaves in Merkle tree | Duplicate last leaf (standard convention) |

### 11.2 Key design decisions

| Decision | Rationale |
|---|---|
| ECDSA P-256 (not RSA) | Smaller keys, faster, standard on IIoT hardware |
| Regular Merkle tree (not SMT) | Sufficient for membership proofs in a single zone; SMT reserved for Assignment 2 |
| Fresh nonces in **every** request | Replay protection at every step, not just initial auth |
| Two-layer revocation | Immediate local block + epoch exclusion: fast response plus long-term consistency |
| Hash-chain root registry | Demonstrates anchoring immutability without full blockchain overhead |
| Self-signed TLS | Satisfies the assignment's protected-connection requirement in a demo setting |

---

## 12. Contribution Table

| Student | Main components | Important files | Testing performed |
|---|---|---|---|
| **Lutfan Shahzad** | Crypto primitives, Merkle tree, fog server core (register, batch, verify, revoke), attacks, performance benchmark | `fog/crypto.py`, `fog/merkle.py`, `fog/models.py`, `fog/server.py`, `attacks/attacks.py`, `perf/benchmark.py` | Unit tests for crypto & Merkle; attack suite; scalability runs; batch-vs-individual comparison |
| **Shahzaibflash** | Device simulator, token module, access policy, TLS transport, README, plots, screenshots | `device/simulator.py`, `fog/policy.py`, `fog/token.py`, `fog/gen_cert.py`, `perf/plot.py`, `README.md` | Integration test of simulator; TLS handshake; policy decisions; graph generation; demo capture |

All code is available on GitHub with per-author commit history.
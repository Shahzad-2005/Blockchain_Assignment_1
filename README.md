# IIoT Decentralized Identity Management — Assignment 1

Single-zone IIoT identity framework: 1 fog node + simulated devices.
Implements batch registration → Merkle proofs → temporary tokens → verification → resource authorization → revocation → attacks → performance evaluation.

---

## 1. Prerequisites

- Python 3.10+ (tested on 3.14)
- pip packages:
```bash
pip install flask cryptography matplotlib requests urllib3
```
- Two terminal windows (one for the fog, one for clients)

---

## 2. Setup (one-time)

### 2.1 Generate the TLS certificate

```bash
cd iiot_idm
python -m fog.gen_cert
```
Creates `fog/cert.pem` and `fog/key.pem`. **Do not commit these.**

### 2.2 Verify installation

```bash
python -c "import flask, cryptography, matplotlib, requests; print('ok')"
```
Should print `ok`.

---

## 3. Running the system

### Step 1 — Start the fog node (Terminal 1)

```bash
cd iiot_idm
python -m fog.server
```

Wait for: `* Running on https://127.0.0.1:5000`

**Important:** must use `python -m fog.server`, not `flask run`. The Flask CLI ignores the TLS `ssl_context`.

**Leave this terminal open.** All client commands go in Terminal 2.

### Step 2 — Run the device simulator (Terminal 2)

Open a **new** PowerShell window:

```bash
cd iiot_idm
python -m device.simulator -n 5
```

Expected: 5 devices register, receive tokens, get proofs, and each prints ALLOW/DENY.

Change `5` to any device count (e.g., `-n 10`, `-n 25`).

### Step 3 — Run the security attacks

```bash
python -m attacks.attacks
```

Expected: four attacks all print `DENY` with distinct reasons (nonce reused, proof invalid, request signature invalid, token revoked).

### Step 4 — Run the performance benchmark

```bash
python -m perf.benchmark
```

Runs 5, 10, 25, 50, 100 devices × 5 runs each. Writes `data/perf_results.csv`. Takes 1–2 minutes.

### Step 5 — Generate the graphs

```bash
python -m perf.plot
```

Produces three PNGs in `data/`: `graph_batch.png`, `graph_verify.png`, `graph_throughput.png`.

### Step 6 — Batch vs individual comparison

```bash
python -m perf.batch_vs_individual
```

Prints a table showing batch registration is 34× faster at N=200.

---

## 4. Tests (optional, individual endpoints)

| Command | Tests |
|---|---|
| `python -m device.test_register` | Phase 1 registration only |
| `python -m device.test_batch` | Batch finalize + proof verification |
| `python -m device.test_token` | Temporary token issuance |
| `python -m device.test_verify` | ALLOW + DENY decisions |
| `python -m device.test_revoke` | Revocation |

All require the fog running in Terminal 1.

---

## 5. Stopping the system

In Terminal 1, press `Ctrl+C` to stop the fog.

---

## 6. Components

| Path | Purpose |
|---|---|
| `fog/crypto.py` | ECDSA keys, sign/verify, SHA-256 |
| `fog/merkle.py` | Merkle tree, proof generation + verification |
| `fog/models.py` | Dataclasses for identity, proof, token, revocation |
| `fog/policy.py` | Role → resource → allowed operations |
| `fog/token.py` | Temporary token issue + validate |
| `fog/server.py` | Flask endpoints + TLS config |
| `fog/gen_cert.py` | Self-signed certificate generator |
| `device/simulator.py` | Multi-device simulator |
| `attacks/attacks.py` | Four security attacks |
| `perf/benchmark.py` | Scalability benchmarks |
| `perf/plot.py` | Graph generation |
| `perf/batch_vs_individual.py` | Batch vs per-device comparison |

---

## 7. API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/register/start` | PSK check, open session |
| POST | `/register/challenge` | Issue PoP nonce |
| POST | `/register/complete` | Verify PoP, add to batch |
| POST | `/batch/finalize` | Build tree, anchor root, generate proofs |
| GET | `/proof/<did>` | Fetch proof package |
| POST | `/token/issue` | Issue temporary token |
| POST | `/resource/request` | Verify identity + token + policy |
| POST | `/revoke` | Revoke device / token |
| POST | `/reset` | Clear in-memory state |

---

## 8. Troubleshooting

| Error | Fix |
|---|---|
| `ConnectionRefusedError` | Fog is not running. Start Terminal 1. |
| `CERTIFICATE_VERIFY_FAILED` | Client isn't using the HTTPS patch. Confirm the 4-line session patch is at the top of the client file. |
| `flask run` doesn't use HTTPS | Use `python -m fog.server` instead. |
| Port 5000 in use | Stop the previous fog (`Ctrl+C`) or change the port in `fog/server.py`. |
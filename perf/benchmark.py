import time, csv, os, requests, statistics
from fog.crypto import generate_keypair, pubkey_to_hex, sign

FOG = "http://127.0.0.1:5000"
PSK = "zone-A-psk-2026"
DEVICE_COUNTS = [5, 10, 25, 50, 100]
RUNS = 5
OUT = "data/perf_results.csv"


def register(did, dtype="temperature-sensor"):
    t0 = time.perf_counter()
    sid = requests.post(f"{FOG}/register/start", json={"psk": PSK}).json()["session_id"]
    sk, pk = generate_keypair()
    pk_hex = pubkey_to_hex(pk)
    n = requests.post(f"{FOG}/register/challenge",
                      json={"session_id": sid, "pk_hex": pk_hex}).json()["nonce_hex"]
    sig = sign(sk, bytes.fromhex(n))
    requests.post(f"{FOG}/register/complete", json={
        "session_id": sid, "did": did, "pk_hex": pk_hex,
        "nonce_hex": n, "signature_hex": sig.hex(),
        "metadata": {"type": dtype}
    })
    return (time.perf_counter() - t0) * 1000, sk, pk_hex


def run_once(n):
    # reset fog state between runs (restart required externally for full reset;
    # here we just count from current)
    requests.post(f"{FOG}/reset")
    reg_times = []
    last = None
    for i in range(n):
        t, sk, pk_hex = register(f"did:iiot:perf-{n}-{i:04d}")
        reg_times.append(t)
        last = (sk, pk_hex)

    # batch processing
    t0 = time.perf_counter()
    fin = requests.post(f"{FOG}/batch/finalize").json()
    batch_ms = (time.perf_counter() - t0) * 1000
    epoch = fin["epoch_finalized"]

    # proof generation (fog side) — measure via proof fetch + verify locally
    did = f"did:iiot:perf-{n}-{n-1:04d}"
    t0 = time.perf_counter()
    pkg = requests.get(f"{FOG}/proof/{did}").json()["package"]
    proof_gen_ms = (time.perf_counter() - t0) * 1000

    sk, pk_hex = last
    token_id = requests.post(f"{FOG}/token/issue",
                             json={"did": did, "pk_hex": pk_hex}).json()["token"]["token_id"]

    # verification latency
    nonce = os.urandom(16).hex()
    sig = sign(sk, (nonce + "temperature" + "WRITE").encode()).hex()
    t0 = time.perf_counter()
    r = requests.post(f"{FOG}/resource/request", json={
        "did": did, "pk_hex": pk_hex, "epoch": epoch,
        "proof": pkg["proof"], "token_id": token_id,
        "resource": "temperature", "operation": "WRITE",
        "nonce": nonce, "request_sig": sig,
    }).json()
    verify_ms = (time.perf_counter() - t0) * 1000
    assert r.get("decision") == "ALLOW", r

    throughput = n / (sum(reg_times) / 1000)
    return {
        "n": n,
        "avg_registration_ms": statistics.mean(reg_times),
        "batch_ms": batch_ms,
        "proof_gen_ms": proof_gen_ms,
        "verify_ms": verify_ms,
        "throughput_reg_per_sec": throughput,
    }


def main():
    os.makedirs("data", exist_ok=True)
    rows = []
    for n in DEVICE_COUNTS:
        for run in range(RUNS):
            print(f"[n={n} run={run+1}/{RUNS}] ...", end=" ", flush=True)
            r = run_once(n)
            print(f"reg={r['avg_registration_ms']:.1f}ms "
                  f"batch={r['batch_ms']:.1f}ms "
                  f"verify={r['verify_ms']:.1f}ms")
            rows.append(r)

    with open(OUT, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys())
        w.writeheader()
        w.writerows(rows)
    print(f"\nSaved {len(rows)} rows to {OUT}")


if __name__ == "__main__":
    main()
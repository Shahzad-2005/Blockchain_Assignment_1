import requests
from fog.crypto import generate_keypair, pubkey_to_hex, sign
from fog.merkle import hash_leaf, verify_proof

FOG = "http://127.0.0.1:5000"
PSK = "zone-A-psk-2026"

def register(did):
    sid = requests.post(f"{FOG}/register/start", json={"psk": PSK}).json()["session_id"]
    sk, pk = generate_keypair()
    pk_hex = pubkey_to_hex(pk)
    n = requests.post(f"{FOG}/register/challenge",
                      json={"session_id": sid, "pk_hex": pk_hex}).json()["nonce_hex"]
    sig = sign(sk, bytes.fromhex(n))
    requests.post(f"{FOG}/register/complete", json={
        "session_id": sid, "did": did, "pk_hex": pk_hex,
        "nonce_hex": n, "signature_hex": sig.hex(),
        "metadata": {"type": "sensor"}
    })
    return pk_hex

if __name__ == "__main__":
    for i in range(4):
        register(f"did:iiot:dev-{i+1:03d}")

    r = requests.post(f"{FOG}/batch/finalize").json()
    print("Finalize:", r)

    # fetch proof for dev-001 and verify locally
    pkg = requests.get(f"{FOG}/proof/did:iiot:dev-001").json()["package"]
    leaf = bytes.fromhex(pkg["leaf_hex"])
    root = bytes.fromhex(pkg["root_hex"])
    proof = [(s, bytes.fromhex(h)) for s, h in pkg["proof"]]
    ok = verify_proof(leaf, proof, root)
    print("Local proof verify for dev-001:", ok)
    print("Proof path length:", len(proof))
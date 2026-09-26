import os, sys, requests
from fog.crypto import generate_keypair, pubkey_to_hex, sign

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_orig_sess_request = requests.Session.request
requests.Session.request = lambda self, *a, **kw: _orig_sess_request(
    self, *a, **{**kw, "verify": False})

FOG = "https://127.0.0.1:5000"
PSK = "zone-A-psk-2026"


def register(did, dtype):
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
    return sk, pk_hex


def make_request(sk, did, pk_hex, epoch, proof, token_id,
                 resource="temperature", operation="WRITE", nonce=None):
    nonce = nonce or os.urandom(16).hex()
    sig = sign(sk, (nonce + resource + operation).encode()).hex()
    return {
        "did": did, "pk_hex": pk_hex, "epoch": epoch,
        "proof": proof, "token_id": token_id,
        "resource": resource, "operation": operation,
        "nonce": nonce, "request_sig": sig,
    }


def send(payload):
    return requests.post(f"{FOG}/resource/request", json=payload).json()


def setup():
    # register filler devices so the tree has real proof paths
    for i in range(4):
        register(f"did:iiot:filler-{i+1:03d}", "temperature-sensor")

    did = "did:iiot:attack-victim"
    sk, pk_hex = register(did, "temperature-sensor")
    tok = requests.post(f"{FOG}/token/issue",
                        json={"did": did, "pk_hex": pk_hex}).json()["token"]
    token_id = tok["token_id"]
    fin = requests.post(f"{FOG}/batch/finalize").json()
    epoch = fin["epoch_finalized"]
    proof = requests.get(f"{FOG}/proof/{did}").json()["package"]["proof"]
    print(f"[setup] victim proof path length = {len(proof)}")
    return did, sk, pk_hex, epoch, proof, token_id


def attack_replay(did, sk, pk_hex, epoch, proof, token_id):
    print("\n=== ATTACK 1: Replay exact request ===")
    payload = make_request(sk, did, pk_hex, epoch, proof, token_id)
    print("  1st time :", send(payload))
    print("  Replayed :", send(payload))
    print("  Detected : fog nonce validator (USED_REQUEST_NONCES)")


def attack_tampered_proof(did, sk, pk_hex, epoch, proof, token_id):
    print("\n=== ATTACK 2: Tampered Merkle proof ===")
    bad_proof = [list(p) for p in proof]
    side, h = bad_proof[0]
    flipped = ('0' if h[0] != '0' else '1') + h[1:]
    bad_proof[0] = [side, flipped]
    payload = make_request(sk, did, pk_hex, epoch, bad_proof, token_id)
    print("  Result   :", send(payload))
    print("  Detected : Merkle proof verification (root mismatch)")


def attack_stolen_token(did, _sk, pk_hex, epoch, proof, token_id):
    print("\n=== ATTACK 3: Stolen valid token ===")
    attacker_sk, _ = generate_keypair()
    payload = make_request(attacker_sk, did, pk_hex, epoch, proof, token_id)
    print("  Result   :", send(payload))
    print("  Detected : request proof-of-possession (signature over nonce)")


def attack_revoked_token(did, sk, pk_hex, epoch, proof, token_id):
    print("\n=== ATTACK 4: Revoked token reuse ===")
    requests.post(f"{FOG}/revoke",
                  json={"did": did, "token_id": token_id, "reason": "attack demo"})
    payload = make_request(sk, did, pk_hex, epoch, proof, token_id)
    print("  Result   :", send(payload))
    print("  Detected : token revocation check")


if __name__ == "__main__":
    did, sk, pk_hex, epoch, proof, token_id = setup()
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which in ("all", "1"): attack_replay(did, sk, pk_hex, epoch, proof, token_id)
    if which in ("all", "2"): attack_tampered_proof(did, sk, pk_hex, epoch, proof, token_id)
    if which in ("all", "3"): attack_stolen_token(did, sk, pk_hex, epoch, proof, token_id)
    if which in ("all", "4"): attack_revoked_token(did, sk, pk_hex, epoch, proof, token_id)
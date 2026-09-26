import os, requests
from fog.crypto import generate_keypair, pubkey_to_hex, sign

FOG = "http://127.0.0.1:5000"
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

def req(sk, did, pk_hex, epoch, proof, token_id, resource, operation):
    nonce = os.urandom(16).hex()
    msg = (nonce + resource + operation).encode()
    sig = sign(sk, msg).hex()
    return requests.post(f"{FOG}/resource/request", json={
        "did": did, "pk_hex": pk_hex, "epoch": epoch,
        "proof": proof, "token_id": token_id,
        "resource": resource, "operation": operation,
        "nonce": nonce, "request_sig": sig,
    }).json()

if __name__ == "__main__":
    did = "did:iiot:temp-777"
    sk, pk_hex = register(did, "temperature-sensor")

    # temporary token
    tok = requests.post(f"{FOG}/token/issue",
                        json={"did": did, "pk_hex": pk_hex, "scope": "provisional"}).json()["token"]
    token_id = tok["token_id"]

    # finalize batch
    fin = requests.post(f"{FOG}/batch/finalize").json()
    epoch = fin["epoch_finalized"]

    # fetch proof package
    pkg = requests.get(f"{FOG}/proof/{did}").json()["package"]
    proof = pkg["proof"]

    # 1. allowed: WRITE temperature
    print("1) WRITE temperature ->", req(sk, did, pk_hex, epoch, proof, token_id, "temperature", "WRITE"))

    # 2. denied: STOP production-line
    print("2) STOP  production-line ->", req(sk, did, pk_hex, epoch, proof, token_id, "production-line", "STOP"))
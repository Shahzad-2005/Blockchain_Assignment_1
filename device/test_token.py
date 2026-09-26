import requests
from fog.crypto import generate_keypair, pubkey_to_hex, sign

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
        "metadata": {"type": "valve-controller"}
    })
    return pk_hex

if __name__ == "__main__":
    did = "did:iiot:valve-099"
    pk_hex = register(did)

    # request temporary token
    r = requests.post(f"{FOG}/token/issue",
                      json={"did": did, "pk_hex": pk_hex, "scope": "provisional"}).json()
    print("Token issued:", r["ok"])
    t = r["token"]
    print("Token ID:", t["token_id"])
    print("Expires in (s):", round(t["expires_at"] - t["issued_at"]))
    print("Scope:", t["scope"])
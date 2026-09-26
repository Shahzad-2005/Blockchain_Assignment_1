import requests
from fog.crypto import generate_keypair, pubkey_to_hex, sign

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_orig_sess_request = requests.Session.request
requests.Session.request = lambda self, *a, **kw: _orig_sess_request(
    self, *a, **{**kw, "verify": False})

FOG = "https://127.0.0.1:5000"
PSK = "zone-A-psk-2026"

def register(did):
    # 1. PSK
    r = requests.post(f"{FOG}/register/start", json={"psk": PSK}).json()
    assert r["ok"], r
    sid = r["session_id"]

    # 2. keypair + challenge
    sk, pk = generate_keypair()
    pk_hex = pubkey_to_hex(pk)
    r = requests.post(f"{FOG}/register/challenge",
                      json={"session_id": sid, "pk_hex": pk_hex}).json()
    assert r["ok"], r
    nonce_hex = r["nonce_hex"]

    # 3. sign nonce + complete
    sig = sign(sk, bytes.fromhex(nonce_hex))
    r = requests.post(f"{FOG}/register/complete", json={
        "session_id": sid, "did": did, "pk_hex": pk_hex,
        "nonce_hex": nonce_hex, "signature_hex": sig.hex(),
        "metadata": {"type": "temperature-sensor", "zone": "A"}
    }).json()
    print(did, "->", r)
    return r

if __name__ == "__main__":
    for i in range(3):
        register(f"did:iiot:temp-{i+1:03d}")
"""IIoT device simulator.

Spawns N virtual devices that register with the fog node, obtain
temporary tokens, request their Merkle proofs, and make resource
requests. Used for the live demo.
"""
import os, time, argparse, requests
from fog.crypto import generate_keypair, pubkey_to_hex, sign

FOG = "http://127.0.0.1:5000"
PSK = "zone-A-psk-2026"

DEVICE_TEMPLATES = [
    ("temperature-sensor", "temperature"),
    ("pressure-sensor",    "pressure"),
    ("valve-controller",   "valve"),
    ("camera",             "stream"),
]


class Device:
    def __init__(self, idx: int):
        self.did = f"did:iiot:sim-{idx:04d}"
        role, resource = DEVICE_TEMPLATES[idx % len(DEVICE_TEMPLATES)]
        self.role = role
        self.resource = resource
        self.sk, self.pk = generate_keypair()
        self.pk_hex = pubkey_to_hex(self.pk)
        self.token_id = None
        self.epoch = None
        self.proof = None

    # --- onboarding ---
    def register(self) -> bool:
        sid = requests.post(f"{FOG}/register/start",
                            json={"psk": PSK}).json()["session_id"]
        n = requests.post(f"{FOG}/register/challenge",
                          json={"session_id": sid,
                                "pk_hex": self.pk_hex}).json()["nonce_hex"]
        sig = sign(self.sk, bytes.fromhex(n))
        r = requests.post(f"{FOG}/register/complete", json={
            "session_id": sid, "did": self.did, "pk_hex": self.pk_hex,
            "nonce_hex": n, "signature_hex": sig.hex(),
            "metadata": {"type": self.role},
        }).json()
        return r.get("ok", False)

    def request_token(self) -> bool:
        r = requests.post(f"{FOG}/token/issue",
                          json={"did": self.did, "pk_hex": self.pk_hex}).json()
        if not r.get("ok"):
            return False
        self.token_id = r["token"]["token_id"]
        return True

    def fetch_proof(self, epoch: int) -> bool:
        r = requests.get(f"{FOG}/proof/{self.did}").json()
        if not r.get("ok"):
            return False
        self.epoch = epoch
        self.proof = r["package"]["proof"]
        return True

    def resource_request(self, operation="WRITE") -> dict:
        nonce = os.urandom(16).hex()
        sig = sign(self.sk, (nonce + self.resource + operation).encode()).hex()
        return requests.post(f"{FOG}/resource/request", json={
            "did": self.did, "pk_hex": self.pk_hex, "epoch": self.epoch,
            "proof": self.proof, "token_id": self.token_id,
            "resource": self.resource, "operation": operation,
            "nonce": nonce, "request_sig": sig,
        }).json()


def main(n_devices: int):
    print(f"[simulator] starting {n_devices} devices\n")
    devices = [Device(i) for i in range(n_devices)]

    # Phase 1: register all
    t0 = time.time()
    for d in devices:
        ok = d.register()
        print(f"  registered {d.did:24s} role={d.role:20s} ok={ok}")
    reg_ms = (time.time() - t0) * 1000
    print(f"\n[simulator] registration done in {reg_ms:.1f} ms\n")

    # Phase 2: temporary tokens
    for d in devices:
        d.request_token()
    print("[simulator] temporary tokens issued\n")

    # Finalize batch
    fin = requests.post(f"{FOG}/batch/finalize").json()
    epoch = fin["epoch_finalized"]
    print(f"[simulator] epoch {epoch} finalized  root={fin['root_hex'][:16]}...\n")

    # Phase 3: proof + resource access
    for d in devices:
        d.fetch_proof(epoch)
        r = d.resource_request("WRITE")
        print(f"  {d.did:24s} -> {r.get('decision')}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", "--devices", type=int, default=5)
    args = ap.parse_args()
    main(args.devices)
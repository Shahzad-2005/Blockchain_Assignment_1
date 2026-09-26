import time, uuid, os
from flask import Flask, request, jsonify
from fog.crypto import hex_to_pubkey, verify
from fog.merkle import hash_leaf
from fog.models import DeviceIdentity

app = Flask(__name__)

# ---- config ----
PSK = "zone-A-psk-2026"
CHALLENGE_TTL = 60  # seconds

# ---- in-memory state ----
SESSIONS = {}                # session_id -> {psk_ok, pk_hex, nonce, nonce_issued_at}
USED_NONCES = set()          # replay protection
PENDING_REGISTRATIONS = {}   # did -> DeviceIdentity
CURRENT_BATCH = []           # list of (did, leaf)
CURRENT_EPOCH = 1
ANCHORED_ROOTS = {}
PROOF_PACKAGES = {}
TOKENS = {}
REVOCATIONS = {}


@app.route("/")
def home():
    return jsonify({"status": "fog running", "epoch": CURRENT_EPOCH,
                    "batch_size": len(CURRENT_BATCH)})


@app.route("/register/start", methods=["POST"])
def register_start():
    data = request.get_json() or {}
    if data.get("psk") != PSK:
        return jsonify({"ok": False, "msg": "invalid PSK"}), 401
    session_id = uuid.uuid4().hex
    SESSIONS[session_id] = {"psk_ok": True, "pk_hex": None,
                            "nonce": None, "nonce_issued_at": None}
    return jsonify({"ok": True, "session_id": session_id})


@app.route("/register/challenge", methods=["POST"])
def register_challenge():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    pk_hex = data.get("pk_hex")
    sess = SESSIONS.get(session_id)
    if not sess or not sess["psk_ok"]:
        return jsonify({"ok": False, "msg": "invalid session"}), 401
    try:
        hex_to_pubkey(pk_hex)
    except Exception:
        return jsonify({"ok": False, "msg": "invalid public key"}), 400
    nonce = os.urandom(32)
    sess["pk_hex"] = pk_hex
    sess["nonce"] = nonce
    sess["nonce_issued_at"] = time.time()
    return jsonify({"ok": True, "nonce_hex": nonce.hex()})


@app.route("/register/complete", methods=["POST"])
def register_complete():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    did = data.get("did")
    pk_hex = data.get("pk_hex")
    nonce_hex = data.get("nonce_hex")
    sig_hex = data.get("signature_hex")
    metadata = data.get("metadata", {})

    sess = SESSIONS.get(session_id)
    if not sess or not sess["psk_ok"]:
        return jsonify({"ok": False, "msg": "invalid session"}), 401
    if sess["nonce"] is None:
        return jsonify({"ok": False, "msg": "challenge not issued"}), 400
    if time.time() - sess["nonce_issued_at"] > CHALLENGE_TTL:
        return jsonify({"ok": False, "msg": "challenge expired"}), 401
    if nonce_hex != sess["nonce"].hex():
        return jsonify({"ok": False, "msg": "nonce mismatch"}), 401
    if nonce_hex in USED_NONCES:
        return jsonify({"ok": False, "msg": "nonce reused"}), 401
    if pk_hex != sess["pk_hex"]:
        return jsonify({"ok": False, "msg": "public key mismatch"}), 401

    pk_obj = hex_to_pubkey(pk_hex)
    try:
        sig_bytes = bytes.fromhex(sig_hex)
    except Exception:
        return jsonify({"ok": False, "msg": "bad signature encoding"}), 400

    if not verify(pk_obj, bytes.fromhex(nonce_hex), sig_bytes):
        return jsonify({"ok": False, "msg": "proof-of-possession failed"}), 401

    USED_NONCES.add(nonce_hex)
    leaf = hash_leaf(did, pk_hex)
    PENDING_REGISTRATIONS[did] = DeviceIdentity(did=did, pk=pk_hex,
                                                metadata=metadata, leaf=leaf)
    CURRENT_BATCH.append((did, leaf))
    del SESSIONS[session_id]

    return jsonify({"ok": True, "did": did, "leaf_hex": leaf.hex(),
                    "epoch": CURRENT_EPOCH, "batch_size": len(CURRENT_BATCH)})


# remaining routes still stubbed — we fill them next step
@app.route("/batch/finalize", methods=["POST"])
def batch_finalize():
    return jsonify({"ok": False, "msg": "not implemented"}), 501

@app.route("/token/issue", methods=["POST"])
def token_issue():
    return jsonify({"ok": False, "msg": "not implemented"}), 501

@app.route("/resource/request", methods=["POST"])
def resource_request():
    return jsonify({"ok": False, "msg": "not implemented"}), 501

@app.route("/revoke", methods=["POST"])
def revoke():
    return jsonify({"ok": False, "msg": "not implemented"}), 501


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
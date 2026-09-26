import time, uuid, os
from flask import Flask, request, jsonify
from fog.crypto import hex_to_pubkey, verify
from fog.models import DeviceIdentity
from fog.crypto import generate_keypair, sign
from fog.merkle import hash_leaf, build_tree, get_root, get_proof, verify_proof  
from fog.policy import is_allowed   
from fog.token import issue_token, validate_token
import hashlib, json

FOG_SK, FOG_PK = generate_keypair()
ANCHOR_CHAIN = []   # [{epoch, root_hex, ts, prev_hash, anchor_hash}]
TOKEN_TTL = 300  # 5 minutes for demo
USED_REQUEST_NONCES = set()
REVOKED_DEVICES = set()   # DIDs blocked from future epochs

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

@app.route("/reset", methods=["POST"])
def reset():
    global CURRENT_EPOCH, CURRENT_BATCH
    SESSIONS.clear()
    USED_NONCES.clear()
    USED_REQUEST_NONCES.clear()
    PENDING_REGISTRATIONS.clear()
    CURRENT_BATCH = []
    CURRENT_EPOCH = 1
    ANCHORED_ROOTS.clear()
    ANCHOR_CHAIN.clear()
    PROOF_PACKAGES.clear()
    TOKENS.clear()
    REVOCATIONS.clear()
    REVOKED_DEVICES.clear()
    return jsonify({"ok": True, "msg": "state reset"})

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

@app.route("/batch/finalize", methods=["POST"])
def batch_finalize():
    global CURRENT_EPOCH, CURRENT_BATCH
    if not CURRENT_BATCH:
        return jsonify({"ok": False, "msg": "batch empty"}), 400

    leaves = [leaf for _, leaf in CURRENT_BATCH]
    levels = build_tree(leaves)
    root = get_root(levels)

    # anchor record (mini blockchain style)
    ts = time.time()
    prev = ANCHOR_CHAIN[-1]["anchor_hash"] if ANCHOR_CHAIN else "0" * 64
    payload = f"{CURRENT_EPOCH}|{root.hex()}|{ts}|{prev}".encode()
    anchor_hash = hashlib.sha256(payload).hexdigest()
    ANCHOR_CHAIN.append({
        "epoch": CURRENT_EPOCH, "root_hex": root.hex(),
        "ts": ts, "prev_hash": prev, "anchor_hash": anchor_hash,
    })
    ANCHORED_ROOTS[CURRENT_EPOCH] = root

    # proof package per device
    for did, leaf in CURRENT_BATCH:
        if did in REVOKED_DEVICES:
            continue
        proof = get_proof(levels, leaf)
        # sign (leaf || root || epoch)
        sign_payload = leaf + root + str(CURRENT_EPOCH).encode()
        sig = sign(FOG_SK, sign_payload)
        PROOF_PACKAGES[did] = {
            "did": did, "leaf_hex": leaf.hex(),
            "epoch": CURRENT_EPOCH, "root_hex": root.hex(),
            "proof": [(s, h.hex()) for s, h in proof],
            "fog_signature_hex": sig.hex(),
        }

    finalized_epoch = CURRENT_EPOCH
    device_count = sum(1 for did, _ in CURRENT_BATCH if did not in REVOKED_DEVICES)
    CURRENT_BATCH = []
    CURRENT_EPOCH += 1

    return jsonify({
        "ok": True, "epoch_finalized": finalized_epoch,
        "root_hex": root.hex(), "devices": device_count,
        "anchor_hash": anchor_hash,
    })

@app.route("/proof/<did>", methods=["GET"])
def get_proof_pkg(did):
    pkg = PROOF_PACKAGES.get(did)
    if not pkg:
        return jsonify({"ok": False, "msg": "no proof for this DID"}), 404
    return jsonify({"ok": True, "package": pkg})

@app.route("/token/issue", methods=["POST"])
def token_issue():
    data = request.get_json() or {}
    did = data.get("did")
    pk_hex = data.get("pk_hex")
    scope = data.get("scope", "provisional")

    if did not in PENDING_REGISTRATIONS:
        return jsonify({"ok": False, "msg": "device not registered"}), 404
    if PENDING_REGISTRATIONS[did].pk != pk_hex:
        return jsonify({"ok": False, "msg": "pk mismatch"}), 401

    tok = issue_token(did, pk_hex, scope, FOG_SK)
    TOKENS[tok["token_id"]] = tok
    return jsonify({"ok": True, "token": tok})

@app.route("/resource/request", methods=["POST"])
def resource_request():
    d = request.get_json() or {}
    did        = d.get("did")
    pk_hex     = d.get("pk_hex")
    epoch      = d.get("epoch")
    proof_in   = d.get("proof")            # [(side, hex), ...]
    token_id   = d.get("token_id")
    resource   = d.get("resource")
    operation  = d.get("operation")
    nonce_hex  = d.get("nonce")
    sig_hex    = d.get("request_sig")

    def deny(reason): return jsonify({"ok": False, "decision": "DENY", "reason": reason})
    def allow():      return jsonify({"ok": True,  "decision": "ALLOW"})

    # 1. epoch root exists
    root = ANCHORED_ROOTS.get(epoch)
    if root is None:
        return deny("unknown epoch")

    # 2. token checks
    tok = TOKENS.get(token_id)
    ok, reason = validate_token(tok, did, pk_hex, set(REVOCATIONS.keys()))
    if not ok:
        return deny(reason)

    # 3. recompute leaf + verify proof
    leaf = hash_leaf(did, pk_hex)
    proof = [(s, bytes.fromhex(h)) for s, h in proof_in]
    if not verify_proof(leaf, proof, root):
        return deny("proof invalid")

    # 4. replay + fresh PoP
    if nonce_hex in USED_REQUEST_NONCES:
        return deny("nonce reused")
    try:
        pk_obj = hex_to_pubkey(pk_hex)
        msg = (nonce_hex + resource + operation).encode()
        if not verify(pk_obj, msg, bytes.fromhex(sig_hex)):
            return deny("request signature invalid")
    except Exception:
        return deny("bad signature encoding")
    USED_REQUEST_NONCES.add(nonce_hex)

    # 5. policy
    role = PENDING_REGISTRATIONS[did].metadata.get("type")
    if not is_allowed(role, resource, operation):
        return deny(f"policy: {role} cannot {operation} {resource}")

    return allow()


@app.route("/revoke", methods=["POST"])
def revoke():
    data = request.get_json() or {}
    did = data.get("did")
    token_id = data.get("token_id")
    reason = data.get("reason", "unspecified")

    if did and did in PENDING_REGISTRATIONS:
        REVOKED_DEVICES.add(did)

    if token_id and token_id in TOKENS:
        REVOCATIONS[token_id] = {
            "token_id": token_id,
            "reason": reason,
            "revoked_at": time.time(),
        }

    return jsonify({"ok": True, "revoked_device": did, "revoked_token": token_id,
                    "revoked_devices": list(REVOKED_DEVICES)})

@app.route("/revocation-status")
def revocation_status():
    return jsonify({
        "revoked_devices": list(REVOKED_DEVICES),
        "revoked_tokens": list(REVOCATIONS.keys()),
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True,
            ssl_context=("fog/cert.pem", "fog/key.pem"))
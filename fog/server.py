from flask import Flask, request, jsonify

app = Flask(__name__)

# ---- in-memory state (we'll replace with SQLite later) ----
PENDING_REGISTRATIONS = {}   # did -> DeviceIdentity
CURRENT_BATCH = []           # list of leaves
CURRENT_EPOCH = 1
ANCHORED_ROOTS = {}          # epoch -> root bytes
PROOF_PACKAGES = {}          # did -> ProofPackage
TOKENS = {}                  # token_id -> Token
REVOCATIONS = {}             # token_id -> Revocation


@app.route("/")
def home():
    return jsonify({"status": "fog running", "epoch": CURRENT_EPOCH})


@app.route("/register/start", methods=["POST"])
def register_start():
    # step 1: PSK auth
    return jsonify({"ok": False, "msg": "not implemented"}), 501


@app.route("/register/challenge", methods=["POST"])
def register_challenge():
    # step 2: fog sends fresh nonce
    return jsonify({"ok": False, "msg": "not implemented"}), 501


@app.route("/register/complete", methods=["POST"])
def register_complete():
    # step 3: device sends DID, PK, signed challenge, metadata
    return jsonify({"ok": False, "msg": "not implemented"}), 501


@app.route("/batch/finalize", methods=["POST"])
def batch_finalize():
    # close batch, build tree, anchor root, generate proofs
    return jsonify({"ok": False, "msg": "not implemented"}), 501


@app.route("/token/issue", methods=["POST"])
def token_issue():
    # issue temporary token
    return jsonify({"ok": False, "msg": "not implemented"}), 501


@app.route("/resource/request", methods=["POST"])
def resource_request():
    # verify proof + token + revocation + policy -> ALLOW/DENY
    return jsonify({"ok": False, "msg": "not implemented"}), 501


@app.route("/revoke", methods=["POST"])
def revoke():
    # revoke a token/device
    return jsonify({"ok": False, "msg": "not implemented"}), 501


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
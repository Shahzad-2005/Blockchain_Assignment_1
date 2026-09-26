"""Temporary-token module (Phase 2).

Issues short-lived, fog-signed tokens that bridge a newly-registered
device until its permanent Merkle proof exists, and validates those
tokens at request time.
"""
import time, uuid
from fog.crypto import sign


TOKEN_TTL_SECONDS = 300   # 5 minutes for demo


def issue_token(did: str, pk_hex: str, scope: str, fog_sk) -> dict:
    """Build a signed token bound to (did, pk_hex)."""
    now = time.time()
    expires_at = now + TOKEN_TTL_SECONDS
    token_id = uuid.uuid4().hex

    payload = f"{did}|{pk_hex}|{scope}|{now}|{expires_at}|{token_id}".encode()
    sig = sign(fog_sk, payload)

    return {
        "did": did,
        "pk_hex": pk_hex,
        "scope": scope,
        "issued_at": now,
        "expires_at": expires_at,
        "token_id": token_id,
        "fog_signature_hex": sig.hex(),
    }


def validate_token(token: dict, did: str, pk_hex: str,
                   revoked_ids: set) -> tuple[bool, str]:
    """Return (is_valid, reason_if_invalid)."""
    if token is None:
        return False, "token not found"
    if token["token_id"] in revoked_ids:
        return False, "token revoked"
    if token["did"] != did or token["pk_hex"] != pk_hex:
        return False, "token/device mismatch"
    if time.time() > token["expires_at"]:
        return False, "token expired"
    return True, ""
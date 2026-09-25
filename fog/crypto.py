from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    """Returns (private_key, public_key) using ECDSA P-256."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, message: bytes) -> bytes:
    """Sign a message with ECDSA + SHA-256. Returns DER-encoded signature."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def verify(public_key, message: bytes, signature: bytes) -> bool:
    """Returns True if signature is valid, False otherwise."""
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def pubkey_to_hex(public_key) -> str:
    """Serialize public key to hex string for storage/transmission."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return der.hex()


def hex_to_pubkey(hex_str: str):
    """Deserialize public key from hex string."""
    der = bytes.fromhex(hex_str)
    return serialization.load_der_public_key(der)
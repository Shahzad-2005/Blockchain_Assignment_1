from crypto import generate_keypair, sign, verify, pubkey_to_hex, hex_to_pubkey

priv, pub = generate_keypair()
msg = b"hello fog node"

sig = sign(priv, msg)
print("valid sig:", verify(pub, msg, sig))
print("wrong msg:", verify(pub, b"tampered", sig))

pub_hex = pubkey_to_hex(pub)
print("pubkey hex len:", len(pub_hex))

pub2 = hex_to_pubkey(pub_hex)
print("roundtrip sig check:", verify(pub2, msg, sig))
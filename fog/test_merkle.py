from merkle import hash_leaf, build_tree, get_root, get_proof, verify_proof

leaves = [
    hash_leaf("did:iiot:temp-101", "PK101"),
    hash_leaf("did:iiot:press-01", "PK201"),
    hash_leaf("did:iiot:cam-01", "PK301"),
    hash_leaf("did:iiot:plc-01", "PK401"),
]

tree = build_tree(leaves)
root = get_root(tree)
print("root:", root.hex())

proof = get_proof(tree, leaves[0])
print("proof len:", len(proof))
print("verify:", verify_proof(leaves[0], proof, root))

# tamper test
bad_leaf = hash_leaf("did:iiot:temp-101", "HACKED")
print("tamper verify:", verify_proof(bad_leaf, proof, root))
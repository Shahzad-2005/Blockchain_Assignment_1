import hashlib

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash_leaf(did: str, pk: str) -> bytes:
    # canonical serialization: DID + "|" + PK
    return sha256(f"{did}|{pk}".encode())

def hash_pair(left: bytes, right: bytes) -> bytes:
    # order matters: left || right
    return sha256(left + right)

def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    """
    Returns tree as list of levels.
    levels[0] = leaves (sorted)
    levels[-1] = [root]
    """
    if not leaves:
        raise ValueError("no leaves")

    # sort deterministically
    leaves = sorted(leaves)
    levels = [leaves]

    current = leaves
    while len(current) > 1:
        # if odd, duplicate last
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        next_level = []
        for i in range(0, len(current), 2):
            next_level.append(hash_pair(current[i], current[i + 1]))
        levels.append(next_level)
        current = next_level

    return levels

def get_root(levels: list[list[bytes]]) -> bytes:
    return levels[-1][0]

def get_proof(levels: list[list[bytes]], leaf: bytes) -> list[tuple[str, bytes]]:
    """
    Returns proof as list of (side, hash).
    side = 'L' means sibling is on the left, 'R' means sibling is on the right.
    """
    # find leaf index in level 0
    idx = levels[0].index(leaf)
    proof = []

    for level in levels[:-1]:
        if idx % 2 == 0:
            # leaf is left child -> sibling is right
            sibling_idx = idx + 1
            side = "R"
        else:
            sibling_idx = idx - 1
            side = "L"

        # handle duplicated last
        if sibling_idx >= len(level):
            sibling_idx = idx

        proof.append((side, level[sibling_idx]))
        idx = idx // 2

    return proof

def verify_proof(leaf: bytes, proof: list[tuple[str, bytes]], root: bytes) -> bool:
    current = leaf
    for side, sibling in proof:
        if side == "L":
            current = hash_pair(sibling, current)
        else:
            current = hash_pair(current, sibling)
    return current == root
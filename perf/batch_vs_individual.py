"""Batch vs individual registration comparison.

Simulates N devices arriving one at a time and compares:
  - Individual: rebuild Merkle tree + root after EACH device
  - Batch:      collect all leaves, build tree + root ONCE
"""
import time, statistics
from fog.merkle import build_tree, get_root, get_proof, hash_leaf

DEVICE_COUNTS = [5, 10, 25, 50, 100, 200]
RUNS = 5


def make_leaves(n):
    return [hash_leaf(f"did:iiot:dev-{i:04d}", f"pk-{i:04d}") for i in range(n)]


def individual_run(n):
    leaves = make_leaves(n)
    t0 = time.perf_counter()
    current = []
    for leaf in leaves:
        current.append(leaf)
        levels = build_tree(current)
        _ = get_root(levels)
    return (time.perf_counter() - t0) * 1000


def batch_run(n):
    leaves = make_leaves(n)
    t0 = time.perf_counter()
    levels = build_tree(leaves)
    _ = get_root(levels)
    for leaf in leaves:
        _ = get_proof(levels, leaf)
    return (time.perf_counter() - t0) * 1000


def main():
    print(f"{'n':>5} | {'individual ms':>15} | {'batch ms':>10} | "
          f"{'speedup':>8} | {'indiv root updates':>18} | "
          f"{'indiv stale proofs':>18}")
    print("-" * 95)
    for n in DEVICE_COUNTS:
        ind_ms = statistics.mean(individual_run(n) for _ in range(RUNS))
        bat_ms = statistics.mean(batch_run(n) for _ in range(RUNS))
        speedup = ind_ms / bat_ms if bat_ms > 0 else 0
        stale = n * (n - 1) // 2
        print(f"{n:>5} | {ind_ms:>15.1f} | {bat_ms:>10.1f} | "
              f"{speedup:>8.1f}x | {n:>18} | {stale:>18}")


if __name__ == "__main__":
    main()
# Project State — IIoT Decentralized Identity (Assignment 1)

## Goal
Single-zone IIoT IdM: 1 fog node, multiple simulated devices.
Implement: registration → batch → proof → token → verification → resource → revocation + attacks + perf.

## Stack
Python 3.14, Flask, cryptography (ECDSA P-256), hashlib (SHA-256), SQLite, matplotlib.
Merkle tree (SMT in Assignment 2).

## Files (current)
- fog/crypto.py       — ECC keygen, ECDSA sign/verify, pubkey hex ser/deser
- fog/merkle.py       — build_tree, get_root, get_proof, verify_proof (sorted leaves)
- fog/models.py       — DeviceIdentity, ProofPackage, Token, Revocation
- fog/server.py       — Flask endpoints (register working; batch/token/verify/revoke stubbed)
- device/test_register.py, test_batch.py, test_token.py, test_verify.py, test_revoke.py
- perf/batch_vs_individual.py
- data/batch_vs_individual.txt
- PROJECT_STATE.md
- README.md
- .gitignore

## Progress checklist
- [x] Step 1: Data models
- [x] Step 2: Crypto utils
- [x] Step 3: Merkle tree + proofs
- [x] Step 4: /register/start, /register/challenge, /register/complete (PSK + PoP + leaf)
- [x] Step 5: Batch finalize + root anchor + proof package
- [x] Step 6: Temporary token
- [x] Step 7: Verification pipeline (leaf → root → proof → token → policy)
- [x] Step 8: Revocation
- [x] Step 9: 3+ attacks
- [x] Step 10: Perf + graphs + report
- [x] Batch vs Individual comparison (perf/batch_vs_individual.py)

## Contribution split (2 people)
- You: crypto, merkle, server core, batch, verify, attacks, perf
- Partner: device simulator, token module, routes wiring, policy.json, README, plots
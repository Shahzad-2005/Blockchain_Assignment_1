from dataclasses import dataclass, field
from typing import Any

@dataclass
class DeviceIdentity:
    did: str
    pk: str
    metadata: dict[str, Any] = field(default_factory=dict)
    leaf: bytes | None = None

@dataclass
class ProofPackage:
    did: str
    pk: str
    leaf: bytes
    epoch: int
    root: bytes
    proof: list[tuple[str, bytes]]
    fog_signature: bytes = b""

@dataclass
class Token:
    did: str
    pk: str
    scope: str
    issued_at: float
    expires_at: float
    token_id: str
    fog_signature: bytes = b""

@dataclass
class Revocation:
    token_id: str
    reason: str
    revoked_at: float
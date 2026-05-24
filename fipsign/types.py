"""
Typed result objects returned by PQAuth methods.
All are plain dataclasses — no behaviour, just structure.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional


# ─── Token ────────────────────────────────────────────────────────────────────

@dataclass
class PQToken:
    """
    A signed FIPSign token. Pass this object to verify() and revoke().
    Store it as JSON; reconstruct with PQToken(**data).
    """
    payload: str
    signature: str
    algorithm: str
    issuedAt: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload": self.payload,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "issuedAt": self.issuedAt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PQToken":
        return cls(
            payload=data["payload"],
            signature=data["signature"],
            algorithm=data["algorithm"],
            issuedAt=data["issuedAt"],
        )


# ─── sign() ───────────────────────────────────────────────────────────────────

@dataclass
class SignMeta:
    algorithm: str
    standard: str
    quantumResistant: bool
    expiresIn: int
    issuedFor: str
    projectId: str
    tokenCost: int
    source: Literal["free", "pack", "free+pack"]


@dataclass
class SignUsage:
    freeRemaining: int
    packRemaining: int
    totalRemaining: int
    month: str


@dataclass
class SignResult:
    token: PQToken
    meta: SignMeta
    usage: SignUsage


# ─── verify() ─────────────────────────────────────────────────────────────────

@dataclass
class VerifyResult:
    """
    Returned by verify(). Never raises — check ``valid`` before using ``payload``.

    Attributes
    ----------
    valid : bool
        True if the token is cryptographically valid, unexpired, and not revoked.
    payload : dict | None
        Decoded token payload. Contains ``sub``, ``iat``, ``exp``, and any
        custom fields passed to sign(). None when valid=False.
    error : str | None
        Human-readable error message when valid=False.
    """
    valid: bool
    payload: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


# ─── revoke() ─────────────────────────────────────────────────────────────────

@dataclass
class RevokeResult:
    success: bool
    message: str
    revokedAt: Optional[int] = None
    sub: Optional[str] = None
    expiresAt: Optional[int] = None
    note: Optional[str] = None


# ─── usage() ──────────────────────────────────────────────────────────────────

@dataclass
class MonthlyEntry:
    month: str
    tokensUsed: int
    fromFree: int
    fromPack: int


@dataclass
class PackEntry:
    id: str
    packType: str
    tokensPurchased: int
    purchasedAt: int
    paymentRef: Optional[str]


@dataclass
class UsageCurrent:
    month: str
    freeUsed: int
    freeRemaining: int
    freeLimit: int
    packRemaining: int
    totalRemaining: int


@dataclass
class UsageResult:
    current: UsageCurrent
    monthlyHistory: List[MonthlyEntry]
    packs: List[PackEntry]
    developer: Dict[str, str]
    note: str


# ─── webhooks ─────────────────────────────────────────────────────────────────

WebhookEvent = Literal[
    "token.signed",
    "token.rejected",
    "token.revoked",
    "limit.warning",
    "limit.reached",
]


@dataclass
class WebhookInfo:
    url: str
    events: List[str]
    secret: Optional[str] = None  # only present after register(), never in get()


@dataclass
class WebhookResult:
    webhook: WebhookInfo


@dataclass
class WebhookGetResult:
    webhook: Optional[WebhookInfo]  # None if no webhook registered


# ─── health() ─────────────────────────────────────────────────────────────────

@dataclass
class HealthResult:
    status: str
    algorithm: str
    quantumResistant: bool
    version: str

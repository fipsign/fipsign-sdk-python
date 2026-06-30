"""
Typed result objects returned by PQAuth methods.
All are plain dataclasses — no behaviour, just structure.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Union


# ─── Token ────────────────────────────────────────────────────────────────────

@dataclass
class PQToken:
    """
    A signed FIPSign token. Pass this object to verify() and revoke().
    Store it as JSON; reconstruct with PQToken.from_dict(data).
    """
    payload: str
    signature: str
    algorithm: str
    issuedAt: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload":   self.payload,
            "signature": self.signature,
            "algorithm": self.algorithm,
            "issuedAt":  self.issuedAt,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PQToken":
        return cls(
            payload   = data["payload"],
            signature = data["signature"],
            algorithm = data["algorithm"],
            issuedAt  = data["issuedAt"],
        )


# ─── sign() ───────────────────────────────────────────────────────────────────

@dataclass
class SignMeta:
    algorithm:        str
    standard:         str
    quantumResistant: bool
    expiresIn:        int
    issuedFor:        str
    projectId:        str
    tokenCost:        int
    source:           Literal["free", "pack", "free+pack"]


@dataclass
class SignUsage:
    freeRemaining:  int
    packRemaining:  int
    totalRemaining: int
    month:          str


@dataclass
class SignResult:
    token: PQToken
    meta:  SignMeta
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
    valid:   bool
    payload: Optional[Dict[str, Any]] = None
    error:   Optional[str]            = None


# ─── revoke() ─────────────────────────────────────────────────────────────────

@dataclass
class RevokeResult:
    success:   bool
    message:   str
    revokedAt: Optional[int] = None
    sub:       Optional[str] = None
    expiresAt: Optional[int] = None
    note:      Optional[str] = None


# ─── usage() ──────────────────────────────────────────────────────────────────

@dataclass
class MonthlyEntry:
    month:      str
    tokensUsed: int
    fromFree:   int
    fromPack:   int


@dataclass
class PackEntry:
    id:              str
    packType:        str
    tokensPurchased: int
    purchasedAt:     int
    paymentRef:      Optional[str]


@dataclass
class UsageCurrent:
    month:          str
    freeUsed:       int
    freeRemaining:  int
    freeLimit:      int
    packRemaining:  int
    totalRemaining: int


@dataclass
class UsageResult:
    current:        UsageCurrent
    monthlyHistory: List[MonthlyEntry]
    packs:          List[PackEntry]
    developer:      Dict[str, str]
    note:           str


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
    url:       str
    events:    List[str]
    secret:    Optional[str] = None   # only present after register(), never in get()
    active:    Optional[bool] = None  # present in get() response
    createdAt: Optional[int] = None   # present in get() response


@dataclass
class WebhookResult:
    webhook: WebhookInfo


@dataclass
class WebhookGetResult:
    webhook: Optional[WebhookInfo]  # None if no webhook registered


# ─── health() ─────────────────────────────────────────────────────────────────

@dataclass
class HealthResult:
    status:           str
    algorithm:        str
    standard:         str   # "NIST FIPS 204"
    quantumResistant: bool
    version:          str


# ─── Certificate Authority ─────────────────────────────────────────────────────
#
# Two CA formats are supported by the FIPSign backend:
#
#   pqcert — FIPSign's native JSON certificate format.
#            certificate field is a PQCert dataclass.
#
#   x509   — Standard X.509 v3 certificate with ML-DSA-65 signature.
#            certificate field is a PEM string (str).
#            Interoperable with OpenSSL 3.5+, standard PKI tooling.
#
# The Python SDK handles both formats transparently. The format of a CA is
# determined at creation time (dashboard) and cannot be changed afterwards.
# All CA operations (issue, revoke, get_cert, get_crl) work with both formats.
#
# Offline cryptographic operations:
#   verify_cert()      — verifies PQCert certificates locally (ca.py).
#   verify_x509_cert() — verifies X.509 PEM certificates locally (ca.py).
#   Both use pyca/cryptography >= 48.0.0, included as a dependency.
#   generate_key_pair() IS available via pyca/cryptography >= 48.0.0 —
#   see ca.py and README for usage and the seed-vs-expanded-key distinction.

CaFormat = Literal["pqcert", "x509"]


@dataclass
class PQCert:
    """A post-quantum certificate in FIPSign's native PQCert format."""
    type:      str
    id:        str
    subject:   str
    publicKey: str
    issuedAt:  int
    algorithm: str
    standard:  str
    signature: str
    caId:      Optional[str]            = None
    expiresAt: Optional[int]            = None
    meta:      Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type":      self.type,
            "id":        self.id,
            "subject":   self.subject,
            "publicKey": self.publicKey,
            "issuedAt":  self.issuedAt,
            "algorithm": self.algorithm,
            "standard":  self.standard,
            "signature": self.signature,
        }
        if self.caId      is not None: d["caId"]      = self.caId
        if self.expiresAt is not None: d["expiresAt"] = self.expiresAt
        if self.meta      is not None: d["meta"]      = self.meta
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PQCert":
        return cls(
            type      = data["type"],
            id        = data["id"],
            subject   = data["subject"],
            publicKey = data["publicKey"],
            issuedAt  = data["issuedAt"],
            algorithm = data["algorithm"],
            standard  = data["standard"],
            signature = data["signature"],
            caId      = data.get("caId"),
            expiresAt = data.get("expiresAt"),
            meta      = data.get("meta"),
        )


def _parse_certificate(raw: Any) -> Union[PQCert, str]:
    """
    Parse a certificate from a backend response.

    The backend returns either:
      - A dict (pqcert format) → PQCert
      - A string (x509 PEM format) → str

    This helper is used internally by ca.issue(), ca.get_cert(), etc.
    """
    if isinstance(raw, str):
        return raw          # x509 PEM
    if isinstance(raw, dict):
        return PQCert.from_dict(raw)
    raise ValueError(f"Unexpected certificate type: {type(raw)}")


@dataclass
class CaIssueMeta:
    certId:    str
    caId:      str
    subject:   str
    issuedAt:  int
    expiresAt: int
    algorithm: str
    standard:  str
    format:    str = "pqcert"  # "pqcert" | "x509"


@dataclass
class CaIssueUsage:
    freeRemaining:  int
    packRemaining:  int
    totalRemaining: int


@dataclass
class CaIssueResult:
    """
    Result of ca.issue().

    Attributes
    ----------
    certificate : PQCert | str
        For pqcert CAs: a PQCert dataclass.
        For x509 CAs: a PEM string (-----BEGIN CERTIFICATE-----...).
    meta : CaIssueMeta
        certId, caId, subject, issuedAt, expiresAt, algorithm, standard, format.
    usage : CaIssueUsage
        Token balance after the operation.
    """
    certificate: Union[PQCert, str]
    meta:        CaIssueMeta
    usage:       CaIssueUsage


@dataclass
class CaRevokeCertResult:
    certId:    str
    revokedAt: int
    reason:    Optional[str]
    usage:     CaIssueUsage
    format:    Optional[str] = None  # "x509" for X.509 CAs, absent for pqcert


@dataclass
class CaCertStatus:
    revoked:   bool
    expired:   bool
    revokedAt: Optional[int]
    expiresAt: int


@dataclass
class CaGetCertMeta:
    """
    Additional metadata returned by get_cert() for X.509 CAs.
    Not present in pqcert CA responses.
    """
    certId:    str
    caId:      str
    subject:   str
    format:    str   # "x509"
    algorithm: str


@dataclass
class CaGetCertResult:
    """
    Result of ca.get_cert().

    Attributes
    ----------
    certificate : PQCert | str
        For pqcert CAs: a PQCert dataclass.
        For x509 CAs: a PEM string.
    status : CaCertStatus
        revoked, expired, revokedAt, expiresAt.
    meta : CaGetCertMeta | None
        Additional metadata for X.509 CAs (certId, caId, subject, format,
        algorithm). None for pqcert CAs.
    """
    certificate: Union[PQCert, str]
    status:      CaCertStatus
    meta:        Optional[CaGetCertMeta] = None


@dataclass
class CrlEntry:
    certId:    str
    revokedAt: int
    reason:    Optional[str]


@dataclass
class CaGetCrlResult:
    """
    Result of ca.get_crl().

    Attributes
    ----------
    caId : str
    subject : str
    crl : list[CrlEntry]
        Revoked certificate entries. Empty list if nothing has been revoked.
    generatedAt : int
        Unix timestamp when the CRL was generated.
    format : str
        "pqcert" or "x509". For x509 CAs the CRL is also signed with ML-DSA-65;
        the raw signed CRL object is available in ``raw`` if you need the signature
        for verification.
    raw : dict | None
        For x509 CAs: the full signed CRL object from the backend, including
        ``signature`` field. None for pqcert CAs.
    """
    caId:        str
    subject:     str
    crl:         List[CrlEntry]
    generatedAt: int
    format:      str        = "pqcert"
    raw:         Optional[Dict[str, Any]] = None


@dataclass
class VerifyCertResult:
    """
    Returned by ca.verify_cert() and ca.verify_x509_cert().

    Attributes
    ----------
    valid : bool
        True if the certificate signature is valid and the certificate has not expired.
        Does NOT check revocation — call is_cert_revoked() for that.
    cert : PQCert | str | None
        For ca.verify_cert() (PQCert format): the verified PQCert dataclass.
        For ca.verify_x509_cert() (X.509 format): the verified PEM string.
        None when valid=False.
    error : str | None
        Human-readable error message when valid=False.

        From ca.verify_cert() (PQCert):
            'Expected a CA_CERT certificate'
            'Expected a CA_ROOT certificate'
            'Certificate was not issued by this CA (caId mismatch)'
            'Certificate has expired'
            'Invalid certificate signature'

        From ca.verify_x509_cert() (X.509):
            'Certificate has expired'
            'Invalid certificate signature — not signed by this root CA'
            'Unsupported signature algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
            'Unsupported root CA algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
    """
    valid: bool
    cert:  Optional[Union[PQCert, str]] = None  # PQCert for pqcert, str (PEM) for x509
    error: Optional[str]                = None


# ─── Key generation ───────────────────────────────────────────────────────────

@dataclass
class KeyPairResult:
    """
    Result of generate_key_pair().

    Attributes
    ----------
    publicKey : str
        Base64-encoded ML-DSA-65 public key (1952 bytes decoded).
        Compatible with the FIPSign backend and the JS SDK.
    secretKey : str
        Base64-encoded ML-DSA-65 key seed (32 bytes decoded).

        **Important:** This is the 32-byte seed form, NOT the 4032-byte
        expanded key returned by the JS SDK's generateKeyPair().
        The formats are not interchangeable.

        To sign from Python using this secretKey::

            from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
            import base64

            private_key = MLDSA65PrivateKey.from_seed_bytes(
                base64.b64decode(secret_key)
            )
            signature = private_key.sign(message)

        If the device signs using the JS SDK, generate the key pair with
        generateKeyPair() from the JS SDK instead — the JS secretKey (4032 bytes)
        is not compatible with the Python secretKey (32-byte seed).
    """
    publicKey: str  # base64(1952 bytes)
    secretKey: str  # base64(32 bytes — seed form, see docstring)

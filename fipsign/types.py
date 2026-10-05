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

# Why verify() answered valid=False.
#   "rejected"         FIPSign looked at the token and it is not acceptable: bad signature, expired, revoked,
#                      malformed, issued for another project, or a Mandate token. Answer 401.
#   "rate_limited"     Your API key sent too many requests in the current minute. The token was NOT checked:
#                      wait ``retry_after`` seconds and try again.
#   "quota_exhausted"  Your free tokens and your packs are used up. The token was NOT checked and waiting
#                      does not help: buy a pack from the dashboard.
#   "unavailable"      FIPSign could not answer: timeout, network failure, a server error, or an invalid
#                      API key. The token was NOT checked.
# Only "rejected" says something about the token. Do not log a user out because of the other three.
VerifyFailure = Literal["rejected", "rate_limited", "quota_exhausted", "unavailable"]

# Why mandate.verify() answered result="denied": the values of VerifyFailure, plus "outcome_unknown".
#   "rejected"         FIPSign looked at the call and refused it (``reason`` says why: scope, budget, expired, revoked,
#                      suspended, agent signature...) or the request was not well formed. Nothing was consumed.
#   "rate_limited"     Your API key sent too many requests in the current minute. Nothing was consumed:
#                      wait ``retry_after`` seconds and try again.
#   "quota_exhausted"  Your free tokens and your packs are used up. Nothing was consumed (the mandate budget is given
#                      back) and waiting does not help: buy a pack from the dashboard.
#   "unavailable"      FIPSign answered but could not check the call (for example, an invalid API key). Nothing was consumed.
#   "outcome_unknown"  NO usable answer arrived: timeout, network failure, an answer that could not be read, or a server
#                      error. FIPSign may have granted the call, used up its budget and charged its tokens without you
#                      ever hearing about it. Do not act as if it was granted and do not send it again blindly: with
#                      ``agent_signature``, send the SAME call again while the signature is still valid ("granted" = it is
#                      applied now, once; "agent_signature_replayed" = it was applied the first time); without one, compare
#                      ``budgetConsumed`` of mandate.get(id) with the value you had before. See Mandate 02c in the guide.
# Decide on ``failure``, not on the text of ``reason``. A call that was not granted is always result="denied", so code
# that only checks ``result != "granted"`` keeps working: it never acts on a call that may not have been granted.
MandateVerifyFailure = Literal["rejected", "rate_limited", "quota_exhausted", "unavailable", "outcome_unknown"]


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
        Human-readable error message when valid=False. For your logs: decide on
        ``failure``, not on this text.
    failure : VerifyFailure | None
        Why ``valid`` is False: ``"rejected"`` (the token is not acceptable) or one of
        ``"rate_limited"``, ``"quota_exhausted"``, ``"unavailable"`` (the check could not
        be done). None when ``valid`` is True.
    retry_after : int | None
        Seconds to wait before trying again. Only set with ``failure="rate_limited"``.
    """
    valid:       bool
    payload:     Optional[Dict[str, Any]] = None
    error:       Optional[str]            = None
    failure:     Optional[VerifyFailure]  = None
    retry_after: Optional[int]            = None


# ─── zes ──────────────────────────────────────────────────────────────────────

@dataclass
class ZesSignResult:
    """
    Returned by zes.sign() / AsyncZes.sign(). Same fields as SignResult,
    plus the SHA-256 hex digest that was actually signed.
    """
    token: PQToken
    hash:  str
    meta:  SignMeta
    usage: SignUsage


@dataclass
class ZesVerifyResult:
    """
    Returned by zes.verify() / AsyncZes.verify(). Same fields as
    VerifyResult, plus whether the supplied data matches the token's hash.

    Attributes
    ----------
    valid : bool
        True if the token itself is cryptographically valid, unexpired,
        and not revoked (same meaning as VerifyResult.valid).
    dataMatches : bool
        True if the data passed to verify() hashes to the same value
        stored in the token. False if the data was altered — even when
        valid is True (the token itself can be legitimate while the data
        given to verify() does not match what was originally signed).
    payload, error, failure, retry_after : same as VerifyResult.
    """
    valid:       bool
    dataMatches: bool
    payload:     Optional[Dict[str, Any]] = None
    error:       Optional[str]            = None
    failure:     Optional[VerifyFailure]  = None
    retry_after: Optional[int]            = None


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
class CaExpiry:
    """
    Present in CaIssueMeta when the requested expiresInSeconds was truncated
    to fit within the CA root's remaining lifetime (RFC 5280 compliance).
    """
    truncated:                 bool
    requestedExpiresInSeconds: int
    resolvedExpiresInSeconds:  int


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
    caExpiry:  Optional["CaExpiry"] = None  # present only when lifetime was truncated


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
        "pqcert" or "x509". The CRL is signed with ML-DSA-65 by the CA, for both
        formats: check the signature with ca.verify_crl().
    raw : dict | None
        The full signed CRL object from the backend, including its ``signature``
        field (both formats). None only for an answer that is a plain array
        without a signature.
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
            'Root CA certificate has expired'
            'Certificate has expired'
            'Invalid certificate signature'

        From ca.verify_x509_cert() (X.509):
            'Root CA certificate has expired'
            'Certificate has expired'
            'Invalid certificate signature — not signed by this root CA'
            'Unsupported signature algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
            'Unsupported root CA algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
    """
    valid: bool
    cert:  Optional[Union[PQCert, str]] = None  # PQCert for pqcert, str (PEM) for x509
    error: Optional[str]                = None


@dataclass
class VerifyCrlResult:
    """
    Returned by ca.verify_crl().

    Attributes
    ----------
    valid : bool
        True if the revocation list was signed by the CA whose root you passed, and
        what you read from it is what was signed.
    generatedAt : int | None
        Unix time (seconds) at which the CA generated and signed the list. Only when
        valid. The signature covers it, so it cannot be moved forward: how old a list
        you are willing to accept is up to you (``time.time() - generatedAt``).
    error : str | None
        Why the list is not valid, when valid=False.
    """
    valid:       bool
    generatedAt: Optional[int] = None
    error:       Optional[str] = None


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


# ─── Mandate ──────────────────────────────────────────────────────────────────
#
# Bounded, revocable authorization for AI agents, IoT devices, and automated
# services. Two layers:
#
#   Immutable — covered by the ML-DSA signature: agentId, issuedBy,
#               scopeOriginal, budgetTotal, expiresAt. Cannot change.
#   Mutable   — stored server-side: scopeCurrent, budgetConsumed, status.
#               Updated via narrow()/suspend()/resume()/revoke() without
#               invalidating the token.
#
# See the developer guide's Mandate section for the full explanation of
# the lifecycle and budget semantics.

MandateStatus = Literal["active", "suspended", "revoked"]

# Every value `reason` takes when mandate.verify() denies a call. `reason` can also
# hold the plain error text of a failure that never reaches the mandate checks
# (invalid API key, rate limit, token quota, network error), so the field itself
# is typed as a plain str.
MandateDenyReason = Literal[
    "invalid_signature",         # the token was not issued by this project, or was altered
    "mandate_expired",
    "mandate_revoked",
    "mandate_suspended",
    "scope_not_authorized",
    "budget_exhausted",
    "agent_signature_required",  # the mandate needs an agent_signature and none was sent
    "agent_signature_invalid",   # bad signature, wrong key, wrong algorithm, or lives too long
    "agent_signature_mismatch",  # valid signature, but for another mandate, action or cost
    "agent_signature_replayed",  # this signature already authorized a call
]

# ML-DSA variants an agent key can use (proof of possession).
AgentAlgorithm = Literal["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


@dataclass
class AgentKeyPairResult:
    """
    Result of generate_agent_key_pair() — the key pair of an agent that must
    prove possession of its mandate. See fipsign/agent.py.

    Attributes
    ----------
    publicKey : str
        Base64 of the raw public key (1312 / 1952 / 2592 bytes for ML-DSA-44 /
        65 / 87). Pass it to mandate.emit(agent_public_key=...).
    secretKey : str
        Base64 of the 32-byte seed. Keep it on the agent; never send it anywhere.
        Not interchangeable with the JS SDK's (expanded) secret key.
    algorithm : str
        The ML-DSA variant of the pair. Store it next to secretKey: a seed does
        not say which variant it belongs to, and sign_agent_call() needs it.
    """
    publicKey: str
    secretKey: str
    algorithm: str  # AgentAlgorithm


@dataclass
class Mandate:
    """
    Full state of a mandate, as returned by mandate.get() and mandate.list().
    Not the same shape as the ``mandate`` field on mandate.emit()'s result —
    see MandateEmitMandate for that.

    ``requiresAgentSignature`` is True when the mandate was emitted with an
    agent_public_key: every verify() must then carry an agent_signature. The
    public key itself is never returned by the API.
    """
    id:               str
    agentId:          str
    issuedBy:         str
    scopeOriginal:    List[str]
    scopeCurrent:     List[str]
    budgetTotal:      int
    budgetConsumed:   int
    budgetRemaining:  int
    status:           str  # MandateStatus
    issuedAt:         int
    expiresAt:        int
    expiresInSeconds: int
    updatedAt:        int
    requiresAgentSignature: bool = False


def _parse_mandate(d: Dict[str, Any]) -> "Mandate":
    """Internal helper — parses a mandate dict from get()/list() into Mandate."""
    return Mandate(
        id=d["id"], agentId=d["agentId"], issuedBy=d["issuedBy"],
        scopeOriginal=d["scopeOriginal"], scopeCurrent=d["scopeCurrent"],
        budgetTotal=d["budgetTotal"], budgetConsumed=d["budgetConsumed"],
        budgetRemaining=d["budgetRemaining"], status=d["status"],
        issuedAt=d["issuedAt"], expiresAt=d["expiresAt"],
        expiresInSeconds=d["expiresInSeconds"], updatedAt=d["updatedAt"],
        requiresAgentSignature=bool(d.get("requiresAgentSignature", False)),
    )


@dataclass
class MandateEmitMandate:
    """
    The ``mandate`` field on MandateEmitResult — lighter than Mandate.

    ``requiresAgentSignature`` is True when the mandate was emitted with an
    agent_public_key (proof of possession).
    """
    id:          str
    agentId:     str
    issuedBy:    str
    scope:       List[str]
    budgetTotal: int
    expiresAt:   int
    status:      str  # MandateStatus
    token:       PQToken
    requiresAgentSignature: bool = False


@dataclass
class MandateEmitUsage:
    freeRemaining:  int
    packRemaining:  int
    totalRemaining: int
    month:          str


@dataclass
class MandateEmitResult:
    """
    Result of mandate.emit(). Cost: 2 tokens.

    ``receipt`` is FIPSign's signature over the event "emitted" of this mandate (see MandateReceipt).
    Keep it next to your own record of the mandate. None only if the answer carried none.
    """
    mandate: MandateEmitMandate
    usage:   MandateEmitUsage
    receipt: Optional["MandateReceipt"] = None


@dataclass
class MandateVerifyResult:
    """
    Returned by mandate.verify(). **Never raises** — every failure,
    including a denied check and an invalid API key, comes back as
    result="denied", never an exception.

    Attributes
    ----------
    result : str
        "granted" or "denied".
    reason : str | None
        Set when denied. One of MandateDenyReason — "invalid_signature",
        "mandate_expired", "mandate_revoked", "mandate_suspended",
        "scope_not_authorized", "budget_exhausted", "agent_signature_required",
        "agent_signature_invalid", "agent_signature_mismatch",
        "agent_signature_replayed" — or the real error text of a failure that
        never reaches the mandate checks (an invalid API key, a rate limit, an
        exhausted token quota, a network error).
    actionMatched, budgetRemaining, expiresInSeconds : set when granted.
    authorizedScope : set when denied for scope_not_authorized.
    budgetConsumedUnits, budgetTotalUnits : set when denied for budget_exhausted.
    failure : MandateVerifyFailure | None
        Why ``result`` is "denied": ``"rejected"`` (FIPSign refused the call), ``"rate_limited"``,
        ``"quota_exhausted"`` or ``"unavailable"`` (FIPSign answered and nothing was consumed), or
        ``"outcome_unknown"`` (no usable answer: the call MAY have been granted and charged; see
        MandateVerifyFailure for what to do). None when granted. Decide on ``failure``, not on ``reason``.
    retry_after : int | None
        Seconds to wait before trying again. Only set with ``failure="rate_limited"``.
    receipt : MandateReceipt | None
        FIPSign's signature over the event this call produced. Only with ``receipt=True`` passed to
        verify(), and only when FIPSign recorded the call (granted, or denied by a mandate check). None otherwise.
    """
    result:               str  # "granted" | "denied"
    reason:               Optional[str]              = None
    actionMatched:        Optional[str]               = None
    budgetRemaining:      Optional[int]                = None
    expiresInSeconds:     Optional[int]                 = None
    authorizedScope:      Optional[List[str]]            = None
    budgetConsumedUnits:  Optional[int]                   = None
    budgetTotalUnits:     Optional[int]                    = None
    usage:                Optional[MandateEmitUsage]        = None
    failure:              Optional[MandateVerifyFailure]     = None
    retry_after:          Optional[int]                       = None
    receipt:              Optional["MandateReceipt"]          = None


@dataclass
class MandatePatchResult:
    """Result of narrow()/suspend()/resume()/revoke(). Free — no token cost."""
    id:        str
    status:    str  # MandateStatus
    scope:     Optional[List[str]] = None
    updatedAt: Optional[int]       = None
    message:   Optional[str]       = None  # only set by suspend() on an already-suspended mandate
    receipt:   Optional["MandateReceipt"] = None  # FIPSign's signature over the event this change produced; None when nothing changed


@dataclass
class MandateGetResult:
    mandate: Mandate


@dataclass
class MandateListResult:
    """
    One page of mandate.list(), most recent first.

    Attributes
    ----------
    mandates : list[Mandate]
        The mandates of this page.
    count : int
        How many mandates this page holds (len(mandates)). Not the total of the
        project: a page can hold fewer than ``limit`` and still have a next one.
    nextCursor : str | None
        Pass it to list(cursor=...) to get the next page. None on the last page.
    """
    mandates:   List[Mandate]
    count:      int
    nextCursor: Optional[str] = None


# ─── Mandate audit: events, receipts, export ──────────────────────────────────
#
# FIPSign keeps a log of everything that happens to a mandate (who emitted it, every call it granted or denied,
# every change) as a chain of events, and signs what it records. These are the objects of that log.
# Everything that carries a signature can be checked on your own machine: see fipsign/mandate_audit.py.

#: What can be recorded about a mandate. The audit log keeps one event per occurrence.
MandateEventType = Literal[
    "emitted",
    "verify_granted",
    "verify_denied",
    "verify_released",
    "narrowed",
    "suspended",
    "resumed",
    "revoked",
    "chain_started",
    "checkpoint",
    "log_limit_reached",
]

#: ``"pinned"``: the key was fixed by you (``public_key`` or ``pin_fingerprint``): the check does not depend on
#: FIPSign's word. ``"fipsign"``: you gave neither, so the keys came from FIPSign itself (mandate.verify_receipt() and
#: mandate.verify_export() only): the check detects a receipt or a log that was altered, but cannot tell a key that
#: FIPSign (or somebody who can write its database) replaced.
MandateKeyTrust = Literal["pinned", "fipsign"]


@dataclass
class MandateEvent:
    """
    One entry of the audit log of a mandate. Entries are chained: ``hash`` is the SHA-256 (lowercase hex) of
    ``prevHash + "\\n" + body``, where ``prevHash`` is the ``hash`` of the entry before it (64 zeros for the first).

    ``body`` is a string: the exact text that was hashed (canonical JSON). Parse it with ``json.loads()`` to read the
    event; never re-serialize it. ``at`` is Unix seconds.
    """
    seq:      int
    type:     str  # MandateEventType
    at:       int
    prevHash: str
    hash:     str
    body:     str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq, "type": self.type, "at": self.at,
            "prevHash": self.prevHash, "hash": self.hash, "body": self.body,
        }


@dataclass
class MandateProjectEvent(MandateEvent):
    """An event as mandate.query_events() lists it: the event plus the mandate it belongs to."""
    mandateId: str

    def to_dict(self) -> Dict[str, Any]:
        d = MandateEvent.to_dict(self)
        d["mandateId"] = self.mandateId
        return d


@dataclass
class MandateReceipt:
    """
    FIPSign's signature over one event of one mandate, returned by mandate.emit(), the change calls (narrow, suspend,
    resume, revoke) and, when you ask for it, mandate.verify(receipt=True). Keep it: it commits to the whole history of
    the mandate up to that event, so the history cannot be rewritten later without the receipt showing it.

    Check it with mandate.verify_receipt() or verify_mandate_receipt(). To keep it as JSON: ``json.dumps(receipt.to_dict())``;
    what ``json.loads()`` gives back can be passed to verify_mandate_receipt() as it is.

    Attributes
    ----------
    signed : str
        The text that was signed: canonical JSON of ``{v, kind, projectId, mandateId, seq, hash, at}``.
    signature : str
        Base64, ML-DSA detached signature (FIPS 204) made with the project key.
    algorithm : str
        "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87".
    keyFingerprint : str
        SHA-256 (lowercase hex) of the public key that made the signature.
    event : MandateEvent
        The event the signature is about.
    """
    signed:         str
    signature:      str
    algorithm:      str
    keyFingerprint: str
    event:          MandateEvent

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signed": self.signed, "signature": self.signature, "algorithm": self.algorithm,
            "keyFingerprint": self.keyFingerprint, "event": self.event.to_dict(),
        }


@dataclass
class MandatePublicKey:
    """
    One public key of the project, as GET /public-keys lists it.

    ``fingerprint`` is the SHA-256 (lowercase hex) of the public key bytes: the value a receipt carries as
    ``keyFingerprint``. ``status`` is "current" or "retired". ``recordedAt`` is Unix seconds: when FIPSign wrote the key
    down (not when the key was made). ``retiredAt`` is Unix seconds: when the project rotated it away; None for the
    current key and for a key retired before the history existed.
    """
    fingerprint: str
    algorithm:   str
    publicKey:   str  # base64
    status:      str  # "current" | "retired"
    recordedAt:  int
    retiredAt:   Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint, "algorithm": self.algorithm, "publicKey": self.publicKey,
            "status": self.status, "recordedAt": self.recordedAt, "retiredAt": self.retiredAt,
        }


@dataclass
class MandatePublicKeysResult:
    """
    Every public key this project has signed with: ``keys`` lists the current one first, then the retired ones, the
    most recently retired first. A receipt is checked with the key that made it, so after a key rotation the old key
    is still needed.
    """
    projectId: str
    keys:      List[MandatePublicKey]
    count:     int


@dataclass
class MandateLogHead:
    """The end of the chain of a mandate as it is right now (mandate.events())."""
    seq:               int
    hash:              str
    lastCheckpointSeq: int


@dataclass
class MandateEventsResult:
    """
    One page of mandate.events(), oldest event first.

    ``nextAfter``: pass it as ``after`` to get the next page; None on the last page.
    ``head``: the end of the chain as it is right now, or None when the mandate has no log yet.
    """
    mandateId: str
    events:    List[MandateEvent]
    count:     int
    nextAfter: Optional[int] = None
    head:      Optional[MandateLogHead] = None


@dataclass
class MandateEventsQueryResult:
    """
    One page of mandate.query_events(), newest event first.

    ``nextCursor``: pass it as ``cursor`` to get the next page, exactly as received; None on the last page.
    ``from_`` and ``to`` are the period that was searched (Unix seconds).
    """
    events:     List[MandateProjectEvent]
    count:      int
    nextCursor: Optional[str] = None
    from_:      Optional[int] = None
    to:         Optional[int] = None


@dataclass
class MandateExportHead:
    """The live end of the chain, signed by FIPSign at the moment of the export. Only present while the mandate is alive."""
    seq:               int
    hash:              str
    at:                int
    source:            str
    lastCheckpointSeq: int
    signed:            str
    signature:         str
    algorithm:         str
    keyFingerprint:    str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq, "hash": self.hash, "at": self.at, "source": self.source,
            "lastCheckpointSeq": self.lastCheckpointSeq, "signed": self.signed, "signature": self.signature,
            "algorithm": self.algorithm, "keyFingerprint": self.keyFingerprint,
        }


@dataclass
class MandateExportPage:
    """
    One page of mandate.export(): the events, FIPSign's signature over the end of the chain at this moment (``head``)
    and the public keys of the project (``publicKeys``, the retired ones too, so a signature made before a key rotation
    can still be checked). Check the pages, in order, with mandate.verify_export() or verify_mandate_export().

    ``nextAfter``: pass it as ``after`` to get the next page; None on the last page.
    To keep the export as JSON: ``json.dumps([p.to_dict() for p in pages])``.
    """
    format:      str
    projectId:   str
    mandateId:   str
    generatedAt: int
    events:      List[MandateEvent]
    count:       int
    nextAfter:   Optional[int] = None
    head:        Optional[MandateExportHead] = None
    publicKeys:  List[MandatePublicKey] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "format": self.format, "projectId": self.projectId, "mandateId": self.mandateId,
            "generatedAt": self.generatedAt, "events": [e.to_dict() for e in self.events], "count": self.count,
            "nextAfter": self.nextAfter, "head": self.head.to_dict() if self.head is not None else None,
            "publicKeys": [k.to_dict() for k in self.publicKeys],
        }


@dataclass
class MandateReceiptCheck:
    """
    What verify_mandate_receipt() / mandate.verify_receipt() found.

    ``valid`` is True only if the signature, the event and the hash all check out and ``problems`` is empty.
    ``keyTrust``: see MandateKeyTrust. ``projectId``, ``mandateId`` and ``event`` are what the receipt says, when it could be read.
    """
    valid:     bool
    problems:  List[str]
    keyTrust:  str  # MandateKeyTrust
    projectId: Optional[str] = None
    mandateId: Optional[str] = None
    event:     Optional[MandateEvent] = None


@dataclass
class MandateExportCheck:
    """
    What verify_mandate_export() / mandate.verify_export() found.

    Attributes
    ----------
    valid : bool
        Every event follows the one before it and is what it says it is, and every signature that is in the export
        verifies. ``problems`` lists what does not.
    problems : list[str]
    notes : list[str]
        Things that are not wrong but limit what was checked (for example: the export starts at event 40).
    keyTrust : str
        See MandateKeyTrust.
    projectId, mandateId : str
    events : int
        Events checked.
    lastSeq : int
    checkpoints : int
        Checkpoints whose signature and covered event were checked.
    sealedThrough : int
        Every event up to this seq is sealed by a verified checkpoint.
    headChecked : bool
        The signed live head was there and matches the chain.
    complete : bool
        The log starts at event 1, ends with a verified checkpoint that seals everything before it, and nothing follows.
        A log that is ``valid`` but not ``complete`` has events at its end that only the signed head (or a receipt you
        hold) protects.
    """
    valid:         bool
    problems:      List[str]
    notes:         List[str]
    keyTrust:      str  # MandateKeyTrust
    projectId:     str = ""
    mandateId:     str = ""
    events:        int = 0
    lastSeq:       int = 0
    checkpoints:   int = 0
    sealedThrough: int = 0
    headChecked:   bool = False
    complete:      bool = False

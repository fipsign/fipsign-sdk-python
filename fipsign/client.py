"""
PQAuth — main client class.

Mirrors the JavaScript fipsign-sdk PQAuth class 1:1 in method names,
behaviour, and error semantics. All I/O is synchronous (requests library).
For async usage see the async_client module (httpx-based).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import ConnectionError, Timeout

from .errors import PQAuthError
from .types import (
    HealthResult,
    MonthlyEntry,
    PackEntry,
    PQToken,
    RevokeResult,
    SignMeta,
    SignResult,
    SignUsage,
    UsageCurrent,
    UsageResult,
    VerifyResult,
)
from .ca import CA

DEFAULT_BASE_URL = "https://api.fipsign.dev"
DEFAULT_TIMEOUT = 10  # seconds

# API keys must be "pqa_" followed by exactly 64 lowercase hex characters.
# Mirrors the validation in the JS SDK: /^pqa_[0-9a-f]{64}$/
_API_KEY_RE = re.compile(r"^pqa_[0-9a-f]{64}$")


class PQAuth:
    """
    FIPSign post-quantum signing client.

    Parameters
    ----------
    api_key : str
        Your FIPSign API key. Must match ``pqa_`` followed by 64 lowercase
        hex characters. Constructor raises ``INVALID_API_KEY`` immediately
        if the key does not match this format.
        Get one at https://app.fipsign.dev
    base_url : str, optional
        Override the API base URL (useful for self-hosted instances).
        Defaults to https://api.fipsign.dev
    timeout : int | float, optional
        Request timeout in seconds. Default: 10.
    session : requests.Session, optional
        Supply a custom requests Session (e.g. for custom TLS or proxies).

    Raises
    ------
    PQAuthError(code="INVALID_API_KEY")
        Raised immediately in the constructor if the key doesn't match
        ``pqa_`` + 64 lowercase hex characters.

    Examples
    --------
    Simple form — just the API key:

    >>> pq = PQAuth("pqa_your_api_key")

    All options:

    >>> pq = PQAuth(
    ...     api_key="pqa_your_api_key",
    ...     base_url="https://api.fipsign.dev",
    ...     timeout=10,
    ... )
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not api_key or not _API_KEY_RE.match(api_key):
            raise PQAuthError(
                'Invalid API key — keys must be "pqa_" followed by 64 lowercase hex '
                "characters. Get one at https://app.fipsign.dev",
                "INVALID_API_KEY",
            )
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._session = session or requests.Session()
        self._session.headers.update(
            {
                "Content-Type": "application/json",
                "X-API-Key": self._api_key,
            }
        )
        self.ca = CA(self)

    # ── Private: HTTP wrapper ─────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            resp = self._session.request(
                method,
                url,
                json=json,
                timeout=self._timeout,
            )
        except Timeout:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except ConnectionError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")
        except Exception as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")

        try:
            data = resp.json()
        except ValueError:
            raise PQAuthError(
                f"Request failed with status {resp.status_code}",
                "API_ERROR",
                resp.status_code,
            )

        if not resp.ok or not data.get("success", False):
            raise PQAuthError(
                data.get("error") or f"Request failed with status {resp.status_code}",
                "API_ERROR",
                resp.status_code,
            )

        return data

    # ── sign() ────────────────────────────────────────────────────────────────

    def sign(self, sub: str, *, expires_in_seconds: Optional[int] = None, **fields: Any) -> SignResult:
        """
        Sign any payload with ML-DSA-65.

        The only required argument is ``sub`` — any string identifying the entity:
        a user, an order, a document, a device, an event, anything.
        All extra keyword arguments are stored in the payload and returned on verify.

        Cost: 1 token.

        Parameters
        ----------
        sub : str
            Required. Entity identifier. Max 128 characters.
        expires_in_seconds : int, optional
            Token lifetime in seconds. Default: 3600 (1 hour).
            Pass ``None`` or omit for non-expiring tokens (document signatures).
        **fields
            Any additional custom fields (max 10; string values max 256 chars).

        Returns
        -------
        SignResult
            .token   — PQToken (pass to verify() / revoke())
            .meta    — algorithm, standard, expiresIn, tokenCost, source, …
            .usage   — freeRemaining, packRemaining, totalRemaining, month

        Raises
        ------
        PQAuthError(code="MISSING_SUB")
            If sub is empty.
        PQAuthError(code="API_ERROR", status=400)
            If more than 10 custom fields are provided, or field values exceed limits.
        PQAuthError(code="API_ERROR", status=429)
            If rate limit or token quota is exceeded.

        Examples
        --------
        >>> result = pq.sign("user_123", email="user@example.com", role="admin", expires_in_seconds=3600)
        >>> result = pq.sign("order_456", amount=299.99, currency="USD", expires_in_seconds=300)
        >>> result = pq.sign("doc_789", hash="sha256:abc...", signed_by="alice")
        """
        if not sub:
            raise PQAuthError('"sub" is required', "MISSING_SUB")

        body: Dict[str, Any] = {"sub": sub, **fields}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = expires_in_seconds

        data = self._request("POST", "/sign", json=body)

        t = data["token"]
        m = data["meta"]
        u = data["usage"]

        return SignResult(
            token=PQToken(
                payload=t["payload"],
                signature=t["signature"],
                algorithm=t["algorithm"],
                issuedAt=t["issuedAt"],
            ),
            meta=SignMeta(
                algorithm=m["algorithm"],
                standard=m["standard"],
                quantumResistant=m["quantumResistant"],
                expiresIn=m["expiresIn"],
                issuedFor=m["issuedFor"],
                projectId=m["projectId"],
                tokenCost=m["tokenCost"],
                source=m["source"],
            ),
            usage=SignUsage(
                freeRemaining=u["freeRemaining"],
                packRemaining=u["packRemaining"],
                totalRemaining=u["totalRemaining"],
                month=u["month"],
            ),
        )

    # ── verify() ──────────────────────────────────────────────────────────────

    def verify(self, token: PQToken) -> VerifyResult:
        """
        Verify a FIPSign token.

        **Never raises.** Returns a VerifyResult with ``valid=False`` and an
        ``error`` message on any failure (invalid signature, expired, revoked,
        network error, etc.).

        Checks: ML-DSA-65 signature · token expiry · revocation list.

        Cost: 1 token.

        Parameters
        ----------
        token : PQToken
            The token returned by sign().

        Returns
        -------
        VerifyResult
            .valid   — True if the token is valid
            .payload — decoded payload dict (sub, iat, exp + custom fields)
            .error   — error message string when valid=False

        Examples
        --------
        >>> result = pq.verify(token)
        >>> if not result.valid:
        ...     raise PermissionError(result.error)
        >>> user_id = result.payload["sub"]
        """
        try:
            data = self._request(
                "POST",
                "/verify",
                json={"token": token.to_dict()},
            )
            return VerifyResult(valid=True, payload=data.get("payload"))
        except PQAuthError as exc:
            return VerifyResult(valid=False, error=exc.message)
        except Exception as exc:
            return VerifyResult(valid=False, error=str(exc))

    # ── revoke() ──────────────────────────────────────────────────────────────

    def revoke(self, token: PQToken, reason: Optional[str] = None) -> RevokeResult:
        """
        Immediately and permanently revoke a token.

        Future verify() calls will reject it even if the signature is still
        valid and the token has not expired.

        Revoking an already-revoked token returns success without consuming
        an extra token — the operation is idempotent.

        Cost: 1 token.

        Parameters
        ----------
        token : PQToken
            The token to revoke.
        reason : str, optional
            Human-readable reason stored server-side (e.g. "user logged out").

        Returns
        -------
        RevokeResult
            .success, .message, .revokedAt, .sub, .expiresAt, .note

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If the token is already expired (expired tokens cannot be revoked).

        Examples
        --------
        >>> pq.revoke(token, "user logged out")
        >>> pq.revoke(token, "suspicious activity detected")
        """
        body: Dict[str, Any] = {"token": token.to_dict()}
        if reason is not None:
            body["reason"] = reason

        data = self._request("POST", "/revoke", json=body)
        return RevokeResult(
            success=data.get("success", False),
            message=data.get("message", ""),
            revokedAt=data.get("revokedAt"),
            sub=data.get("sub"),
            expiresAt=data.get("expiresAt"),
            note=data.get("note"),
        )

    # ── usage() ───────────────────────────────────────────────────────────────

    def usage(self) -> UsageResult:
        """
        Get current token balance and 6-month usage history.

        No token cost.

        Free tokens reset on the 1st of each month (UTC). Unused free tokens
        do not carry over. Pack tokens never expire and accumulate across
        purchases. All projects under the same account share a single pool.

        Returns
        -------
        UsageResult
            .current        — month, freeUsed, freeRemaining, freeLimit, packRemaining, totalRemaining
            .monthlyHistory — list of 6 MonthlyEntry (oldest → newest)
            .packs          — list of PackEntry for purchased packs
            .developer      — {"email": "..."}
            .note           — informational string

        Examples
        --------
        >>> u = pq.usage()
        >>> print(f"{u.current.freeRemaining} / {u.current.freeLimit} free tokens remaining")
        >>> for entry in u.monthlyHistory:
        ...     print(f"{entry.month}: {entry.tokensUsed} used")
        """
        data = self._request("GET", "/usage")
        c = data["current"]
        return UsageResult(
            current=UsageCurrent(
                month=c["month"],
                freeUsed=c["freeUsed"],
                freeRemaining=c["freeRemaining"],
                freeLimit=c["freeLimit"],
                packRemaining=c["packRemaining"],
                totalRemaining=c["totalRemaining"],
            ),
            monthlyHistory=[
                MonthlyEntry(
                    month=e["month"],
                    tokensUsed=e["tokensUsed"],
                    fromFree=e["fromFree"],
                    fromPack=e["fromPack"],
                )
                for e in data.get("monthlyHistory", [])
            ],
            packs=[
                PackEntry(
                    id=p["id"],
                    packType=p["packType"],
                    tokensPurchased=p["tokensPurchased"],
                    purchasedAt=p["purchasedAt"],
                    paymentRef=p.get("paymentRef"),
                )
                for p in data.get("packs", [])
            ],
            developer=data.get("developer", {}),
            note=data.get("note", ""),
        )

    # ── preload_public_key() ──────────────────────────────────────────────────

    def preload_public_key(self) -> str:
        """
        Fetch and return the server's ML-DSA-65 public key.

        The FIPSign Python SDK performs all verification server-side, so this
        method is provided for interoperability — e.g. if you want to verify
        tokens locally in Python using a third-party ML-DSA-65 library.

        Returns
        -------
        str
            Base64-encoded ML-DSA-65 public key.

        Examples
        --------
        >>> pub_key_b64 = pq.preload_public_key()
        """
        try:
            resp = self._session.get(
                f"{self._base_url}/public-key",
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
        except Timeout:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except ConnectionError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")
        if "publicKey" not in data:
            raise PQAuthError("Public key response missing publicKey field", "NETWORK_ERROR")
        return data["publicKey"]

    # ── health() ──────────────────────────────────────────────────────────────

    def health(self) -> HealthResult:
        """
        Check the health of the FIPSign service.

        Public endpoint — no API key required, no token cost.

        Returns
        -------
        HealthResult
            .status ("ok"), .algorithm ("ML-DSA-65"), .standard ("NIST FIPS 204"),
            .quantumResistant (True), .version

        Examples
        --------
        >>> h = pq.health()
        >>> assert h.status == "ok"
        >>> assert h.standard == "NIST FIPS 204"
        """
        try:
            resp = self._session.get(
                f"{self._base_url}/health",
                timeout=self._timeout,
            )
            data = resp.json()
        except Timeout:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except ConnectionError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")

        return HealthResult(
            status=data.get("status", ""),
            algorithm=data.get("algorithm", ""),
            standard=data.get("standard", ""),
            quantumResistant=data.get("quantumResistant", False),
            version=data.get("version", ""),
        )

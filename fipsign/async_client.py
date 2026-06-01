"""
AsyncPQAuth — async variant of PQAuth using httpx.

Install extra: pip install fipsign-sdk[async]   (pulls in httpx)

All methods are identical to PQAuth but async.
Use this in FastAPI, aiohttp, or any asyncio-based application.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

try:
    import httpx
except ImportError:
    raise ImportError(
        "AsyncPQAuth requires httpx. Install it with: pip install fipsign-sdk[async]"
    )

from .errors import PQAuthError
from .types import (
    CaGetCertResult,
    CaGetCrlResult,
    CaIssueMeta,
    CaIssueResult,
    CaIssueUsage,
    CaRevokeCertResult,
    CaCertStatus,
    CrlEntry,
    HealthResult,
    MonthlyEntry,
    PackEntry,
    PQCert,
    PQToken,
    RevokeResult,
    SignMeta,
    SignResult,
    SignUsage,
    UsageCurrent,
    UsageResult,
    VerifyResult,
    WebhookGetResult,
    WebhookInfo,
    WebhookResult,
    _parse_certificate,
)

DEFAULT_BASE_URL = "https://api.fipsign.dev"
DEFAULT_TIMEOUT  = 10


# ─── AsyncWebhooks ────────────────────────────────────────────────────────────

class AsyncWebhooks:
    def __init__(self, client: "AsyncPQAuth") -> None:
        self._client = client

    async def register(self, url: str, events: Optional[List[str]] = None) -> WebhookResult:
        body: dict = {"url": url}
        if events is not None:
            body["events"] = events
        data = await self._client._request("POST", "/webhooks", json=body)
        wh   = data["webhook"]
        return WebhookResult(
            webhook=WebhookInfo(url=wh["url"], events=wh["events"], secret=wh.get("secret"))
        )

    async def get(self) -> WebhookGetResult:
        data = await self._client._request("GET", "/webhooks")
        wh   = data.get("webhook")
        if wh is None:
            return WebhookGetResult(webhook=None)
        return WebhookGetResult(webhook=WebhookInfo(url=wh["url"], events=wh["events"]))

    async def delete(self) -> dict:
        return await self._client._request("DELETE", "/webhooks")

    async def test(self) -> dict:
        return await self._client._request("POST", "/webhooks/test")


# ─── AsyncCA ──────────────────────────────────────────────────────────────────

class AsyncCA:
    """
    Async Certificate Authority sub-client.

    Mirrors CA (sync) 1:1. Supports both pqcert and x509 CA formats.
    See ca.py for full documentation on formats and offline operation limitations.

    Usage
    -----
    async with AsyncPQAuth("pqa_your_key") as pq:
        result = await pq.ca.issue(
            subject="device-serial-00123",
            public_key=device_public_key_b64,
            expires_in_seconds=365 * 24 * 60 * 60,
        )
        # pqcert CA: result.certificate is PQCert
        # x509 CA:   result.certificate is a PEM string

        crl    = await pq.ca.get_crl()
        if pq.ca.is_cert_revoked(result.certificate, crl.crl):
            raise PermissionError("Certificate revoked")
    """

    def __init__(self, client: "AsyncPQAuth") -> None:
        self._client = client

    async def issue(
        self,
        subject: str,
        public_key: str,
        expires_in_seconds: int,
        meta: Optional[Dict[str, Any]] = None,
    ) -> CaIssueResult:
        """
        Issue a certificate signed by this project's CA.

        Works with both pqcert and x509 CA formats.
        Cost: 1 token.

        Parameters
        ----------
        subject : str
            Entity identifier. Max 256 characters.
        public_key : str
            Base64-encoded ML-DSA-65 public key (1952 bytes decoded).
        expires_in_seconds : int
            Certificate lifetime. Min 60, max 157_680_000 (5 years).
        meta : dict, optional
            Up to 10 key-value pairs (pqcert only).

        Returns
        -------
        CaIssueResult
            .certificate — PQCert (pqcert) or PEM string (x509)
            .meta        — certId, caId, subject, issuedAt, expiresAt, format
            .usage       — token balance

        Examples
        --------
        >>> result = await pq.ca.issue("device-001", pub_key_b64, 86400 * 365)
        >>> cert_id = result.meta.certId
        """
        body: Dict[str, Any] = {
            "subject":          subject,
            "publicKey":        public_key,
            "expiresInSeconds": expires_in_seconds,
        }
        if meta is not None:
            body["meta"] = meta

        data = await self._client._request("POST", "/ca/issue", json=body)
        m    = data["meta"]
        u    = data["usage"]

        return CaIssueResult(
            certificate = _parse_certificate(data["certificate"]),
            meta        = CaIssueMeta(
                certId    = m["certId"],
                caId      = m["caId"],
                subject   = m["subject"],
                issuedAt  = m["issuedAt"],
                expiresAt = m["expiresAt"],
                algorithm = m["algorithm"],
                standard  = m["standard"],
                format    = m.get("format", "pqcert"),
            ),
            usage = CaIssueUsage(
                freeRemaining  = u["freeRemaining"],
                packRemaining  = u["packRemaining"],
                totalRemaining = u["totalRemaining"],
            ),
        )

    async def revoke_cert(
        self, cert_id: str, reason: Optional[str] = None
    ) -> CaRevokeCertResult:
        """
        Revoke a certificate immediately.

        Cost: 1 token.

        Parameters
        ----------
        cert_id : str
            The certificate ID. For pqcert: PQCert.id. For x509: CaIssueMeta.certId.
        reason : str, optional
            Human-readable reason for revocation.

        Examples
        --------
        >>> await pq.ca.revoke_cert("cert_...", "device decommissioned")
        """
        body: Dict[str, Any] = {"certId": cert_id}
        if reason is not None:
            body["reason"] = reason

        data = await self._client._request("POST", "/ca/revoke", json=body)
        u    = data["usage"]
        return CaRevokeCertResult(
            certId    = data["certId"],
            revokedAt = data["revokedAt"],
            reason    = data.get("reason"),
            usage     = CaIssueUsage(
                freeRemaining  = u["freeRemaining"],
                packRemaining  = u["packRemaining"],
                totalRemaining = u["totalRemaining"],
            ),
        )

    async def get_cert(self, cert_id: str) -> CaGetCertResult:
        """
        Get a certificate by ID. Free — no token cost.

        Parameters
        ----------
        cert_id : str
            The certificate ID. For pqcert: PQCert.id. For x509: CaIssueMeta.certId.

        Returns
        -------
        CaGetCertResult
            .certificate — PQCert (pqcert) or PEM string (x509)
            .status      — revoked, expired, revokedAt, expiresAt

        Examples
        --------
        >>> result = await pq.ca.get_cert("cert_...")
        >>> if result.status.revoked:
        ...     raise PermissionError("Certificate revoked")
        """
        data = await self._client._request("GET", f"/ca/certificate/{cert_id}")
        s    = data["status"]
        return CaGetCertResult(
            certificate = _parse_certificate(data["certificate"]),
            status      = CaCertStatus(
                revoked   = s["revoked"],
                expired   = s["expired"],
                revokedAt = s.get("revokedAt"),
                expiresAt = s["expiresAt"],
            ),
        )

    async def get_crl(self) -> CaGetCrlResult:
        """
        Get the Certificate Revocation List. Free — no token cost.

        Returns
        -------
        CaGetCrlResult
            .crl    — list of CrlEntry (certId, revokedAt, reason)
            .format — "pqcert" or "x509"
            .raw    — for x509: full signed CRL object with ML-DSA-65 signature

        Examples
        --------
        >>> crl = await pq.ca.get_crl()
        >>> for entry in crl.crl:
        ...     print(entry.certId, entry.revokedAt)
        """
        data    = await self._client._request("GET", "/ca/crl")
        raw_crl = data.get("crl")

        if isinstance(raw_crl, dict):
            entries = [
                CrlEntry(
                    certId    = e["certId"],
                    revokedAt = e["revokedAt"],
                    reason    = e.get("reason"),
                )
                for e in raw_crl.get("revokedCerts", [])
            ]
            return CaGetCrlResult(
                caId        = raw_crl.get("caId",        data.get("caId",    "")),
                subject     = raw_crl.get("subject",     data.get("subject", "")),
                crl         = entries,
                generatedAt = raw_crl.get("generatedAt", data.get("generatedAt", 0)),
                format      = raw_crl.get("format", "x509"),
                raw         = raw_crl,
            )
        else:
            entries = [
                CrlEntry(
                    certId    = e["certId"],
                    revokedAt = e["revokedAt"],
                    reason    = e.get("reason"),
                )
                for e in (raw_crl or [])
            ]
            return CaGetCrlResult(
                caId        = data.get("caId",        ""),
                subject     = data.get("subject",     ""),
                crl         = entries,
                generatedAt = data.get("generatedAt", 0),
                format      = "pqcert",
                raw         = None,
            )

    def is_cert_revoked(
        self,
        cert: Union[PQCert, str],
        crl: List[CrlEntry],
    ) -> bool:
        """
        Check if a certificate appears in a CRL. Offline — no API call.

        Parameters
        ----------
        cert : PQCert | str
            PQCert object (uses .id) or certId string (for x509).
        crl : list[CrlEntry]
            The CRL entries from get_crl().crl.

        Returns
        -------
        bool
            True if the certificate has been revoked.

        Examples
        --------
        >>> crl = await pq.ca.get_crl()
        >>> if pq.ca.is_cert_revoked(result.meta.certId, crl.crl):
        ...     raise PermissionError("Revoked")
        """
        cert_id = cert if isinstance(cert, str) else cert.id
        return any(entry.certId == cert_id for entry in crl)


# ─── AsyncPQAuth ──────────────────────────────────────────────────────────────

class AsyncPQAuth:
    """
    Async version of PQAuth. Use with ``async with`` or call ``await pq.aclose()`` when done.

    Examples
    --------
    >>> async with AsyncPQAuth("pqa_your_key") as pq:
    ...     result = await pq.sign("user_123", role="admin")
    ...     v      = await pq.verify(result.token)
    ...
    ...     # CA operations
    ...     cert   = await pq.ca.issue("device-001", pub_key_b64, 86400 * 365)
    ...     crl    = await pq.ca.get_crl()
    ...     if pq.ca.is_cert_revoked(cert.certificate, crl.crl):
    ...         raise PermissionError("Revoked")
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str  = DEFAULT_BASE_URL,
        timeout:  float = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key or not api_key.startswith("pqa_"):
            raise PQAuthError(
                'Invalid API key — keys must start with "pqa_". '
                "Get one at https://app.fipsign.dev",
                "INVALID_API_KEY",
            )
        self._api_key  = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout  = timeout
        self._http     = httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "X-API-Key":    self._api_key,
            },
            timeout=timeout,
        )
        self.webhooks = AsyncWebhooks(self)
        self.ca       = AsyncCA(self)

    async def __aenter__(self) -> "AsyncPQAuth":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(
        self,
        method: str,
        path:   str,
        *,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            resp = await self._http.request(method, url, json=json)
        except httpx.TimeoutException:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except httpx.NetworkError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")

        try:
            data = resp.json()
        except ValueError:
            raise PQAuthError(
                f"Request failed with status {resp.status_code}",
                "API_ERROR",
                resp.status_code,
            )

        if not resp.is_success or not data.get("success", False):
            raise PQAuthError(
                data.get("error") or f"Request failed with status {resp.status_code}",
                "API_ERROR",
                resp.status_code,
            )

        return data

    async def sign(
        self,
        sub: str,
        *,
        expires_in_seconds: Optional[int] = None,
        **fields: Any,
    ) -> SignResult:
        """
        Sign any payload with ML-DSA-65. Cost: 1 token.

        Parameters
        ----------
        sub : str
            Required. Entity identifier. Max 128 characters.
        expires_in_seconds : int, optional
            Token lifetime in seconds. Default: 3600 (1 hour).
        **fields
            Any additional custom fields (max 10).

        Examples
        --------
        >>> result = await pq.sign("user_123", role="admin", expires_in_seconds=3600)
        """
        if not sub:
            raise PQAuthError('"sub" is required', "MISSING_SUB")
        body: Dict[str, Any] = {"sub": sub, **fields}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = expires_in_seconds
        data = await self._request("POST", "/sign", json=body)
        t, m, u = data["token"], data["meta"], data["usage"]
        return SignResult(
            token = PQToken(
                payload   = t["payload"],
                signature = t["signature"],
                algorithm = t["algorithm"],
                issuedAt  = t["issuedAt"],
            ),
            meta  = SignMeta(
                algorithm        = m["algorithm"],
                standard         = m["standard"],
                quantumResistant = m["quantumResistant"],
                expiresIn        = m["expiresIn"],
                issuedFor        = m["issuedFor"],
                projectId        = m["projectId"],
                tokenCost        = m["tokenCost"],
                source           = m["source"],
            ),
            usage = SignUsage(
                freeRemaining  = u["freeRemaining"],
                packRemaining  = u["packRemaining"],
                totalRemaining = u["totalRemaining"],
                month          = u["month"],
            ),
        )

    async def verify(self, token: PQToken) -> VerifyResult:
        """
        Verify a FIPSign token. Never raises — returns valid=False on failure.

        Examples
        --------
        >>> result = await pq.verify(token)
        >>> if not result.valid:
        ...     raise PermissionError(result.error)
        """
        try:
            data = await self._request("POST", "/verify", json={"token": token.to_dict()})
            return VerifyResult(valid=True, payload=data.get("payload"))
        except PQAuthError as exc:
            return VerifyResult(valid=False, error=exc.message)
        except Exception as exc:
            return VerifyResult(valid=False, error=str(exc))

    async def revoke(self, token: PQToken, reason: Optional[str] = None) -> RevokeResult:
        """
        Revoke a token immediately. Cost: 1 token.

        Examples
        --------
        >>> await pq.revoke(token, "user logged out")
        """
        body: Dict[str, Any] = {"token": token.to_dict()}
        if reason is not None:
            body["reason"] = reason
        data = await self._request("POST", "/revoke", json=body)
        return RevokeResult(
            success   = data.get("success", False),
            message   = data.get("message", ""),
            revokedAt = data.get("revokedAt"),
            sub       = data.get("sub"),
            expiresAt = data.get("expiresAt"),
            note      = data.get("note"),
        )

    async def usage(self) -> UsageResult:
        """Get current token balance and 6-month usage history."""
        data = await self._request("GET", "/usage")
        c    = data["current"]
        return UsageResult(
            current = UsageCurrent(
                month          = c["month"],
                freeUsed       = c["freeUsed"],
                freeRemaining  = c["freeRemaining"],
                freeLimit      = c["freeLimit"],
                packRemaining  = c["packRemaining"],
                totalRemaining = c["totalRemaining"],
            ),
            monthlyHistory = [
                MonthlyEntry(
                    month      = e["month"],
                    tokensUsed = e["tokensUsed"],
                    fromFree   = e["fromFree"],
                    fromPack   = e["fromPack"],
                )
                for e in data.get("monthlyHistory", [])
            ],
            packs = [
                PackEntry(
                    id              = p["id"],
                    packType        = p["packType"],
                    tokensPurchased = p["tokensPurchased"],
                    purchasedAt     = p["purchasedAt"],
                    paymentRef      = p.get("paymentRef"),
                )
                for p in data.get("packs", [])
            ],
            developer = data.get("developer", {}),
            note      = data.get("note", ""),
        )

    async def preload_public_key(self) -> str:
        """Fetch and return the server's ML-DSA-65 public key (base64)."""
        resp = await self._http.get(f"{self._base_url}/public-key")
        return resp.json()["publicKey"]

    async def health(self) -> HealthResult:
        """Check the health of the FIPSign service."""
        try:
            resp = await self._http.get(f"{self._base_url}/health")
            data = resp.json()
        except httpx.TimeoutException:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except httpx.NetworkError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")
        return HealthResult(
            status           = data.get("status", ""),
            algorithm        = data.get("algorithm", ""),
            quantumResistant = data.get("quantumResistant", False),
            version          = data.get("version", ""),
        )

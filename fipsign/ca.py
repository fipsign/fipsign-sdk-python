"""
CA sub-client — mirrors pq.ca.* from the JS SDK.
Accessed via pq.ca.issue(...), pq.ca.get_crl(), etc.

The CA root is created once per project from the dashboard.
Use ca.issue() to certify devices, services, or any entity at scale.

Note on offline verification and key generation
------------------------------------------------
The Python SDK does not include ca.verify_cert() or generate_key_pair().
This is intentional: there is no production-ready Python library for
ML-DSA-65 (NIST FIPS 204) at this time. The JavaScript SDK uses
@noble/post-quantum, which is audited and production-ready.

For offline certificate verification and device key pair generation,
use the JavaScript fipsign-sdk:
    npm install fipsign-sdk

All server-side operations (issue, revoke, get_cert, get_crl) work
normally from Python — only the local cryptographic operations are
unavailable until a reliable Python ML-DSA-65 library matures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional

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
    PQCert,
)

if TYPE_CHECKING:
    from .client import PQAuth


class CA:
    """
    Certificate Authority sub-client.

    Usage
    -----
    pq = PQAuth("pqa_your_key")

    # Issue a certificate for a device
    result = pq.ca.issue(
        subject="device-serial-00123",
        public_key=device_public_key_b64,
        expires_in_seconds=365 * 24 * 60 * 60,
        meta={"model": "lock-v2", "batch": "2026-05"},
    )

    # Check revocation
    crl_result = pq.ca.get_crl()
    if pq.ca.is_cert_revoked(device_cert, crl_result.crl):
        raise PermissionError("Device certificate has been revoked")

    Note on offline operations
    --------------------------
    verify_cert() and generate_key_pair() are not available in the Python SDK.
    No production-ready Python library for ML-DSA-65 (NIST FIPS 204) exists yet.
    Use the JavaScript fipsign-sdk for offline certificate verification and
    device key pair generation. See https://fipsign.dev/guide for details.
    """

    def __init__(self, client: "PQAuth") -> None:
        self._client = client

    def issue(
        self,
        subject: str,
        public_key: str,
        expires_in_seconds: int,
        meta: Optional[Dict[str, Any]] = None,
    ) -> CaIssueResult:
        """
        Issue a certificate signed by this project's CA.

        Cost: 1 token.

        Parameters
        ----------
        subject : str
            Entity identifier (e.g. device serial number, service name).
            Max 256 characters.
        public_key : str
            Base64-encoded ML-DSA-65 public key of the entity to certify.
            Generate this on the device using the JS SDK's generateKeyPair().
        expires_in_seconds : int
            Certificate lifetime in seconds. Required.
            Minimum: 60 (1 minute). Maximum: 157_680_000 (5 years).
        meta : dict, optional
            Up to 10 key-value pairs stored in the certificate.

        Returns
        -------
        CaIssueResult
            .certificate — the issued PQCert
            .meta        — certId, caId, subject, issuedAt, expiresAt, algorithm, standard
            .usage       — freeRemaining, packRemaining, totalRemaining

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If expires_in_seconds is below 60 or above 157_680_000.
        PQAuthError(code="API_ERROR", status=404)
            If no active CA exists for this project. Create one from the dashboard.
        PQAuthError(code="API_ERROR", status=429)
            If token quota is exhausted.

        Examples
        --------
        >>> result = pq.ca.issue(
        ...     subject="lock-serial-00123",
        ...     public_key=device_public_key_b64,
        ...     expires_in_seconds=365 * 24 * 60 * 60,
        ...     meta={"model": "lock-v3", "batch": "2026-05"},
        ... )
        """
        body: Dict[str, Any] = {
            "subject":          subject,
            "publicKey":        public_key,
            "expiresInSeconds": expires_in_seconds,
        }
        if meta is not None:
            body["meta"] = meta

        data = self._client._request("POST", "/ca/issue", json=body)
        c = data["certificate"]
        m = data["meta"]
        u = data["usage"]

        return CaIssueResult(
            certificate=PQCert.from_dict(c),
            meta=CaIssueMeta(
                certId    = m["certId"],
                caId      = m["caId"],
                subject   = m["subject"],
                issuedAt  = m["issuedAt"],
                expiresAt = m["expiresAt"],
                algorithm = m["algorithm"],
                standard  = m["standard"],
            ),
            usage=CaIssueUsage(
                freeRemaining  = u["freeRemaining"],
                packRemaining  = u["packRemaining"],
                totalRemaining = u["totalRemaining"],
            ),
        )

    def revoke_cert(self, cert_id: str, reason: Optional[str] = None) -> CaRevokeCertResult:
        """
        Revoke a certificate immediately.

        Cost: 1 token. The certificate will appear in the CRL from this point on.

        Parameters
        ----------
        cert_id : str
            The certificate ID (cert_...).
        reason : str, optional
            Human-readable reason for revocation.

        Returns
        -------
        CaRevokeCertResult
            .certId, .revokedAt, .reason, .usage

        Raises
        ------
        PQAuthError(code="API_ERROR", status=409)
            If the certificate is already revoked.

        Examples
        --------
        >>> pq.ca.revoke_cert("cert_...", "device decommissioned")
        """
        body: Dict[str, Any] = {"certId": cert_id}
        if reason is not None:
            body["reason"] = reason

        data = self._client._request("POST", "/ca/revoke", json=body)
        u = data["usage"]
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

    def get_cert(self, cert_id: str) -> CaGetCertResult:
        """
        Get a certificate by ID.

        Free — no token cost.

        Use this when you need the real-time revocation status of a specific
        certificate — for example, before authorizing a high-value operation.
        For bulk offline checks, use get_crl() + is_cert_revoked() instead.

        Parameters
        ----------
        cert_id : str
            The certificate ID (cert_...).

        Returns
        -------
        CaGetCertResult
            .certificate — the PQCert
            .status      — revoked, expired, revokedAt, expiresAt

        Raises
        ------
        PQAuthError(code="API_ERROR", status=404)
            If the certificate does not exist or belongs to a different project.

        Examples
        --------
        >>> result = pq.ca.get_cert("cert_...")
        >>> print(result.status.revoked)
        """
        data = self._client._request("GET", f"/ca/certificate/{cert_id}")
        s = data["status"]
        return CaGetCertResult(
            certificate = PQCert.from_dict(data["certificate"]),
            status      = CaCertStatus(
                revoked   = s["revoked"],
                expired   = s["expired"],
                revokedAt = s.get("revokedAt"),
                expiresAt = s["expiresAt"],
            ),
        )

    def get_crl(self) -> CaGetCrlResult:
        """
        Get the Certificate Revocation List for this project's CA.

        Free — no token cost.

        Use get_crl() when you need to verify revocation offline or in bulk —
        download the list once and check multiple certificates against it locally
        using is_cert_revoked(). For a single real-time check, use get_cert().

        Returns
        -------
        CaGetCrlResult
            .caId, .subject, .crl (list of CrlEntry), .generatedAt

        Notes
        -----
        CrlEntry.reason may be None if no reason was provided at revocation time.

        Examples
        --------
        >>> result = pq.ca.get_crl()
        >>> print(f"{len(result.crl)} revoked certificates")
        >>> for entry in result.crl:
        ...     print(f"{entry.certId} — {entry.reason or 'no reason'}")
        """
        data = self._client._request("GET", "/ca/crl")
        return CaGetCrlResult(
            caId        = data["caId"],
            subject     = data["subject"],
            crl         = [
                CrlEntry(
                    certId    = e["certId"],
                    revokedAt = e["revokedAt"],
                    reason    = e.get("reason"),
                )
                for e in data.get("crl", [])
            ],
            generatedAt = data["generatedAt"],
        )

    def is_cert_revoked(self, cert: PQCert, crl: List[CrlEntry]) -> bool:
        """
        Check if a certificate appears in a CRL.

        Offline — pass the result of get_crl().crl.

        Parameters
        ----------
        cert : PQCert
            The certificate to check.
        crl : list[CrlEntry]
            The CRL entries from get_crl().crl.

        Returns
        -------
        bool
            True if the certificate has been revoked.

        Examples
        --------
        >>> crl_result = pq.ca.get_crl()
        >>> if pq.ca.is_cert_revoked(device_cert, crl_result.crl):
        ...     raise PermissionError("Device revoked")
        """
        return any(entry.certId == cert.id for entry in crl)

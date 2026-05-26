"""
CA sub-client — mirrors pq.ca.* from the JS SDK.
Accessed via pq.ca.issue(...), pq.ca.verify_cert(...), etc.

The CA root is created once per project from the dashboard.
Use ca.issue() to certify devices, services, or any entity at scale.
"""

from __future__ import annotations

import base64
import json
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
    VerifyCertResult,
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

    # Verify a certificate offline
    result = pq.ca.verify_cert(device_cert, root_cert)
    if not result.valid:
        raise PermissionError(result.error)

    # Check revocation
    crl_result = pq.ca.get_crl()
    if pq.ca.is_cert_revoked(device_cert, crl_result.crl):
        raise PermissionError("Device certificate has been revoked")
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
        expires_in_seconds : int
            Certificate lifetime in seconds. Required. Max 5 years (157_680_000).
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
        PQAuthError(code="API_ERROR", status=404)
            If no active CA exists for this project.
        PQAuthError(code="API_ERROR", status=429)
            If the active certificate limit is reached or token quota is exhausted.

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

        Parameters
        ----------
        cert_id : str
            The certificate ID (cert_...).

        Returns
        -------
        CaGetCertResult
            .certificate — the PQCert
            .status      — revoked, expired, revokedAt, expiresAt

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

        Returns
        -------
        CaGetCrlResult
            .caId, .subject, .crl (list of CrlEntry), .generatedAt

        Examples
        --------
        >>> result = pq.ca.get_crl()
        >>> print(f"{len(result.crl)} revoked certificates")
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

    def verify_cert(self, cert: PQCert, root_cert: PQCert) -> VerifyCertResult:
        """
        Verify a certificate offline using the CA root certificate.

        No API call — pure Python verification using the canonicalized
        certificate payload and the root CA's public key.

        Does NOT check revocation — call get_crl() and is_cert_revoked() for that.

        Parameters
        ----------
        cert : PQCert
            The certificate to verify (type must be CA_CERT).
        root_cert : PQCert
            The CA root certificate (type must be CA_ROOT).

        Returns
        -------
        VerifyCertResult
            .valid, .cert (if valid), .error (if not valid)

        Examples
        --------
        >>> result = pq.ca.verify_cert(device_cert, root_cert)
        >>> if not result.valid:
        ...     raise PermissionError(result.error)
        """
        try:
            _verify_cert_locally(cert, root_cert)
            return VerifyCertResult(valid=True, cert=cert)
        except PQAuthError as err:
            return VerifyCertResult(valid=False, error=err.message)
        except Exception as err:
            return VerifyCertResult(valid=False, error=str(err))

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


# ─── Local certificate verification ──────────────────────────────────────────

def _canonicalize(cert_dict: Dict[str, Any]) -> str:
    """JSON with keys sorted alphabetically — mirrors the JS canonicalize()."""
    return json.dumps(cert_dict, sort_keys=True, separators=(",", ":"))


def _from_base64(b64: str) -> bytes:
    return base64.b64decode(b64)


def _verify_cert_locally(cert: PQCert, root_cert: PQCert) -> None:
    """
    Verify a PQCert signature using the root CA public key.
    Raises PQAuthError on any failure.
    """
    import time as _time

    if cert.type != "CA_CERT":
        raise PQAuthError(
            f"Expected a CA_CERT, got {cert.type}", "INVALID_CERT_TYPE"
        )
    if root_cert.type != "CA_ROOT":
        raise PQAuthError(
            f"Expected a CA_ROOT, got {root_cert.type}", "INVALID_CERT_TYPE"
        )
    if cert.caId != root_cert.id:
        raise PQAuthError(
            "Certificate was not issued by this CA", "CA_MISMATCH"
        )

    now = int(_time.time())
    if cert.expiresAt is not None and cert.expiresAt < now:
        raise PQAuthError(
            f"Certificate expired {now - cert.expiresAt} seconds ago",
            "CERT_EXPIRED",
        )

    # Reconstruct the canonical payload — same as JS backend
    cert_dict = cert.to_dict()
    cert_dict.pop("signature")
    canonical = _canonicalize(cert_dict)

    try:
        from dilithium_py.ml_dsa import ML_DSA_65  # type: ignore
    except ImportError:
        raise PQAuthError(
            "offline certificate verification requires dilithium-py. "
            "Install it with: pip install dilithium-py",
            "MISSING_DEPENDENCY",
        )

    pub_key   = _from_base64(root_cert.publicKey)
    signature = _from_base64(cert.signature)
    msg       = canonical.encode("utf-8")

    is_valid = ML_DSA_65.verify(pub_key, msg, signature)
    if not is_valid:
        raise PQAuthError(
            "Invalid certificate signature — not issued by this CA",
            "INVALID_CERT_SIGNATURE",
        )
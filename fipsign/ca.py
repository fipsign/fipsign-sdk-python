"""
CA sub-client — mirrors pq.ca.* from the JS SDK.
Accessed via pq.ca.issue(...), pq.ca.get_crl(), etc.

The CA root is created once per project from the dashboard.
Use ca.issue() to certify devices, services, or any entity at scale.

Two CA formats are supported:

  pqcert  FIPSign's native JSON certificate format. certificate field is a
          PQCert dataclass. Fully supported in Python.

  x509    Standard X.509 v3 with ML-DSA-65 signature. certificate field is
          a PEM string. All server-side operations (issue, revoke, get_cert,
          get_crl) are fully supported in Python.

Note on offline cryptographic operations
-----------------------------------------
The following JS SDK methods are NOT available in the Python SDK:

  generateKeyPair()
      Generates an ML-DSA-65 keypair for a device or entity.
      Not available because there is no Python library with the same
      audit profile as @noble/post-quantum (used by the JS SDK).

      Alternative: use the JS SDK on the device side (Node.js, browser,
      firmware). Or use pyca/cryptography >= 44.0.0 directly:

          from cryptography.hazmat.primitives.asymmetric.mldsa import (
              MLDSAPrivateKey, generate_private_key
          )
          from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65
          private_key = generate_private_key(MLDSA65())
          public_key  = private_key.public_key()
          # Serialize public key to base64 for ca.issue():
          import base64
          from cryptography.hazmat.primitives.serialization import (
              Encoding, PublicFormat
          )
          pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
          pub_b64   = base64.b64encode(pub_bytes).decode()

  ca.verifyCert(cert, root_cert)
      Verifies a PQCert certificate signature offline (no API call).
      Not available: requires ML-DSA-65 local crypto.

      Alternative for pqcert format: verify server-side via ca.get_cert()
      which returns the live revocation status. Or use the JS SDK.

  ca.verifyX509Cert(cert_pem, root_pem)
      Verifies an X.509 PEM certificate offline (no API call).
      Not available: requires ML-DSA-65 local crypto + ASN.1 parsing.

      Alternative for x509 format: use pyca/cryptography >= 44.0.0:

          from cryptography import x509
          from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65
          from cryptography.hazmat.primitives.serialization import load_pem_public_key
          import base64

          # Load root cert to get its public key
          root_cert   = x509.load_pem_x509_certificate(root_pem.encode())
          root_pub    = root_cert.public_key()

          # Load leaf cert and verify its signature
          leaf_cert   = x509.load_pem_x509_certificate(leaf_pem.encode())
          tbs_der     = leaf_cert.tbs_certificate_bytes
          signature   = leaf_cert.signature
          root_pub.verify(signature, tbs_der, MLDSA65())
          # Raises InvalidSignature on failure, returns None on success.

The typical FIPSign workflow is:
  1. Device generates keypair with JS SDK (generateKeyPair())
  2. Server issues cert with Python SDK (pq.ca.issue())
  3. Device verifies cert with JS SDK (pq.ca.verifyCert() or verifyX509Cert())
  4. Server checks revocation with Python SDK (pq.ca.get_crl() + is_cert_revoked())

All server-side operations work fully from Python. The JS SDK handles device-side
cryptography. Both SDKs share the same API key and backend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

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
    _parse_certificate,
)

if TYPE_CHECKING:
    from .client import PQAuth


class CA:
    """
    Certificate Authority sub-client.

    Supports both pqcert and x509 CA formats transparently.
    The format is determined at CA creation time (dashboard) and cannot change.

    Usage
    -----
    pq = PQAuth("pqa_your_key")

    # Issue a certificate for a device (works for both pqcert and x509 CAs)
    result = pq.ca.issue(
        subject="device-serial-00123",
        public_key=device_public_key_b64,
        expires_in_seconds=365 * 24 * 60 * 60,
        meta={"model": "lock-v2", "batch": "2026-05"},
    )

    # pqcert CA: result.certificate is a PQCert dataclass
    # x509 CA:   result.certificate is a PEM string

    # Check revocation (works for both formats)
    crl_result = pq.ca.get_crl()
    if pq.ca.is_cert_revoked(result.certificate, crl_result.crl):
        raise PermissionError("Device certificate has been revoked")

    # For x509: is_cert_revoked also accepts a certId string
    if pq.ca.is_cert_revoked(result.meta.certId, crl_result.crl):
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

        Works with both pqcert and x509 CA formats. The returned
        ``certificate`` field reflects the CA format:
          - pqcert CA → PQCert dataclass
          - x509 CA   → PEM string (-----BEGIN CERTIFICATE-----)

        Cost: 1 token.

        Parameters
        ----------
        subject : str
            Entity identifier (e.g. device serial number, service name).
            Max 256 characters.
        public_key : str
            Base64-encoded ML-DSA-65 public key of the entity to certify.
            Must be exactly 1952 bytes when decoded (ML-DSA-65 public key size).

            Generate on the device using the JS SDK:
                const { publicKey, secretKey } = await generateKeyPair()

            Or using pyca/cryptography >= 44.0.0 (see module docstring).
        expires_in_seconds : int
            Certificate lifetime in seconds. Required.
            Minimum: 60 (1 minute). Maximum: 157_680_000 (5 years).
        meta : dict, optional
            Up to 10 key-value pairs stored in the certificate (pqcert only).
            Ignored for x509 CAs.

        Returns
        -------
        CaIssueResult
            .certificate — PQCert (pqcert) or PEM string (x509)
            .meta        — certId, caId, subject, issuedAt, expiresAt,
                           algorithm, standard, format
            .usage       — freeRemaining, packRemaining, totalRemaining

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If expires_in_seconds is below 60 or above 157_680_000,
            or if the public_key is not a valid 1952-byte ML-DSA-65 key.
        PQAuthError(code="API_ERROR", status=404)
            If no active CA exists for this project. Create one from the dashboard.
        PQAuthError(code="API_ERROR", status=429)
            If token quota is exhausted.

        Examples
        --------
        >>> # pqcert CA
        >>> result = pq.ca.issue(
        ...     subject="lock-serial-00123",
        ...     public_key=device_public_key_b64,
        ...     expires_in_seconds=365 * 24 * 60 * 60,
        ...     meta={"model": "lock-v3", "batch": "2026-05"},
        ... )
        >>> cert = result.certificate  # PQCert
        >>> print(cert.id)

        >>> # x509 CA
        >>> result = pq.ca.issue(
        ...     subject="device-serial-00123",
        ...     public_key=device_public_key_b64,
        ...     expires_in_seconds=365 * 24 * 60 * 60,
        ... )
        >>> pem = result.certificate  # str — PEM
        >>> cert_id = result.meta.certId
        """
        body: Dict[str, Any] = {
            "subject":          subject,
            "publicKey":        public_key,
            "expiresInSeconds": expires_in_seconds,
        }
        if meta is not None:
            body["meta"] = meta

        data = self._client._request("POST", "/ca/issue", json=body)
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

    def revoke_cert(self, cert_id: str, reason: Optional[str] = None) -> CaRevokeCertResult:
        """
        Revoke a certificate immediately.

        Works with both pqcert and x509 CA formats.
        Cost: 1 token. The certificate will appear in the CRL from this point on.

        Parameters
        ----------
        cert_id : str
            The certificate ID (cert_...).
            For pqcert: use PQCert.id
            For x509:   use CaIssueMeta.certId returned by ca.issue()
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
        >>> # pqcert CA
        >>> pq.ca.revoke_cert(cert.id, "device decommissioned")

        >>> # x509 CA
        >>> pq.ca.revoke_cert(result.meta.certId, "device decommissioned")
        """
        body: Dict[str, Any] = {"certId": cert_id}
        if reason is not None:
            body["reason"] = reason

        data = self._client._request("POST", "/ca/revoke", json=body)
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

    def get_cert(self, cert_id: str) -> CaGetCertResult:
        """
        Get a certificate by ID.

        Free — no token cost.
        Works with both pqcert and x509 CA formats.

        Use this when you need the real-time revocation status of a specific
        certificate — for example, before authorizing a high-value operation.
        For bulk offline checks, use get_crl() + is_cert_revoked() instead.

        Parameters
        ----------
        cert_id : str
            The certificate ID (cert_...).
            For pqcert: use PQCert.id
            For x509:   use CaIssueMeta.certId

        Returns
        -------
        CaGetCertResult
            .certificate — PQCert (pqcert) or PEM string (x509)
            .status      — revoked, expired, revokedAt, expiresAt

        Raises
        ------
        PQAuthError(code="API_ERROR", status=404)
            If the certificate does not exist or belongs to a different project.

        Examples
        --------
        >>> result = pq.ca.get_cert("cert_...")
        >>> if result.status.revoked:
        ...     raise PermissionError("Certificate revoked")
        """
        data = self._client._request("GET", f"/ca/certificate/{cert_id}")
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

    def get_crl(self) -> CaGetCrlResult:
        """
        Get the Certificate Revocation List for this project's CA.

        Free — no token cost.
        Works with both pqcert and x509 CA formats.

        Use get_crl() when you need to verify revocation offline or in bulk —
        download the list once and check multiple certificates against it locally
        using is_cert_revoked(). For a single real-time check, use get_cert().

        Returns
        -------
        CaGetCrlResult
            .caId        — CA identifier
            .subject     — CA subject string
            .crl         — list of CrlEntry (certId, revokedAt, reason)
            .generatedAt — Unix timestamp
            .format      — "pqcert" or "x509"
            .raw         — for x509 CAs: the full signed CRL object including
                           the ML-DSA-65 signature. None for pqcert CAs.

        Notes
        -----
        For x509 CAs, the CRL is signed with ML-DSA-65 by the CA private key.
        To verify the CRL signature offline, use pyca/cryptography >= 44.0.0
        with the root CA public key (see module docstring for details).

        CrlEntry.reason may be None if no reason was provided at revocation time.

        Examples
        --------
        >>> result = pq.ca.get_crl()
        >>> print(f"{len(result.crl)} revoked certificates")
        >>> for entry in result.crl:
        ...     print(f"{entry.certId} — revoked at {entry.revokedAt}")
        """
        data = self._client._request("GET", "/ca/crl")

        # The backend returns different shapes for pqcert vs x509:
        #
        # pqcert: { success, caId, subject, crl: [ {certId, revokedAt, reason} ], generatedAt }
        #
        # x509:   { success, crl: { caId, subject, format, algorithm, generatedAt,
        #                           revokedCerts: [ {certId, revokedAt, reason} ],
        #                           signature }, generatedAt }
        #
        # We normalize both into CaGetCrlResult with a flat crl: List[CrlEntry].

        raw_crl = data.get("crl")

        if isinstance(raw_crl, dict):
            # x509 format — nested object with revokedCerts
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
            # pqcert format — flat list
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
        Check if a certificate appears in a CRL.

        Offline — pass the result of get_crl().crl.
        Works with both pqcert and x509 CA formats.

        Parameters
        ----------
        cert : PQCert | str
            For pqcert CAs: pass the PQCert dataclass (uses PQCert.id).
            For x509 CAs:   pass the certId string (from CaIssueMeta.certId).
            Also accepts a PQCert for x509 CAs if you have it (uses PQCert.id).
        crl : list[CrlEntry]
            The CRL entries from get_crl().crl.

        Returns
        -------
        bool
            True if the certificate has been revoked.

        Examples
        --------
        >>> crl_result = pq.ca.get_crl()

        >>> # pqcert CA — pass the PQCert object
        >>> if pq.ca.is_cert_revoked(device_cert, crl_result.crl):
        ...     raise PermissionError("Device revoked")

        >>> # x509 CA — pass the certId string
        >>> if pq.ca.is_cert_revoked(result.meta.certId, crl_result.crl):
        ...     raise PermissionError("Device revoked")

        >>> # x509 CA — also works if you pass a PQCert (uses its .id)
        >>> if pq.ca.is_cert_revoked(device_pqcert, crl_result.crl):
        ...     raise PermissionError("Device revoked")
        """
        cert_id = cert if isinstance(cert, str) else cert.id
        return any(entry.certId == cert_id for entry in crl)

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

generate_key_pair()
-------------------
Available as a top-level function in this module. Generates an ML-DSA-65
key pair using pyca/cryptography >= 48.0.0 (required). Works out of the
box with a standard ``pip install cryptography`` since cryptography 48.0.0
ships wheels with OpenSSL 4.0.0 which includes ML-DSA support.

    from fipsign.ca import generate_key_pair

    kp = generate_key_pair()
    # kp.publicKey — base64(1952 bytes) — pass to ca.issue()
    # kp.secretKey — base64(32 bytes, seed form) — store on device

    # To sign from Python using secretKey:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    import base64
    private_key = MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(kp.secretKey))
    signature   = private_key.sign(message)

**secretKey format note:** The ``secretKey`` returned by ``generate_key_pair()``
is the 32-byte ML-DSA-65 seed — NOT the 4032-byte expanded key returned by
the JS SDK's ``generateKeyPair()``. The formats are not interchangeable.
If the device signs using the JS SDK, generate the key pair with
``generateKeyPair()`` from the JS SDK instead.

Note on offline cryptographic operations
-----------------------------------------
ca.verify_cert(cert, root_cert)
    Verifies a PQCert certificate signature offline (no API call).
    Never raises — returns VerifyCertResult(valid, cert, error).

ca.verify_x509_cert(cert_pem, root_pem)
    Verifies an X.509 PEM certificate offline (no API call).
    Uses pyca/cryptography directly (included as a dependency).
    Never raises — returns VerifyCertResult(valid, cert, error).
    Mirrors ca.verifyX509Cert() from the JS SDK.

The typical FIPSign workflow is:
  1. Server (or device setup script) generates keypair with generate_key_pair()
  2. Server issues cert with Python SDK (pq.ca.issue())
  3. Server or device verifies cert with pq.ca.verify_cert() (PQCert)
     or pq.ca.verify_x509_cert() (X.509)
  4. Server checks revocation with Python SDK (pq.ca.get_crl() + is_cert_revoked())

All operations work fully from Python.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from .errors import PQAuthError
from .types import (
    CaGetCertMeta,
    CaGetCertResult,
    CaGetCrlResult,
    CaIssueMeta,
    CaIssueResult,
    CaIssueUsage,
    CaRevokeCertResult,
    CaCertStatus,
    CrlEntry,
    KeyPairResult,
    PQCert,
    VerifyCertResult,
    _parse_certificate,
)

if TYPE_CHECKING:
    from .client import PQAuth

# OID for ML-DSA-65 per RFC 9881
_OID_ML_DSA_65 = "2.16.840.1.101.3.4.3.18"


# ─── generate_key_pair() ──────────────────────────────────────────────────────

def generate_key_pair() -> KeyPairResult:
    """
    Generate an ML-DSA-65 key pair for a device or entity.

    Requires ``pyca/cryptography >= 48.0.0``. Install with::

        pip install "cryptography>=48.0.0"

    The standard ``pip install cryptography`` gives you 48.0.0 or later,
    which ships wheels with OpenSSL 4.0.0 — ML-DSA support is included
    out of the box.

    Returns
    -------
    KeyPairResult
        .publicKey — base64(1952 bytes). Pass to ``pq.ca.issue()``.
                     Compatible with the FIPSign backend and the JS SDK.
        .secretKey — base64(32 bytes, seed form). Store securely on the device.
                     **Not** the 4032-byte expanded key returned by the JS SDK.

    Notes
    -----
    The ``secretKey`` is the 32-byte ML-DSA-65 seed, not the expanded key.
    The JS SDK's ``generateKeyPair()`` returns a 4032-byte expanded key.
    These formats are NOT interchangeable.

    Use this function when the device runs Python. If the device runs
    JavaScript (Node.js, browser, firmware), use ``generateKeyPair()``
    from the JS SDK instead — the JS secretKey cannot be reconstructed
    from the Python secretKey.

    To sign from Python using the returned secretKey::

        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
        import base64

        private_key = MLDSA65PrivateKey.from_seed_bytes(
            base64.b64decode(kp.secretKey)
        )
        signature = private_key.sign(message)  # bytes

    Examples
    --------
    Server-side device provisioning:

    >>> kp = generate_key_pair()
    >>> # kp.secretKey: store on device (32-byte seed, base64)
    >>> result = pq.ca.issue(
    ...     subject="device-serial-00123",
    ...     public_key=kp.publicKey,   # 1952 bytes raw, base64
    ...     expires_in_seconds=365 * 24 * 60 * 60,
    ... )

    Raises
    ------
    ImportError
        If ``cryptography`` is not installed or version < 48.0.0.
    cryptography.exceptions.UnsupportedAlgorithm
        If the installed cryptography build does not support ML-DSA
        (requires OpenSSL 3.5+ / AWS-LC / BoringSSL backend).
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    except ImportError:
        raise ImportError(
            "generate_key_pair() requires cryptography >= 48.0.0. "
            "Install with: pip install 'cryptography>=48.0.0'"
        )

    private_key = MLDSA65PrivateKey.generate()
    public_key  = private_key.public_key()

    pub_b64  = base64.b64encode(public_key.public_bytes_raw()).decode()
    seed_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()

    return KeyPairResult(publicKey=pub_b64, secretKey=seed_b64)


# ─── CA sub-client ────────────────────────────────────────────────────────────

class CA:
    """
    Certificate Authority sub-client.

    Supports both pqcert and x509 CA formats transparently.
    The format is determined at CA creation time (dashboard) and cannot change.

    Usage
    -----
    pq = PQAuth("pqa_your_key")

    # Generate a key pair for a device (Python server-side)
    from fipsign.ca import generate_key_pair
    kp = generate_key_pair()

    # Issue a certificate for a device (works for both pqcert and x509 CAs)
    result = pq.ca.issue(
        subject="device-serial-00123",
        public_key=kp.publicKey,
        expires_in_seconds=365 * 24 * 60 * 60,
        meta={"model": "lock-v2", "batch": "2026-05"},  # pqcert only
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

            Generate using generate_key_pair() from this module, or from
            the JS SDK: ``const { publicKey, secretKey } = await generateKeyPair()``
        expires_in_seconds : int
            Certificate lifetime in seconds. Required.
            Minimum: 60 (1 minute). Maximum: 157_680_000 (5 years).
        meta : dict, optional
            Up to 10 key-value pairs stored in the certificate (pqcert only).
            Passing meta to an x509 CA returns a 400 error from the backend.

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
            if the public_key is not a valid 1952-byte ML-DSA-65 key,
            or if meta is passed to an x509 CA.
        PQAuthError(code="API_ERROR", status=404)
            If no active CA exists for this project.
        PQAuthError(code="API_ERROR", status=429)
            If token quota is exhausted.

        Examples
        --------
        >>> # pqcert CA
        >>> result = pq.ca.issue(
        ...     subject="lock-serial-00123",
        ...     public_key=kp.publicKey,
        ...     expires_in_seconds=365 * 24 * 60 * 60,
        ...     meta={"model": "lock-v3", "batch": "2026-05"},
        ... )
        >>> cert = result.certificate  # PQCert
        >>> print(cert.id)

        >>> # x509 CA
        >>> result = pq.ca.issue(
        ...     subject="device-serial-00123",
        ...     public_key=kp.publicKey,
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
            .certId, .revokedAt, .reason, .usage, .format

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
            format = data.get("format"),  # "x509" for X.509 CAs, absent for pqcert
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
            .meta        — certId, caId, subject, format, algorithm
                           (x509 CAs only; None for pqcert)

        Raises
        ------
        PQAuthError(code="API_ERROR", status=404)
            If the certificate does not exist or belongs to a different project.

        Examples
        --------
        >>> result = pq.ca.get_cert("cert_...")
        >>> if result.status.revoked:
        ...     raise PermissionError("Certificate revoked")
        >>>
        >>> # X.509 CA: access additional metadata
        >>> if result.meta:
        ...     print(result.meta.certId)
        """
        data = self._client._request("GET", f"/ca/certificate/{cert_id}")
        s    = data["status"]

        raw_meta = data.get("meta")
        parsed_meta: Optional[CaGetCertMeta] = None
        if raw_meta is not None:
            parsed_meta = CaGetCertMeta(
                certId    = raw_meta["certId"],
                caId      = raw_meta["caId"],
                subject   = raw_meta["subject"],
                format    = raw_meta["format"],
                algorithm = raw_meta["algorithm"],
            )

        return CaGetCertResult(
            certificate = _parse_certificate(data["certificate"]),
            status      = CaCertStatus(
                revoked   = s["revoked"],
                expired   = s["expired"],
                revokedAt = s.get("revokedAt"),
                expiresAt = s["expiresAt"],
            ),
            meta = parsed_meta,
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
                           the ML-DSA-65 signature field. None for pqcert CAs.

        Notes
        -----
        For x509 CAs, the CRL is signed with ML-DSA-65 by the CA private key.
        The raw signed object (including ``signature``) is available in
        ``result.raw`` if you need to verify the CRL signature offline.

        CrlEntry.reason may be None if no reason was provided at revocation time.

        Examples
        --------
        >>> result = pq.ca.get_crl()
        >>> print(f"{len(result.crl)} revoked certificates")
        >>> for entry in result.crl:
        ...     print(f"{entry.certId} — revoked at {entry.revokedAt}")
        >>>
        >>> # X.509 CA: verify CRL signature independently
        >>> if result.raw:
        ...     print(result.raw["signature"][:16] + "...")
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

    def verify_cert(
        self,
        cert: PQCert,
        root_cert: PQCert,
    ) -> "VerifyCertResult":
        """
        Verify a PQCert certificate offline using the CA root certificate.

        No API call — verifies the ML-DSA-65 signature locally using
        pyca/cryptography (included as a dependency).

        Does NOT check revocation — call get_crl() + is_cert_revoked() for that.
        Never raises — always returns a VerifyCertResult.

        This method is for PQCert format only. For X.509 certificates use
        ca.verify_x509_cert() instead.

        Parameters
        ----------
        cert : PQCert
            The leaf certificate to verify (type must be "CA_CERT").
        root_cert : PQCert
            The root CA certificate (type must be "CA_ROOT"). This is the
            certificate shown once at CA creation time — store it securely.

        Returns
        -------
        VerifyCertResult
            .valid — True if the signature is valid and cert has not expired.
            .cert  — The verified PQCert dataclass. None when valid=False.
            .error — Error message when valid=False:
                'Expected a CA_CERT certificate'
                'Expected a CA_ROOT certificate'
                'Certificate was not issued by this CA (caId mismatch)'
                'Certificate has expired'
                'Invalid certificate signature'

        Examples
        --------
        >>> import json
        >>> with open("root-cert.json") as f:
        ...     root_cert = PQCert.from_dict(json.load(f))
        >>>
        >>> result = pq.ca.verify_cert(device_cert, root_cert)
        >>> if not result.valid:
        ...     raise PermissionError(result.error)
        >>> print(result.cert.subject)   # "device-serial-00123"
        >>> print(result.cert.expiresAt) # Unix timestamp
        >>>
        >>> # Then check revocation
        >>> crl = pq.ca.get_crl()
        >>> if pq.ca.is_cert_revoked(device_cert, crl.crl):
        ...     raise PermissionError("Certificate revoked")
        """
        import json as _json
        import time as _time

        from .types import VerifyCertResult

        try:
            # ── Type checks ───────────────────────────────────────────────────
            if cert.type != "CA_CERT":
                return VerifyCertResult(
                    valid=False,
                    error="Expected a CA_CERT certificate",
                )
            if root_cert.type != "CA_ROOT":
                return VerifyCertResult(
                    valid=False,
                    error="Expected a CA_ROOT certificate",
                )

            # ── caId match ────────────────────────────────────────────────────
            if cert.caId != root_cert.id:
                return VerifyCertResult(
                    valid=False,
                    error="Certificate was not issued by this CA (caId mismatch)",
                )

            # ── Expiry check ──────────────────────────────────────────────────
            now = int(_time.time())
            if cert.expiresAt is not None and cert.expiresAt < now:
                return VerifyCertResult(
                    valid=False,
                    error=f"Certificate has expired",
                )

            # ── Canonical message — mirrors backend ca.ts canonicalize() ──────
            # Backend (fixed): recursive sortedKeys() that covers all nested fields.
            # All fields including meta are covered by the ML-DSA-65 signature.
            # Python equivalent: recursively sort all keys at every level,
            # no spaces (JSON.stringify default), UTF-8 encoding.
            def sorted_keys_recursive(obj):
                if isinstance(obj, list):
                    return [sorted_keys_recursive(v) for v in obj]
                if isinstance(obj, dict):
                    return {k: sorted_keys_recursive(obj[k]) for k in sorted(obj.keys())}
                return obj

            cert_dict = cert.to_dict()
            cert_dict.pop("signature", None)          # exclude signature field
            canonical = _json.dumps(sorted_keys_recursive(cert_dict), separators=(",", ":"))
            msg_bytes = canonical.encode("utf-8")

            # ── Signature verification ────────────────────────────────────────
            from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
            from cryptography.exceptions import InvalidSignature

            pub_key_bytes = base64.b64decode(root_cert.publicKey)
            sig_bytes     = base64.b64decode(cert.signature)

            public_key = MLDSA65PublicKey.from_public_bytes(pub_key_bytes)
            public_key.verify(sig_bytes, msg_bytes)  # raises InvalidSignature on failure

            return VerifyCertResult(valid=True, cert=cert)

        except InvalidSignature:
            return VerifyCertResult(
                valid=False,
                error="Invalid certificate signature",
            )
        except Exception as exc:
            return VerifyCertResult(
                valid=False,
                error=str(exc),
            )

    def verify_x509_cert(
        self,
        cert_pem: str,
        root_pem: str,
    ) -> "VerifyCertResult":
        """
        Verify an X.509 ML-DSA-65 certificate offline using the root CA PEM.

        No API call — uses pyca/cryptography (included as a dependency).
        Does NOT check revocation — call get_crl() + is_cert_revoked() for that.
        Never raises — always returns a VerifyCertResult.

        This method is for X.509 format only. For PQCert certificates use
        ca.verify_cert() instead.

        Mirrors ``ca.verifyX509Cert()`` from the JS SDK.

        Parameters
        ----------
        cert_pem : str
            The leaf certificate PEM string to verify (-----BEGIN CERTIFICATE-----...).
            This is the ``certificate`` field returned by ``ca.issue()`` for X.509 CAs.
        root_pem : str
            The root CA PEM string shown once at CA creation time.
            Store it securely — treat it like a private key.

        Returns
        -------
        VerifyCertResult
            .valid — True if the signature is valid and cert has not expired.
            .cert  — The verified PEM string (cert_pem). None when valid=False.
            .error — Error message when valid=False. One of:
                'Certificate has expired'
                'Invalid certificate signature — not signed by this root CA'
                'Unsupported signature algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'
                'Unsupported root CA algorithm: <OID>. Expected ML-DSA-65 (2.16.840.1.101.3.4.3.18)'

        Examples
        --------
        >>> root_pem = os.environ["FIPSIGN_ROOT_CERT_PEM"]
        >>>
        >>> result = pq.ca.verify_x509_cert(cert_pem, root_pem)
        >>> if not result.valid:
        ...     raise PermissionError(result.error)
        >>> print(result.cert[:27])  # "-----BEGIN CERTIFICATE-----"
        >>>
        >>> # Then check revocation using certId from ca.issue()
        >>> crl = pq.ca.get_crl()
        >>> if pq.ca.is_cert_revoked(cert_id, crl.crl):
        ...     raise PermissionError("Certificate revoked")
        """
        from .types import VerifyCertResult

        try:
            from cryptography import x509
            from cryptography.exceptions import InvalidSignature
        except ImportError:
            return VerifyCertResult(
                valid=False,
                error="verify_x509_cert() requires cryptography >= 48.0.0. "
                      "Install with: pip install 'cryptography>=48.0.0'",
            )

        try:
            # ── Load both certificates ────────────────────────────────────────
            leaf_cert = x509.load_pem_x509_certificate(cert_pem.encode())
            root_cert = x509.load_pem_x509_certificate(root_pem.encode())

            # ── Check leaf certificate expiry ─────────────────────────────────
            import datetime
            now = datetime.datetime.now(datetime.timezone.utc)
            if leaf_cert.not_valid_after_utc < now:
                return VerifyCertResult(
                    valid=False,
                    error="Certificate has expired",
                )

            # ── Verify leaf certificate algorithm OID ─────────────────────────
            leaf_oid = leaf_cert.signature_algorithm_oid.dotted_string
            if leaf_oid != _OID_ML_DSA_65:
                return VerifyCertResult(
                    valid=False,
                    error=(
                        f"Unsupported signature algorithm: {leaf_oid}. "
                        f"Expected ML-DSA-65 ({_OID_ML_DSA_65})"
                    ),
                )

            # ── Verify root CA algorithm OID ──────────────────────────────────
            root_oid = root_cert.signature_algorithm_oid.dotted_string
            if root_oid != _OID_ML_DSA_65:
                return VerifyCertResult(
                    valid=False,
                    error=(
                        f"Unsupported root CA algorithm: {root_oid}. "
                        f"Expected ML-DSA-65 ({_OID_ML_DSA_65})"
                    ),
                )

            # ── Verify leaf certificate signature using root CA public key ─────
            # root_cert.public_key() returns an MLDSA65PublicKey for ML-DSA-65 certs.
            # MLDSA65PublicKey.verify(signature, data) — no algorithm parameter,
            # unlike ECDSA/RSA. Raises InvalidSignature on failure, None on success.
            root_cert.public_key().verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
            )

            return VerifyCertResult(valid=True, cert=cert_pem)

        except InvalidSignature:
            return VerifyCertResult(
                valid=False,
                error="Invalid certificate signature — not signed by this root CA",
            )
        except Exception as exc:
            return VerifyCertResult(
                valid=False,
                error=str(exc),
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
            Also accepts a certId string for pqcert CAs.
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

        >>> # certId string also works for pqcert CAs
        >>> if pq.ca.is_cert_revoked(result.meta.certId, crl_result.crl):
        ...     raise PermissionError("Device revoked")
        """
        cert_id = cert if isinstance(cert, str) else cert.id
        return any(entry.certId == cert_id for entry in crl)

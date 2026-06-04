"""
fipsign-sdk · Post-quantum signing SDK for Python.
Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.

Sign anything: users, orders, documents, devices, events.
The only required field is `sub` — any string identifying the entity.

CA formats supported:
  pqcert — FIPSign native JSON certificate format
  x509   — Standard X.509 v3 with ML-DSA-65, interoperable with OpenSSL 3.5+

Key pair generation:
  generate_key_pair() — generates an ML-DSA-65 key pair using pyca/cryptography >= 48.0.0.
  publicKey: 1952-byte raw key (base64), compatible with ca.issue() and the JS SDK.
  secretKey: 32-byte seed (base64) — see KeyPairResult docstring for signing usage.
"""

from .client import PQAuth
from .async_client import AsyncPQAuth
from .errors import PQAuthError
from .middleware import flask_middleware, fastapi_middleware
from .ca import generate_key_pair
from .types import (
    # Token
    PQToken,
    # Key pair
    KeyPairResult,
    # sign()
    SignResult, SignMeta, SignUsage,
    # verify()
    VerifyResult,
    # revoke()
    RevokeResult,
    # usage()
    UsageResult, UsageCurrent, MonthlyEntry, PackEntry,
    # webhooks
    WebhookResult, WebhookGetResult, WebhookInfo,
    # health
    HealthResult,
    # CA
    PQCert, CaFormat,
    CaIssueResult, CaIssueMeta, CaIssueUsage,
    CaRevokeCertResult,
    CaGetCertResult, CaGetCertMeta, CaCertStatus,
    CaGetCrlResult, CrlEntry,
    VerifyCertResult,
)

__all__ = [
    "PQAuth",
    "AsyncPQAuth",
    "PQAuthError",
    "flask_middleware",
    "fastapi_middleware",
    "generate_key_pair",
    # Token
    "PQToken",
    # Key pair
    "KeyPairResult",
    # sign()
    "SignResult", "SignMeta", "SignUsage",
    # verify()
    "VerifyResult",
    # revoke()
    "RevokeResult",
    # usage()
    "UsageResult", "UsageCurrent", "MonthlyEntry", "PackEntry",
    # webhooks
    "WebhookResult", "WebhookGetResult", "WebhookInfo",
    # health
    "HealthResult",
    # CA
    "PQCert", "CaFormat",
    "CaIssueResult", "CaIssueMeta", "CaIssueUsage",
    "CaRevokeCertResult",
    "CaGetCertResult", "CaGetCertMeta", "CaCertStatus",
    "CaGetCrlResult", "CrlEntry",
    "VerifyCertResult",
]

__version__ = "0.9.1"

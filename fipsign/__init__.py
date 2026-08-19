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

from typing import TYPE_CHECKING

from .client import PQAuth
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
    # zes
    ZesSignResult, ZesVerifyResult,
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
    # Mandate
    Mandate, MandateStatus,
    MandateEmitResult, MandateEmitMandate, MandateEmitUsage,
    MandateVerifyResult, MandatePatchResult,
    MandateGetResult, MandateListResult,
)

if TYPE_CHECKING:
    # Solo se importa para type checkers estaticos (mypy, autocompletado).
    # En runtime, AsyncPQAuth se importa de forma perezosa via __getattr__
    # mas abajo, para que `import fipsign` / `from fipsign import PQAuth`
    # funcionen sin httpx instalado -- httpx solo hace falta si de verdad
    # se usa AsyncPQAuth.
    from .async_client import AsyncPQAuth

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
    # zes
    "ZesSignResult", "ZesVerifyResult",
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
    # Mandate
    "Mandate", "MandateStatus",
    "MandateEmitResult", "MandateEmitMandate", "MandateEmitUsage",
    "MandateVerifyResult", "MandatePatchResult",
    "MandateGetResult", "MandateListResult",
]


def __getattr__(name: str):
    """
    Import perezoso a nivel de modulo (PEP 562). AsyncPQAuth exige httpx
    (dependencia opcional -- pip install fipsign-sdk[async]); importarla
    sin condicion aca rompia `import fipsign` para quien solo usa el
    cliente sync y nunca instalo el extra [async].
    """
    if name == "AsyncPQAuth":
        from .async_client import AsyncPQAuth
        return AsyncPQAuth
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


try:
    from importlib.metadata import version as _version
    __version__ = _version("fipsign-sdk")
except Exception:
    __version__ = "0.9.5"  # fallback si el paquete no está instalado

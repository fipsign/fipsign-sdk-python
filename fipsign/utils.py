"""
Internal utility functions for fipsign-sdk.
Not part of the public API.
"""

from __future__ import annotations
import hashlib
import json
import re
from typing import Any, Optional

from .errors import PQAuthError
from .types import VerifyResult


def canonicalize_for_signing(obj: Any) -> str:
    """
    Canonicalize an object for ML-DSA-65 signature verification.

    Recursively sorts all dict keys at every level, then serializes to JSON
    with no spaces. Must be byte-identical to the backend canonicalizeJson()
    (utils.ts) and the JS SDK canonicalizeForSigning().

    Used internally by CA.verify_cert() and AsyncCA.verify_cert().
    """
    def sorted_keys_recursive(o: Any) -> Any:
        if isinstance(o, list):
            return [sorted_keys_recursive(v) for v in o]
        if isinstance(o, dict):
            return {k: sorted_keys_recursive(o[k]) for k in sorted(o.keys())}
        return o

    return json.dumps(sorted_keys_recursive(obj), separators=(",", ":"))


def zes_hash(data: Any) -> str:
    """
    SHA-256 hex digest of the canonicalized form of ``data``.

    Used by Zes.sign()/Zes.verify() and AsyncZes.sign()/AsyncZes.verify()
    (Zero-Exposure Signing). Byte-identical to the JS SDK's zes hash and
    the manual recipe documented in the REST guide (section 03b), since
    both use the same recursive key-sort as canonicalize_for_signing().
    """
    return hashlib.sha256(canonicalize_for_signing(data).encode()).hexdigest()


def parse_retry_after(value: Optional[str]) -> Optional[int]:
    """Retry-After as a whole number of seconds (the only form FIPSign sends); anything else is ignored."""
    if value is None:
        return None
    text = value.strip()
    return int(text) if re.fullmatch(r"[0-9]+", text) else None


def api_error(status: int, data: Any, retry_after: Optional[int]) -> PQAuthError:
    """The error for an answer that is not a success: keeps the server's ``code`` and Retry-After."""
    body = data if isinstance(data, dict) else {}
    server_code = body.get("code")
    return PQAuthError(
        body.get("error") or f"Request failed with status {status}",
        "API_ERROR",
        status,
        server_code=server_code if isinstance(server_code, str) else None,
        retry_after=retry_after,
    )


def verify_failure_result(status: int, data: Any, retry_after: Optional[int]) -> VerifyResult:
    """
    What a failed POST /verify answer means: the token was refused, or FIPSign could not decide.

    401 with ``"valid": false`` is a token that was looked at and refused (the other 401, an invalid
    API key, has no ``valid`` field); 400 is a token object that is not well formed; 429 is a rate
    limit or an exhausted quota; anything else means FIPSign could not answer.
    """
    body = data if isinstance(data, dict) else {}
    message = body.get("error") or f"Request failed with status {status}"
    if status == 429:
        if body.get("code") == "token_quota_exhausted":
            return VerifyResult(valid=False, error=message, failure="quota_exhausted")
        return VerifyResult(valid=False, error=message, failure="rate_limited", retry_after=retry_after)
    if (status == 401 and body.get("valid") is False) or status == 400:
        return VerifyResult(valid=False, error=message, failure="rejected")
    return VerifyResult(valid=False, error=message, failure="unavailable")

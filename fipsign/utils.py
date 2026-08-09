"""
Internal utility functions for fipsign-sdk.
Not part of the public API.
"""

from __future__ import annotations
import hashlib
import json
from typing import Any


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

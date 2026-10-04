"""
Internal utility functions for fipsign-sdk.
Not part of the public API.
"""

from __future__ import annotations
import hashlib
import json
import math
import re
from typing import Any, Optional

from .errors import PQAuthError
from .types import VerifyResult


_NEEDS_ESCAPE = re.compile('[\x00-\x1f"\\\\\ud800-\udfff]')
_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _js_quote(s: str) -> str:
    """A string the way JSON.stringify writes it: only ", \\, control characters and lone surrogates are escaped."""
    def escape(m: "re.Match[str]") -> str:
        c = m.group(0)
        return _SHORT_ESCAPES.get(c) or "\\u%04x" % ord(c)
    return '"' + _NEEDS_ESCAPE.sub(escape, s) + '"'


def _js_number(x: Any) -> str:
    """A number the way JSON.stringify writes it (ECMAScript Number::toString): 10.0 -> 10, 0.00001 -> 0.00001, 1e21 -> 1e+21."""
    if isinstance(x, int):
        if -(2 ** 53) <= x <= 2 ** 53:
            return str(x)
        try:
            x = float(x)          # JS reads every number as a double
        except OverflowError:
            return "null"
    if x != x or x in (math.inf, -math.inf):
        return "null"             # what JSON.stringify writes for NaN and Infinity
    if x == 0:
        return "0"                # also for -0.0
    sign = "-" if x < 0 else ""
    mantissa, _, exponent = repr(abs(x)).partition("e")      # repr() gives the shortest digits that read back the same, as JS does
    int_part, _, frac_part = mantissa.partition(".")
    raw = int_part + frac_part
    digits = raw.strip("0")
    n = len(int_part) + (int(exponent) if exponent else 0) - (len(raw) - len(raw.lstrip("0")))   # the value is 0.DIGITS x 10^n
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        tail = "e" + ("+" if e >= 0 else "-") + str(abs(e))
        body = digits + tail if k == 1 else digits[0] + "." + digits[1:] + tail
    return sign + body


def _js_key_order(keys: Any) -> list:
    """The order in which JS lists the keys of an object whose keys were added in sorted order: the keys that are
    array indexes ("0", "1", "10", up to 4294967294) first, in numeric order, then the others by UTF-16 code unit."""
    def is_index(k: str) -> bool:
        return k.isascii() and k.isdigit() and (k == "0" or k[0] != "0") and int(k) <= 4294967294
    index_keys = sorted((k for k in keys if is_index(k)), key=int)
    other_keys = sorted((k for k in keys if not is_index(k)), key=lambda k: k.encode("utf-16-be", "surrogatepass"))
    return index_keys + other_keys


def _js_canonical(o: Any) -> str:
    if o is None:
        return "null"
    if o is True:
        return "true"
    if o is False:
        return "false"
    if isinstance(o, str):
        return _js_quote(o)
    if isinstance(o, (int, float)):
        return _js_number(o)
    if isinstance(o, (list, tuple)):
        return "[" + ",".join(_js_canonical(v) for v in o) + "]"
    if isinstance(o, dict):
        items = {(k if isinstance(k, str) else json.dumps(k)): v for k, v in o.items()}
        return "{" + ",".join(_js_quote(k) + ":" + _js_canonical(items[k]) for k in _js_key_order(items)) + "}"
    raise TypeError("Object of type %s is not JSON serializable" % type(o).__name__)


def canonicalize_for_signing(obj: Any) -> str:
    r"""
    Canonicalize an object for ML-DSA-65 signature verification and for the ZES hash.

    The text is exactly what the backend (canonicalizeJson() in utils.ts) and the JS SDK produce: the keys of every
    object sorted recursively, then JSON.stringify. That is not what json.dumps writes, so this does not use it:

    - non-ASCII characters are written as they are, not as \uXXXX escapes;
    - numbers are written as JavaScript writes them (10.0 is 10, 0.00001 is 0.00001, 1e21 is 1e+21);
    - keys that look like array indexes ("2", "10") come first, in numeric order, as JS lists them; the other keys follow
      in UTF-16 code unit order;
    - NaN and Infinity are written as null, and lone surrogates are escaped.

    Used internally by CA.verify_cert(), AsyncCA.verify_cert() and zes_hash().
    """
    return _js_canonical(obj)


def zes_hash(data: Any) -> str:
    """
    SHA-256 hex digest of the canonicalized form of ``data``.

    Used by Zes.sign()/Zes.verify() and AsyncZes.sign()/AsyncZes.verify()
    (Zero-Exposure Signing). Byte-identical to the JS SDK's zes hash and
    the manual recipe documented in the REST guide (section 03b), since
    both use the same recursive key-sort as canonicalize_for_signing().
    """
    return hashlib.sha256(canonicalize_for_signing(data).encode("utf-8")).hexdigest()


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

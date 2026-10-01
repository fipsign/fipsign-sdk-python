"""
PQAuthError — raised by all methods except verify().
verify() never raises; it always returns a VerifyResult with valid=False on failure
(and ``failure`` says why: see VerifyFailure).
"""

from __future__ import annotations
from typing import Optional


class PQAuthError(Exception):
    """
    Raised when a FIPSign API call fails or the SDK detects a local error.

    Attributes
    ----------
    message : str
        Human-readable description of the error.
    code : str
        Machine-readable error code. One of:
            INVALID_API_KEY     — key missing or doesn't start with ``pqa_`` followed by 64 hex chars
            API_ERROR           — server returned an error (check ``status``)
            TIMEOUT             — request exceeded the configured timeout
            NETWORK_ERROR       — connection failed
            MISSING_SUB         — sign() called without ``sub`` field
    status : int | None
        HTTP status code returned by the server, if applicable.
    server_code : str | None
        The ``code`` field of the server's error answer, when it has one. Today:
        ``"rate_limited"`` (too many requests in the current minute) or
        ``"token_quota_exhausted"`` (free tokens and packs used up). ``code`` stays
        ``"API_ERROR"`` for both.
    retry_after : int | None
        Seconds to wait, from the ``Retry-After`` header of the server's answer.
        Sent with ``"rate_limited"``.
    """

    def __init__(
        self,
        message: str,
        code: str,
        status: Optional[int] = None,
        server_code: Optional[str] = None,
        retry_after: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status
        self.server_code = server_code
        self.retry_after = retry_after

    def __repr__(self) -> str:
        return f"PQAuthError(code={self.code!r}, status={self.status!r}, message={self.message!r})"

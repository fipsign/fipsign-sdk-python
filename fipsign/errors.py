"""
PQAuthError — raised by all methods except verify().
verify() never raises; it always returns a VerifyResult with valid=False on failure.
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
    """

    def __init__(self, message: str, code: str, status: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status

    def __repr__(self) -> str:
        return f"PQAuthError(code={self.code!r}, status={self.status!r}, message={self.message!r})"

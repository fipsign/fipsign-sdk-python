"""
ZES (Zero-Exposure Signing) sub-client — mirrors pq.zes.* from the JS SDK.
Accessed via pq.zes.sign(...), pq.zes.verify(...).

Hashes data locally (SHA-256, recursive key sort via canonicalize_for_signing)
and signs only the hash — the original data never reaches the API. This is a
convenience wrapper over sign()/verify(); the same effect can be achieved by
calling those directly with sub="zes:<hash>" and zes=True — see REST guide
section 03b for the full explanation of the pattern.

revoke(), middleware, and everything else work unchanged with a ZES token —
it is a regular token as far as they are concerned. There is no zes.revoke():
use pq.revoke(token) directly, same as any other token. zes.verify() also
respects the caller's normal verify() behaviour, so any future local/offline
verification support would apply to it automatically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

from .utils import zes_hash
from .types import PQToken, ZesSignResult, ZesVerifyResult

if TYPE_CHECKING:
    from .client import PQAuth


class Zes:
    """
    ZES (Zero-Exposure Signing) sub-client.

    Usage
    -----
    pq = PQAuth("pqa_your_key")

    result = pq.zes.sign({"patient": "Jane Doe", "diagnosis": "confidential"})
    # result.hash  — the 64-char SHA-256 hex digest that was signed
    # result.token — pass to zes.verify() or revoke() like any token

    check = pq.zes.verify(result.token, {"patient": "Jane Doe", "diagnosis": "confidential"})
    if not check.valid or not check.dataMatches:
        raise PermissionError("invalid or tampered")
    """

    def __init__(self, client: "PQAuth") -> None:
        self._client = client

    def sign(self, data: Any, *, expires_in_seconds: Optional[int] = None) -> ZesSignResult:
        """
        Hash ``data`` locally with SHA-256 (keys sorted recursively —
        nested objects too) and sign only the hash. Costs 1 token, same
        as sign().

        Parameters
        ----------
        data : Any
            JSON-serializable data to hash. Never sent to the API.
        expires_in_seconds : int, optional
            Token lifetime in seconds. Default: 3600 (1 hour).

        Returns
        -------
        ZesSignResult
            .token — pass to zes.verify() or revoke()
            .hash  — the SHA-256 hex digest that was signed
            .meta, .usage — same as SignResult

        Examples
        --------
        >>> result = pq.zes.sign({"patient": "Jane Doe", "diagnosis": "confidential"})
        """
        digest = zes_hash(data)

        kwargs: Dict[str, Any] = {"zes": True}
        if expires_in_seconds is not None:
            kwargs["expires_in_seconds"] = expires_in_seconds

        result = self._client.sign("zes:" + digest, **kwargs)

        return ZesSignResult(
            token=result.token,
            hash=digest,
            meta=result.meta,
            usage=result.usage,
        )

    def verify(self, token: PQToken, data: Any) -> ZesVerifyResult:
        """
        Re-hash ``data`` locally and verify the token, confirming the
        hash inside the token matches. ``data`` is never sent to the API.

        Parameters
        ----------
        token : PQToken
            The token returned by zes.sign().
        data : Any
            The data to check against the token's hash.

        Returns
        -------
        ZesVerifyResult
            .valid       — True if the token is cryptographically valid
            .dataMatches — True if data hashes to the same value in the token
            .payload, .error — same as VerifyResult

        Examples
        --------
        >>> check = pq.zes.verify(token, {"patient": "Jane Doe", "diagnosis": "confidential"})
        >>> if not check.valid or not check.dataMatches:
        ...     raise PermissionError("invalid or tampered")
        """
        digest = zes_hash(data)
        result = self._client.verify(token)

        data_matches = bool(
            result.valid
            and result.payload is not None
            and result.payload.get("sub") == "zes:" + digest
        )

        return ZesVerifyResult(
            valid=result.valid,
            dataMatches=data_matches,
            payload=result.payload,
            error=result.error,
        )

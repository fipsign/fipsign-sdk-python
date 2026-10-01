"""
Middleware helpers for Flask and FastAPI.

Flask
-----
from fipsign import flask_middleware

pq = PQAuth("pqa_your_key")

@app.route("/api/profile")
@flask_middleware(pq)
def profile():
    from flask import g
    return {"user": g.fipsign_user}


FastAPI
-------
from fipsign import fastapi_middleware
from fastapi import Depends

pq = PQAuth("pqa_your_key")
require_auth = fastapi_middleware(pq)

@app.get("/api/profile")
def profile(user=Depends(require_auth)):
    return {"sub": user["sub"]}
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json as _json
from typing import Any, Callable, Optional

from .client import PQAuth
from .types import PQToken


# ─── Flask ────────────────────────────────────────────────────────────────────

def flask_middleware(pq: PQAuth) -> Callable:
    """
    Flask route decorator that verifies a FIPSign Bearer token.

    Reads ``Authorization: Bearer <base64(token_json)>`` from the request.
    On success, sets ``flask.g.fipsign_user`` to the decoded payload dict.

    Answers 401 only when the token is refused (``failure="rejected"``), or when the
    Authorization header is missing or not a token. When FIPSign could not check the
    token (rate limit, quota, timeout, network, server error, invalid API key) it answers
    503 with ``{"error": "Authentication service temporarily unavailable"}``, plus a
    ``Retry-After`` header when the wait is known, so the user is not logged out for
    something that is not their fault. To log the real cause, call ``pq.verify()``
    yourself and read ``error`` and ``failure``.

    Parameters
    ----------
    pq : PQAuth
        An authenticated PQAuth client.

    Returns
    -------
    Callable
        A decorator you apply to individual Flask route functions.

    Examples
    --------
    >>> @app.route("/api/profile")
    ... @flask_middleware(pq)
    ... def profile():
    ...     from flask import g
    ...     return {"user": g.fipsign_user}
    """
    try:
        from flask import g, jsonify, request
    except ImportError:
        raise ImportError(
            "flask_middleware requires Flask. Install it with: pip install flask"
        )

    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return (
                    jsonify({"error": "Authorization header required (Bearer <token>)"}),
                    401,
                )

            try:
                raw        = base64.b64decode(auth_header[7:]).decode("utf-8")
                token_data = _json.loads(raw)
                token      = PQToken.from_dict(token_data)
            except Exception:
                return jsonify({"error": "Invalid token format"}), 401

            result = pq.verify(token)
            if not result.valid:
                if result.failure is None or result.failure == "rejected":
                    return jsonify({"error": result.error or "Invalid token"}), 401
                # FIPSign could not check the token: it is not to blame, so not a 401 (the app would log the user out).
                response = jsonify({"error": "Authentication service temporarily unavailable"})
                response.status_code = 503
                if result.retry_after is not None:
                    response.headers["Retry-After"] = str(result.retry_after)
                return response

            g.fipsign_user = result.payload
            return f(*args, **kwargs)

        return wrapper

    return decorator


# ─── FastAPI ──────────────────────────────────────────────────────────────────

def fastapi_middleware(pq: PQAuth) -> Callable:
    """
    FastAPI dependency that verifies a FIPSign Bearer token.

    Use with ``Depends()``. Returns the decoded payload dict on success.

    Raises ``HTTPException(401)`` only when the token is refused (``failure="rejected"``), or
    when the Authorization header is missing or not a token. When FIPSign could not check the
    token (rate limit, quota, timeout, network, server error, invalid API key) it raises
    ``HTTPException(503)`` with the detail "Authentication service temporarily unavailable",
    plus a ``Retry-After`` header when the wait is known, so the user is not logged out for
    something that is not their fault. To log the real cause, call ``pq.verify()`` yourself
    and read ``error`` and ``failure``.

    Parameters
    ----------
    pq : PQAuth
        An authenticated PQAuth client.

    Returns
    -------
    Callable
        A FastAPI dependency callable, ready to use with ``Depends()``.

    Examples
    --------
    >>> require_auth = fastapi_middleware(pq)
    >>>
    >>> @app.get("/api/profile")
    ... def profile(user = Depends(require_auth)):
    ...     return {"sub": user["sub"], "role": user.get("role")}
    """
    try:
        from fastapi import Depends, HTTPException
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    except ImportError:
        raise ImportError(
            "fastapi_middleware requires FastAPI. Install it with: pip install fastapi"
        )

    security = HTTPBearer(auto_error=False)

    def dependency(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> dict:
        if credentials is None or not credentials.credentials:
            raise HTTPException(status_code=401, detail="Authorization header required")

        try:
            raw        = base64.b64decode(credentials.credentials).decode("utf-8")
            token_data = _json.loads(raw)
            token      = PQToken.from_dict(token_data)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token format")

        result = pq.verify(token)
        if not result.valid:
            if result.failure is None or result.failure == "rejected":
                raise HTTPException(status_code=401, detail=result.error or "Invalid token")
            # FIPSign could not check the token: it is not to blame, so not a 401 (the app would log the user out).
            raise HTTPException(
                status_code=503,
                detail="Authentication service temporarily unavailable",
                headers={"Retry-After": str(result.retry_after)} if result.retry_after is not None else None,
            )

        return result.payload

    return dependency


# ─── Webhook signature verification helper ────────────────────────────────────

def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """
    Verify the HMAC-SHA256 signature on an incoming webhook request.

    Parameters
    ----------
    payload_bytes : bytes
        Raw request body bytes (do not decode before passing).
    signature_header : str
        Value of the ``X-PQAuth-Signature`` header (format: ``sha256=<hex>``).
    secret : str
        The webhook secret shown at registration time.

    Returns
    -------
    bool
        True if the signature is valid.

    Examples
    --------
    Flask:

    >>> @app.route("/webhooks/fipsign", methods=["POST"])
    ... def webhook():
    ...     sig = request.headers.get("X-PQAuth-Signature", "")
    ...     if not verify_webhook_signature(request.data, sig, WEBHOOK_SECRET):
    ...         abort(401)
    ...     event = request.json
    ...     ...

    FastAPI:

    >>> @app.post("/webhooks/fipsign")
    ... async def webhook(request: Request):
    ...     body = await request.body()
    ...     sig = request.headers.get("X-PQAuth-Signature", "")
    ...     if not verify_webhook_signature(body, sig, WEBHOOK_SECRET):
    ...         raise HTTPException(401)
    ...     event = await request.json()
    ...     ...
    """
    if not signature_header.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature_header, expected)

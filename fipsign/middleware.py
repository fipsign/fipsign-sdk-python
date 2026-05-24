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

import functools
from typing import Any, Callable, Optional

from .client import PQAuth
from .types import PQToken


# ─── Flask ────────────────────────────────────────────────────────────────────

def flask_middleware(pq: PQAuth) -> Callable:
    """
    Flask route decorator that verifies a FIPSign Bearer token.

    Reads ``Authorization: Bearer <base64(token_json)>`` from the request.
    On success, sets ``flask.g.fipsign_user`` to the decoded payload dict.
    On failure, returns a 401 JSON response.

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
            import base64
            import json as _json

            try:
                raw = base64.b64decode(auth_header[7:]).decode("utf-8")
                token_data = _json.loads(raw)
                token = PQToken.from_dict(token_data)
            except Exception:
                return jsonify({"error": "Invalid token format"}), 401

            result = pq.verify(token)
            if not result.valid:
                return jsonify({"error": result.error or "Invalid token"}), 401

            g.fipsign_user = result.payload
            return f(*args, **kwargs)

        return wrapper

    return decorator


# ─── FastAPI ──────────────────────────────────────────────────────────────────

def fastapi_middleware(pq: PQAuth) -> Callable:
    """
    FastAPI dependency that verifies a FIPSign Bearer token.

    Use with ``Depends()``. Raises ``HTTPException(401)`` on invalid tokens.
    Returns the decoded payload dict on success.

    Parameters
    ----------
    pq : PQAuth
        An authenticated PQAuth client.

    Returns
    -------
    Callable
        A FastAPI dependency callable.

    Examples
    --------
    >>> require_auth = fastapi_middleware(pq)
    >>>
    >>> @app.get("/api/profile")
    ... def profile(user = Depends(require_auth)):
    ...     return {"sub": user["sub"], "role": user.get("role")}
    """
    try:
        from fastapi import Header, HTTPException
        from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
    except ImportError:
        raise ImportError(
            "fastapi_middleware requires FastAPI. Install it with: pip install fastapi"
        )

    security = HTTPBearer(auto_error=False)

    def verify_token(
        credentials: Optional[Any] = None,
    ) -> dict:
        import base64
        import json as _json
        from fastapi import Depends, HTTPException
        from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

        if credentials is None or not credentials.credentials:
            raise HTTPException(status_code=401, detail="Authorization header required")

        try:
            raw = base64.b64decode(credentials.credentials).decode("utf-8")
            token_data = _json.loads(raw)
            token = PQToken.from_dict(token_data)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid token format")

        result = pq.verify(token)
        if not result.valid:
            raise HTTPException(status_code=401, detail=result.error or "Invalid token")

        return result.payload

    # Return a proper FastAPI dependency that uses the security scheme
    def dependency(
        credentials: Optional[Any] = __import__("fastapi", fromlist=["Depends"]).Depends(security),
    ) -> dict:
        return verify_token(credentials)

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
    import hashlib
    import hmac

    if not signature_header.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()  # type: ignore[attr-defined]

    return hmac.compare_digest(signature_header, expected)

"""
Webhooks — dashboard-only.

Webhook management (register, get, delete, test) is performed from the
FIPSign dashboard at https://app.fipsign.dev.  It requires a session
cookie, not an API key, so it is not part of the SDK.

This module is kept for the webhook-signature verification helper
(verify_webhook_signature) which lives in fipsign/middleware.py and is
still fully supported.

Event types that FIPSign can deliver to your endpoint:
  token.signed  |  token.rejected  |  token.revoked
  limit.warning  |  limit.reached

Each POST from FIPSign includes the headers:
  X-PQAuth-Event       — event type string
  X-PQAuth-Signature   — sha256=<hmac-sha256-hex>
  X-PQAuth-Timestamp   — Unix timestamp

Verify incoming requests:

    from fipsign.middleware import verify_webhook_signature

    # Flask
    @app.route("/webhooks/fipsign", methods=["POST"])
    def webhook():
        from flask import request
        sig = request.headers.get("X-PQAuth-Signature", "")
        if not verify_webhook_signature(request.data, sig, WEBHOOK_SECRET):
            return "Invalid signature", 401
        event = request.json
        # handle event["event"] ...
        return "ok", 200

    # FastAPI
    from fastapi import Request
    @app.post("/webhooks/fipsign")
    async def webhook(request: Request):
        body = await request.body()
        sig  = request.headers.get("X-PQAuth-Signature", "")
        if not verify_webhook_signature(body, sig, WEBHOOK_SECRET):
            raise HTTPException(status_code=401, detail="Invalid signature")
        event = await request.json()
        # handle event["event"] ...
        return "ok"
"""

# fipsign-sdk

Post-quantum signing SDK for Python.

Signs and verifies any payload using **ML-DSA-65** (NIST FIPS 204) — the post-quantum digital signature standard resistant to Shor's algorithm. Standardized by NIST in August 2024.

**Not just for auth.** Sign users, orders, documents, devices, events — any entity that needs a tamper-proof, quantum-resistant signature.

---

## Install

```bash
pip install fipsign-sdk
```

For async support (httpx-based):

```bash
pip install fipsign-sdk[async]
```

---

## Quick start

**1.** Create a free account at [app.fipsign.dev](https://app.fipsign.dev)
— enter your email, verify the OTP code sent to your inbox.

**2.** In the dashboard, create a project, then create an API key inside that project.
Save the key — it will not be shown again.

**3.** Use the key in your app:

```python
from fipsign import PQAuth

pq = PQAuth("pqa_your_api_key")
```

---

## sign() — Sign anything

The only required argument is `sub` — any string identifying the entity you want to sign. All other keyword arguments are stored in the payload and returned on verify. Cost: 1 token.

```python
# Sign a user session
result = pq.sign("user_123", email="user@example.com", role="admin", expires_in_seconds=3600)
token   = result.token
meta    = result.meta
usage   = result.usage

# Sign an order
result = pq.sign("order_456", amount=299.99, currency="USD", expires_in_seconds=300)

# Sign a document
result = pq.sign("doc_789", hash="sha256:abc...", signed_by="alice")

# Sign a device
result = pq.sign("device_iot_001", firmware="2.1.4")

# Monitor quota and token source
print(f"{usage.freeRemaining} free tokens remaining this month")
print(f"{usage.packRemaining} pack tokens remaining")
print(f"{usage.totalRemaining} total remaining")
print(f"charged from: {meta.source}")  # "free" | "pack" | "free+pack"
```

### sign() response shape

```
SignResult
  .token   PQToken
               .payload    str   # base64 encoded payload
               .signature  str   # ML-DSA-65 signature
               .algorithm  str   # "ML-DSA-65"
               .issuedAt   int   # Unix timestamp
  .meta    SignMeta
               .algorithm        str
               .standard         str   # "NIST FIPS 204"
               .quantumResistant bool
               .expiresIn        int   # seconds
               .issuedFor        str   # your developer account email
               .projectId        str
               .tokenCost        int   # always 1
               .source           str   # "free" | "pack" | "free+pack"
  .usage   SignUsage
               .freeRemaining  int
               .packRemaining  int
               .totalRemaining int
               .month          str   # e.g. "2026-05"
```

---

## verify() — Verify a token

**Never raises.** Returns a `VerifyResult` with `valid=False` and an `error` message on any failure.

```python
result = pq.verify(token)

if not result.valid:
    raise PermissionError(result.error)

print(result.payload["sub"])   # "user_123"
print(result.payload["exp"])   # expiry timestamp (Unix)
print(result.payload["iat"])   # issued at timestamp (Unix)
# All custom fields passed to sign() are in payload too
```

---

## revoke() — Revoke a token

Immediately and permanently invalidates a token. Future `verify()` calls will reject it even if the signature is valid and it hasn't expired. Cost: 1 token.

```python
pq.revoke(token, "user logged out")
pq.revoke(token, "order cancelled")
pq.revoke(token, "suspicious activity detected")
```

Revoking an already-revoked token returns success without consuming an extra token — the operation is idempotent.

> **Note:** Calling `revoke()` on an already-expired token raises `PQAuthError(code="API_ERROR", status=400)`.

---

## Flask middleware

```python
from flask import Flask, g
from fipsign import PQAuth, flask_middleware

app = Flask(__name__)
pq  = PQAuth("pqa_your_api_key")
auth = flask_middleware(pq)

@app.route("/login", methods=["POST"])
def login():
    import base64, json
    # authenticate user however you like, then:
    result  = pq.sign(user.id, email=user.email, role=user.role, expires_in_seconds=3600)
    encoded = base64.b64encode(json.dumps(result.token.__dict__).encode()).decode()
    return {"token": encoded}

@app.route("/logout", methods=["POST"])
def logout():
    import base64, json
    from flask import request
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        from fipsign.types import PQToken
        token = PQToken(**json.loads(base64.b64decode(header[7:]).decode()))
        pq.revoke(token, "user logged out")
    return {"success": True}

@app.route("/api/profile")
@auth
def profile():
    return {"user": g.fipsign_user}
```

---

## FastAPI middleware

```python
from fastapi import FastAPI, Depends
from fipsign import PQAuth, fastapi_middleware

app         = FastAPI()
pq          = PQAuth("pqa_your_api_key")
require_auth = fastapi_middleware(pq)

@app.get("/api/profile")
def profile(user=Depends(require_auth)):
    return {"sub": user["sub"], "role": user.get("role")}
```

---

## Async client

```python
from fipsign.async_client import AsyncPQAuth

async with AsyncPQAuth("pqa_your_api_key") as pq:
    result = await pq.sign("user_123", role="admin", expires_in_seconds=3600)
    v      = await pq.verify(result.token)
    print(v.valid, v.payload["sub"])
```

---

## usage() — Token balance

Free tokens reset on the 1st of each month (UTC). Pack tokens never expire and accumulate across purchases. No token cost.

```python
u = pq.usage()

# Current balance
print(f"Month: {u.current.month}")
print(f"Free:  {u.current.freeRemaining} / {u.current.freeLimit}")
print(f"Used:  {u.current.freeUsed} this month")
print(f"Pack:  {u.current.packRemaining}")
print(f"Total: {u.current.totalRemaining}")
print(f"Account: {u.developer['email']}")

# 6-month history (always 6 entries, months with no activity show 0)
for entry in u.monthlyHistory:
    print(f"{entry.month}: {entry.tokensUsed} used ({entry.fromFree} free + {entry.fromPack} pack)")

# Purchased packs
from datetime import datetime
for pack in u.packs:
    date = datetime.fromtimestamp(pack.purchasedAt).strftime("%Y-%m-%d")
    print(f"{pack.packType}: {pack.tokensPurchased} tokens — {date}")
```

---

## webhooks — Real-time notifications

**Events:** `token.signed` · `token.rejected` · `token.revoked` · `limit.warning` · `limit.reached`

```python
# Register
result = pq.webhooks.register(
    url="https://yourapp.com/webhooks/fipsign",
    events=["limit.warning", "limit.reached", "token.revoked"],
)
print(result.webhook.secret)  # store this — shown only once

# Send a test event
pq.webhooks.test()

# Get current config (secret is never returned after registration)
config = pq.webhooks.get()
if config.webhook is None:
    print("No webhook configured")

# Delete
pq.webhooks.delete()
```

### Verifying incoming webhook requests

```python
from fipsign.middleware import verify_webhook_signature

# Flask
@app.route("/webhooks/fipsign", methods=["POST"])
def webhook():
    from flask import request
    sig = request.headers.get("X-PQAuth-Signature", "")
    if not verify_webhook_signature(request.data, sig, WEBHOOK_SECRET):
        return {"error": "Invalid signature"}, 401
    event = request.json
    if event["event"] == "limit.warning":
        print(f"Warning — {event['data']['freeRemaining']} tokens left")
    return "ok", 200

# FastAPI
from fastapi import Request, HTTPException

@app.post("/webhooks/fipsign")
async def webhook(request: Request):
    body = await request.body()
    sig  = request.headers.get("X-PQAuth-Signature", "")
    if not verify_webhook_signature(body, sig, WEBHOOK_SECRET):
        raise HTTPException(401, detail="Invalid signature")
    event = await request.json()
    return "ok"
```

---

## ca — Certificate Authority

Issue and verify post-quantum certificates for devices, services, or any entity that needs a tamper-proof identity. Built on ML-DSA-65 — the same algorithm used for token signing.

**Typical use case:** A manufacturer of smart locks, IoT sensors, or logistics devices creates a CA root once per project from the dashboard. For each device manufactured, the system calls `ca.issue()` with the device's public key. The device stores its certificate. Verification happens entirely offline — no API call needed at runtime.

**Setup:** Create a project in the dashboard, then click "Create CA" inside that project. Download the root certificate — you will need it for offline verification.

**One CA per project.** Each project can have one root CA. The CA is created from the dashboard — not via API. When you call `ca.issue()` or other CA methods, the SDK automatically uses the CA associated with the project that owns the API key.

---

### ca.issue() — Issue a certificate

Issue a certificate signed by your project's CA. Cost: 1 token.

```python
result = pq.ca.issue(
    subject="device-serial-00123",       # any identifier
    public_key=device_public_key_b64,    # base64 ML-DSA-65 public key
    expires_in_seconds=365 * 24 * 60 * 60,  # required — max 5 years
    meta={"model": "lock-v2", "batch": "2026-05"},  # optional
)

print(result.certificate.id)        # cert_...
print(result.certificate.caId)      # ca_... — the CA that signed it
print(result.certificate.expiresAt) # Unix timestamp
print(result.meta.certId)           # same as certificate.id
```

---

### ca.verify_cert() — Verify a certificate offline

Verify a certificate entirely in memory using the CA root certificate. No API call. Does not check revocation.

```python
import json

with open("root-cert.json") as f:
    from fipsign.types import PQCert
    root_cert = PQCert.from_dict(json.load(f))

result = pq.ca.verify_cert(device_cert, root_cert)

if not result.valid:
    raise PermissionError(result.error)  # 'Invalid certificate signature', 'CERT_EXPIRED', etc.

print(result.cert.subject)    # 'device-serial-00123'
print(result.cert.expiresAt)  # Unix timestamp
```

---

### ca.is_cert_revoked() — Check revocation offline

Check if a certificate appears in a CRL. Offline — pass the result of `ca.get_crl()`.

```python
crl_result = pq.ca.get_crl()

if pq.ca.is_cert_revoked(device_cert, crl_result.crl):
    raise PermissionError("Device certificate has been revoked")
```

---

### ca.get_crl() — Get the Certificate Revocation List

Fetch the current CRL for your project's CA. Free — no token cost.

```python
result = pq.ca.get_crl()

print(f"CA: {result.subject}")
print(f"{len(result.crl)} revoked certificates")

for entry in result.crl:
    from datetime import datetime
    print(f"{entry.certId} — {datetime.fromtimestamp(entry.revokedAt).isoformat()} — {entry.reason}")
```

---

### ca.get_cert() — Get a certificate by ID

Retrieve a certificate and its current status. Free — no token cost.

```python
result = pq.ca.get_cert("cert_...")

print(result.status.revoked)    # bool
print(result.status.expired)    # bool
print(result.status.revokedAt)  # Unix timestamp or None
print(result.status.expiresAt)  # Unix timestamp
```

---

### ca.revoke_cert() — Revoke a certificate

Revoke a certificate immediately. Cost: 1 token.

```python
pq.ca.revoke_cert("cert_...", "device decommissioned")
pq.ca.revoke_cert("cert_...", "device reported stolen")
```

---

### Full device lifecycle example

```python
import json
from fipsign import PQAuth
from fipsign.types import PQCert

pq = PQAuth("pqa_your_api_key")

# Load the root certificate downloaded from the dashboard
with open("root-cert.json") as f:
    root_cert = PQCert.from_dict(json.load(f))

# 1. Factory: issue a certificate for the device
result = pq.ca.issue(
    subject="lock-serial-00123",
    public_key=device_public_key_b64,    # generated on the device
    expires_in_seconds=365 * 24 * 60 * 60,
    meta={"model": "lock-v3", "batch": "2026-05"},
)
certificate = result.certificate
# store certificate on the device

# 2. At runtime: verify the device certificate offline
verify_result = pq.ca.verify_cert(certificate, root_cert)
if not verify_result.valid:
    raise PermissionError(verify_result.error)

# 3. At runtime: check the device is not revoked
crl_result = pq.ca.get_crl()
if pq.ca.is_cert_revoked(certificate, crl_result.crl):
    raise PermissionError("Device revoked")

# 4. Decommission: revoke the certificate
pq.ca.revoke_cert(certificate.id, "device decommissioned")
```

---

## Error handling

`verify()` never raises — it returns `VerifyResult(valid=False, error="...")` on any failure.
All other methods raise `PQAuthError` on failure.

```python
from fipsign import PQAuth, PQAuthError

try:
    result = pq.sign("user_123")
except PQAuthError as err:
    match err.code:
        case "INVALID_API_KEY":    # key missing or doesn't start with pqa_
            ...
        case "API_ERROR":          # server returned an error (check err.status)
            ...
        case "TIMEOUT":            # request exceeded timeout
            ...
        case "NETWORK_ERROR":      # connection failed
            ...
        case "MISSING_SUB":        # sign() called without sub
            ...
        case "INVALID_CERT_TYPE":      # ca.verify_cert(): expected CA_ROOT or CA_CERT
            ...
        case "CA_MISMATCH":            # ca.verify_cert(): cert was not issued by this CA
            ...
        case "CERT_EXPIRED":           # ca.verify_cert(): certificate has expired
            ...
        case "INVALID_CERT_SIGNATURE": # ca.verify_cert(): signature invalid
            ...
        case "MISSING_DEPENDENCY":     # ca.verify_cert(): dilithium-py not installed
            ...
    print(err.code, err.message, err.status)
```

---

## Token quota

Every account gets **10,000 free tokens per month**, reset on the 1st (UTC). Unused free tokens do not carry over. Additional tokens are available as non-expiring packs, purchased from the dashboard.

Each of these operations costs **1 token**: signing, verification, revocation, certificate issuance (`ca.issue()`), and certificate revocation (`ca.revoke_cert()`). Checking usage, fetching the public key, and all CA read operations (`ca.get_crl()`, `ca.get_cert()`) are free.

---

## Rate limits

300 requests per minute per API key on `/sign`, `/verify`, and `/revoke`. On excess the API returns HTTP 429.

CA operations (`ca.issue()`, `ca.revoke_cert()`) are rate limited at 300 requests per minute per API key. Read operations (`ca.get_crl()`, `ca.get_cert()`) are not rate limited.

Token quota and rate limits are separate controls:
- `"Rate limit exceeded"` → back off and retry with exponential backoff
- `"Token limit reached"` → purchase a pack from the dashboard, retrying won't help

---

## Constructor options

```python
pq = PQAuth(
    api_key="pqa_...",                    # required — must start with pqa_
    base_url="https://api.fipsign.dev",   # optional, override for self-hosting
    timeout=10,                            # optional, seconds (default: 10)
)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `api_key` | str | — | Required. From the dashboard. Raises `INVALID_API_KEY` immediately if not prefixed with `pqa_`. |
| `base_url` | str | `https://api.fipsign.dev` | Override for local dev or self-hosted instances. |
| `timeout` | float | `10` | Request timeout in seconds. Raises `TIMEOUT` on exceeded. |
| `session` | requests.Session | — | Custom session (e.g. for proxies or custom TLS). |

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens use ECDSA or RSA — both vulnerable to Shor's algorithm running on a sufficiently powerful quantum computer. ML-DSA-65 is based on the hardness of lattice problems (Module-LWE / Module-SIS), which have no known quantum speedup. It was standardized by NIST in August 2024 as FIPS 204.

---

## Integration tests

```bash
FIPSIGN_API_KEY=pqa_your_key \
WEBHOOK_URL=https://webhook.site/your-uuid \
WEBHOOK_SITE_TOKEN=your-uuid \
python tests/test_sdk.py
```

---

## Links

- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- Developer guide: [fipsign.dev/guide](https://fipsign.dev/guide)
- API status: [api.fipsign.dev/health](https://api.fipsign.dev/health)
- JS SDK: [npmjs.com/package/fipsign-sdk](https://www.npmjs.com/package/fipsign-sdk)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)

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
token  = result.token
meta   = result.meta
usage  = result.usage

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

**Never raises.** Returns a `VerifyResult` with `valid=False` and an `error` message on any failure. Cost: 1 token.

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

Reads `Authorization: Bearer <token>` and attaches the decoded payload to `flask.g.fipsign_user`. Returns 401 automatically on invalid tokens.

```python
from flask import Flask, g
from fipsign import PQAuth, flask_middleware

app  = Flask(__name__)
pq   = PQAuth("pqa_your_api_key")
auth = flask_middleware(pq)

@app.route("/login", methods=["POST"])
def login():
    import base64, json
    # authenticate user however you like, then:
    result  = pq.sign(user.id, email=user.email, role=user.role, expires_in_seconds=3600)
    encoded = base64.b64encode(json.dumps(result.token.to_dict()).encode()).decode()
    return {"token": encoded}

@app.route("/logout", methods=["POST"])
def logout():
    import base64, json
    from flask import request
    from fipsign.types import PQToken
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        token = PQToken.from_dict(json.loads(base64.b64decode(header[7:]).decode()))
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

app          = FastAPI()
pq           = PQAuth("pqa_your_api_key")
require_auth = fastapi_middleware(pq)

@app.get("/api/profile")
def profile(user=Depends(require_auth)):
    return {"sub": user["sub"], "role": user.get("role")}
```

---

## Async client

All methods are identical to `PQAuth` but async. Use in FastAPI, aiohttp, or any asyncio-based application. Requires `pip install fipsign-sdk[async]`.

```python
from fipsign.async_client import AsyncPQAuth
from fipsign import generate_key_pair

async with AsyncPQAuth("pqa_your_api_key") as pq:
    result = await pq.sign("user_123", role="admin", expires_in_seconds=3600)
    v      = await pq.verify(result.token)
    print(v.valid, v.payload["sub"])

    # CA operations work the same way
    kp   = generate_key_pair()  # generate_key_pair() is synchronous
    cert = await pq.ca.issue(
        subject="device-serial-00123",
        public_key=kp.publicKey,
        expires_in_seconds=365 * 24 * 60 * 60,
    )
    crl = await pq.ca.get_crl()
    if pq.ca.is_cert_revoked(cert.meta.certId, crl.crl):
        raise PermissionError("Device revoked")
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

# Send a test event to confirm your endpoint is reachable
pq.webhooks.test()

# Get current config (secret is never returned after registration)
config = pq.webhooks.get()
if config.webhook is None:
    print("No webhook configured")

# Delete
pq.webhooks.delete()
```

Re-registering an existing webhook updates the URL and events but preserves the original secret. To rotate the secret, delete and re-register.

### Webhook event payloads

Each incoming POST has a top-level `event` string and a `data` dict. The fields available in `data` depend on the event type:

**`token.signed`**
```python
{
    "sub":            str,          # subject passed to sign()
    "email":          str | None,
    "role":           str | None,
    "projectId":      str,
    "apiKeyName":     str,
    "tokensUsed":     int,
    "freeRemaining":  int,
    "packRemaining":  int,
    "totalRemaining": int,
    "source":         str,          # "free" | "pack" | "free+pack"
    "month":          str,          # e.g. "2026-05"
}
```

**`token.rejected`**
```python
{
    "reason":     str,          # why verification failed
    "sub":        str | None,   # subject extracted from payload (if decodable)
    "projectId":  str,
    "apiKeyName": str,
}
```

**`token.revoked`**
```python
{
    "sub":            str,
    "reason":         str,
    "apiKeyName":     str,
    "projectId":      str,
    "freeRemaining":  int,
    "packRemaining":  int,
    "totalRemaining": int,
}
```

**`limit.warning`** — fired when free tokens drop below 20% of monthly limit
```python
{
    "freeRemaining":  int,
    "freeLimit":      int,    # always 10000
    "packRemaining":  int,
    "totalRemaining": int,
    "percentUsed":    int,    # e.g. 82
    "month":          str,
    "apiKeyName":     str,
}
```

**`limit.reached`** — fired when free tokens are exhausted and no pack is available
```python
{
    "freeRemaining":  int,    # always 0
    "packRemaining":  int,
    "totalRemaining": int,
    "month":          str,
    "apiKeyName":     str,
}
```

### Verifying incoming webhook requests

Each incoming POST includes the headers `X-PQAuth-Event`, `X-PQAuth-Signature` (`sha256=...`), and `X-PQAuth-Timestamp`.

```python
from fipsign.middleware import verify_webhook_signature

# Flask
@app.route("/webhooks/fipsign", methods=["POST"])
def webhook():
    from flask import request
    sig = request.headers.get("X-PQAuth-Signature", "")
    if not verify_webhook_signature(request.data, sig, FIPSIGN_WEBHOOK_SECRET):
        return "Invalid signature", 401

    event = request.json
    match event["event"]:
        case "limit.warning":
            print(f"Usage warning — {event['data']['freeRemaining']} free tokens left")
        case "limit.reached":
            print(f"Limit reached — pack remaining: {event['data']['packRemaining']}")
        case "token.revoked":
            print(f"Token revoked for sub: {event['data']['sub']}")

    return "ok", 200


# FastAPI
from fastapi import Request
@app.post("/webhooks/fipsign")
async def webhook(request: Request):
    body = await request.body()
    sig  = request.headers.get("X-PQAuth-Signature", "")
    if not verify_webhook_signature(body, sig, FIPSIGN_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="Invalid signature")

    event = await request.json()
    # handle event["event"] ...
    return "ok"
```

---

## ca — Certificate Authority

Issue post-quantum certificates for devices, services, or any entity that needs a tamper-proof identity. Built on ML-DSA-65 — the same algorithm used for token signing.

**Typical use case:** A manufacturer of smart locks, IoT sensors, or logistics devices creates a CA root once per project from the dashboard. For each device manufactured, the server calls `ca.issue()` with the device's public key. The device stores its certificate. Runtime verification happens entirely offline — no API call needed.

**Setup:** Create a project in the dashboard, then click "Create CA" inside that project. Choose a certificate format:

- **PQCert** — FIPSign's native JSON format. Certificates are JSON objects (dataclasses in Python). Simpler to work with in pure Python environments.
- **X.509** — Standard X.509 v3 PEM certificates signed with ML-DSA-65 (OID `2.16.840.1.101.3.4.3.18`, RFC 9881). Compatible with OpenSSL 3.5+, standard PKI tooling, and enterprise infrastructure.

The format is chosen once at CA creation and applies to all certificates issued by that CA. One CA per project — you cannot mix formats within a project.

> **Save the root certificate now.** It is shown only once at CA creation. Without it, offline certificate verification is not possible. Store it in a secrets manager or secure file — treat it like a private key.

When you call `ca.issue()` or other CA methods, the SDK automatically uses the CA associated with the project that owns the API key. No `caId` parameter needed.

---

### generate_key_pair() — Generate a key pair for a device

Generate an ML-DSA-65 key pair for a device or entity. The device keeps the `secretKey` and the server passes the `publicKey` to `ca.issue()`. Works for both PQCert and X.509 CAs.

Requires `cryptography >= 48.0.0`, which is included as a dependency — no additional install needed.

```python
from fipsign import generate_key_pair

kp = generate_key_pair()
# kp.publicKey — base64(1952 bytes) — pass to ca.issue()
# kp.secretKey — base64(32 bytes, seed form) — store securely on the device
```

> **Important — secretKey format:** The `secretKey` is the 32-byte ML-DSA-65 seed, **not** the 4032-byte expanded key returned by the JS SDK's `generateKeyPair()`. The formats are not interchangeable.
>
> Use `generate_key_pair()` when the device runs Python. If the device runs JavaScript (Node.js, browser, firmware), use `generateKeyPair()` from the JS SDK instead.

**To sign from Python using the returned secretKey:**

```python
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
import base64

private_key = MLDSA65PrivateKey.from_seed_bytes(base64.b64decode(kp.secretKey))
signature   = private_key.sign(message)   # bytes, 3309 bytes for ML-DSA-65
```

**Alternatively, generate key pairs in Python using pyca/cryptography directly** (same underlying library):

```python
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64

private_key = MLDSA65PrivateKey.generate()
public_key  = private_key.public_key()
pub_bytes   = public_key.public_bytes_raw()   # 1952 bytes
pub_b64     = base64.b64encode(pub_bytes).decode()

# pass pub_b64 to ca.issue()
```

---

### ca.issue() — Issue a certificate

Issue a certificate signed by your project's CA. Cost: 1 token.

`expires_in_seconds` is required and must be between 60 seconds (minimum) and 157,680,000 seconds (5 years maximum).

The type of `result.certificate` depends on the CA format:

- **PQCert CA** — `certificate` is a `PQCert` dataclass with fields `.id`, `.caId`, `.signature`, `.expiresAt`, etc.
- **X.509 CA** — `certificate` is a PEM string (`"-----BEGIN CERTIFICATE-----\n..."`). Certificate metadata is available in `meta`.

```python
# PQCert CA
result = pq.ca.issue(
    subject="device-serial-00123",
    public_key=kp.publicKey,
    expires_in_seconds=365 * 24 * 60 * 60,
    meta={"model": "lock-v2", "batch": "2026-05"},  # optional, max 10 keys
)

# result.certificate is a PQCert dataclass
print(result.certificate.id)         # cert_...
print(result.certificate.caId)       # ca_...
print(result.certificate.expiresAt)  # Unix timestamp
print(result.meta.certId)            # same as certificate.id
print(result.meta.format)            # "pqcert"


# X.509 CA
result = pq.ca.issue(
    subject="device-serial-00123",
    public_key=kp.publicKey,
    expires_in_seconds=365 * 24 * 60 * 60,
    # meta is not supported for X.509 CAs — passing it returns 400
)

# result.certificate is a PEM string
print(type(result.certificate))   # <class 'str'>
print(result.certificate[:27])    # "-----BEGIN CERTIFICATE-----"
print(result.meta.certId)         # cert_... — use this for revocation
print(result.meta.caId)           # ca_...
print(result.meta.expiresAt)      # Unix timestamp
print(result.meta.format)         # "x509"
```

> **Note for X.509:** Store `meta.certId` alongside the PEM certificate. You will need it for `ca.revoke_cert()` and `ca.is_cert_revoked()`.

---

### ca.verify_cert() — Offline certificate verification

> **Not available in the Python SDK.** Offline verification requires ML-DSA-65 local cryptography over FIPSign's PQCert JSON format.
>
> **For PQCert CAs**, use the JavaScript SDK:
> ```javascript
> import rootCert from './root-cert.json' assert { type: 'json' }
> const result = fipsign.ca.verifyCert(deviceCert, rootCert)
> if (!result.valid) return reject(result.error)
> ```
>
> **For X.509 CAs**, use `pyca/cryptography >= 44.0.0` directly:
> ```python
> from cryptography import x509
> from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65
>
> root_cert = x509.load_pem_x509_certificate(root_pem.encode())
> leaf_cert = x509.load_pem_x509_certificate(leaf_pem.encode())
> root_pub  = root_cert.public_key()
>
> # Raises InvalidSignature on failure, returns None on success
> root_pub.verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes, MLDSA65())
> ```
>
> **For real-time server-side status checks**, use `ca.get_cert()` from Python — it returns the live revocation status without needing the root certificate.

---

### ca.is_cert_revoked() — Check revocation offline

Check if a certificate appears in a CRL. Offline — pass the result of `ca.get_crl()`. Works for both PQCert and X.509 formats.

Accepts either a **PQCert object** (for PQCert CAs) or a **certId string** (for X.509 CAs or when you only have the ID). The `certId` is returned in `meta.certId` from `ca.issue()`.

```python
crl_result = pq.ca.get_crl()

# PQCert CA — pass the PQCert dataclass
if pq.ca.is_cert_revoked(device_cert, crl_result.crl):
    raise PermissionError("Device certificate has been revoked")

# X.509 CA — pass the certId string from meta
if pq.ca.is_cert_revoked(meta.certId, crl_result.crl):
    raise PermissionError("Device certificate has been revoked")

# certId string also works for PQCert CAs
if pq.ca.is_cert_revoked(result.meta.certId, crl_result.crl):
    raise PermissionError("Device certificate has been revoked")
```

---

### ca.get_crl() — Get the Certificate Revocation List

Fetch the current CRL for your project's CA. Free — no token cost. Works for both PQCert and X.509 formats.

Use `get_crl()` when you need to verify revocation in bulk — download the list once and check multiple certificates against it locally using `is_cert_revoked()`. For checking the status of a single certificate in real time (e.g. before a high-value transaction), use `get_cert()` instead.

```python
result = pq.ca.get_crl()

print(f"CA: {result.subject}")
print(f"Format: {result.format}")       # "pqcert" or "x509"
print(f"{len(result.crl)} revoked certificates")

from datetime import datetime
for entry in result.crl:
    # entry.reason may be None if no reason was provided at revocation time
    ts = datetime.fromtimestamp(entry.revokedAt).isoformat()
    print(f"{entry.certId} — {ts} — {entry.reason or 'no reason'}")
```

For X.509 CAs, the CRL is signed with ML-DSA-65 by the CA private key. The raw signed object (including signature) is available in `result.raw` if you need it for verification.

---

### ca.get_cert() — Get a certificate by ID

Retrieve a certificate and its current real-time status. Use this for single certificate checks before high-value operations. Free — no token cost. Works for both PQCert and X.509 formats.

```python
result = pq.ca.get_cert("cert_...")

print(result.status.revoked)    # bool
print(result.status.expired)    # bool
print(result.status.revokedAt)  # Unix timestamp or None
print(result.status.expiresAt)  # Unix timestamp

# For PQCert CAs, result.certificate is a PQCert dataclass
# For X.509 CAs, result.certificate is a PEM string and result.meta contains
# additional fields:
if result.meta:
    print(result.meta.certId)    # cert_...
    print(result.meta.caId)      # ca_...
    print(result.meta.subject)   # "device-serial-00123"
    print(result.meta.format)    # "x509"
    print(result.meta.algorithm) # "ML-DSA-65"
```

---

### ca.revoke_cert() — Revoke a certificate

Revoke a certificate immediately. It will appear in the CRL from this point on. Cost: 1 token.

```python
# PQCert CA — use certificate.id
pq.ca.revoke_cert(device_cert.id, "device decommissioned")

# X.509 CA — use meta.certId from ca.issue()
result = pq.ca.revoke_cert(meta.certId, "device reported stolen")
# For X.509 CAs, result.format == "x509"

# certId string works for both formats
pq.ca.revoke_cert("cert_...", "device decommissioned")
```

---

### Full device lifecycle — PQCert

```python
from fipsign import PQAuth, generate_key_pair

pq = PQAuth("pqa_your_api_key")

# 1. Factory: generate key pair for the device
kp = generate_key_pair()
# kp.secretKey — store securely on the device (32-byte seed, base64)
# kp.publicKey — pass to ca.issue()

# 2. Factory: issue a certificate for the device
result = pq.ca.issue(
    subject="lock-serial-00123",
    public_key=kp.publicKey,
    expires_in_seconds=365 * 24 * 60 * 60,
    meta={"model": "lock-v3", "batch": "2026-05"},
)
certificate = result.certificate   # PQCert dataclass — store on device

# 3. At runtime: real-time revocation check (single cert, server-side)
status = pq.ca.get_cert(certificate.id)
if status.status.revoked:
    raise PermissionError("Device revoked")

# 4. At runtime: bulk revocation check (offline, from cached CRL)
crl_result = pq.ca.get_crl()
if pq.ca.is_cert_revoked(certificate, crl_result.crl):
    raise PermissionError("Device revoked")

# 5. Decommission: revoke the certificate
pq.ca.revoke_cert(certificate.id, "device decommissioned")
```

---

### Full device lifecycle — X.509

```python
from fipsign import PQAuth, generate_key_pair

pq = PQAuth("pqa_your_api_key")

# root_pem — the PEM string shown once at CA creation, stored securely
root_pem = os.environ["FIPSIGN_ROOT_CERT_PEM"]

# 1. Factory: generate key pair for the device
kp = generate_key_pair()
# kp.secretKey — store securely on the device (32-byte seed, base64)
# kp.publicKey — pass to ca.issue()

# 2. Factory: issue a certificate for the device
result  = pq.ca.issue(
    subject="lock-serial-00123",
    public_key=kp.publicKey,
    expires_in_seconds=365 * 24 * 60 * 60,
)
cert_pem = result.certificate    # PEM string — store on device
cert_id  = result.meta.certId   # store alongside the PEM

# 3. At runtime: offline signature verification (no API call)
#    Requires pyca/cryptography >= 44.0.0 (included as a dependency)
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65

root_cert = x509.load_pem_x509_certificate(root_pem.encode())
leaf_cert = x509.load_pem_x509_certificate(cert_pem.encode())
root_cert.public_key().verify(
    leaf_cert.signature,
    leaf_cert.tbs_certificate_bytes,
    MLDSA65()
)  # raises InvalidSignature on failure

# 4. At runtime: bulk revocation check (offline, from cached CRL)
crl_result = pq.ca.get_crl()
if pq.ca.is_cert_revoked(cert_id, crl_result.crl):
    raise PermissionError("Device revoked")

# 5. Decommission: revoke the certificate using certId
pq.ca.revoke_cert(cert_id, "device decommissioned")
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
        case "INVALID_API_KEY":  # key missing or doesn't match pqa_ + 64 hex chars
            ...
        case "API_ERROR":        # server returned an error (check err.status)
            ...
        case "TIMEOUT":          # request exceeded timeout (default: 10s)
            ...
        case "NETWORK_ERROR":    # connection failed
            ...
        case "MISSING_SUB":      # sign() called without sub
            ...
    print(err.code, err.message, err.status)
```

Common `err.status` values for `API_ERROR`:
- `400` — invalid parameters (e.g. `expires_in_seconds` out of range, invalid public key, `meta` passed to X.509 CA)
- `401` — API key missing or invalid
- `404` — resource not found (e.g. no active CA for the project)
- `409` — conflict (e.g. revoking an already-revoked certificate)
- `429` — token quota exhausted or rate limit exceeded

---

## Token quota

Every account gets **10,000 free tokens per month**, reset on the 1st (UTC). Unused free tokens do not carry over. Additional tokens are available as non-expiring packs, purchased from the dashboard.

Each of these operations costs **1 token**: signing (`sign()`), verification (`verify()`), revocation (`revoke()`), certificate issuance (`ca.issue()`), and certificate revocation (`ca.revoke_cert()`). Checking usage (`usage()`), fetching the public key, and all CA read operations (`ca.get_crl()`, `ca.get_cert()`) are free.

---

## Rate limits

300 requests per minute per API key on `sign()`, `verify()`, and `revoke()`. On excess the API returns HTTP 429.

CA operations (`ca.issue()`, `ca.revoke_cert()`) are rate limited at 300 requests per minute per API key, consistent with signing and verification. Read operations (`ca.get_crl()`, `ca.get_cert()`) are not rate limited.

Token quota and rate limits are separate controls — check the error message to distinguish them:
- `"Rate limit exceeded"` → back off and retry with exponential backoff
- `"Token limit reached"` → purchase a pack from the dashboard, retrying won't help

---

## Constructor options

```python
pq = PQAuth(
    api_key="pqa_...",                    # required — pqa_ + 64 lowercase hex chars
    base_url="https://api.fipsign.dev",   # optional, override for self-hosting
    timeout=10,                           # optional, seconds (default: 10)
    session=None,                         # optional, custom requests.Session
)
```

| Option | Type | Default | Description |
|---|---|---|---|
| `api_key` | str | — | Required. From the dashboard. Must match `pqa_` followed by 64 lowercase hex characters. Raises `INVALID_API_KEY` immediately if the format doesn't match. |
| `base_url` | str | `https://api.fipsign.dev` | Override for local dev or self-hosted instances. |
| `timeout` | float | `10` | Request timeout in seconds. Raises `TIMEOUT` on exceeded. |
| `session` | requests.Session | `None` | Custom session for proxies, custom TLS, or testing. |

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
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- API health: [api.fipsign.dev/health](https://api.fipsign.dev/health)
- JS SDK: [npmjs.com/package/fipsign-sdk](https://www.npmjs.com/package/fipsign-sdk)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)

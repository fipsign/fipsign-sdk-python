# fipsign-sdk

[![PyPI](https://img.shields.io/pypi/v/fipsign-sdk)](https://pypi.org/project/fipsign-sdk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-blue)](https://csrc.nist.gov/pubs/fips/204/final)

Post-quantum signing SDK for Python. Signs and verifies any payload using **ML-DSA-65** (NIST FIPS 204) — resistant to Shor's algorithm, standardized by NIST in August 2024.

**Not just for auth.** Sign users, orders, documents, devices, AI agents, events — any entity that needs a tamper-proof, quantum-resistant signature.

📖 **[Full documentation, API reference, and guides →](https://fipsign.dev/guide)**

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

1. Create a free account at [app.fipsign.dev](https://app.fipsign.dev).
2. In the dashboard, create a project, then create an API key inside it. Save the key — it won't be shown again.
3. Use it:

```python
from fipsign import PQAuth

pq = PQAuth("pqa_your_api_key")

result = pq.sign("user_123", role="admin")
token  = result.token

verified = pq.verify(token)
if not verified.valid:
    raise PermissionError("invalid token")

print(verified.payload["sub"])  # "user_123"
```

That's signing and verifying. The SDK also covers async usage (`AsyncPQAuth`), Flask/FastAPI middleware, offline (in-memory) verification, revocation, webhooks, and a full Certificate Authority module (PQCert + X.509) for issuing post-quantum certificates to devices and services — all in the [developer guide](https://fipsign.dev/guide).

---

## Mandate — authorization for AI agents

Give an agent a bounded, revocable credential: which actions it may perform, how much it may spend, and until when. Check every action with one call, and suspend or revoke the mandate at any time.

```python
result = pq.mandate.emit(
    agent_id="agent-reporting-v2",
    issued_by="user@empresa.com",
    scope=["read:crm", "send_reply"],
    budget_total=1000,
    expires_in_seconds=28800,
)

check = pq.mandate.verify(result.mandate.token, "send_reply", 1)
if check.result != "granted":
    raise PermissionError(check.reason)
```

To make a copied token useless on its own, emit the mandate with the agent's public key (`agent_public_key=`): the agent then signs every call with its private key (`generate_agent_key_pair()` and `sign_agent_call()`). Details in the [Mandate section of the guide](https://fipsign.dev/guide#py13).

---

## When verify() says no

`verify()` never raises. When `valid` is `False`, `failure` says why:

| `failure` | Meaning | What to do |
|---|---|---|
| `"rejected"` | The token is not acceptable (bad signature, expired, revoked, ...) | Answer 401 |
| `"rate_limited"` | Too many requests in the current minute. The token was not checked | Wait `retry_after` seconds and try again |
| `"quota_exhausted"` | Free tokens and packs used up. The token was not checked | Buy a pack from the dashboard |
| `"unavailable"` | FIPSign could not answer (timeout, network, server error, invalid API key). The token was not checked | Try again; answer 503 |

```python
verified = pq.verify(token)
if not verified.valid and verified.failure == "rejected":
    raise PermissionError("invalid token")                    # the token is bad
if not verified.valid:
    raise RuntimeError("could not check the token, try again")  # not the token's fault
```

`flask_middleware()` and `fastapi_middleware()` do this for you: 401 for a refused token, 503 (with `Retry-After` when known) for the rest.

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens rely on ECDSA or RSA — both breakable by Shor's algorithm on a sufficiently powerful quantum computer. ML-DSA-65 is based on lattice problems (Module-LWE / Module-SIS) with no known quantum speedup. Standardized by NIST in August 2024 as FIPS 204.

---

## Links

- 📖 [Developer guide — full API reference, error codes, webhooks, CA/X.509](https://fipsign.dev/guide)
- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)

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

## Prove what an agent was allowed to do

FIPSign keeps a log of everything that happens to a mandate (emitted, each call it granted or denied, narrowed, suspended, resumed, revoked) and signs it. Pass your own id as `correlation_id` (a ticket, a request id) to find an event later, and ask for a **receipt** on the calls you may have to prove:

```python
result = pq.mandate.emit(..., correlation_id="ticket-4821")                                   # result.receipt
check  = pq.mandate.verify(token, "send_reply", 1, receipt=True, correlation_id="req-77")     # check.receipt
done   = pq.mandate.revoke(result.mandate.id, correlation_id="ticket-4822")                   # done.receipt
```

`emit()` and the changes (`narrow`, `suspend`, `resume`, `revoke`) always return a receipt; `verify()` returns one when you pass `receipt=True`, granted or denied. Keep it next to your own record (`json.dumps(result.receipt.to_dict())`). It is FIPSign's signature over that event and over everything the log held before it, so the history cannot be rewritten later without the receipt showing it. Check it on your own machine, with no network:

```python
from fipsign import public_key_fingerprint, verify_mandate_receipt

# Once, the day you integrate. `public_key` is the answer of:  curl -H "X-API-Key: pqa_your_api_key" https://api.fipsign.dev/public-key
# Save it (or just its fingerprint):
fingerprint = public_key_fingerprint(public_key)

# Any day later:
check = verify_mandate_receipt(receipt, public_key=public_key)
if not check.valid:
    print(check.problems)
```

A project that rotated its keys has more than one: a receipt is checked with the key that made it. Pin the fingerprint you saved and let `mandate.public_keys()` (every key the project has had, the retired ones too) supply the keys; a key is accepted only if its own fingerprint is the one you pinned:

```python
keys = pq.mandate.public_keys().keys
check = verify_mandate_receipt(receipt, pin_fingerprint=fingerprint, keys=keys)
```

Read the log, one mandate or the whole project:

```python
for e in pq.mandate.events_all(mandate_id):
    print(e.seq, e.type, json.loads(e.body))
page = pq.mandate.query_events(correlation_id="ticket-4821")      # also: type, action, key_id, trace_id, from_, to
for e in pq.mandate.query_events_all(type="verify_denied"):
    print(e.mandateId, e.at)
```

Export the whole log of a mandate and check it, with no network:

```python
from fipsign import verify_mandate_export

pages = pq.mandate.export_all(mandate_id)
check = verify_mandate_export(pages, pin_fingerprint=fingerprint)   # or public_key=public_key
print(check.valid, check.complete, check.problems)
```

| Field | Meaning |
|---|---|
| `valid` | Every event follows the one before it and is what it says it is, and every signature that is in the export verifies. `problems` lists what does not |
| `complete` | The log starts at event 1 and ends in a checkpoint that seals everything before it. A log that is `valid` but not `complete` has events at its end that only the signed head (or a receipt you hold) protects |
| `keyTrust` | `"pinned"`: the key was fixed by you (`public_key` or `pin_fingerprint`). `"fipsign"`: you gave neither, so the keys came from FIPSign (`mandate.verify_receipt()` and `mandate.verify_export()` only): that detects a log that was altered, but not a key that FIPSign itself replaced |

`verify_mandate_receipt()` and `verify_mandate_export()` never raise and need no API key. `AsyncPQAuth` has the same calls (`await` them; use `async for` with `events_all()`, `query_events_all()`). A signature proves what FIPSign recorded and when; it does not prove that your service made the request. Events are kept for 365 days.

## Check the revocation list of your CA

`ca.get_crl()` returns the certificates your CA has revoked, and the list is signed by the CA (ML-DSA-65). `ca.verify_crl()` checks that signature offline, so a list that was altered on the way, or that belongs to another CA, is not taken as good:

```python
revocations = pq.ca.get_crl()
check = pq.ca.verify_crl(revocations, root_cert)  # the CA_ROOT you saved when the CA was created (a PEM string for an X.509 CA)
if not check.valid:
    raise RuntimeError(check.error)
if pq.ca.is_cert_revoked(cert, revocations.crl):
    raise PermissionError("revoked")
```

The signature covers `generatedAt`, so an old list cannot pass as a new one, but a correctly signed old list is still valid: `check.generatedAt` tells you when it was made, and how old a list you accept is up to you. `verify_crl()` is offline, so it is a plain call with `AsyncPQAuth` too. Details: the CA chapter of the [guide](https://fipsign.dev/guide).

---

## Why ML-DSA-65?

JWT with RS256/ES256 and standard OAuth tokens rely on ECDSA or RSA — both breakable by Shor's algorithm on a sufficiently powerful quantum computer. ML-DSA-65 is based on lattice problems (Module-LWE / Module-SIS) with no known quantum speedup. Standardized by NIST in August 2024 as FIPS 204.

---

## Links

- 📖 [Developer guide — full API reference, error codes, webhooks, CA/X.509](https://fipsign.dev/guide)
- Dashboard: [app.fipsign.dev](https://app.fipsign.dev)
- API status: [status.fipsign.dev](https://status.fipsign.dev)
- NIST FIPS 204: [csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)

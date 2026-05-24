#!/usr/bin/env python3
"""
FIPSign SDK — Integration test (Python)
Runs against the live backend using the published fipsign-sdk

Usage:
    FIPSIGN_API_KEY=pqa_...              \\
    WEBHOOK_URL=https://webhook.site/... \\
    WEBHOOK_SITE_TOKEN=your-uuid         \\
    python test_sdk.py

Prerequisites:
    1. Create a free account at https://app.fipsign.dev
    2. Create a project and an API key inside that project
    3. Create a free endpoint at https://webhook.site and copy your UUID
    4. pip install fipsign-sdk requests
"""

import json
import os
import sys
import time
from datetime import datetime

import requests as _requests

try:
    from fipsign import PQAuth, PQAuthError
    from fipsign.types import PQToken
except ImportError:
    print("\033[31mError: fipsign package not found. Install it with: pip install fipsign-sdk\033[0m")
    sys.exit(1)

# ─── Required environment variables ───────────────────────────────────────────

API_KEY            = os.environ.get("FIPSIGN_API_KEY")
WEBHOOK_URL        = os.environ.get("WEBHOOK_URL")
WEBHOOK_SITE_TOKEN = os.environ.get("WEBHOOK_SITE_TOKEN")

if not API_KEY:
    print("\033[31mError: FIPSIGN_API_KEY is required.\033[0m")
    print("Get your API key at https://app.fipsign.dev")
    sys.exit(1)

if not WEBHOOK_URL or not WEBHOOK_SITE_TOKEN:
    print("\033[31mError: WEBHOOK_URL and WEBHOOK_SITE_TOKEN are required.\033[0m")
    print("Create a free endpoint at https://webhook.site and copy your UUID.")
    print("  WEBHOOK_URL=https://webhook.site/<your-uuid>")
    print("  WEBHOOK_SITE_TOKEN=<your-uuid>")
    sys.exit(1)

# ─── Helpers ──────────────────────────────────────────────────────────────────

GREEN = "\033[32m"
RED   = "\033[31m"
CYAN  = "\033[36m"
DIM   = "\033[2m"
RESET = "\033[0m"
BOLD  = "\033[1m"

passed = 0
failed = 0


def log(label: str, msg: str) -> None:
    print(f"  {DIM}{label:<32}{RESET} {msg}")


def pass_test(name: str) -> None:
    global passed
    passed += 1
    print(f"{GREEN}  ✓{RESET} {name}")


def fail_test(name: str, err) -> None:
    global failed
    failed += 1
    print(f"{RED}  ✗{RESET} {name}")
    print(f"    {DIM}→ {err}{RESET}")


def section(title: str) -> None:
    print(f"\n{CYAN}{BOLD}── {title}{RESET}")


def run() -> None:
    print(f"\n{BOLD}FIPSign SDK — Integration Test (Python){RESET}")
    print(f"{DIM}fipsign-sdk@0.5.2 · {datetime.utcnow().isoformat()}Z{RESET}\n")

    pq = PQAuth(API_KEY)

    # ─── 01 Health ───────────────────────────────────────────────────────────
    section("01 · Health check")
    try:
        h = pq.health()
        if h.status != "ok":           raise AssertionError(f'status is "{h.status}", expected "ok"')
        if h.algorithm != "ML-DSA-65": raise AssertionError(f'algorithm is "{h.algorithm}", expected "ML-DSA-65"')
        if not h.quantumResistant:     raise AssertionError("quantumResistant is False")
        if not h.version:              raise AssertionError("missing version field")
        log("status",           h.status)
        log("algorithm",        h.algorithm)
        log("quantumResistant", str(h.quantumResistant))
        log("version",          h.version)
        pass_test("health() returns correct fields")
    except Exception as err:
        fail_test("health()", err)

    # ─── 02 Invalid API key ──────────────────────────────────────────────────
    section("02 · Invalid API key rejection")
    try:
        PQAuth("bad_key")
        fail_test("constructor rejects bad key", "should have raised")
    except PQAuthError as err:
        if err.code == "INVALID_API_KEY":
            pass_test("constructor raises PQAuthError(INVALID_API_KEY) for bad key")
        else:
            fail_test("constructor rejects bad key", err)
    except Exception as err:
        fail_test("constructor rejects bad key", err)

    # ─── 03 sign() ───────────────────────────────────────────────────────────
    section("03 · sign()")
    user_token = order_token = doc_token = None

    try:
        r = pq.sign("user_test", email="test@example.com", role="admin", expires_in_seconds=3600)
        if not r.token.payload:              raise AssertionError("missing token.payload")
        if not r.token.signature:            raise AssertionError("missing token.signature")
        if r.token.algorithm != "ML-DSA-65": raise AssertionError(f"wrong algorithm: {r.token.algorithm}")
        if r.meta.tokenCost != 1:            raise AssertionError(f"tokenCost is {r.meta.tokenCost}, expected 1")
        if r.meta.source not in ("free", "pack", "free+pack"):
            raise AssertionError(f"unexpected source: {r.meta.source}")
        if not r.meta.projectId:             raise AssertionError("missing meta.projectId")
        if not r.meta.issuedFor:             raise AssertionError("missing meta.issuedFor")
        if r.meta.expiresIn != 3600:         raise AssertionError(f"meta.expiresIn is {r.meta.expiresIn}, expected 3600")
        if not isinstance(r.usage.freeRemaining, int):  raise AssertionError("missing usage.freeRemaining")
        if not isinstance(r.usage.packRemaining, int):  raise AssertionError("missing usage.packRemaining")
        if not isinstance(r.usage.totalRemaining, int): raise AssertionError("missing usage.totalRemaining")
        if not r.usage.month:                raise AssertionError("missing usage.month")
        log("algorithm",     r.token.algorithm)
        log("tokenCost",     str(r.meta.tokenCost))
        log("source",        r.meta.source)
        log("expiresIn",     str(r.meta.expiresIn))
        log("usage.month",   r.usage.month)
        log("freeRemaining", str(r.usage.freeRemaining))
        user_token = r.token
        pass_test("sign() user session — correct shape and all fields present")
    except Exception as err:
        fail_test("sign() user session", err)

    try:
        r = pq.sign("order_456", amount=1500.00, currency="USD", expires_in_seconds=300)
        log("sub",      "order_456")
        log("amount",   "1500")
        log("currency", "USD")
        order_token = r.token
        pass_test("sign() payment order — custom fields accepted")
    except Exception as err:
        fail_test("sign() payment order", err)

    try:
        r = pq.sign("doc_789", hash="sha256:abc123", signedBy="alice")
        log("sub",      "doc_789")
        log("hash",     "sha256:abc123")
        log("signedBy", "alice")
        doc_token = r.token
        pass_test("sign() document — custom fields accepted")
    except Exception as err:
        fail_test("sign() document", err)

    try:
        pq.sign("")
        fail_test("sign() rejects empty sub", "should have raised")
    except PQAuthError as err:
        if err.code == "MISSING_SUB":
            pass_test("sign() raises PQAuthError(MISSING_SUB) when sub is empty")
        else:
            fail_test("sign() rejects empty sub", err)
    except Exception as err:
        fail_test("sign() rejects empty sub", err)

    try:
        pq.sign(
            "test_fields",
            f1="a", f2="b", f3="c", f4="d", f5="e",
            f6="f", f7="g", f8="h", f9="i", f10="j", f11="k",
        )
        fail_test("sign() rejects >10 custom fields", "should have raised")
    except PQAuthError as err:
        if err.code == "API_ERROR" and err.status == 400:
            pass_test("sign() raises API_ERROR(400) when >10 custom fields")
        else:
            fail_test("sign() rejects >10 custom fields", err)
    except Exception as err:
        fail_test("sign() rejects >10 custom fields", err)

    # ─── 04 verify() remote ──────────────────────────────────────────────────
    section("04 · verify() — remote")

    if user_token:
        try:
            r = pq.verify(user_token)
            if not r.valid:               raise AssertionError("valid is False")
            if not r.payload.get("sub"):  raise AssertionError("missing payload.sub")
            if r.payload["sub"] != "user_test": raise AssertionError(f'sub is "{r.payload["sub"]}", expected "user_test"')
            if r.payload.get("role") != "admin": raise AssertionError(f'role is "{r.payload.get("role")}", expected "admin"')
            if not isinstance(r.payload.get("iat"), (int, float)): raise AssertionError("missing payload.iat")
            if not isinstance(r.payload.get("exp"), (int, float)): raise AssertionError("missing payload.exp")
            log("valid", str(r.valid))
            log("sub",   r.payload["sub"])
            log("role",  str(r.payload.get("role")))
            log("iat",   str(r.payload.get("iat")))
            log("exp",   str(r.payload.get("exp")))
            pass_test("verify() valid token — correct payload returned")
        except Exception as err:
            fail_test("verify() valid token", err)

        try:
            import dataclasses
            tampered = dataclasses.replace(user_token, payload="TAMPERED_PAYLOAD")
            r = pq.verify(tampered)
            if r.valid:   raise AssertionError("valid should be False for tampered token")
            if not r.error: raise AssertionError("missing error message")
            log("valid", str(r.valid))
            log("error", r.error)
            pass_test("verify() tampered token — returns valid=False without raising")
        except Exception as err:
            fail_test("verify() tampered token", err)

    if order_token:
        try:
            r = pq.verify(order_token)
            if not r.valid: raise AssertionError("valid is False")
            if r.payload["sub"] != "order_456": raise AssertionError(f'sub is "{r.payload["sub"]}"')
            if r.payload.get("amount") != 1500: raise AssertionError(f'amount is {r.payload.get("amount")}')
            log("sub",    r.payload["sub"])
            log("amount", str(r.payload.get("amount")))
            pass_test("verify() order token — custom fields preserved in payload")
        except Exception as err:
            fail_test("verify() order token", err)

    # ─── 05 revoke() ─────────────────────────────────────────────────────────
    section("05 · revoke()")
    revoked_token = None

    if doc_token:
        try:
            r = pq.revoke(doc_token, "integration test")
            if not r.success: raise AssertionError("success is False")
            if not r.message: raise AssertionError("missing message")
            if r.sub != "doc_789": raise AssertionError(f'sub is "{r.sub}", expected "doc_789"')
            if not isinstance(r.revokedAt, (int, float)): raise AssertionError("missing revokedAt")
            if not isinstance(r.expiresAt, (int, float)): raise AssertionError("missing expiresAt")
            if not r.note:    raise AssertionError("missing note")
            log("success",   str(r.success))
            log("message",   r.message)
            log("sub",       r.sub)
            log("revokedAt", str(r.revokedAt))
            log("expiresAt", str(r.expiresAt))
            revoked_token = doc_token
            pass_test("revoke() — token revoked, all fields present")
        except Exception as err:
            fail_test("revoke()", err)

    if revoked_token:
        try:
            r = pq.verify(revoked_token)
            if r.valid:  raise AssertionError("valid should be False for revoked token")
            if not r.error: raise AssertionError("missing error message")
            if r.error != "Token has been revoked":
                raise AssertionError(f"unexpected error: {r.error}")
            log("valid", str(r.valid))
            log("error", r.error)
            pass_test("verify() revoked token — returns valid=False with correct error")
        except Exception as err:
            fail_test("verify() after revoke", err)

        try:
            r = pq.revoke(revoked_token, "second revoke attempt")
            if not r.success: raise AssertionError("success should be True")
            if not r.message: raise AssertionError("missing message")
            log("message", r.message)
            pass_test("revoke() idempotent — revoking already-revoked token returns success")
        except Exception as err:
            fail_test("revoke() idempotent", err)

    try:
        r = pq.sign("expire_revoke_test", expires_in_seconds=1)
        time.sleep(2)
        pq.revoke(r.token, "revoke after expiry")
        fail_test("revoke() expired token returns 400", "should have raised")
    except PQAuthError as err:
        if err.code == "API_ERROR" and err.status == 400:
            pass_test("revoke() expired token — raises API_ERROR(400)")
        else:
            fail_test("revoke() expired token returns 400", err)
    except Exception as err:
        fail_test("revoke() expired token returns 400", err)

    # ─── 06 Expired token ────────────────────────────────────────────────────
    section("06 · Expired token")
    try:
        r = pq.sign("expiry_test", expires_in_seconds=1)
        pass_test("sign() with expires_in_seconds=1 — token created")
        print(f"  {DIM}Waiting 2 seconds for token to expire...{RESET}")
        time.sleep(2)
        v = pq.verify(r.token)
        if v.valid:   raise AssertionError("valid should be False for expired token")
        if not v.error: raise AssertionError("missing error message")
        log("valid", str(v.valid))
        log("error", v.error)
        pass_test("verify() expired token — returns valid=False")
    except Exception as err:
        fail_test("expired token test", err)

    # ─── 07 usage() ──────────────────────────────────────────────────────────
    section("07 · usage()")
    try:
        r = pq.usage()
        if not r.current.month:                      raise AssertionError("missing current.month")
        if not isinstance(r.current.freeUsed, int):       raise AssertionError("missing current.freeUsed")
        if not isinstance(r.current.freeRemaining, int):  raise AssertionError("missing current.freeRemaining")
        if not isinstance(r.current.freeLimit, int):      raise AssertionError("missing current.freeLimit")
        if not isinstance(r.current.packRemaining, int):  raise AssertionError("missing current.packRemaining")
        if not isinstance(r.current.totalRemaining, int): raise AssertionError("missing current.totalRemaining")
        if not isinstance(r.monthlyHistory, list):        raise AssertionError("monthlyHistory is not a list")
        if len(r.monthlyHistory) != 6:                    raise AssertionError(f"monthlyHistory has {len(r.monthlyHistory)} entries, expected 6")
        if not isinstance(r.packs, list):                 raise AssertionError("packs is not a list")
        if not r.developer.get("email"):                  raise AssertionError("missing developer.email")
        log("month",          r.current.month)
        log("freeUsed",       str(r.current.freeUsed))
        log("freeRemaining",  str(r.current.freeRemaining))
        log("freeLimit",      str(r.current.freeLimit))
        log("packRemaining",  str(r.current.packRemaining))
        log("totalRemaining", str(r.current.totalRemaining))
        log("historyMonths",  str(len(r.monthlyHistory)))
        pass_test("usage() — correct shape, all fields present, 6-month history")
    except Exception as err:
        fail_test("usage()", err)

    # ─── 08 Default expiry ───────────────────────────────────────────────────
    section("08 · sign() — default expiry (no expires_in_seconds)")
    try:
        import base64
        r = pq.sign("default_expiry_test")
        payload = json.loads(base64.b64decode(r.token.payload).decode("utf-8"))
        expected_exp = payload["iat"] + 3600
        diff = abs(payload["exp"] - expected_exp)
        if diff > 5:
            raise AssertionError(f"exp is {payload['exp']}, expected ~{expected_exp} (1 hour from iat)")
        log("iat",          str(payload["iat"]))
        log("exp",          str(payload["exp"]))
        log("diff from 1h", f"{diff}s")
        pass_test("sign() — default expires_in_seconds is 3600 (1 hour)")
    except Exception as err:
        fail_test("sign() default expiry", err)

    # ─── 09 Malformed tokens ─────────────────────────────────────────────────
    section("09 · verify() — malformed token shapes")
    try:
        r = pq.verify(PQToken(payload="", signature="", algorithm="ML-DSA-65", issuedAt=0))
        if r.valid:   raise AssertionError("should be invalid")
        if not r.error: raise AssertionError("missing error message")
        log("valid", str(r.valid))
        log("error", r.error)
        pass_test("verify() empty payload/signature — returns valid=False without raising")
    except Exception as err:
        fail_test("verify() empty payload/signature", err)

    try:
        r = pq.verify(PQToken(payload="abc", signature="xyz", algorithm="UNKNOWN-ALG", issuedAt=0))
        if r.valid:   raise AssertionError("should be invalid")
        if not r.error: raise AssertionError("missing error message")
        log("valid", str(r.valid))
        log("error", r.error)
        pass_test("verify() unknown algorithm — returns valid=False without raising")
    except Exception as err:
        fail_test("verify() unknown algorithm", err)

    # ─── 10 Webhooks ─────────────────────────────────────────────────────────
    section("10 · webhooks — get before register, register, get, test, delete")

    try:
        try:
            pq.webhooks.delete()
        except Exception:
            pass
        result = pq.webhooks.get()
        if result.webhook is not None:
            raise AssertionError("webhook should be None before registering")
        log("webhook", "None")
        pass_test("webhooks.get() before register — returns None")
    except Exception as err:
        fail_test("webhooks.get() before register", err)

    try:
        result = pq.webhooks.register(
            url=WEBHOOK_URL,
            events=["token.signed", "limit.warning"],
        )
        if not result.webhook.url:     raise AssertionError("missing webhook.url")
        if not result.webhook.secret:  raise AssertionError("missing webhook.secret")
        if not result.webhook.events:  raise AssertionError("events is empty")
        log("url",    result.webhook.url)
        log("events", ", ".join(result.webhook.events))
        log("secret", result.webhook.secret[:8] + "...")
        pass_test("webhooks.register() — webhook created with secret")
    except Exception as err:
        fail_test("webhooks.register()", err)

    try:
        result = pq.webhooks.get()
        if result.webhook is None:         raise AssertionError("webhook is None after register")
        if not result.webhook.url:         raise AssertionError("missing webhook.url")
        if not result.webhook.events:      raise AssertionError("events is empty")
        if result.webhook.secret is not None:
            raise AssertionError("secret should not be returned by get()")
        log("url",    result.webhook.url)
        log("events", ", ".join(result.webhook.events))
        pass_test("webhooks.get() — returns webhook without secret")
    except Exception as err:
        fail_test("webhooks.get()", err)

    try:
        r = pq.webhooks.test()
        if not r.get("message"): raise AssertionError("missing message")
        log("message", r["message"])
        pass_test("webhooks.test() — test event dispatched")
    except Exception as err:
        fail_test("webhooks.test()", err)

    try:
        pq.webhooks.delete()
        result = pq.webhooks.get()
        if result.webhook is not None:
            raise AssertionError("webhook should be None after delete")
        pass_test("webhooks.delete() — webhook removed, get() returns None")
    except Exception as err:
        fail_test("webhooks.delete()", err)

    # ─── 11 Distinct signatures for identical payloads ───────────────────────
    section("11 · Distinct signatures for identical payloads")
    try:
        r1 = pq.sign("replay_test", role="admin", expires_in_seconds=3600)
        r2 = pq.sign("replay_test", role="admin", expires_in_seconds=3600)

        if r1.token.signature == r2.token.signature:
            raise AssertionError("signatures are identical — possible replay attack vulnerability")
        if r1.token.payload == r2.token.payload:
            raise AssertionError("payloads are identical — iat should differ between calls")

        log("signature1", r1.token.signature[:24] + "...")
        log("signature2", r2.token.signature[:24] + "...")
        log("distinct",   "yes ✓")
        pass_test("signing same payload twice produces distinct signatures — no replay vulnerability")
    except Exception as err:
        fail_test("distinct signatures test", err)

    # ─── 12 Webhook delivery confirmation ────────────────────────────────────
    section("12 · Webhook delivery confirmation")
    try:
        try:
            pq.webhooks.delete()
        except Exception:
            pass
        pq.webhooks.register(url=WEBHOOK_URL, events=["token.signed"])

        unique_sub = f"webhook_delivery_test_{int(time.time() * 1000)}"
        pq.sign(unique_sub, expires_in_seconds=300)

        print(f"  {DIM}Waiting 3 seconds for webhook delivery...{RESET}")
        time.sleep(3)

        wh_resp = _requests.get(
            f"https://webhook.site/token/{WEBHOOK_SITE_TOKEN}/requests",
            params={"sorting": "newest", "per_page": 5},
            headers={"Accept": "application/json"},
        )
        if not wh_resp.ok:
            raise AssertionError(f"webhook.site API returned {wh_resp.status_code}")

        wh_data  = wh_resp.json()
        requests_list = wh_data.get("data", [])

        if not requests_list:
            raise AssertionError("no requests received at webhook.site")

        found = None
        for req in requests_list:
            try:
                body = req["content"] if isinstance(req["content"], dict) else json.loads(req["content"])
                if body.get("event") == "token.signed" and body.get("data", {}).get("sub") == unique_sub:
                    found = body
                    break
            except Exception:
                continue

        if found is None:
            raise AssertionError(f'event for sub "{unique_sub}" not found in recent requests')

        log("event",     found["event"])
        log("sub",       found["data"]["sub"])
        log("timestamp", str(found.get("timestamp")))
        log("delivered", "yes ✓")
        pass_test("webhook delivered and confirmed — event arrived with correct payload")

        pq.webhooks.delete()
    except Exception as err:
        fail_test("webhook delivery confirmation", err)

    # ─── Summary ─────────────────────────────────────────────────────────────
    total = passed + failed
    print("\n" + "─" * 48)
    print(f"{BOLD}Results: {passed}/{total} passed{RESET}")
    if failed == 0:
        print(f"{GREEN}{BOLD}All tests passed. SDK is working correctly.{RESET}\n")
    else:
        print(f"{RED}{BOLD}{failed} test(s) failed. See above for details.{RESET}\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        run()
    except Exception as err:
        print(f"\n{RED}Unexpected error:{RESET}", err)
        import traceback
        traceback.print_exc()
        sys.exit(1)

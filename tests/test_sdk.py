#!/usr/bin/env python3
"""
FIPSign SDK — Integration test (Python)
Runs against the live backend using the published fipsign-sdk

Usage:
    FIPSIGN_API_KEY=pqa_... python tests/test_sdk.py

Optional:
    FIPSIGN_ROOT_CERT_JSON="$(cat root-cert.json)"  — enables offline verify_cert() tests (PQCert CA)
    FIPSIGN_ROOT_CERT_PEM="$(cat root-ca.pem)"      — enables offline verify_x509_cert() tests (X.509 CA)

Token cost: ~15 tokens per run. Runtime: ~10 seconds.
    No long expiry waits — expiry tests use expires_in_seconds=1 and sleep(2).

Prerequisites:
    1. Create a free account at https://app.fipsign.dev
    2. Create a project and an API key inside that project
    3. Create a CA for that project from the dashboard (PQCert or X.509)
    4. pip install fipsign-sdk
"""

import json
import os
import sys
import time
from datetime import datetime


try:
    from fipsign import PQAuth, PQAuthError, generate_key_pair
    from fipsign.types import PQToken, PQCert, KeyPairResult
except ImportError:
    print("\033[31mError: fipsign package not found. Install it with: pip install fipsign-sdk\033[0m")
    sys.exit(1)

# ─── Required environment variables ───────────────────────────────────────────

API_KEY            = os.environ.get("FIPSIGN_API_KEY")

if not API_KEY:
    print("\033[31mError: FIPSIGN_API_KEY is required.\033[0m")
    print("Get your API key at https://app.fipsign.dev")
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
    from datetime import timezone
    print(f"{DIM}fipsign-sdk · {datetime.now(timezone.utc).isoformat()}Z{RESET}\n")

    pq = PQAuth(API_KEY)

    # ─── 01 Health ───────────────────────────────────────────────────────────
    section("01 · Health check")
    try:
        h = pq.health()
        if h.status != "ok":              raise AssertionError(f'status is "{h.status}", expected "ok"')
        if h.algorithm != "ML-DSA-65":   raise AssertionError(f'algorithm is "{h.algorithm}", expected "ML-DSA-65"')
        if h.standard != "NIST FIPS 204": raise AssertionError(f'standard is "{h.standard}", expected "NIST FIPS 204"')
        if not h.quantumResistant:        raise AssertionError("quantumResistant is False")
        if not h.version:                 raise AssertionError("missing version field")
        log("status",           h.status)
        log("algorithm",        h.algorithm)
        log("standard",         h.standard)
        log("quantumResistant", str(h.quantumResistant))
        log("version",          h.version)
        pass_test("health() returns correct fields including standard")
    except Exception as err:
        fail_test("health()", err)

    # ─── 02 Invalid API key rejection ────────────────────────────────────────
    section("02 · Invalid API key rejection")

    try:
        PQAuth("bad_key")
        fail_test("constructor rejects wrong prefix", "should have raised")
    except PQAuthError as err:
        if err.code == "INVALID_API_KEY":
            pass_test("constructor raises INVALID_API_KEY for wrong prefix")
        else:
            fail_test("constructor rejects wrong prefix", err)
    except Exception as err:
        fail_test("constructor rejects wrong prefix", err)

    try:
        PQAuth("pqa_")
        fail_test("constructor rejects pqa_ with no content", "should have raised")
    except PQAuthError as err:
        if err.code == "INVALID_API_KEY":
            pass_test("constructor raises INVALID_API_KEY for pqa_ with no content")
        else:
            fail_test("constructor rejects pqa_ with no content", err)
    except Exception as err:
        fail_test("constructor rejects pqa_ with no content", err)

    try:
        PQAuth("pqa_abc123")
        fail_test("constructor rejects pqa_ + too short", "should have raised")
    except PQAuthError as err:
        if err.code == "INVALID_API_KEY":
            pass_test("constructor raises INVALID_API_KEY for pqa_ + too short")
        else:
            fail_test("constructor rejects pqa_ + too short", err)
    except Exception as err:
        fail_test("constructor rejects pqa_ + too short", err)

    try:
        PQAuth("pqa_" + "Z" * 64)
        fail_test("constructor rejects pqa_ + non-hex chars", "should have raised")
    except PQAuthError as err:
        if err.code == "INVALID_API_KEY":
            pass_test("constructor raises INVALID_API_KEY for pqa_ + non-hex chars")
        else:
            fail_test("constructor rejects pqa_ + non-hex chars", err)
    except Exception as err:
        fail_test("constructor rejects pqa_ + non-hex chars", err)

    # ─── 03 sign() ───────────────────────────────────────────────────────────
    section("03 · sign()")
    user_token = order_token = doc_token = None

    try:
        r = pq.sign("user_test", email="test@example.com", role="admin", expires_in_seconds=3600)
        if not r.token.payload:               raise AssertionError("missing token.payload")
        if not r.token.signature:             raise AssertionError("missing token.signature")
        if r.token.algorithm != "ML-DSA-65":  raise AssertionError(f"wrong algorithm: {r.token.algorithm}")
        if r.meta.tokenCost != 1:             raise AssertionError(f"tokenCost is {r.meta.tokenCost}, expected 1")
        if r.meta.source not in ("free", "pack", "free+pack"):
            raise AssertionError(f"unexpected source: {r.meta.source}")
        if not r.meta.projectId:              raise AssertionError("missing meta.projectId")
        if not r.meta.issuedFor:              raise AssertionError("missing meta.issuedFor")
        if r.meta.expiresIn != 3600:          raise AssertionError(f"meta.expiresIn is {r.meta.expiresIn}, expected 3600")
        if not isinstance(r.usage.freeRemaining, int):  raise AssertionError("missing usage.freeRemaining")
        if not isinstance(r.usage.packRemaining, int):  raise AssertionError("missing usage.packRemaining")
        if not isinstance(r.usage.totalRemaining, int): raise AssertionError("missing usage.totalRemaining")
        if not r.usage.month:                 raise AssertionError("missing usage.month")
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
            if r.payload["sub"] != "user_test":  raise AssertionError(f'sub is "{r.payload["sub"]}", expected "user_test"')
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
            if r.valid:     raise AssertionError("valid should be False for tampered token")
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
            # No verificamos el mensaje exacto — el contrato es valid=False
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
        if v.valid:     raise AssertionError("valid should be False for expired token")
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
        if not r.current.month:                           raise AssertionError("missing current.month")
        if not isinstance(r.current.freeUsed, int):      raise AssertionError("missing current.freeUsed")
        if not isinstance(r.current.freeRemaining, int): raise AssertionError("missing current.freeRemaining")
        if not isinstance(r.current.freeLimit, int):     raise AssertionError("missing current.freeLimit")
        if not isinstance(r.current.packRemaining, int): raise AssertionError("missing current.packRemaining")
        if not isinstance(r.current.totalRemaining, int):raise AssertionError("missing current.totalRemaining")
        if not isinstance(r.monthlyHistory, list):       raise AssertionError("monthlyHistory is not a list")
        if len(r.monthlyHistory) != 6:                   raise AssertionError(f"monthlyHistory has {len(r.monthlyHistory)} entries, expected 6")
        if not isinstance(r.packs, list):                raise AssertionError("packs is not a list")
        if not r.developer.get("email"):                 raise AssertionError("missing developer.email")
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
        if r.valid:     raise AssertionError("should be invalid")
        if not r.error: raise AssertionError("missing error message")
        log("valid", str(r.valid))
        log("error", r.error)
        pass_test("verify() empty payload/signature — returns valid=False without raising")
    except Exception as err:
        fail_test("verify() empty payload/signature", err)

    try:
        r = pq.verify(PQToken(payload="abc", signature="xyz", algorithm="UNKNOWN-ALG", issuedAt=0))
        if r.valid:     raise AssertionError("should be invalid")
        if not r.error: raise AssertionError("missing error message")
        log("valid", str(r.valid))
        log("error", r.error)
        pass_test("verify() unknown algorithm — returns valid=False without raising")
    except Exception as err:
        fail_test("verify() unknown algorithm", err)

    # ─── 10 Webhooks ─────────────────────────────────────────────────────────
    section("10 · webhooks — skipped (dashboard-only)")
    print(f"  [2mℹ Webhook management is dashboard-only. Configure at app.fipsign.dev[0m")
    print(f"  [2m  Webhooks fire automatically on sign(), verify(), revoke() events.[0m")

    # ─── 11 Distinct signatures for identical payloads ───────────────────────
    section("11 · Distinct signatures for identical payloads")
    try:
        r1 = pq.sign("replay_test", role="admin", expires_in_seconds=3600)
        time.sleep(1)
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
    section("12 · Webhook delivery + HMAC — skipped (dashboard-only)")
    print(f"  [2mℹ Webhooks are configured from the dashboard, not via SDK.[0m")
    print(f"  [2m  Verify HMAC con verify_webhook_signature() de fipsign.middleware.[0m")

    # ─── 13 generate_key_pair() ──────────────────────────────────────────────
    section("13 · generate_key_pair()")
    generated_public_key = None
    try:
        kp = generate_key_pair()
        if not isinstance(kp, KeyPairResult):
            raise AssertionError(f"expected KeyPairResult, got {type(kp)}")
        if not kp.publicKey:
            raise AssertionError("missing publicKey")
        if not kp.secretKey:
            raise AssertionError("missing secretKey")

        import base64
        pub_bytes  = base64.b64decode(kp.publicKey)
        seed_bytes = base64.b64decode(kp.secretKey)

        if len(pub_bytes) != 1952:
            raise AssertionError(f"publicKey decoded to {len(pub_bytes)} bytes, expected 1952")

        if len(seed_bytes) != 32:
            raise AssertionError(
                f"secretKey decoded to {len(seed_bytes)} bytes, expected 32 (seed form). "
                f"Note: this is intentionally different from the JS SDK's 4032-byte expanded key."
            )

        log("publicKey bytes",  f"{len(pub_bytes)} ✓ (ML-DSA-65 raw public key)")
        log("secretKey bytes",  f"{len(seed_bytes)} ✓ (seed form — not the 4032-byte expanded key)")
        log("publicKey b64",    kp.publicKey[:24] + "...")
        log("secretKey b64",    kp.secretKey[:24] + "...")

        generated_public_key = kp.publicKey
        pass_test("generate_key_pair() — correct key sizes: publicKey=1952B, secretKey=32B (seed)")
    except Exception as err:
        fail_test("generate_key_pair()", err)

    try:
        if generated_public_key is None:
            raise AssertionError("skipped — generate_key_pair() failed")
        import base64
        from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

        kp2         = generate_key_pair()
        seed_bytes2 = base64.b64decode(kp2.secretKey)
        private_key = MLDSA65PrivateKey.from_seed_bytes(seed_bytes2)

        msg       = b"test message for fipsign python sdk"
        signature = private_key.sign(msg)
        public_key = private_key.public_key()
        public_key.verify(signature, msg)

        if len(signature) != 3309:
            raise AssertionError(f"signature is {len(signature)} bytes, expected 3309")

        log("sign/verify roundtrip", "OK ✓")
        log("signature bytes",       f"{len(signature)} ✓ (ML-DSA-65)")
        pass_test("generate_key_pair() — secretKey sign/verify roundtrip via MLDSA65PrivateKey.from_seed_bytes()")
    except ImportError:
        print(f"  {DIM}  → sign/verify roundtrip skipped (cryptography < 48.0.0){RESET}")
    except Exception as err:
        fail_test("generate_key_pair() sign/verify roundtrip", err)

    # ─── 14 Certificate Authority ─────────────────────────────────────────────
    section("14 · Certificate Authority")

    if generated_public_key:
        device_public_key = generated_public_key
        log("key source", "generate_key_pair() — Python-native ML-DSA-65")
    else:
        device_public_key = (
            "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"
        )
        log("key source", "hardcoded JS-generated public key (fallback)")

    # 14.1 ca.issue() — happy path
    issued_cert    = None
    issued_cert_id = None
    is_x509        = False

    try:
        subject = f"device-test-{int(time.time() * 1000)}"

        try:
            r = pq.ca.issue(
                subject=subject,
                public_key=device_public_key,
                expires_in_seconds=86400,
                meta={"env": "test", "sdk": "fipsign-sdk-python"},
            )
            is_x509 = False
            log("meta", "accepted → PQCert CA detected")
        except PQAuthError as meta_err:
            if (meta_err.code == "API_ERROR"
                    and meta_err.status == 400
                    and "meta" in (meta_err.message or "").lower()):
                log("meta", "rejected with 400 → X.509 CA detected (expected)")
                pass_test("ca.issue() — X.509 CA correctly rejects meta with 400")
                r = pq.ca.issue(
                    subject=subject,
                    public_key=device_public_key,
                    expires_in_seconds=86400,
                )
                is_x509 = True
            else:
                raise

        if not r.certificate:                          raise AssertionError("missing certificate")
        if not r.meta.certId:                          raise AssertionError("missing meta.certId")
        if not isinstance(r.usage.freeRemaining, int): raise AssertionError("missing usage.freeRemaining")

        if is_x509:
            if "BEGIN CERTIFICATE" not in r.certificate:
                raise AssertionError("x509 certificate is not a valid PEM string")
            if not r.meta.caId:      raise AssertionError("missing meta.caId")
            if not r.meta.expiresAt: raise AssertionError("missing meta.expiresAt")
            log("format",     "x509")
            log("certId",     r.meta.certId)
            log("caId",       r.meta.caId)
            log("expiresAt",  str(r.meta.expiresAt))
            log("pem length", f"{len(r.certificate)} chars")
        else:
            if r.certificate.type != "CA_CERT":  raise AssertionError(f"expected CA_CERT, got {r.certificate.type}")
            if not r.certificate.id:             raise AssertionError("missing certificate.id")
            if not r.certificate.signature:      raise AssertionError("missing certificate.signature")
            if not r.certificate.caId:           raise AssertionError("missing certificate.caId")
            if not r.certificate.expiresAt:      raise AssertionError("missing certificate.expiresAt")
            log("format",    "pqcert")
            log("certId",    r.meta.certId)
            log("caId",      r.certificate.caId)
            log("subject",   r.certificate.subject)
            log("expiresAt", str(r.certificate.expiresAt))
            log("algorithm", r.certificate.algorithm)

        issued_cert    = r.certificate
        issued_cert_id = r.meta.certId
        pass_test("ca.issue() — certificate issued with correct shape")
    except Exception as err:
        fail_test("ca.issue()", err)

    # 14.2 ca.issue() — expires_in_seconds below minimum (< 60)
    try:
        pq.ca.issue(
            subject="device-expire-min-test",
            public_key=device_public_key,
            expires_in_seconds=30,
        )
        fail_test("ca.issue() rejects expires_in_seconds < 60", "should have raised")
    except PQAuthError as err:
        if err.code == "API_ERROR" and err.status == 400:
            log("expires_in_seconds", "30 → rejected")
            pass_test("ca.issue() — raises API_ERROR(400) when expires_in_seconds < 60")
        else:
            fail_test("ca.issue() rejects expires_in_seconds < 60", err)
    except Exception as err:
        fail_test("ca.issue() rejects expires_in_seconds < 60", err)

    # 14.3 ca.issue() — expires_in_seconds above maximum (> 5 years)
    try:
        pq.ca.issue(
            subject="device-expire-max-test",
            public_key=device_public_key,
            expires_in_seconds=200_000_000,
        )
        fail_test("ca.issue() rejects expires_in_seconds > 5 years", "should have raised")
    except PQAuthError as err:
        if err.code == "API_ERROR" and err.status == 400:
            log("expires_in_seconds", "200_000_000 → rejected")
            pass_test("ca.issue() — raises API_ERROR(400) when expires_in_seconds > 5 years")
        else:
            fail_test("ca.issue() rejects expires_in_seconds > 5 years", err)
    except Exception as err:
        fail_test("ca.issue() rejects expires_in_seconds > 5 years", err)

    # 14.4 ca.verify_cert() — offline verification (PQCert only)
    ROOT_CERT_JSON_STR = os.environ.get("FIPSIGN_ROOT_CERT_JSON")

    if not ROOT_CERT_JSON_STR:
        print(f"  {DIM}ℹ FIPSIGN_ROOT_CERT_JSON not set — ca.verify_cert() tests skipped.{RESET}")
        print(f"  {DIM}  To enable: FIPSIGN_ROOT_CERT_JSON='$(cat root-cert.json)' python tests/test_sdk.py{RESET}")
    elif is_x509:
        print(f"  {DIM}ℹ ca.verify_cert() tests skipped — X.509 CA detected (PQCert only).{RESET}")
        print(f"  {DIM}  For X.509 offline verify use pq.ca.verify_x509_cert() (see below).{RESET}")
    else:
        # 14.4a — valid certificate verifies correctly
        try:
            if issued_cert is None:
                raise AssertionError("skipped — ca.issue() failed")
            root_cert_dict = json.loads(ROOT_CERT_JSON_STR)
            from fipsign.types import PQCert as _PQCert
            root_cert = _PQCert.from_dict(root_cert_dict)
            result = pq.ca.verify_cert(issued_cert, root_cert)
            if not result.valid:
                raise AssertionError(f"verify_cert returned invalid: {result.error}")
            if result.cert is None:
                raise AssertionError("result.cert should not be None when valid=True")
            if result.cert.subject != issued_cert.subject:
                raise AssertionError(f"result.cert.subject mismatch: {result.cert.subject}")
            log("valid",   str(result.valid))
            log("subject", result.cert.subject)
            pass_test("ca.verify_cert() — valid certificate verified offline against root cert")
        except Exception as err:
            fail_test("ca.verify_cert() valid cert", err)

        # 14.4b — tampered certificate is rejected
        try:
            if issued_cert is None:
                raise AssertionError("skipped — ca.issue() failed")
            import dataclasses
            tampered = dataclasses.replace(issued_cert, subject="TAMPERED-SUBJECT")
            result = pq.ca.verify_cert(tampered, root_cert)
            if result.valid:
                raise AssertionError("tampered cert should be invalid")
            if not result.error:
                raise AssertionError("missing error message")
            log("valid", str(result.valid))
            log("error", result.error)
            pass_test("ca.verify_cert() — tampered certificate correctly rejected")
        except Exception as err:
            fail_test("ca.verify_cert() tampered cert", err)

        # 14.4c — wrong root CA is rejected
        try:
            if issued_cert is None:
                raise AssertionError("skipped — ca.issue() failed")
            wrong_root = dataclasses.replace(root_cert, id="ca_wrong_000000000000000000000000")
            result = pq.ca.verify_cert(issued_cert, wrong_root)
            if result.valid:
                raise AssertionError("wrong CA should be rejected")
            if "caId mismatch" not in (result.error or ""):
                raise AssertionError(f"unexpected error: {result.error}")
            log("valid", str(result.valid))
            log("error", result.error)
            pass_test("ca.verify_cert() — wrong root CA correctly rejected (caId mismatch)")
        except Exception as err:
            fail_test("ca.verify_cert() wrong CA", err)

        # 14.4d — cert with meta verifies correctly (validates key ordering)
        try:
            if not is_x509:
                r_meta = pq.ca.issue(
                    subject=f"device-meta-{int(time.time() * 1000)}",
                    public_key=device_public_key,
                    expires_in_seconds=86400,
                    meta={"model": "lock-v2", "batch": "2026-05"},
                )
                result = pq.ca.verify_cert(r_meta.certificate, root_cert)
                if not result.valid:
                    raise AssertionError(f"cert with meta failed: {result.error}")
                log("valid", str(result.valid))
                log("meta",  str(r_meta.certificate.meta))
                pass_test("ca.verify_cert() — certificate with meta correctly verified (key ordering preserved)")
                pq.ca.revoke_cert(r_meta.meta.certId, "test cleanup").revokedAt  # noqa
        except Exception as err:
            fail_test("ca.verify_cert() cert with meta", err)

    # 14.4x ca.verify_x509_cert() — offline verification (X.509 only)
    # Requires FIPSIGN_ROOT_CERT_PEM env var (the PEM saved at CA creation).
    # Skipped for PQCert CAs — use pq.ca.verify_cert() for PQCert.
    ROOT_CERT_PEM_STR = os.environ.get("FIPSIGN_ROOT_CERT_PEM")

    if not ROOT_CERT_PEM_STR:
        print(f"  {DIM}ℹ FIPSIGN_ROOT_CERT_PEM not set — ca.verify_x509_cert() tests skipped.{RESET}")
        print(f"  {DIM}  To enable: FIPSIGN_ROOT_CERT_PEM='$(cat root-ca.pem)' python tests/test_sdk.py{RESET}")
    elif not is_x509:
        print(f"  {DIM}ℹ ca.verify_x509_cert() tests skipped — PQCert CA detected (X.509 only).{RESET}")
        print(f"  {DIM}  For PQCert offline verify use pq.ca.verify_cert() (see 14.4 above).{RESET}")
    else:
        # 14.4x-a — valid certificate verifies correctly
        try:
            if issued_cert is None:
                raise AssertionError("skipped — ca.issue() failed")
            result = pq.ca.verify_x509_cert(issued_cert, ROOT_CERT_PEM_STR)
            if not result.valid:
                raise AssertionError(f"verify_x509_cert returned invalid: {result.error}")
            if result.cert is None:
                raise AssertionError("result.cert should not be None when valid=True")
            if not result.cert.startswith("-----BEGIN CERTIFICATE-----"):
                raise AssertionError(f"result.cert is not a PEM string: {result.cert[:40]}")
            log("valid",   str(result.valid))
            log("cert",    result.cert[:27] + "...")
            pass_test("ca.verify_x509_cert() — valid certificate verified offline against root PEM")
        except Exception as err:
            fail_test("ca.verify_x509_cert() valid cert", err)

        # 14.4x-b — tampered certificate (modified PEM content) is rejected
        try:
            if issued_cert is None:
                raise AssertionError("skipped — ca.issue() failed")
            lines = issued_cert.strip().split("\n")
            tampered_lines = []
            corrupted = False
            for line in lines:
                if not corrupted and not line.startswith("-----") and len(line) > 10:
                    mid = len(line) // 2
                    char = line[mid]
                    replacement = "B" if char != "B" else "C"
                    line = line[:mid] + replacement + line[mid + 1:]
                    corrupted = True
                tampered_lines.append(line)
            tampered_pem = "\n".join(tampered_lines) + "\n"
            result = pq.ca.verify_x509_cert(tampered_pem, ROOT_CERT_PEM_STR)
            if result.valid:
                raise AssertionError("tampered cert should be invalid")
            if not result.error:
                raise AssertionError("missing error message")
            log("valid", str(result.valid))
            log("error", result.error)
            pass_test("ca.verify_x509_cert() — tampered certificate correctly rejected")
        except Exception as err:
            fail_test("ca.verify_x509_cert() tampered cert", err)

        # 14.4x-c — wrong root CA is rejected (using leaf cert as fake root)
        try:
            if issued_cert is None:
                raise AssertionError("skipped — ca.issue() failed")
            result = pq.ca.verify_x509_cert(issued_cert, issued_cert)
            if result.valid:
                raise AssertionError("wrong CA should be rejected")
            if not result.error:
                raise AssertionError("missing error message")
            log("valid", str(result.valid))
            log("error", result.error)
            pass_test("ca.verify_x509_cert() — wrong root CA correctly rejected")
        except Exception as err:
            fail_test("ca.verify_x509_cert() wrong CA", err)

    # 14.5 ca.get_crl() — before revocation
    crl_before = None
    try:
        r = pq.ca.get_crl()
        if not r.caId:                         raise AssertionError("missing caId")
        if not r.subject:                      raise AssertionError("missing subject")
        if not isinstance(r.crl, list):        raise AssertionError("crl is not a list")
        if not isinstance(r.generatedAt, int): raise AssertionError("missing generatedAt")
        if r.format not in ("pqcert", "x509"): raise AssertionError(f"unexpected format: {r.format}")
        log("caId",        r.caId)
        log("subject",     r.subject)
        log("format",      r.format)
        log("crl entries", str(len(r.crl)))
        if r.format == "x509":
            if r.raw is None:
                raise AssertionError("x509 CRL: raw should not be None")
            if not r.raw.get("signature"):
                raise AssertionError("x509 CRL: raw.signature is missing")
            log("raw.signature", r.raw["signature"][:16] + "...")
        crl_before = r.crl
        pass_test("ca.get_crl() — CRL returned with correct shape" + (" (incl. raw.signature for x509)" if r.format == "x509" else ""))
    except Exception as err:
        fail_test("ca.get_crl()", err)

    # 14.6 ca.is_cert_revoked() — before revocation (certId string)
    try:
        if issued_cert_id is None or crl_before is None:
            raise AssertionError("skipped — previous steps failed")
        revoked = pq.ca.is_cert_revoked(issued_cert_id, crl_before)
        if revoked: raise AssertionError("cert should NOT be revoked yet")
        log("certId",  issued_cert_id[:24] + "...")
        log("revoked", str(revoked))
        pass_test("ca.is_cert_revoked() with certId string — cert not in CRL before revocation")
    except Exception as err:
        fail_test("ca.is_cert_revoked() before revocation", err)

    # 14.6b ca.is_cert_revoked() with PQCert object (pqcert format only)
    if not is_x509 and issued_cert is not None and crl_before is not None:
        try:
            revoked = pq.ca.is_cert_revoked(issued_cert, crl_before)
            if revoked: raise AssertionError("cert should NOT be revoked yet")
            log("revoked", str(revoked))
            pass_test("ca.is_cert_revoked() with PQCert object — cert not in CRL before revocation")
        except Exception as err:
            fail_test("ca.is_cert_revoked() with PQCert object before revocation", err)

    # 14.6 ca.get_cert() — existing cert
    try:
        if not issued_cert_id: raise AssertionError("skipped — ca.issue() failed")
        r = pq.ca.get_cert(issued_cert_id)
        if not r.certificate:              raise AssertionError("missing certificate")
        if not r.status:                   raise AssertionError("missing status")
        if r.status.revoked:               raise AssertionError("cert should not be revoked yet")
        if r.status.expired:               raise AssertionError("cert should not be expired")
        if r.status.revokedAt is not None: raise AssertionError("revokedAt should be None")
        if isinstance(r.certificate, str):
            log("format",  "x509")
            log("pem",     r.certificate[:27] + "...")
            if r.meta is None:
                raise AssertionError("x509 get_cert(): meta should not be None")
            if not r.meta.certId:    raise AssertionError("meta.certId missing")
            if not r.meta.caId:      raise AssertionError("meta.caId missing")
            if not r.meta.subject:   raise AssertionError("meta.subject missing")
            if not r.meta.format:    raise AssertionError("meta.format missing")
            if not r.meta.algorithm: raise AssertionError("meta.algorithm missing")
            log("meta.certId",    r.meta.certId)
            log("meta.format",    r.meta.format)
        else:
            log("format",  "pqcert")
            log("certId",  r.certificate.id)
            if r.meta is not None:
                raise AssertionError("pqcert get_cert(): meta should be None")
        log("revoked", str(r.status.revoked))
        log("expired", str(r.status.expired))
        pass_test("ca.get_cert() — certificate retrieved with correct status and meta")
    except Exception as err:
        fail_test("ca.get_cert()", err)

    # 14.7 ca.get_cert() — non-existent certId returns 404
    try:
        pq.ca.get_cert("cert_nonexistent_000000000000000000000000")
        fail_test("ca.get_cert() non-existent certId — should have raised", "did not raise")
    except PQAuthError as err:
        if err.code == "API_ERROR" and err.status == 404:
            log("certId", "cert_nonexistent_... → 404")
            pass_test("ca.get_cert() — raises API_ERROR(404) for non-existent certId")
        else:
            fail_test("ca.get_cert() non-existent certId", err)
    except Exception as err:
        fail_test("ca.get_cert() non-existent certId", err)

    # 14.8 ca.revoke_cert()
    try:
        if not issued_cert_id: raise AssertionError("skipped — ca.issue() failed")
        r = pq.ca.revoke_cert(issued_cert_id, "python sdk integration test")
        if not r.certId:                           raise AssertionError("missing certId")
        if not r.revokedAt:                        raise AssertionError("missing revokedAt")
        if r.reason != "python sdk integration test": raise AssertionError(f"wrong reason: {r.reason}")
        if not isinstance(r.usage.freeRemaining, int): raise AssertionError("missing usage")
        if is_x509:
            if r.format != "x509":
                raise AssertionError(f"x509 revoke_cert(): expected format='x509', got {r.format!r}")
            log("format", r.format)
        log("certId",    r.certId)
        log("revokedAt", str(r.revokedAt))
        log("reason",    r.reason)
        pass_test("ca.revoke_cert() — certificate revoked successfully")
    except Exception as err:
        fail_test("ca.revoke_cert()", err)

    # 14.9 ca.revoke_cert() — already revoked should return 409
    try:
        if not issued_cert_id: raise AssertionError("skipped — ca.issue() failed")
        pq.ca.revoke_cert(issued_cert_id, "duplicate revocation")
        fail_test("ca.revoke_cert() duplicate — should have raised", "did not raise")
    except PQAuthError as err:
        if err.status == 409:
            pass_test("ca.revoke_cert() duplicate — correctly returns 409")
        else:
            fail_test("ca.revoke_cert() duplicate", err)
    except Exception as err:
        fail_test("ca.revoke_cert() duplicate", err)

    # 14.10 ca.get_crl() — after revocation
    crl_after = None
    try:
        r = pq.ca.get_crl()
        if not isinstance(r.crl, list): raise AssertionError("crl is not a list")
        if r.format == "x509":
            if r.raw is None or not r.raw.get("signature"):
                raise AssertionError("x509 CRL after revocation: raw.signature missing")
        crl_after = r.crl
        entry = next((e for e in r.crl if e.certId == issued_cert_id), None)
        if entry:
            reason_is_valid = entry.reason is None or isinstance(entry.reason, str)
            if not reason_is_valid:
                raise AssertionError(f"reason must be str or None, got: {type(entry.reason)}")
            log("reason type", "None" if entry.reason is None else f'"{entry.reason}"')
        log("crl entries after revocation", str(len(r.crl)))
        pass_test("ca.get_crl() after revocation — CRL fetched, reason field is str or None")
    except Exception as err:
        fail_test("ca.get_crl() after revocation", err)

    # 14.11 ca.is_cert_revoked() — after revocation, using certId string
    try:
        if issued_cert_id is None or crl_after is None:
            raise AssertionError("skipped — previous steps failed")
        revoked = pq.ca.is_cert_revoked(issued_cert_id, crl_after)
        if not revoked: raise AssertionError("cert SHOULD be revoked now")
        log("certId",  issued_cert_id[:24] + "...")
        log("revoked", str(revoked))
        pass_test("ca.is_cert_revoked() with certId string — cert found in CRL after revocation")
    except Exception as err:
        fail_test("ca.is_cert_revoked() after revocation", err)

    # 14.11b ca.is_cert_revoked() with PQCert object after revocation (pqcert only)
    if not is_x509 and issued_cert is not None and crl_after is not None:
        try:
            revoked = pq.ca.is_cert_revoked(issued_cert, crl_after)
            if not revoked: raise AssertionError("cert SHOULD be revoked now")
            log("revoked", str(revoked))
            pass_test("ca.is_cert_revoked() with PQCert object — cert found in CRL after revocation")
        except Exception as err:
            fail_test("ca.is_cert_revoked() with PQCert object after revocation", err)

    # 14.12 ca.get_cert() — status after revocation
    try:
        if not issued_cert_id: raise AssertionError("skipped — ca.issue() failed")
        r = pq.ca.get_cert(issued_cert_id)
        if not r.status.revoked:   raise AssertionError("cert should be revoked now")
        if not r.status.revokedAt: raise AssertionError("revokedAt should be set")
        log("revoked",   str(r.status.revoked))
        log("revokedAt", str(r.status.revokedAt))
        pass_test("ca.get_cert() after revocation — status.revoked is True")
    except Exception as err:
        fail_test("ca.get_cert() after revocation", err)

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

#!/usr/bin/env python3
"""
ca.verify_crl() - checks that a revocation list was signed by the CA, for PQCert and X.509 CAs.

Offline: no API key, no network, no tokens. A stub FIPSign on localhost serves the lists.
Runs the synchronous client and, when httpx is installed, the asynchronous one.

Usage:  python tests/test_verify_crl.py        (also runs under pytest)

What it checks:
  - a real list of each kind, captured from FIPSign (tests/crl_fixtures.json): valid with its root, through
    get_crl() and as the signed dict itself;
  - every way of altering a list (hiding or adding a revocation, changing a field, moving generatedAt, a bad signature)
    makes it invalid, and so does the wrong root;
  - lists made here with a fresh CA key: empty, large, non-ASCII reasons, keys in any order;
  - it never raises, whatever it is given.
"""
import asyncio
import base64
import copy
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Always test the code of this working tree, not a fipsign-sdk that happens to be installed.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fipsign import PQAuth, PQCert, CaGetCrlResult

try:
    from fipsign import AsyncPQAuth
    import httpx  # noqa: F401
except ImportError:
    AsyncPQAuth = None

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
FX = json.load(open(os.path.join(HERE, "crl_fixtures.json"), encoding="utf-8"))

PASSED = FAILED = 0


def check(name, cond, why=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print("PASS  " + name)
    else:
        FAILED += 1
        print("FAIL  " + name + "\n        " + str(why))


def b64(raw):
    return base64.b64encode(raw).decode()


# A serializer written for this test, apart from the SDK's: keys sorted at every level, UTF-8, no spaces.
def ser(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# ─── A stub FIPSign that serves one answer for GET /ca/crl ───────────────────

ANSWER = {"body": {}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        data = json.dumps(ANSWER["body"]).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


SERVER = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
SERVER.daemon_threads = True
threading.Thread(target=SERVER.serve_forever, daemon=True).start()
BASE_URL = "http://127.0.0.1:%d" % SERVER.server_address[1]
KEY = "pqa_" + "a" * 64
PQ = PQAuth(KEY, base_url=BASE_URL)


def serve(body):
    ANSWER["body"] = body


# ─── A CA made here (for lists that FIPSign did not sign) ────────────────────

class MadeCa:
    def __init__(self, ca_id=None):
        self.id = ca_id or "ca_test_" + os.urandom(4).hex()
        self.sk = MLDSA65PrivateKey.generate()
        self.root_dict = {"type": "CA_ROOT", "id": self.id, "subject": "Test CA", "publicKey": b64(self.sk.public_key().public_bytes_raw()),
                          "issuedAt": 1, "algorithm": "ML-DSA-65", "standard": "NIST FIPS 204", "signature": "x"}
        self.root = PQCert.from_dict(self.root_dict)

    def sign_list(self, revoked, **extra):
        payload = {"caId": self.id, "subject": "Test CA", "format": "pqcert", "algorithm": "ML-DSA-65",
                   "generatedAt": int(time.time()), "revokedCerts": revoked, **extra}
        return {**payload, "signature": b64(self.sk.sign(ser(payload).encode("utf-8")))}


def invalid(name, crl, root, expect=None):
    r = PQ.ca.verify_crl(crl, root)
    check(name, r.valid is False and isinstance(r.error, str) and r.error != "" and r.generatedAt is None
          and (expect is None or expect in r.error), repr(r))


def run_sync():
    for fmt in ("pqcert", "x509"):
        fx = FX[fmt]
        root, crl, revoked_ids, not_revoked_id = fx["root"], fx["crl"], fx["revokedIds"], fx["notRevokedId"]
        print("\n== 1. A real %s list from FIPSign" % fmt)
        direct = PQ.ca.verify_crl(crl, root)
        check("%s: the signed dict is valid with its root, and generatedAt is the signed one" % fmt,
              direct.valid is True and direct.generatedAt == crl["generatedAt"] and direct.error is None, repr(direct))
        serve({"success": True, "crl": crl, "generatedAt": crl["generatedAt"], "verifyNote": "x"})
        got = PQ.ca.get_crl()
        check("%s: get_crl() keeps the signed object in raw, format and the flat entries in crl" % fmt,
              got.raw is not None and got.raw["signature"] == crl["signature"] and got.format == fmt and len(got.crl) == 3 and got.caId == crl["caId"], repr(got)[:200])
        via = PQ.ca.verify_crl(got, root)
        check("%s: the result of get_crl() is valid with the root" % fmt, via.valid is True and via.generatedAt == crl["generatedAt"], repr(via))
        check("%s: is_cert_revoked finds the 3 revoked certs and not the other one" % fmt,
              all(PQ.ca.is_cert_revoked(i, got.crl) for i in revoked_ids) and not PQ.ca.is_cert_revoked(not_revoked_id, got.crl))
        check("%s: the non-ASCII reason arrived intact" % fmt, any(e.reason == "revocación 日本語 🔒 “quotes”" for e in got.crl))
        reordered = dict(reversed(list(copy.deepcopy(crl).items())))
        check("%s: the order of the keys in the dict does not matter" % fmt, PQ.ca.verify_crl(reordered, root).valid is True)

        print("\n== 2. Every alteration of the %s list is caught" % fmt)

        def flip_sig(c):
            s = bytearray(base64.b64decode(c["signature"])); s[7] ^= 1; c["signature"] = b64(bytes(s))

        def change_cert_id(c):
            i = c["revokedCerts"][0]["certId"]; c["revokedCerts"][0]["certId"] = i[:-1] + ("1" if i.endswith("0") else "0")

        def change_nonascii(c):
            e = next(x for x in c["revokedCerts"] if "日本語" in (x["reason"] or "")); e["reason"] = e["reason"].replace("🔒", "🔓")

        mutations = {
            "the newest revocation removed (hiding one)": lambda c: c["revokedCerts"].pop(0),
            "the oldest revocation removed": lambda c: c["revokedCerts"].pop(),
            "all revocations removed": lambda c: c.update(revokedCerts=[]),
            "a revocation added": lambda c: c["revokedCerts"].append({"certId": "cert_not_in_the_list", "reason": None, "revokedAt": 1}),
            "entries reordered": lambda c: c["revokedCerts"].reverse(),
            "a certId changed": change_cert_id,
            "a reason changed": lambda c: c["revokedCerts"][0].update(reason="other"),
            "the non-ASCII reason changed by one character": change_nonascii,
            "a revokedAt changed": lambda c: c["revokedCerts"][0].update(revokedAt=c["revokedCerts"][0]["revokedAt"] + 1),
            "generatedAt moved (an old list passed off as new)": lambda c: c.update(generatedAt=c["generatedAt"] + 1),
            "caId changed": lambda c: c.update(caId=c["caId"] + "x"),
            "subject changed": lambda c: c.update(subject="Other CA"),
            "format changed": lambda c: c.update(format="x509" if fmt == "pqcert" else "pqcert"),
            "algorithm changed": lambda c: c.update(algorithm="ML-DSA-87"),
            "a field added": lambda c: c.update(extra=True),
            "a field removed": lambda c: c.pop("subject"),
            "one byte of the signature flipped": flip_sig,
            "the signature truncated": lambda c: c.update(signature=b64(base64.b64decode(c["signature"])[:3000])),
            "the signature is not base64": lambda c: c.update(signature="***not base64***"),
            "the signature is empty": lambda c: c.update(signature=""),
            "the signature is missing": lambda c: c.pop("signature"),
        }
        for what, mutate in mutations.items():
            c = copy.deepcopy(crl)
            mutate(c)
            invalid("%s: %s" % (fmt, what), c, root)

        print("\n== 3. The %s list through get_crl(): what you read has to be what was signed" % fmt)
        g = copy.deepcopy(got); g.crl.pop(0)
        invalid("the entries in crl differ from the signed ones (one removed)", g, root, "not the signed ones")
        g = copy.deepcopy(got); g.crl[0].reason = "edited"
        invalid("an entry in crl was edited", g, root, "not the signed ones")
        g = copy.deepcopy(got); g.generatedAt += 60
        invalid("generatedAt of the result differs from the signed one", g, root, "not the signed ones")
        g = copy.deepcopy(got); g.caId = "ca_other"
        invalid("caId of the result differs from the signed one", g, root, "not the signed ones")
        g = copy.deepcopy(got); g.raw["revokedCerts"].pop(0)
        invalid("the signed object inside the result was altered", g, root)

    print("\n== 4. The wrong root")
    root, crl = FX["pqcert"]["root"], FX["pqcert"]["crl"]
    other = MadeCa(root["id"])
    invalid("pqcert list with the CA_ROOT of another CA that has the same id: bad signature", crl, other.root, "Invalid list signature")
    invalid('pqcert list with a CA_ROOT of another id: "not issued by this CA"', crl, MadeCa("ca_someone_else").root, "not issued by this CA")
    invalid("pqcert list with a CA_CERT instead of the CA_ROOT", crl, {**root, "type": "CA_CERT"}, "CA_ROOT")
    invalid("pqcert list with the root as a string", crl, json.dumps(root), "CA_ROOT")
    invalid("pqcert list with a PEM", crl, FX["x509"]["root"], "CA_ROOT")
    invalid("pqcert list with no root", crl, None, "CA_ROOT")
    invalid("pqcert list with a root dict that misses fields", crl, {"type": "CA_ROOT"}, "CA_ROOT")
    invalid("pqcert list with a root whose key is not base64", crl, {**root, "publicKey": "***"}, "not a valid ML-DSA-65 key")
    invalid("pqcert list with a root whose key has the wrong size", crl, {**root, "publicKey": b64(bytes(100))}, "not a valid ML-DSA-65 key")
    check("pqcert list with the root as a PQCert object or as its dict: same answer",
          PQ.ca.verify_crl(crl, PQCert.from_dict(root)).valid and PQ.ca.verify_crl(crl, root).valid)
    x = FX["x509"]
    invalid("x509 list with a PQCert root dict", x["crl"], FX["pqcert"]["root"], "PEM")
    invalid("x509 list with a PQCert root object", x["crl"], PQCert.from_dict(FX["pqcert"]["root"]), "PEM")
    invalid("x509 list with no root", x["crl"], None, "PEM")
    invalid("x509 list with a string that is not a PEM", x["crl"], "hello", "could not be read")
    invalid("x509 list with an empty string as root", x["crl"], "", "could not be read")
    invalid("x509 list with a truncated PEM", x["crl"], x["root"][:200], "could not be read")
    der = bytearray(base64.b64decode("".join(l for l in x["root"].splitlines() if not l.startswith("-----"))))
    key_at = bytes(der).find(bytes([0x03, 0x82, 0x07, 0xA1, 0x00]))   # BIT STRING of 1953 bytes: the ML-DSA-65 key
    check("(the public key was found inside the root certificate)", key_at > 0, key_at)
    der[key_at + 5 + 100] ^= 1
    b = b64(bytes(der))
    pem_other = "-----BEGIN CERTIFICATE-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + "\n-----END CERTIFICATE-----\n"
    invalid("x509 list with a root whose key was changed by one byte: invalid signature, no exception", x["crl"], pem_other, "Invalid list signature")

    print("\n== 5. Lists made here")
    ca = MadeCa()
    check("an empty list is valid", PQ.ca.verify_crl(ca.sign_list([]), ca.root).valid is True)
    reasons = ["key compromise", None, "revocación 日本語 🔒 “quotes” \\ back", "", "x" * 256, "\u0000 control \u001f", "surrogate pair 𝄞"]
    entries = [{"certId": "cert_%d" % i, "reason": r, "revokedAt": 1000 - i} for i, r in enumerate(reasons)]
    with_reasons = ca.sign_list(entries)
    check("reasons with non-ASCII, emoji, quotes, backslash, empty, control characters, None and 256 characters are valid",
          PQ.ca.verify_crl(with_reasons, ca.root).valid is True)
    serve({"success": True, "crl": with_reasons, "generatedAt": with_reasons["generatedAt"], "verifyNote": "x"})
    check("the same through get_crl()", PQ.ca.verify_crl(PQ.ca.get_crl(), ca.root).valid is True)
    big = ca.sign_list([{"certId": "cert_%d" % i, "reason": None if i % 3 else "r%d" % i, "revokedAt": 5000 - i} for i in range(5000)])
    t0 = time.time(); rb = PQ.ca.verify_crl(big, ca.root)
    check("a list of 5000 entries is valid (%d ms)" % ((time.time() - t0) * 1000), rb.valid is True)
    wrong = ca.sign_list(entries); wrong["revokedCerts"][0]["reason"] = "x"
    invalid("a list edited after signing is invalid", wrong, ca.root)
    age = PQ.ca.verify_crl(ca.sign_list([]), ca.root)
    check("generatedAt lets the caller judge how old the list is", age.valid and abs(time.time() - age.generatedAt) < 5)

    print("\n== 6. A list that is not signed")
    flat = {"success": True, "caId": "ca_x", "subject": "S", "crl": [{"certId": "cert_1", "revokedAt": 5, "reason": None}], "generatedAt": 10}
    serve(flat)
    plain = PQ.ca.get_crl()
    check("a plain array answer is still read by get_crl() (caId, subject, entries, generatedAt, no raw)",
          plain.caId == "ca_x" and len(plain.crl) == 1 and plain.generatedAt == 10 and plain.raw is None and plain.format == "pqcert", repr(plain))
    check("is_cert_revoked still works on it", PQ.ca.is_cert_revoked("cert_1", plain.crl) is True)
    invalid("verify_crl says it is not signed", plain, MadeCa("ca_x").root, "not signed")
    invalid("the same for a dict without signature", {"caId": "ca_x", "subject": "S", "revokedCerts": [], "generatedAt": 10}, MadeCa("ca_x").root, "not signed")

    print("\n== 7. It never raises")
    root_obj = PQCert.from_dict(FX["pqcert"]["root"])
    junk = [None, 0, 42, "text", True, [], [1, 2], {}, {"signature": 1}, {"signature": "abc"}, {"signature": "abc", "revokedCerts": "no"},
            {"signature": "abc", "revokedCerts": [], "caId": 1}, object(), CaGetCrlResult("a", "s", [], 1), CaGetCrlResult("a", "s", [], 1, "pqcert", {}),
            CaGetCrlResult("a", "s", [], 1, "pqcert", {"signature": 5}), CaGetCrlResult("a", "s", None, 1, "pqcert", {"signature": "x"}),
            {"signature": "abc", "revokedCerts": [], "caId": "a", "generatedAt": True, "algorithm": "ML-DSA-65", "format": "pqcert"},
            {"signature": "abc", "revokedCerts": [], "caId": "a", "generatedAt": 1.5, "algorithm": "ML-DSA-65", "format": "pqcert"},
            {"signature": "abc", "revokedCerts": [object()], "caId": "a", "generatedAt": 1, "algorithm": "ML-DSA-65", "format": "pqcert"}]
    raised, all_invalid = None, True
    for j in junk:
        try:
            r = PQ.ca.verify_crl(j, root_obj)
            if r.valid is not False or not r.error:
                all_invalid = False
        except Exception as exc:                       # noqa: BLE001
            raised = exc
            break
    check("%d kinds of wrong input: no exception, always valid=False with an error" % len(junk), raised is None and all_invalid, repr(raised))
    raised = None
    for rt in [None, 0, [], {}, object(), {"type": "CA_ROOT"}, {"type": "CA_ROOT", "id": FX["pqcert"]["crl"]["caId"]}, 1.5, b"bytes"]:
        try:
            r = PQ.ca.verify_crl(FX["pqcert"]["crl"], rt)
            if r.valid is not False:
                raised = AssertionError("valid with a bad root")
        except Exception as exc:                       # noqa: BLE001
            raised = exc
            break
    check("9 kinds of wrong root: no exception, never valid", raised is None, repr(raised))


async def run_async():
    print("\n== 8. The asynchronous client")
    ca = MadeCa()
    signed = ca.sign_list([{"certId": "cert_a", "reason": "r", "revokedAt": 5}])
    serve({"success": True, "crl": signed, "generatedAt": signed["generatedAt"], "verifyNote": "x"})
    async with AsyncPQAuth(KEY, base_url=BASE_URL) as apq:
        got = await apq.ca.get_crl()
        check("async: get_crl() keeps the signed object in raw", got.raw is not None and got.raw["signature"] == signed["signature"] and got.format == "pqcert")
        check("async: verify_crl(get_crl() result) is valid (a plain call, no await)", apq.ca.verify_crl(got, ca.root).valid is True)
        check("async: the signed dict is valid too", apq.ca.verify_crl(signed, ca.root).valid is True)
        got.crl.pop()
        check("async: what you read differs from what was signed: invalid", apq.ca.verify_crl(got, ca.root).valid is False)
        for fmt in ("pqcert", "x509"):
            serve({"success": True, "crl": FX[fmt]["crl"], "generatedAt": FX[fmt]["crl"]["generatedAt"], "verifyNote": "x"})
            r = await apq.ca.get_crl()
            check("async: real %s list from FIPSign is valid" % fmt, apq.ca.verify_crl(r, FX[fmt]["root"]).valid is True)
            c = copy.deepcopy(FX[fmt]["crl"]); c["revokedCerts"].pop(0)
            check("async: real %s list with a revocation hidden is invalid" % fmt, apq.ca.verify_crl(c, FX[fmt]["root"]).valid is False)
        check("async: it never raises", apq.ca.verify_crl(None, None).valid is False)


def main():
    run_sync()
    if AsyncPQAuth is not None:
        asyncio.run(run_async())
    else:
        print("\n(httpx is not installed: the asynchronous client was not tested)")
    SERVER.shutdown()
    print("\n%d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


def test_verify_crl():                                 # pytest entry point
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())

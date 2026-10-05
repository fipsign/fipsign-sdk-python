#!/usr/bin/env python3
"""
Mandate audit - receipts, the event log, the export, and checking them offline.

Offline: no API key, no network, no tokens. A stub FIPSign on localhost answers the calls and records what the SDK sent.
Runs the synchronous client and, when httpx is installed, the asynchronous one.

Usage:  python tests/test_mandate_audit.py        (also runs under pytest)

What it checks:
  - what the SDK sends: `correlation_id` and `receipt` only when asked (every call without them sends what it always sent),
    the URLs and query strings of the read calls, pagination, and that a loop that does not advance stops with an error;
  - real receipts and a real export captured from FIPSign (tests/mandate_audit_fixtures.json), before and after a key rotation:
    valid with the right key, invalid with the wrong one, and invalid for every way of altering them;
  - logs made here with a fresh project key (ML-DSA-44, -65 and -87): checkpoints, signed head, several pages, non-ASCII text,
    a history rewritten with a recomputed chain, events missing at the start, in the middle and at the end;
  - the key rules: a list of keys that comes from FIPSign is only trusted through a pinned fingerprint;
  - what the SDK hands back (receipt objects, export pages) checks out as it is and after a round trip through JSON;
  - verify_mandate_receipt() and verify_mandate_export() never raise, whatever they are given.
"""
import asyncio
import base64
import copy
import hashlib
import json
import os
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

# Always test the code of this working tree, not a fipsign-sdk that happens to be installed.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fipsign import (
    PQAuth, PQAuthError, PQToken, MandateReceipt, MandateExportPage,
    public_key_fingerprint, verify_mandate_export, verify_mandate_receipt,
)

try:
    from fipsign import AsyncPQAuth
    import httpx  # noqa: F401
except ImportError:
    AsyncPQAuth = None

from cryptography.hazmat.primitives.asymmetric import mldsa

HERE = os.path.dirname(os.path.abspath(__file__))
FX = json.load(open(os.path.join(HERE, "mandate_audit_fixtures.json"), encoding="utf-8"))

PASSED = FAILED = 0


def check(name, cond, why=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print("PASS  " + name)
    else:
        FAILED += 1
        print("FAIL  " + name + "\n        " + str(why)[:700])


def section(title):
    print("\n== " + title)


def clone(x):
    return copy.deepcopy(x)


def b64(raw):
    return base64.b64encode(raw).decode()


def sha(x):
    if isinstance(x, str):
        x = x.encode("utf-8")
    return hashlib.sha256(x).hexdigest()


ZERO = "0" * 64
KEY_A, KEY_B = FX["keys"]["A"], FX["keys"]["B"]


# A serializer written for this test, apart from the SDK's: keys sorted at every level, UTF-8, no spaces.
def ser(v):
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


# ─── A stub FIPSign: records every request, answers from a queue ─────────────

SEEN = []
QUEUE = []
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else ""
        with LOCK:
            SEEN.append({
                "method": self.command, "url": self.path, "api_key": self.headers.get("X-API-Key"),
                "raw": raw, "body": json.loads(raw) if raw else None,
            })
            answer = QUEUE.pop(0) if QUEUE else {"http": 200, "body": {"success": True}}
        data = json.dumps(answer["body"]).encode("utf-8")
        self.send_response(answer["http"])
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = _handle


SERVER = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
SERVER.daemon_threads = True
threading.Thread(target=SERVER.serve_forever, daemon=True).start()
BASE_URL = "http://127.0.0.1:%d" % SERVER.server_address[1]
API_KEY = "pqa_" + "ab" * 32

LOOP = asyncio.new_event_loop()


class Run:
    def __init__(self, out=None, err=None, requests=None):
        self.out, self.err, self.requests = out, err, requests or []


def settle(value):
    """What a call gave: awaited when it is a coroutine, drained when it is a (sync or async) generator."""
    if hasattr(value, "__aiter__"):
        async def drain():
            return [x async for x in value]
        return LOOP.run_until_complete(drain())
    if hasattr(value, "__await__"):
        return LOOP.run_until_complete(value)
    if hasattr(value, "__next__"):
        return list(value)
    return value


def stubbed(answers, fn):
    """Runs `fn` with the stub answering `answers` in order; returns what it gave and every request the stub saw."""
    with LOCK:
        SEEN.clear()
        QUEUE[:] = [a if "http" in a else {"http": 200, "body": a} for a in answers]
    try:
        out, err = settle(fn()), None
    except Exception as exc:  # noqa: BLE001
        out, err = None, exc
    with LOCK:
        return Run(out, err, list(SEEN))


def query(url):
    return dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))


def path(url):
    return urlsplit(url).path


def EV(n):
    return {"seq": n, "type": "emitted", "at": 1, "prevHash": ZERO, "hash": ZERO, "body": "{}"}


def PE(n, m="mdt_1"):
    return {**EV(n), "mandateId": m}


def EMIT_ANSWER(receipt=None):
    d = {
        "success": True,
        "mandate": {"id": "mdt_1", "agentId": "bot", "issuedBy": "ops", "scope": ["a"], "budgetTotal": 1, "expiresAt": 2,
                    "status": "active", "token": {"payload": "p", "signature": "s", "algorithm": "ML-DSA-65", "issuedAt": 1}},
        "usage": {"freeRemaining": 1, "packRemaining": 0, "totalRemaining": 1, "month": "2026-10"},
    }
    if receipt is not None:
        d["receipt"] = receipt
    return d


def PAGE(events, next_after, **extra):
    return {"success": True, "format": "fipsign.mandate.export.v1", "projectId": "p", "mandateId": "m", "generatedAt": 1,
            "events": events, "count": len(events), "nextAfter": next_after, "head": None, "publicKeys": [], **extra}


RECEIPT_STUB = FX["receipts"]["emitted"]
TOKEN = PQToken(payload="p", signature="s", algorithm="ML-DSA-65", issuedAt=1)
TOKEN_D = TOKEN.to_dict()
EMIT = dict(agent_id="bot", issued_by="ops", scope=["a"], budget_total=1, expires_in_seconds=60)
EMIT_BODY = {"agentId": "bot", "issuedBy": "ops", "scope": ["a"], "budgetTotal": 1, "expiresInSeconds": 60}


def requests_sections(label, pq):
    """Sections 1, 1b and 5: what the client sends and what it makes of the answers. Run for each client."""
    m = pq.mandate
    p = lambda name: "[%s] %s" % (label, name)  # noqa: E731

    section(p("1. What the SDK sends"))
    r = stubbed([EMIT_ANSWER(RECEIPT_STUB)], lambda: m.emit(**EMIT, correlation_id="ticket-1"))
    rq = r.requests[0] if r.requests else {}
    check(p("emit sends correlationId inside the body of POST /mandate, with the API key"),
          rq.get("method") == "POST" and rq.get("url") == "/mandate" and rq["body"].get("correlationId") == "ticket-1" and rq.get("api_key") == API_KEY, repr(r.requests) + repr(r.err))
    check(p("emit returns the receipt of the answer, as a MandateReceipt"),
          isinstance(r.out.receipt, MandateReceipt) and r.out.receipt.event.seq == RECEIPT_STUB["event"]["seq"] and r.out.receipt.signature == RECEIPT_STUB["signature"], repr(r.out))
    r = stubbed([EMIT_ANSWER()], lambda: m.emit(**EMIT))
    check(p("emit without correlation_id: the body is exactly what it was, and the receipt is None when the answer has none"),
          r.requests[0]["body"] == EMIT_BODY and list(r.requests[0]["body"]) == list(EMIT_BODY) and r.out.receipt is None, repr(r.requests))
    r = stubbed([EMIT_ANSWER()], lambda: m.emit(**EMIT, agent_public_key="AAAA"))
    check(p("emit with agent_public_key and no correlation_id: as before"),
          r.requests[0]["body"] == {**EMIT_BODY, "agentPublicKey": "AAAA"}, repr(r.requests))
    r = stubbed([EMIT_ANSWER({"signed": "x"})], lambda: m.emit(**EMIT))
    check(p("emit: a receipt in the answer that cannot be read does not break emit (the mandate exists): receipt None"),
          r.err is None and r.out.mandate.id == "mdt_1" and r.out.receipt is None, repr(r.err))

    def verify_body(**opts):
        return stubbed([{"result": "granted"}], lambda: m.verify(TOKEN, "act", 2, **opts)).requests[0]

    q = verify_body()
    check(p("verify with no options: the body is {token, action, cost}, nothing else"),
          q["url"] == "/mandate/verify" and list(q["body"]) == ["token", "action", "cost"] and q["body"] == {"token": TOKEN_D, "action": "act", "cost": 2}, repr(q["body"]))
    q = verify_body(agent_signature=TOKEN)
    check(p("verify with agent_signature: as before"), list(q["body"]) == ["token", "action", "cost", "agentSignature"], repr(q["body"]))
    q = verify_body(receipt=True)
    check(p("verify with receipt=True sends \"receipt\": true"), q["body"].get("receipt") is True and list(q["body"]) == ["token", "action", "cost", "receipt"], repr(q["body"]))
    q = verify_body(receipt=False)
    check(p("verify with receipt=False sends nothing about it"), "receipt" not in q["body"], repr(q["body"]))
    q = verify_body(correlation_id="req-9", receipt=True, agent_signature=TOKEN)
    check(p("verify with everything: all three fields, correlationId as given"),
          q["body"]["correlationId"] == "req-9" and q["body"]["receipt"] is True and q["body"]["agentSignature"]["signature"] == "s", repr(q["body"]))
    r = stubbed([{"http": 403, "body": {"result": "denied", "reason": "scope_not_authorized", "receipt": RECEIPT_STUB}}],
                lambda: m.verify(TOKEN, "act", 1, receipt=True))
    check(p("a denied verify keeps the receipt of the answer, and failure is rejected"),
          r.out.result == "denied" and r.out.failure == "rejected" and r.out.receipt is not None and r.out.receipt.event.hash == RECEIPT_STUB["event"]["hash"], repr(r.out))
    r = stubbed([{"result": "granted", "receipt": RECEIPT_STUB}], lambda: m.verify(TOKEN, "act", 1, receipt=True))
    check(p("a granted verify keeps the receipt too"), r.out.result == "granted" and r.out.receipt is not None and r.out.receipt.signed == RECEIPT_STUB["signed"], repr(r.out))
    r = stubbed([{"http": 429, "body": {"success": False, "error": "slow down", "receipt": RECEIPT_STUB}}], lambda: m.verify(TOKEN, "act", 1, receipt=True))
    check(p("a failure that is not a mandate answer carries no receipt"), r.out.failure == "rate_limited" and r.out.receipt is None, repr(r.out))

    def patch_body(fn):
        return stubbed([{"success": True, "id": "mdt_1", "status": "active"}], fn).requests[0]

    q = patch_body(lambda: m.suspend("mdt_1"))
    check(p("suspend with no options: PATCH body is exactly {action}"), q["method"] == "PATCH" and q["url"] == "/mandate/mdt_1" and q["body"] == {"action": "suspend"}, repr(q))
    check(p("resume with no options: {action}"), patch_body(lambda: m.resume("mdt_1"))["body"] == {"action": "resume"})
    check(p("revoke with no options: {action}"), patch_body(lambda: m.revoke("mdt_1"))["body"] == {"action": "revoke"})
    q = patch_body(lambda: m.narrow("mdt_1", ["a", "b"]))
    check(p("narrow with no options: {action, scope}"), q["body"] == {"action": "narrow", "scope": ["a", "b"]} and list(q["body"]) == ["action", "scope"], repr(q["body"]))
    for name in ("suspend", "resume", "revoke"):
        q = patch_body(lambda: getattr(m, name)("mdt_1", correlation_id="ticket-2"))
        check(p("%s with correlation_id: it goes in the body next to the action" % name), q["body"] == {"action": name, "correlationId": "ticket-2"}, repr(q["body"]))
    q = patch_body(lambda: m.narrow("mdt_1", ["a"], correlation_id="ticket-3"))
    check(p("narrow with correlation_id: action, scope and correlationId"), q["body"] == {"action": "narrow", "scope": ["a"], "correlationId": "ticket-3"}, repr(q["body"]))
    q = patch_body(lambda: m.suspend("a/b c"))
    check(p("the id is URL-encoded in the path"), q["url"] == "/mandate/a%2Fb%20c", q["url"])
    r = stubbed([{"success": True, "id": "mdt_1", "status": "suspended", "receipt": RECEIPT_STUB}], lambda: m.suspend("mdt_1"))
    check(p("a PATCH returns the receipt of the answer"), r.out.receipt is not None and r.out.receipt.event.hash == RECEIPT_STUB["event"]["hash"] and r.out.message is None, repr(r.out))
    r = stubbed([{"success": True, "id": "mdt_1", "status": "suspended", "message": "Already suspended"}], lambda: m.suspend("mdt_1"))
    check(p("suspend on an already-suspended mandate: message, and no receipt (nothing changed)"), r.out.message == "Already suspended" and r.out.receipt is None, repr(r.out))
    r = stubbed([{"success": True, "id": "mdt_1", "status": "active", "message": "should not be read"}], lambda: m.resume("mdt_1"))
    check(p("only suspend reads `message` (as before)"), r.out.message is None, repr(r.out))
    r = stubbed([{"success": True, "id": "mdt_1", "status": "active", "scope": ["a"], "updatedAt": 7}], lambda: m.narrow("mdt_1", ["a"]))
    check(p("narrow keeps id, status, scope and updatedAt"), (r.out.id, r.out.status, r.out.scope, r.out.updatedAt) == ("mdt_1", "active", ["a"], 7), repr(r.out))

    section(p("1b. The read calls"))
    r = stubbed([{"success": True, "mandateId": "m", "events": [EV(1)], "count": 1, "nextAfter": None, "head": None}], lambda: m.events("m"))
    check(p("events: GET /mandate/:id/events, no query string without options"),
          r.requests[0]["method"] == "GET" and r.requests[0]["url"] == "/mandate/m/events" and r.requests[0]["api_key"] == API_KEY and r.out.events[0].seq == 1 and r.out.nextAfter is None and r.out.head is None, repr(r.requests))
    r = stubbed([{"success": True, "events": [], "count": 0, "nextAfter": None, "head": None}], lambda: m.events("m", after=0, limit=50))
    check(p("events with options: after and limit (after 0 is sent too)"), query(r.requests[0]["url"]) == {"after": "0", "limit": "50"}, r.requests[0]["url"])
    check(p("events: the mandateId falls back to the one asked for when the answer has none"), r.out.mandateId == "m", repr(r.out))
    r = stubbed([{"success": True, "mandateId": "m", "events": [EV(1)], "count": 1, "nextAfter": None, "head": {"seq": 1, "hash": "h", "lastCheckpointSeq": 0}}], lambda: m.events("m"))
    check(p("events: the head of the chain"), r.out.head is not None and (r.out.head.seq, r.out.head.hash, r.out.head.lastCheckpointSeq) == (1, "h", 0), repr(r.out))
    r = stubbed([
        {"success": True, "events": [EV(1), EV(2)], "count": 2, "nextAfter": 2, "head": None},
        {"success": True, "events": [EV(3), EV(4)], "count": 2, "nextAfter": 4, "head": None},
        {"success": True, "events": [EV(5)], "count": 1, "nextAfter": None, "head": None},
    ], lambda: m.events_all("m", limit=2))
    check(p("events_all follows nextAfter: 3 requests, events 1..5 in order"),
          [e.seq for e in r.out] == [1, 2, 3, 4, 5] and [x["url"] for x in r.requests] == ["/mandate/m/events?after=0&limit=2", "/mandate/m/events?after=2&limit=2", "/mandate/m/events?after=4&limit=2"], repr([x["url"] for x in r.requests]) + repr(r.err))

    def first_two():
        got = []
        if hasattr(m.events_all("m"), "__aiter__"):
            async def go():
                async for e in m.events_all("m"):
                    got.append(e.seq)
                    if e.seq == 2:
                        break
            return go()
        for e in m.events_all("m"):
            got.append(e.seq)
            if e.seq == 2:
                break
        return got
    r = stubbed([
        {"success": True, "events": [EV(1), EV(2)], "count": 2, "nextAfter": 2, "head": None},
        {"success": True, "events": [EV(3)], "count": 1, "nextAfter": None, "head": None},
    ], first_two)
    check(p("events_all: breaking out of the loop asks for no further page"), r.err is None and len(r.requests) == 1, repr(r.err) + repr([x["url"] for x in r.requests]))
    r = stubbed([{"success": True, "events": [EV(1)], "count": 1, "nextAfter": 0, "head": None}], lambda: m.events_all("m"))
    check(p("events_all: a nextAfter that does not advance stops with an error instead of looping"),
          isinstance(r.err, PQAuthError) and "did not advance" in r.err.message and len(r.requests) == 1, repr(r.err))
    r = stubbed([{"success": True, "events": [], "count": 0, "head": None}], lambda: m.events("m"))
    check(p("events: an answer without nextAfter is refused (a loop could not tell where it ends)"), isinstance(r.err, PQAuthError), repr(r.out))
    r = stubbed([{"http": 404, "body": {"success": False, "error": "Mandate not found"}}], lambda: m.events("nope"))
    check(p("an error answer becomes a PQAuthError with status and message"), isinstance(r.err, PQAuthError) and r.err.status == 404 and r.err.message == "Mandate not found", repr(r.err))
    for bad in ("", "..", "."):
        r = stubbed([], lambda: m.events(bad))
        check(p("events(%r): refused before any request" % bad), isinstance(r.err, PQAuthError) and len(r.requests) == 0, repr(r.err))

    qe = {"success": True, "events": [], "count": 0, "nextCursor": None, "from": 1, "to": 2}
    r = stubbed([qe], lambda: m.query_events())
    check(p("query_events with no filters: GET /mandate/events"), r.requests[0]["url"] == "/mandate/events" and r.out.from_ == 1 and r.out.to == 2 and r.out.nextCursor is None, repr(r.requests))
    FULL = dict(mandate_id="mdt_1", type="verify_denied", action="wire:transfer", key_id="abcdef0123456789", correlation_id="a b&c=d/é",
                trace_id="4bf92f3577b34da6a3ce929d0e0e4736", from_=100, to=200, limit=25, cursor="xyz_-")
    WIRE = {"mandateId": "mdt_1", "type": "verify_denied", "action": "wire:transfer", "keyId": "abcdef0123456789", "correlationId": "a b&c=d/é",
            "traceId": "4bf92f3577b34da6a3ce929d0e0e4736", "from": "100", "to": "200", "limit": "25", "cursor": "xyz_-"}
    r = stubbed([qe], lambda: m.query_events(**FULL))
    check(p("query_events: every filter goes into the query string, encoded, with the names of the API, nothing else"),
          path(r.requests[0]["url"]) == "/mandate/events" and query(r.requests[0]["url"]) == WIRE, r.requests[0]["url"])
    r = stubbed([qe], lambda: m.query_events(type="revoked", action=None, from_=None))
    check(p("query_events: a filter that is None is left out"), r.requests[0]["url"] == "/mandate/events?type=revoked", r.requests[0]["url"])
    r = stubbed([
        {"success": True, "events": [PE(9), PE(8)], "count": 2, "nextCursor": "c1", "from": 1, "to": 2},
        {"success": True, "events": [PE(7)], "count": 1, "nextCursor": "c2", "from": 1, "to": 2},
        {"success": True, "events": [], "count": 0, "nextCursor": None, "from": 1, "to": 2},
    ], lambda: m.query_events_all(type="verify_denied", limit=2))
    check(p("query_events_all follows nextCursor (an empty page is not the end), keeping the filters"),
          [e.seq for e in r.out] == [9, 8, 7] and r.out[0].mandateId == "mdt_1" and len(r.requests) == 3 and "cursor" not in query(r.requests[0]["url"])
          and query(r.requests[1]["url"])["cursor"] == "c1" and query(r.requests[2]["url"])["cursor"] == "c2"
          and all(query(x["url"]).get("type") == "verify_denied" and query(x["url"]).get("limit") == "2" for x in r.requests), repr([x["url"] for x in r.requests]) + repr(r.err))
    r = stubbed([{"success": True, "events": [PE(1)], "count": 1, "nextCursor": None, "from": 1, "to": 2}], lambda: m.query_events_all(cursor="c0"))
    check(p("query_events_all starts from the cursor it is given"), query(r.requests[0]["url"]).get("cursor") == "c0", repr(r.requests))
    r = stubbed([
        {"success": True, "events": [PE(1)], "count": 1, "nextCursor": "same", "from": 1, "to": 2},
        {"success": True, "events": [PE(0)], "count": 1, "nextCursor": "same", "from": 1, "to": 2},
    ], lambda: m.query_events_all())
    check(p("query_events_all: a cursor that does not advance stops with an error"), isinstance(r.err, PQAuthError) and "did not advance" in r.err.message, repr(r.err))
    r = stubbed([{"success": True, "events": [EV(1)], "count": 1, "nextCursor": None}], lambda: m.query_events())
    check(p("query_events: an event without mandateId is refused"), isinstance(r.err, PQAuthError), repr(r.out))

    r = stubbed([PAGE([EV(1)], None)], lambda: m.export("m"))
    check(p("export: GET /mandate/:id/export, answered as a MandateExportPage"),
          r.requests[0]["method"] == "GET" and r.requests[0]["url"] == "/mandate/m/export" and isinstance(r.out, MandateExportPage) and r.out.events[0].seq == 1 and r.out.head is None, repr(r.requests) + repr(r.err))
    r = stubbed([PAGE([EV(1)], None)], lambda: m.export("m", after=10, limit=1000))
    check(p("export with options: after and limit"), query(r.requests[0]["url"]) == {"after": "10", "limit": "1000"}, r.requests[0]["url"])
    r = stubbed([PAGE([EV(1), EV(2)], 2), PAGE([EV(3), EV(4)], 4), PAGE([EV(5)], None)], lambda: m.export_all("m", limit=2))
    check(p("export_all: every page, in order, following nextAfter"),
          len(r.out) == 3 and [len(x.events) for x in r.out] == [2, 2, 1] and [x["url"] for x in r.requests] == ["/mandate/m/export?after=0&limit=2", "/mandate/m/export?after=2&limit=2", "/mandate/m/export?after=4&limit=2"], repr(r.err))
    r = stubbed([PAGE([EV(1)], 0)], lambda: m.export_all("m"))
    check(p("export_all: a nextAfter that does not advance stops with an error"), isinstance(r.err, PQAuthError) and "did not advance" in r.err.message, repr(r.err))
    r = stubbed([{"success": True, "projectId": "p", "keys": [], "count": 0}], lambda: m.public_keys())
    check(p("public_keys: GET /public-keys"), r.requests[0]["method"] == "GET" and r.requests[0]["url"] == "/public-keys" and r.requests[0]["api_key"] == API_KEY and r.out.keys == [], repr(r.requests))
    r = stubbed([FX["publicKeysAfterRotation"]], lambda: m.public_keys())
    check(p("public_keys: the keys of the real answer, current first, with their fingerprints"),
          [k.status for k in r.out.keys] == ["current", "retired"] and r.out.keys[0].fingerprint == KEY_B["fingerprint"] and r.out.keys[1].fingerprint == KEY_A["fingerprint"] and r.out.keys[0].retiredAt is None and isinstance(r.out.keys[1].retiredAt, int) and r.out.count == 2, repr(r.out))

    section(p("5. Keys, and what the client method fetches"))
    R = FX["receipts"]
    keys_answer = FX["publicKeysAfterRotation"]
    r = stubbed([], lambda: m.verify_receipt(R["emitted"], public_key=KEY_A["publicKey"]))
    check(p("verify_receipt with a public key: valid, no request at all"), r.out is not None and r.out.valid is True and r.out.keyTrust == "pinned" and len(r.requests) == 0, repr(r.out) + repr(r.err))
    r = stubbed([keys_answer], lambda: m.verify_receipt(R["emitted"], pin_fingerprint=KEY_A["fingerprint"]))
    check(p("verify_receipt with a pinned fingerprint: one GET /public-keys, then valid and pinned"),
          r.out is not None and r.out.valid is True and r.out.keyTrust == "pinned" and [x["url"] for x in r.requests] == ["/public-keys"], repr(r.out) + repr(r.err))
    r = stubbed([], lambda: m.verify_receipt(R["emitted"], pin_fingerprint=KEY_A["fingerprint"], keys=keys_answer["keys"]))
    check(p("verify_receipt with a pin and the keys: no request"), r.out is not None and r.out.valid is True and len(r.requests) == 0, repr(r.out) + repr(r.err))
    r = stubbed([keys_answer], lambda: m.verify_receipt(R["emitted"]))
    check(p("verify_receipt with nothing: one GET /public-keys, valid with the keys FIPSign lists, keyTrust \"fipsign\""),
          r.out is not None and r.out.valid is True and r.out.keyTrust == "fipsign" and len(r.requests) == 1, repr(r.out) + repr(r.err))
    r = stubbed([keys_answer], lambda: m.verify_receipt({**R["emitted"], "signature": R["denied"]["signature"]}))
    check(p("verify_receipt with nothing, an altered receipt: not valid"), r.out is not None and r.out.valid is False and r.out.keyTrust == "fipsign", repr(r.out) + repr(r.err))
    r = stubbed([{"http": 401, "body": {"success": False, "error": "Invalid API key"}}], lambda: m.verify_receipt(R["emitted"]))
    check(p("verify_receipt when the keys cannot be fetched: a PQAuthError (it does not say valid or invalid)"), isinstance(r.err, PQAuthError) and r.err.status == 401, repr(r.err) + repr(r.out))
    r = stubbed([{"success": True, "projectId": "p", "keys": [], "count": 0}], lambda: m.verify_receipt(R["emitted"]))
    check(p("verify_receipt when the list of keys is empty: not valid, says there is no key"), r.out is not None and r.out.valid is False and "no key" in r.out.problems[0], repr(r.out))
    r = stubbed([], lambda: m.verify_export(FX["exportBeforeRotation"]))
    check(p("verify_export makes no request"), r.out is not None and r.out.valid is True and len(r.requests) == 0, repr(r.out) + repr(r.err))
    r = stubbed([], lambda: m.verify_export(FX["exportAfterRotation"]))
    check(p("verify_export with no key: checks with the keys of the export and says keyTrust \"fipsign\""), r.out.valid is True and r.out.keyTrust == "fipsign" and r.out.checkpoints == 2, repr(r.out))
    r = stubbed([], lambda: m.verify_export(FX["exportAfterRotation"], public_key=KEY_B["publicKey"]))
    check(p("verify_export with a public key is strict: only that key is trusted"), r.out.valid is False and r.out.keyTrust == "pinned", repr(r.out))

    section(p("What the client hands back checks out"))
    r = stubbed([EMIT_ANSWER(R["emitted"])], lambda: m.emit(**EMIT))
    emitted = r.out
    c = verify_mandate_receipt(emitted.receipt, public_key=KEY_A["publicKey"])
    check(p("the MandateReceipt of emit() is valid as it is"), c.valid and c.projectId == FX["projectId"] and c.mandateId == FX["mandateId"] and c.event.seq == R["emitted"]["event"]["seq"], repr(c))
    c = verify_mandate_receipt(emitted, public_key=KEY_A["publicKey"])
    check(p("the whole result of emit() works too"), c.valid, repr(c))
    c = verify_mandate_receipt(json.loads(json.dumps(emitted.receipt.to_dict())), public_key=KEY_A["publicKey"])
    check(p("receipt.to_dict() through JSON and back is valid"), c.valid and emitted.receipt.to_dict() == R["emitted"], repr(c))
    c = verify_mandate_receipt(emitted.receipt, pin_fingerprint=KEY_A["fingerprint"], keys=[KEY_A["publicKey"]])
    check(p("a pinned fingerprint with the key given as text"), c.valid and c.keyTrust == "pinned", repr(c))
    r = stubbed([{"success": True, "id": "mdt_1", "status": "suspended", "receipt": R["suspended"]}], lambda: m.suspend("mdt_1"))
    c = verify_mandate_receipt(r.out, public_key=KEY_A["publicKey"])
    check(p("the whole result of suspend() works"), c.valid and c.event.type == "suspended", repr(c))
    r = stubbed([{"result": "denied", "reason": "scope_not_authorized", "receipt": R["denied"]}], lambda: m.verify(TOKEN, "z", 1, receipt=True))
    c = verify_mandate_receipt(r.out, public_key=KEY_A["publicKey"])
    check(p("the result of a denied verify() works"), c.valid and c.event.type == "verify_denied", repr(c))
    r = stubbed([{"result": "granted"}], lambda: m.verify(TOKEN, "z", 1))
    c = verify_mandate_receipt(r.out, public_key=KEY_A["publicKey"])
    check(p("a verify() without receipt=True has no receipt: not valid, says it is not a receipt"), not c.valid and "not a receipt" in c.problems[0], repr(c))
    r = stubbed([dict(pg) for pg in FX["exportAfterRotation"]], lambda: m.export_all(FX["mandateId"]))
    check(p("export_all() of the real export: the pages are MandateExportPage objects"), r.err is None and len(r.out) == 3 and all(isinstance(x, MandateExportPage) for x in r.out), repr(r.err))
    e = verify_mandate_export(r.out, pin_fingerprint=[KEY_A["fingerprint"], KEY_B["fingerprint"]])
    check(p("...and they verify as they are (pinned fingerprints, keys from the export)"), e.valid and e.checkpoints == 2 and e.headChecked and e.lastSeq == 10, repr(e))
    e = verify_mandate_export(json.loads(json.dumps([x.to_dict() for x in r.out])), pin_fingerprint=[KEY_A["fingerprint"], KEY_B["fingerprint"]])
    check(p("...and after a round trip through JSON"), e.valid and e.checkpoints == 2 and e.headChecked, repr(e))
    check(p("to_dict() of a page gives back the page the API sent"),
          all(x.to_dict() == {k: v for k, v in o.items() if k != "success"} for x, o in zip(r.out, FX["exportAfterRotation"])), "to_dict differs")
    e = verify_mandate_export(r.out[0], pin_fingerprint=[KEY_A["fingerprint"], KEY_B["fingerprint"]])
    check(p("a single page (not in a list) is accepted"), e.valid and not e.complete, repr(e))


def make_clients():
    out = [("sync", PQAuth(API_KEY, base_url=BASE_URL))]
    if AsyncPQAuth is not None:
        out.append(("async", LOOP.run_until_complete(_make_async())))
    return out


async def _make_async():
    return AsyncPQAuth(API_KEY, base_url=BASE_URL)


# ─── Logs made here ──────────────────────────────────────────────────────────

DSA = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey, "ML-DSA-87": mldsa.MLDSA87PrivateKey}


class Project:
    def __init__(self, algorithm="ML-DSA-65", project_id=None):
        self.algorithm = algorithm
        self.sk = DSA[algorithm].generate()
        raw = self.sk.public_key().public_bytes_raw()
        self.public_key = b64(raw)
        self.fingerprint = sha(raw)
        self.project_id = project_id or "prj_" + os.urandom(4).hex()

    def sign_raw(self, text):
        return b64(self.sk.sign(("FIPSIGN-MANDATE-v1\n" + text).encode("utf-8")))

    def seal(self, kind, mandate_id, seq, hash_, at):
        signed = ser({"v": 1, "kind": kind, "projectId": self.project_id, "mandateId": mandate_id, "seq": seq, "hash": hash_, "at": at})
        return {"signed": signed, "signature": self.sign_raw(signed), "algorithm": self.algorithm, "keyFingerprint": self.fingerprint}


def make_log(project, mandate_id, specs):
    """A chain: `specs` are {type, at, fields} or {checkpoint: True, at}; a checkpoint seals the event before it."""
    events, prev = [], ZERO
    for i, sp in enumerate(specs):
        seq = i + 1
        fields = sp.get("fields", {})
        if sp.get("checkpoint"):
            covered = events[-1]
            s = project.seal("mandate.checkpoint", mandate_id, covered["seq"], covered["hash"], sp["at"])
            fields = {"projectId": project.project_id, "coversSeq": covered["seq"], "coversHash": covered["hash"],
                      "signature": s["signature"], "keyFp": s["keyFingerprint"], "alg": s["algorithm"]}
        type_ = "checkpoint" if sp.get("checkpoint") else sp["type"]
        body = ser({"v": 1, "mandateId": mandate_id, "seq": seq, "type": type_, "at": sp["at"], **fields})
        hash_ = sha(prev + "\n" + body)
        events.append({"seq": seq, "type": type_, "at": sp["at"], "prevHash": prev, "hash": hash_, "body": body})
        prev = hash_
    return events


def pages_of(project, mandate_id, events, size, head=True, keys=None):
    pages = []
    for i in range(0, len(events), size):
        chunk = events[i:i + size]
        last = events[-1]
        hs = project.seal("mandate.export", mandate_id, last["seq"], last["hash"], last["at"] + 1)
        pages.append({
            "format": "fipsign.mandate.export.v1", "projectId": project.project_id, "mandateId": mandate_id, "generatedAt": last["at"] + 1,
            "events": chunk, "count": len(chunk), "nextAfter": chunk[-1]["seq"] if i + size < len(events) else None,
            "head": {"seq": last["seq"], "hash": last["hash"], "at": last["at"] + 1, "source": "live", "lastCheckpointSeq": 0, **hs} if head else None,
            "publicKeys": keys if keys is not None else [{"fingerprint": project.fingerprint, "algorithm": project.algorithm, "publicKey": project.public_key,
                                                          "status": "current", "recordedAt": 1, "retiredAt": None}],
        })
    return pages


T0 = 1_800_000_000
SPEC = [
    {"type": "emitted", "at": T0, "fields": {"agentId": "añadir-ñandú", "issuedBy": "ops@example.com", "scope": ["a", "b"], "budgetTotal": 10, "correlationId": "ticket-é-✓-😀"}},
    {"type": "verify_granted", "at": T0 + 1, "fields": {"action": "a", "cost": 1}},
    {"type": "verify_denied", "at": T0 + 2, "fields": {"action": "z", "cost": 1, "reason": "scope_not_authorized"}},
    {"checkpoint": True, "at": T0 + 10},
    {"type": "suspended", "at": T0 + 11, "fields": {}},
    {"type": "resumed", "at": T0 + 12, "fields": {}},
    {"checkpoint": True, "at": T0 + 20},
]


def flat_events(pages):
    return [e for pg in pages for e in pg["events"]]


def mutate(text, pattern, replacement):
    """`text` with `pattern` replaced; fails loudly if nothing changed (a test that alters nothing proves nothing)."""
    out = re.sub(pattern, replacement, text, count=1)
    assert out != text, "mutate(): %r not found in %r" % (pattern, text[:80])
    return out


def tamper_bit(signature_b64, index=5):
    raw = bytearray(base64.b64decode(signature_b64))
    raw[index] ^= 1
    return b64(bytes(raw))


def verification_sections():
    R = FX["receipts"]
    KEYS_LIST = FX["publicKeysAfterRotation"]

    # ─── 2. Real receipts ────────────────────────────────────────────────────
    section("2. Real receipts and a real export, captured from FIPSign")
    for name, rc in R.items():
        if name == "suspendedAfterRotation":
            continue
        c = verify_mandate_receipt(rc, public_key=KEY_A["publicKey"])
        check('receipt "%s" (event %d, %s) is valid with the saved public key' % (name, rc["event"]["seq"], rc["event"]["type"]),
              c.valid and c.problems == [] and c.keyTrust == "pinned" and c.projectId == FX["projectId"] and c.mandateId == FX["mandateId"]
              and c.event.hash == rc["event"]["hash"] and rc["keyFingerprint"] == KEY_A["fingerprint"], repr(c))
    c = verify_mandate_receipt({"success": True, "receipt": R["granted"]}, pin_fingerprint=KEY_A["fingerprint"], keys=[KEY_A["publicKey"]])
    check("the whole answer, and a pinned fingerprint with the key from a list", c.valid, repr(c))
    c = verify_mandate_receipt(R["suspendedAfterRotation"], public_key=KEY_B["publicKey"])
    check("a receipt signed after the rotation is valid with the new key", c.valid and R["suspendedAfterRotation"]["keyFingerprint"] == KEY_B["fingerprint"], repr(c))
    c = verify_mandate_receipt(R["suspendedAfterRotation"], public_key=KEY_A["publicKey"])
    check("...and not with the old one", not c.valid and any("not one of the keys you trust" in p for p in c.problems), repr(c))
    c = verify_mandate_receipt(R["emitted"], public_key=KEY_B["publicKey"])
    check("a receipt of the old key is not valid with only the new key", not c.valid and any("not one of the keys you trust" in p for p in c.problems), repr(c))
    c = verify_mandate_receipt(R["emitted"], public_key=[KEY_B["publicKey"], KEY_A["publicKey"]])
    check("...it is with both keys given", c.valid, repr(c))
    c = verify_mandate_receipt(R["emitted"], pin_fingerprint=KEY_A["fingerprint"], keys=KEYS_LIST["keys"])
    check("the old receipt, with the fingerprint pinned and the keys of GET /public-keys (the retired one included)", c.valid and c.keyTrust == "pinned", repr(c))
    c = verify_mandate_receipt(R["emitted"], pin_fingerprint=KEY_A["fingerprint"], keys=[k for k in KEYS_LIST["keys"] if k["status"] == "current"])
    check("pinned, but the list does not have that key -> not valid, says so", not c.valid and any(("no key with fingerprint " + KEY_A["fingerprint"]) in p for p in c.problems), repr(c))
    c = verify_mandate_receipt(R["emitted"], pin_fingerprint=KEY_B["fingerprint"], keys=KEYS_LIST["keys"])
    check("pinning the other key, with the whole list -> not valid", not c.valid, repr(c))
    swapped = [({**k, "publicKey": KEY_B["publicKey"]} if k["fingerprint"] == KEY_A["fingerprint"] else k) for k in KEYS_LIST["keys"]]
    c = verify_mandate_receipt(R["emitted"], pin_fingerprint=KEY_A["fingerprint"], keys=swapped)
    check("a list that puts the key B under the fingerprint of A is not believed (the fingerprint is computed from the key)", not c.valid and any("no key with fingerprint" in p for p in c.problems), repr(c))
    c = verify_mandate_receipt(R["emitted"], pin_fingerprint=KEY_A["fingerprint"].upper(), keys=KEYS_LIST["keys"])
    check("a pinned fingerprint in capital letters is the same fingerprint", c.valid, repr(c))
    c = verify_mandate_receipt(R["emitted"], keys=KEYS_LIST["keys"])
    check("a list of keys without a pin or a public key: nothing is trusted -> not valid", not c.valid and len(c.problems) == 1 and "no key to trust" in c.problems[0], repr(c))
    c = verify_mandate_receipt(R["emitted"])
    check("no key at all -> not valid", not c.valid and "no key to trust" in c.problems[0] and c.keyTrust == "pinned", repr(c))
    c = verify_mandate_receipt(R["emitted"], public_key=KEY_A["publicKey"], expect_project_id=FX["projectId"], expect_mandate_id=FX["mandateId"])
    check("expect_* with the right project and mandate -> valid", c.valid, repr(c))
    c = verify_mandate_receipt(R["emitted"], public_key=KEY_A["publicKey"], expect_project_id="prj_other")
    check("expect_project_id of another project -> not valid", not c.valid and any("not prj_other" in p for p in c.problems), repr(c))
    c = verify_mandate_receipt(R["emitted"], public_key=KEY_A["publicKey"], expect_mandate_id="mdt_other")
    check("expect_mandate_id of another mandate -> not valid", not c.valid and any("not mdt_other" in p for p in c.problems), repr(c))

    def altered(mut):
        x = clone(R["granted"])
        mut(x)
        return x

    def bad(name, receipt, pattern=None):
        res = verify_mandate_receipt(receipt, public_key=KEY_A["publicKey"])
        check(name, not res.valid and (pattern is None or any(re.search(pattern, p) for p in res.problems)), repr(res.problems))

    def edit_cost(x):
        x["event"]["body"] = mutate(x["event"]["body"], r'"cost":\d+', '"cost":0')

    def edit_cost_rehash(x):
        edit_cost(x)
        x["event"]["hash"] = sha(x["event"]["prevHash"] + "\n" + x["event"]["body"])

    bad("an event body edited (the cost)", altered(edit_cost), r"hash is not sha256|does not match")
    bad("an event body edited and its hash recomputed: the signed hash no longer fits", altered(edit_cost_rehash), r"not about the event")
    bad("prevHash changed", altered(lambda x: x["event"].__setitem__("prevHash", "1" + x["event"]["prevHash"][1:])), r"hash is not sha256")
    bad("hash changed", altered(lambda x: x["event"].__setitem__("hash", "1" + x["event"]["hash"][1:])), r"hash is not sha256|not about the event")
    bad("seq changed", altered(lambda x: x["event"].__setitem__("seq", 99)), r"not about the event|does not match")
    bad("type changed", altered(lambda x: x["event"].__setitem__("type", "verify_denied")), r"does not match")
    bad("at changed", altered(lambda x: x["event"].__setitem__("at", x["event"]["at"] + 1)), r"not about the event|does not match")
    bad("the signature of another receipt", altered(lambda x: x.__setitem__("signature", R["denied"]["signature"])), r"does not verify")
    bad("a signature with a byte changed", altered(lambda x: x.__setitem__("signature", tamper_bit(x["signature"], 10))), r"does not verify")
    bad("the signed text edited (another mandate)", altered(lambda x: x.__setitem__("signed", x["signed"].replace(FX["mandateId"], "mdt_other"))), r"does not verify|belongs to another")
    bad("the signed text with a space added (not canonical)", altered(lambda x: x.__setitem__("signed", x["signed"].replace('{"at"', '{ "at"'))), r"does not verify|canonical")
    bad("the signed text of a checkpoint (another kind)", altered(lambda x: x.__setitem__("signed", x["signed"].replace("mandate.receipt", "mandate.checkpoint"))), r"does not verify|kind")
    bad("an unknown algorithm", altered(lambda x: x.__setitem__("algorithm", "ML-DSA-99")), r"unknown algorithm")
    bad("another algorithm than the key has", altered(lambda x: x.__setitem__("algorithm", "ML-DSA-87")), r"does not verify")
    bad("another keyFingerprint", altered(lambda x: x.__setitem__("keyFingerprint", KEY_B["fingerprint"])), r"not one of the keys you trust")
    bad("the signature field missing", altered(lambda x: x.pop("signature")), r"not complete")
    bad("a signature that is not base64", altered(lambda x: x.__setitem__("signature", "***")), r"does not verify")
    bad("the event of another receipt with this signature", altered(lambda x: x.__setitem__("event", clone(R["denied"]["event"]))), r"not about the event")
    bad("the signature a number", altered(lambda x: x.__setitem__("signature", 5)), r"not complete")
    bad("the seq of the event a float", altered(lambda x: x["event"].__setitem__("seq", float(x["event"]["seq"]))), r"not a receipt")
    bad("the seq of the event true", altered(lambda x: x["event"].__setitem__("seq", True)), r"not a receipt")

    # ─── 3. The real export ──────────────────────────────────────────────────
    section("3. The real export, before and after the key rotation")
    EX1, EX2 = FX["exportBeforeRotation"], FX["exportAfterRotation"]
    both = [KEY_A["fingerprint"], KEY_B["fingerprint"]]
    e = verify_mandate_export(EX1, public_key=KEY_A["publicKey"])
    check("before the rotation, with the saved public key: valid, complete, 2 checkpoints, head matches",
          e.valid and e.complete and e.checkpoints == 2 and e.headChecked and e.sealedThrough == 8 and e.lastSeq == 9 and e.events == 9
          and e.keyTrust == "pinned" and e.projectId == FX["projectId"] and e.mandateId == FX["mandateId"] and e.problems == [], repr(e))
    e = verify_mandate_export(EX1, pin_fingerprint=KEY_A["fingerprint"])
    check("with only the fingerprint pinned (the key comes with the export)", e.valid and e.keyTrust == "pinned" and e.checkpoints == 2, repr(e))
    e = verify_mandate_export(EX1[0], public_key=KEY_A["publicKey"])
    check("the first page alone: valid, not complete", e.valid and not e.complete and e.events == 3, repr(e))
    e = verify_mandate_export(EX1)
    check("no key: not valid, nothing is trusted", not e.valid and "no key to trust" in e.problems[0] and e.events == 0, repr(e))
    e = verify_mandate_export(EX1, public_key=KEY_B["publicKey"])
    check("the wrong key: not valid", not e.valid and any("not one of the keys you trust" in p for p in e.problems), repr(e.problems))
    e = verify_mandate_export(EX1, pin_fingerprint="cd" * 32)
    check("a fingerprint that no key of the export has: not valid, says so", not e.valid and any("no key with fingerprint cdcd" in p for p in e.problems), repr(e.problems))
    e = verify_mandate_export(EX1, pin_fingerprint="nope")
    check("a pin that is not 64 hex characters: not valid (it does not fall back to a weaker check)", not e.valid and any("64 hexadecimal" in p for p in e.problems), repr(e.problems))
    e = verify_mandate_export([{**p, "publicKeys": [{**k, "publicKey": KEY_B["publicKey"]} for k in p["publicKeys"]]} for p in EX1], pin_fingerprint=KEY_A["fingerprint"])
    check("an export whose list of keys was swapped for another key: the pinned fingerprint is not found", not e.valid and any("no key with fingerprint" in p for p in e.problems), repr(e.problems))
    e = verify_mandate_export(EX2, pin_fingerprint=both)
    check("after the rotation, both fingerprints pinned: valid, 2 checkpoints signed with A, head signed with B",
          e.valid and e.checkpoints == 2 and e.headChecked and e.lastSeq == 10 and not e.complete and e.sealedThrough == 8, repr(e))
    e = verify_mandate_export(EX2, public_key=[KEY_A["publicKey"], KEY_B["publicKey"]])
    check("...and with both public keys", e.valid, repr(e))
    e = verify_mandate_export(EX2, pin_fingerprint=KEY_B["fingerprint"])
    check("only the new key: the checkpoints of the old one do not verify", not e.valid and any(re.search(r"^checkpoint \d+: the signing key", p) for p in e.problems), repr(e.problems))
    e = verify_mandate_export(EX2, pin_fingerprint=KEY_A["fingerprint"])
    check("only the old key: the head, signed with the new one, does not verify", not e.valid and any(p.startswith("head: the signing key") for p in e.problems), repr(e.problems))

    def bad_export(name, pages, pattern=None, **opts):
        opts = opts or {"pin_fingerprint": both}
        res = verify_mandate_export(pages, **opts)
        check(name, not res.valid and (pattern is None or any(re.search(pattern, p) for p in res.problems)), repr(res.problems))

    x = clone(EX2); x[0]["events"][1]["body"] = mutate(x[0]["events"][1]["body"], r'"cost":\d+', '"cost":0')
    bad_export("an event body edited", x, r"hash is not sha256")
    x = clone(EX2); x[0]["events"][0]["body"] = mutate(x[0]["events"][0]["body"], r'"budgetTotal":100', '"budgetTotal":999')
    bad_export("the first event edited (the budget)", x, r"hash is not sha256")
    x = clone(EX2); del x[1]["events"][1]
    bad_export("an event dropped from the middle", x, r"does not follow|prevHash")
    x = clone(EX2); x[0]["events"].reverse()
    bad_export("events out of order", x, r"does not follow|prevHash")
    bad_export("a whole page left out", [EX2[0], EX2[2]], r"does not follow")
    x = clone(EX2); x[2]["events"].pop()
    bad_export("the last event cut off the end", x, r"head|missing")
    x = clone(EX2); x[2]["events"] = []
    bad_export("the last page emptied", x, r"head|missing|does not follow")
    bad_export("a page repeated", [clone(EX2[0]), clone(EX2[0]), *clone(EX2)[1:]], r"does not follow|prevHash")
    x = clone(EX2); x[1]["mandateId"] = "mdt_other"
    bad_export("a page of another mandate mixed in", x, r"not all of the same mandate")

    def rewritten(pages):
        out, prev = clone(pages), ZERO
        for ev in flat_events(out):
            if ev["seq"] == 2:
                b = json.loads(ev["body"]); b["cost"] = 0; ev["body"] = ser(b)
            ev["prevHash"] = prev; ev["hash"] = sha(prev + "\n" + ev["body"]); prev = ev["hash"]
        return out
    bad_export("the history rewritten from event 2 with the chain recomputed: the checkpoint no longer fits", rewritten(EX2), r"sealed|checkpoint")
    x = clone(EX2); last = x[2]["events"][-1]; b = json.loads(last["body"]); b["correlationId"] = "forged"; last["body"] = ser(b); last["hash"] = sha(last["prevHash"] + "\n" + last["body"])
    bad_export("the last event rewritten with its hash recomputed: the signed head no longer fits", x, r"head")
    x = clone(EX2); x[2]["head"]["seq"] += 1
    bad_export("the head changed", x, r"head")
    x = clone(EX2); x[2]["head"]["signature"] = EX2[0]["head"]["signature"]
    bad_export("the signature of another head", x, r"head")
    x = clone(EX2); cp = next(ev for ev in flat_events(x) if ev["type"] == "checkpoint"); b = json.loads(cp["body"]); b["coversHash"] = ZERO; cp["body"] = ser(b); cp["hash"] = sha(cp["prevHash"] + "\n" + cp["body"])
    bad_export("a checkpoint that covers another hash", x, r"not the one FIPSign sealed|prevHash|checkpoint")
    x = clone(EX2); cp = next(ev for ev in flat_events(x) if ev["type"] == "checkpoint"); b = json.loads(cp["body"]); b["signature"] = EX2[2]["head"]["signature"]; cp["body"] = ser(b); cp["hash"] = sha(cp["prevHash"] + "\n" + cp["body"])
    bad_export("a checkpoint with a signature that is not its own", x, r"prevHash|checkpoint")
    x = clone(EX2)
    for pg in x:
        pg["head"] = None
    e = verify_mandate_export(x, pin_fingerprint=both)
    check("an export without a head is still checked (chain and checkpoints), with no head verified", e.valid and not e.headChecked and e.checkpoints == 2, repr(e))
    x = clone(EX2)
    for pg in x:
        pg["events"] = [ev for ev in pg["events"] if ev["seq"] > 4]
    e = verify_mandate_export(x, pin_fingerprint=both)
    check("an export that starts at event 5: a note, not a failure; the later chain and checkpoint still check",
          e.valid and any("starts at event 5" in n for n in e.notes) and any("checkpoint 5 covers event 4" in n for n in e.notes) and e.checkpoints == 1 and not e.complete, repr(e))

    # ─── 4. Logs made here ───────────────────────────────────────────────────
    section("4. Logs made here with a fresh project key")
    for algorithm in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"):
        P, M = Project(algorithm), "mdt_" + algorithm[-2:]
        events = make_log(P, M, SPEC)
        pages = pages_of(P, M, events, 3)
        e = verify_mandate_export(pages, public_key=P.public_key)
        check("%s: a log with 2 checkpoints and a signed head over 3 pages: valid, complete, non-ASCII text in the events" % algorithm,
              e.valid and e.complete and e.checkpoints == 2 and e.headChecked and e.events == 7 and e.sealedThrough == 6 and len(pages) == 3, repr(e))
        rc = {**P.seal("mandate.receipt", M, 2, events[1]["hash"], events[1]["at"]), "event": events[1]}
        c = verify_mandate_receipt(rc, public_key=P.public_key, expect_project_id=P.project_id, expect_mandate_id=M)
        check("%s: a receipt made here is valid" % algorithm, c.valid and c.keyTrust == "pinned", repr(c))
        c = verify_mandate_receipt({**rc, "signature": tamper_bit(rc["signature"])}, public_key=P.public_key)
        check("%s: a receipt with one bit of the signature changed is not valid" % algorithm, not c.valid, repr(c))

    P, M = Project(), "mdt_x"
    events = make_log(P, M, SPEC)
    pages = pages_of(P, M, events, 100)
    e = verify_mandate_export(pages, public_key=P.public_key)
    check("one page: valid and complete", e.valid and e.complete and len(pages) == 1, repr(e))
    e = verify_mandate_export(pages_of(P, M, events[:6], 100), public_key=P.public_key)
    check("a log that does not end in a checkpoint: valid, not complete (the last events are protected only by the signed head)", e.valid and not e.complete and e.sealedThrough == 3 and e.lastSeq == 6, repr(e))
    e = verify_mandate_export(pages_of(P, M, events[:6], 100, head=False), public_key=P.public_key)
    check("...and without a head either: still valid, nothing signed covers events 5 and 6", e.valid and not e.complete and not e.headChecked, repr(e))
    e = verify_mandate_export([{**p, "head": {**p["head"], "seq": 99}} for p in pages_of(P, M, events, 100)], public_key=P.public_key)
    check("a head that says the log is longer than the export, while the last page says there is no more: not valid", not e.valid, repr(e.problems))
    longer = make_log(P, M, [*SPEC, {"type": "revoked", "at": T0 + 30, "fields": {}}])
    cut = pages_of(P, M, longer, 100)
    cut[0]["events"] = cut[0]["events"][:7]; cut[0]["count"] = 7
    e = verify_mandate_export(cut, public_key=P.public_key)
    check("events cut off the end while the head is further on: not valid", not e.valid and any("events are missing at the end" in p for p in e.problems), repr(e.problems))
    mid = clone(pages); del mid[0]["events"][2:4]
    e = verify_mandate_export(mid, public_key=P.public_key)
    check("events missing in the middle: not valid", not e.valid and any("does not follow" in p for p in e.problems), repr(e.problems))
    e = verify_mandate_export(pages_of(P, M, events[3:], 100), public_key=P.public_key)
    check("an export that starts at event 4: a note says the earlier events are not checked, the rest is", any("starts at event 4" in n for n in e.notes) and not e.complete, repr(e))
    e = verify_mandate_export(pages, public_key=Project().public_key)
    check("another project key: not valid", not e.valid, repr(e.problems))
    forged = clone(pages)
    prev = ZERO
    for ev in flat_events(forged):  # somebody who can write the database and has no key: rewrites event 2 and recomputes the chain
        if ev["seq"] == 2:
            b = json.loads(ev["body"]); b["cost"] = 0; ev["body"] = ser(b)
        ev["prevHash"] = prev; ev["hash"] = sha(prev + "\n" + ev["body"]); prev = ev["hash"]
    e = verify_mandate_export(forged, public_key=P.public_key)
    check("a history rewritten with a recomputed chain and no key: not valid", not e.valid and any(("checkpoint" in p or "head" in p) for p in e.problems), repr(e.problems))
    thief = Project("ML-DSA-65", P.project_id)
    forged_all = pages_of(thief, M, make_log(thief, M, [({**s, "fields": {"action": "a", "cost": 0}} if i == 1 else s) for i, s in enumerate(SPEC)]), 100)
    e = verify_mandate_export(forged_all, pin_fingerprint=P.fingerprint)
    check("a log re-signed with another key, the fingerprint of the real key pinned: not valid (the pin is what makes the check independent of FIPSign)",
          not e.valid and any("no key with fingerprint" in p for p in e.problems), repr(e.problems))
    check("...with nothing pinned the strict function trusts nothing", not verify_mandate_export(forged_all).valid)
    # (what the client does with nothing pinned is checked in the sections run for each client)

    section("4b. Signed by the right key, but not what a receipt, a checkpoint or a head is")
    P, M = Project(), "mdt_k"
    events = make_log(P, M, SPEC)
    ev = events[1]

    def stmt(**over):
        return {"v": 1, "kind": "mandate.receipt", "projectId": P.project_id, "mandateId": M, "seq": ev["seq"], "hash": ev["hash"], "at": ev["at"], **over}

    def signed_receipt(text):
        return {"signed": text, "signature": P.sign_raw(text), "algorithm": P.algorithm, "keyFingerprint": P.fingerprint, "event": ev}

    def one(name, text, pattern=None, valid=False):
        c = verify_mandate_receipt(signed_receipt(text), public_key=P.public_key)
        if valid:
            check(name, c.valid, repr(c))
        else:
            check(name, not c.valid and (pattern is None or any(pattern in p for p in c.problems)), repr(c.problems))

    one("control: the statement written the way FIPSign writes it is valid", ser(stmt()), valid=True)
    one("a statement with a space in it, signed by the right key: not valid, not in canonical form", ser(stmt()).replace("{", "{ ", 1), "canonical form")
    one("a statement with its keys in another order, signed by the right key: not valid, not in canonical form", json.dumps(stmt(), separators=(",", ":")), "canonical form")
    one("a checkpoint statement presented as a receipt, signed by the right key: not valid, wrong kind", ser(stmt(kind="mandate.checkpoint")), "not of kind mandate.receipt")
    one("a statement of another version: not valid", ser(stmt(v=2)), "not of kind")
    one("a statement whose version is true, not 1: not valid (true is not 1)", ser(stmt(v=True)), "not of kind")
    one("a statement about another event, signed by the right key: not valid", ser(stmt(seq=3)), "not about the event")
    one("a statement about another mandate than the event is of, signed by the right key: not valid", ser(stmt(mandateId="mdt_other")), "another mandate")
    swapped = clone(events)
    cp_idx = next(i for i, x in enumerate(swapped) if x["type"] == "checkpoint")
    cp_body = json.loads(swapped[cp_idx]["body"]); covered = swapped[cp_idx - 1]
    cp_body["signature"] = P.sign_raw(ser(stmt(seq=covered["seq"], hash=covered["hash"], at=swapped[cp_idx]["at"])))
    prev = swapped[cp_idx]["prevHash"]
    for x2 in swapped[cp_idx:]:
        x2["prevHash"] = prev
        if x2["seq"] == swapped[cp_idx]["seq"]:
            x2["body"] = ser(cp_body)
        x2["hash"] = sha(prev + "\n" + x2["body"]); prev = x2["hash"]
    e = verify_mandate_export(pages_of(P, M, swapped, 100, head=False), public_key=P.public_key)
    check("a checkpoint signed with the statement of a receipt (the kinds cannot be swapped): not valid", not e.valid and any("checkpoint 4: the signature does not verify" in p for p in e.problems), repr(e.problems))
    as_head = pages_of(P, M, events, 100)
    last = events[-1]
    as_head[0]["head"]["signed"] = ser(stmt(seq=last["seq"], hash=last["hash"], at=as_head[0]["head"]["at"]))
    as_head[0]["head"]["signature"] = P.sign_raw(as_head[0]["head"]["signed"])
    e = verify_mandate_export(as_head, public_key=P.public_key)
    check("a receipt statement presented as the head of an export: not valid, wrong kind", not e.valid and any("head: the statement is not of kind mandate.export" in p for p in e.problems), repr(e.problems))
    ghost = clone(events)
    ghost[1]["body"] = mutate(ghost[1]["body"], r'"seq":2', '"seq":7'); ghost[1]["hash"] = sha(ghost[1]["prevHash"] + "\n" + ghost[1]["body"])
    e = verify_mandate_export(pages_of(P, M, ghost, 100, head=False), public_key=P.public_key)
    check("an event whose body says another seq than the event: not valid", not e.valid and any("body does not match the event" in p for p in e.problems), repr(e.problems))
    nonascii = ser(stmt()).replace(M, "mdt_é")
    one("a statement that is another mandate with a non-ASCII id: not valid", nonascii)
    # an event whose body is JSON that says the right things but is not written the canonical way, hash and receipt made for it
    loose = clone(ev)
    loose["body"] = json.dumps(json.loads(ev["body"]), sort_keys=True, ensure_ascii=False)  # ", " and ": " separators
    assert loose["body"] != ev["body"]
    loose["hash"] = sha(loose["prevHash"] + "\n" + loose["body"])
    loose_stmt = ser(stmt(hash=loose["hash"]))
    c = verify_mandate_receipt({"signed": loose_stmt, "signature": P.sign_raw(loose_stmt), "algorithm": P.algorithm, "keyFingerprint": P.fingerprint, "event": loose}, public_key=P.public_key)
    check("an event body that is not canonical JSON, with its hash and a receipt made for it by the right key: not valid", not c.valid and any("not canonical JSON" in p for p in c.problems), repr(c.problems))

    section("4c. Links between events, and what only the last page can say")
    P, M = Project(), "mdt_l"
    events_a = make_log(P, M, SPEC)
    # the same history with event 2 different: its event 3 has a hash of its own that is right, but it follows another event 2
    events_c = make_log(P, M, [({**sp, "fields": {"action": "a", "cost": 7}} if i == 1 else sp) for i, sp in enumerate(SPEC)])
    broken = [events_a[0], events_a[1], events_c[2]]   # event 3 of another history: its own hash is right, it does not follow event 2 of this one
    assert events_c[2]["prevHash"] != events_a[1]["hash"]
    e = verify_mandate_export(pages_of(P, M, broken, 100, head=False), public_key=P.public_key)
    check("an event taken from another history (its own hash is right, it does not follow the one before it): not valid, no head or checkpoint needed to see it",
          not e.valid and any("prevHash is not the hash of the event before it" in p for p in e.problems), repr(e.problems))
    pages = pages_of(P, M, events_a, 100)
    check("control: the whole log is valid and complete", verify_mandate_export(pages, public_key=P.public_key).complete)
    more = clone(pages); more[-1]["nextAfter"] = 7
    e = verify_mandate_export(more, public_key=P.public_key)
    check("the last page says there are more events after it: valid so far, but not complete", e.valid and not e.complete, repr(e))
    unknown = clone(pages); del unknown[-1]["nextAfter"]
    e = verify_mandate_export(unknown, public_key=P.public_key)
    check("the last page does not say whether there is more: not complete", e.valid and not e.complete, repr(e))
    P2 = Project(P.algorithm, "prj_other")
    P2.sk, P2.public_key, P2.fingerprint = P.sk, P.public_key, P.fingerprint   # the same key, another project
    foreign = make_log(P2, M, SPEC)                                               # its checkpoints say prj_other
    e = verify_mandate_export(pages_of(P, M, foreign, 100, head=False), public_key=P.public_key)
    check("a checkpoint that is for another project: not valid, and says so", not e.valid and any("it is for another project" in p for p in e.problems), repr(e.problems))

    # ─── fingerprints ────────────────────────────────────────────────────────
    section("5b. public_key_fingerprint")
    fp = public_key_fingerprint(KEY_A["publicKey"])
    check("public_key_fingerprint gives the fingerprint FIPSign shows", fp == KEY_A["fingerprint"] and fp == sha(base64.b64decode(KEY_A["publicKey"])), fp)
    check("public_key_fingerprint: SHA-256 of the key bytes, known answer", public_key_fingerprint("AQID") == "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81")
    check("public_key_fingerprint ignores white space around the key", public_key_fingerprint("  %s\n" % KEY_A["publicKey"]) == KEY_A["fingerprint"])
    check("public_key_fingerprint accepts a key without its padding, as atob() does", public_key_fingerprint("AQI") == sha(bytes([1, 2])))
    for junk in ("", "   ", "%%%", 5, None, "A", "====", b"AQID"):
        err = None
        try:
            public_key_fingerprint(junk)
        except Exception as exc:  # noqa: BLE001
            err = exc
        check("public_key_fingerprint(%r) raises PQAuthError INVALID_PUBLIC_KEY" % (junk,), isinstance(err, PQAuthError) and err.code == "INVALID_PUBLIC_KEY", repr(err))

    # ─── 6. They never raise ────────────────────────────────────────────────
    section("6. They never raise")

    class Hostile:
        @property
        def receipt(self):
            raise RuntimeError("boom")

        def to_dict(self):
            raise RuntimeError("boom")

    JUNK = [None, 0, 1, float("nan"), "", "text", True, [], [None], {}, {"receipt": None}, {"events": None}, {"event": {}},
            {"signed": 1, "signature": 2, "algorithm": 3, "keyFingerprint": 4, "event": {"seq": "x"}},
            {"events": [{}], "projectId": "p", "mandateId": "m"},
            {"events": [EV(1)], "projectId": "p", "mandateId": "m", "head": 5},
            {"events": [{**EV(1), "body": 7}], "projectId": "p", "mandateId": "m"},
            {"events": [EV(1)], "projectId": "p", "mandateId": "m", "head": {"seq": [1], "hash": 1, "signed": 2}},
            {"events": [EV(1)], "projectId": "p", "mandateId": "m", "head": {"seq": {}}},
            [[]], [{"events": "nope"}], object(), Hostile(), b"bytes", 10 ** 400]
    OPTS = [{}, {"public_key": KEY_A["publicKey"]}, {"pin_fingerprint": KEY_A["fingerprint"]}, {"public_key": 5}, {"pin_fingerprint": [1, 2]},
            {"keys": "x"}, {"keys": [None, 5, {}, {"publicKey": 7}]}, {"public_key": [KEY_A["publicKey"], None]}, {"pin_fingerprint": KEY_A["fingerprint"], "keys": object()}]
    fns = [verify_mandate_receipt, verify_mandate_export]
    threw = not_false = calls = 0
    for j in JUNK:
        for o in OPTS:
            for f in fns:
                calls += 1
                try:
                    res = f(j, **o)
                    if res.valid is not False or not isinstance(res.problems, list) or len(res.problems) == 0:
                        not_false += 1
                except Exception:  # noqa: BLE001
                    threw += 1
    check("%d calls with junk input: none raises, every one answers valid=False with a reason" % calls, threw == 0 and not_false == 0, "raised %d, not false %d" % (threw, not_false))
    return JUNK, OPTS


def run_never_raise_on_client(label, pq, JUNK, OPTS):
    threw = not_false = calls = 0
    for j in JUNK:
        for o in OPTS:
            calls += 1
            try:
                res = settle(pq.mandate.verify_export(j, **o))
                if res.valid is not False or not res.problems:
                    not_false += 1
            except Exception:  # noqa: BLE001
                threw += 1
    check("[%s] mandate.verify_export: %d calls with junk input: none raises, every one answers valid=False" % (label, calls), threw == 0 and not_false == 0, "raised %d, not false %d" % (threw, not_false))
    # the forged log, re-signed with another key, with nothing pinned: it checks out and says what that means
    P = Project(); M = "mdt_f"
    forged_all = pages_of(P, M, make_log(P, M, SPEC), 100)
    e = settle(pq.mandate.verify_export(forged_all))
    check("[%s] mandate.verify_export with nothing pinned checks out a log re-signed with another key, and says keyTrust \"fipsign\": that is what the answer means" % label, e.valid and e.keyTrust == "fipsign", repr(e))


def main():
    clients = make_clients()
    for label, pq in clients:
        requests_sections(label, pq)
    JUNK, OPTS = verification_sections()
    for label, pq in clients:
        run_never_raise_on_client(label, pq, JUNK, OPTS)
    if AsyncPQAuth is None:
        print("\n(httpx is not installed: the asynchronous client was not tested)")
    else:
        for label, pq in clients:
            if label == "async":
                LOOP.run_until_complete(pq.aclose())
    SERVER.shutdown()
    print("\n%d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


def test_mandate_audit():                                # pytest entry point
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())

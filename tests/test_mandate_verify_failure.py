#!/usr/bin/env python3
"""
mandate.verify() - what it returns when FIPSign denies a call and when the answer never arrives.

Offline: no API key, no network, no tokens. A stub FIPSign on localhost sends exactly the replies we need.
Runs the synchronous client and, when httpx is installed, the asynchronous one.

Usage:  python tests/test_mandate_verify_failure.py        (also runs under pytest)

What it checks, for 24 kinds of answer (and a few more things at the end):
  - a call that is not granted is always result "denied" (never a third value) and always has a `failure`;
  - "outcome_unknown" (the call may have been granted and charged) only when no usable answer arrived;
  - the SDK sends exactly one request per call: it never repeats a call by itself.
"""
import asyncio
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Always test the code of this working tree, not a fipsign-sdk that happens to be installed.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fipsign import PQAuth

try:
    from fipsign import AsyncPQAuth
    import httpx  # noqa: F401
except ImportError:
    AsyncPQAuth = None

# ─── The stub FIPSign ────────────────────────────────────────────────────────

STATE = {"hits": 0, "last_body": "", "behavior": None}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        STATE["hits"] += 1
        length = int(self.headers.get("Content-Length") or 0)
        STATE["last_body"] = self.rfile.read(length).decode("utf-8")
        STATE["behavior"](self)


def json_reply(status, body, headers=None):
    def run(h):
        data = json.dumps(body).encode("utf-8")
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.end_headers()
        h.wfile.write(data)
    return run


def text_reply(status, body, content_type="text/html"):
    def run(h):
        data = body.encode("utf-8")
        h.send_response(status)
        h.send_header("Content-Type", content_type)
        h.send_header("Content-Length", str(len(data)))
        h.end_headers()
        h.wfile.write(data)
    return run


def never(h):          # the request is received and never answered
    time.sleep(3)


def drop(h):           # the connection breaks before any answer
    h.close_connection = True
    h.connection.shutdown(socket.SHUT_RDWR)


def cut(status, headers=None):   # the answer starts, then the connection breaks
    def run(h):
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", "200")
        for k, v in (headers or {}).items():
            h.send_header(k, v)
        h.end_headers()
        h.wfile.write(b'{"result":"gra')
        h.wfile.flush()
        time.sleep(0.02)
        h.close_connection = True
        h.connection.shutdown(socket.SHUT_RDWR)
    return run


def stall(status):     # the answer starts and never ends
    def run(h):
        h.send_response(status)
        h.send_header("Content-Type", "application/json")
        h.send_header("Content-Length", "200")
        h.end_headers()
        h.wfile.write(b'{"result":"gra')
        h.wfile.flush()
        time.sleep(3)
    return run


SERVER = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
SERVER.daemon_threads = True
threading.Thread(target=SERVER.serve_forever, daemon=True).start()
BASE_URL = "http://127.0.0.1:%d" % SERVER.server_address[1]

KEY = "pqa_" + "a" * 64
TOKEN = {"payload": "eyJ4IjoxfQ==", "signature": "AAAA", "algorithm": "ML-DSA-65", "issuedAt": 1}
TIMEOUT = 0.4

RATE = {"success": False, "error": "Rate limit exceeded. Maximum 300 requests per minute per API key.", "code": "rate_limited"}
QUOTA = {"success": False, "error": "Token limit reached.", "code": "token_quota_exhausted"}
FAILURES = ["rejected", "rate_limited", "quota_exhausted", "unavailable", "outcome_unknown"]

# [label, what the stub does, expected result, expected failure, expected retry_after, `reason`: the exact text or a prefix ending in "..."]
CASES = [
    ("200 granted", json_reply(200, {"success": True, "result": "granted", "actionMatched": "send_email", "budgetRemaining": 4, "expiresInSeconds": 60}), "granted", None, None, None),
    ("403 denied: scope_not_authorized", json_reply(403, {"success": False, "result": "denied", "reason": "scope_not_authorized", "authorizedScope": ["read"]}), "denied", "rejected", None, "scope_not_authorized"),
    ("403 denied: budget_exhausted", json_reply(403, {"success": False, "result": "denied", "reason": "budget_exhausted", "budgetConsumedUnits": 5, "budgetTotalUnits": 5}), "denied", "rejected", None, "budget_exhausted"),
    ("403 denied: agent_signature_replayed", json_reply(403, {"success": False, "result": "denied", "reason": "agent_signature_replayed"}), "denied", "rejected", None, "agent_signature_replayed"),
    ("400 request not well formed", json_reply(400, {"success": False, "error": '"cost" must be a non-negative integer'}), "denied", "rejected", None, '"cost" must be a non-negative integer'),
    ("401 invalid API key", json_reply(401, {"success": False, "error": "API key required or invalid. Include the X-API-Key header."}), "denied", "unavailable", None, "API key required or invalid. Include the X-API-Key header."),
    ("415 unsupported content type", json_reply(415, {"success": False, "error": "Content-Type must be application/json"}), "denied", "unavailable", None, "Content-Type must be application/json"),
    ("429 rate limit + Retry-After 7", json_reply(429, RATE, {"Retry-After": "7"}), "denied", "rate_limited", 7, RATE["error"]),
    ("429 rate limit without Retry-After", json_reply(429, RATE), "denied", "rate_limited", None, RATE["error"]),
    ("429 token quota exhausted", json_reply(429, QUOTA), "denied", "quota_exhausted", None, QUOTA["error"]),
    ("429 from a gateway (HTML)", text_reply(429, "<html>Too Many Requests</html>"), "denied", "rate_limited", None, "Request failed with status 429"),
    ("403 from a firewall (HTML)", text_reply(403, "<html>Forbidden</html>"), "denied", "unavailable", None, "Request failed with status 403"),
    ("500 server error (JSON)", json_reply(500, {"success": False, "error": "Internal server error"}), "denied", "outcome_unknown", None, "Internal server error"),
    ("502 bad gateway (HTML)", text_reply(502, "<html>Bad Gateway</html>"), "denied", "outcome_unknown", None, "Request failed with status 502"),
    ("503 empty body", text_reply(503, "", "text/plain"), "denied", "outcome_unknown", None, "Request failed with status 503"),
    ("200 but the body is HTML", text_reply(200, "<html>hello</html>"), "denied", "outcome_unknown", None, "Request failed with status 200"),
    ("200 JSON without result", json_reply(200, {"success": True}), "denied", "outcome_unknown", None, "Request failed with status 200"),
    ("200 with body null", text_reply(200, "null", "application/json"), "denied", "outcome_unknown", None, "Request failed with status 200"),
    ("connection dropped before any answer", drop, "denied", "outcome_unknown", None, "Network error..."),
    ("no answer within the timeout", never, "denied", "outcome_unknown", None, "Network error..."),
    ("200 starts and never ends (timeout)", stall(200), "denied", "outcome_unknown", None, "Network error..."),
    ("200 starts, then the connection breaks", cut(200), "denied", "outcome_unknown", None, "Network error..."),
    # An answer that breaks off is "no usable answer" here, even with a 4xx status: the HTTP libraries of the SDK do not
    # hand over the status of an answer they could not read to the end. It is the safe side: nothing is assumed about the call.
    ("429 starts, then the connection breaks", cut(429, {"Retry-After": "5"}), "denied", "outcome_unknown", None, "Network error..."),
    ("403 starts, then the connection breaks", cut(403), "denied", "outcome_unknown", None, "Network error..."),
]

PASSED = 0
FAILED = 0


def report(name, problems):
    global PASSED, FAILED
    if problems:
        FAILED += 1
        print("FAIL  %s\n        %s" % (name, "; ".join(problems)))
    else:
        PASSED += 1
        print("PASS  %s" % name)


def reason_ok(reason, expected):
    if expected is None:
        return True
    if expected.endswith("..."):
        return isinstance(reason, str) and reason.startswith(expected[:-3])
    return reason == expected


def check_case(call, label, behavior, result, failure, retry_after, reason, expect_hits=1):
    STATE["hits"] = 0
    STATE["behavior"] = behavior
    r = call("send_email", 1)
    problems = []
    if r.result != result:
        problems.append("result is %r, expected %r" % (r.result, result))
    got_failure = getattr(r, "failure", None)       # getattr: an SDK without the field fails the test instead of crashing it
    got_retry_after = getattr(r, "retry_after", None)
    if got_failure != failure:
        problems.append("failure is %r, expected %r" % (got_failure, failure))
    if got_retry_after != retry_after:
        problems.append("retry_after is %r, expected %r" % (got_retry_after, retry_after))
    if not reason_ok(r.reason, reason):
        problems.append("reason is %r, expected %r" % (r.reason, reason))
    if result == "denied" and got_failure not in FAILURES:
        problems.append("a denied call without a known failure")
    if STATE["hits"] != expect_hits:
        problems.append("the stub got %d requests, expected exactly %d (no repeats)" % (STATE["hits"], expect_hits))
    report("%s%s" % (label, ("  ->  " + failure) if failure else ""), problems)
    return r


def run_client(prefix, call):
    for label, behavior, result, failure, retry_after, reason in CASES:
        check_case(call, "[%s] %s" % (prefix, label), behavior, result, failure, retry_after, reason)

    # What a denial from FIPSign carries is passed through untouched.
    STATE["hits"] = 0
    STATE["behavior"] = json_reply(403, {"success": False, "result": "denied", "reason": "scope_not_authorized", "authorizedScope": ["read", "write"]})
    r = call("delete", 1)
    report("[%s] a denial keeps its authorizedScope" % prefix, [] if r.authorizedScope == ["read", "write"] else [repr(r)])
    STATE["behavior"] = json_reply(403, {"success": False, "result": "denied", "reason": "budget_exhausted", "budgetConsumedUnits": 5, "budgetTotalUnits": 5})
    r = call("send_email", 1)
    report("[%s] a denial keeps budgetConsumedUnits and budgetTotalUnits" % prefix,
           [] if (r.budgetConsumedUnits, r.budgetTotalUnits) == (5, 5) else [repr(r)])
    STATE["behavior"] = json_reply(200, {"success": True, "result": "granted", "actionMatched": "send_email", "budgetRemaining": 4, "expiresInSeconds": 60,
                                         "usage": {"freeRemaining": 1, "packRemaining": 2, "totalRemaining": 9, "month": "2026-10"}})
    r = call("send_email", 1)
    report("[%s] a granted call keeps its fields and has no failure" % prefix,
           [] if (r.budgetRemaining, r.expiresInSeconds, r.usage.totalRemaining, getattr(r, "failure", None), getattr(r, "retry_after", None)) == (4, 60, 9, None, None) else [repr(r)])


def closed_port_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return "http://127.0.0.1:%d" % port


def run_sync():
    pq = PQAuth(KEY, base_url=BASE_URL, timeout=TIMEOUT)
    run_client("sync", lambda action, cost: pq.mandate.verify(TOKEN, action, cost))

    # What the SDK sends.
    STATE["behavior"] = json_reply(200, {"success": True, "result": "granted"})
    pq.mandate.verify(TOKEN, "send_email", 3)
    plain = json.loads(STATE["last_body"])
    sig = {"payload": "eyJzIjoxfQ==", "signature": "BBBB", "algorithm": "ML-DSA-65", "issuedAt": 2}
    pq.mandate.verify(TOKEN, "send_email", 3, agent_signature=sig)
    signed = json.loads(STATE["last_body"])
    ok = (plain["action"] == "send_email" and plain["cost"] == 3 and plain["token"]["signature"] == "AAAA"
          and "agentSignature" not in plain and signed["agentSignature"]["signature"] == "BBBB")
    report("[sync] the request carries token, action, cost and (only when given) agentSignature", [] if ok else [STATE["last_body"]])

    # Arguments the API could never accept are refused here, and nothing is sent.
    STATE["hits"] = 0
    r = pq.mandate.verify("not a token", "send_email", 1)
    report("[sync] a token that is not a token  ->  rejected, nothing sent",
           [] if (r.result, getattr(r, "failure", None), STATE["hits"]) == ("denied", "rejected", 0) else [repr(r), "hits=%d" % STATE["hits"]])

    # Nothing listens: a refused connection is also "no answer" (the SDK cannot tell it from a lost one).
    r = PQAuth(KEY, base_url=closed_port_url(), timeout=TIMEOUT).mandate.verify(TOKEN, "send_email", 1)
    report("[sync] connection refused  ->  outcome_unknown",
           [] if (r.result, getattr(r, "failure", None)) == ("denied", "outcome_unknown") and str(r.reason).startswith("Network error") else [repr(r)])


def run_async():
    if AsyncPQAuth is None:
        print("SKIP  async client (httpx is not installed: pip install fipsign-sdk[async])")
        return

    def make_call(url=BASE_URL):
        def call(action, cost):
            async def go():
                async with AsyncPQAuth(KEY, base_url=url, timeout=TIMEOUT) as pq:
                    return await pq.mandate.verify(TOKEN, action, cost)
            return asyncio.run(go())
        return call

    run_client("async", make_call())

    STATE["hits"] = 0
    async def bad_token():
        async with AsyncPQAuth(KEY, base_url=BASE_URL, timeout=TIMEOUT) as pq:
            return await pq.mandate.verify("not a token", "send_email", 1)
    r = asyncio.run(bad_token())
    report("[async] a token that is not a token  ->  rejected, nothing sent",
           [] if (r.result, getattr(r, "failure", None), STATE["hits"]) == ("denied", "rejected", 0) else [repr(r), "hits=%d" % STATE["hits"]])

    r = make_call(closed_port_url())("send_email", 1)
    report("[async] connection refused  ->  outcome_unknown",
           [] if (r.result, getattr(r, "failure", None)) == ("denied", "outcome_unknown") and str(r.reason).startswith("Network error") else [repr(r)])


def main():
    run_sync()
    run_async()
    print("\n%d passed, %d failed" % (PASSED, FAILED))
    return 1 if FAILED else 0


def test_mandate_verify_failure():     # for pytest
    assert main() == 0


if __name__ == "__main__":
    code = main()
    SERVER.shutdown()
    sys.exit(code)

#!/usr/bin/env python3
"""
Offline tests of canonicalize_for_signing(), zes_hash() and ca.verify_cert() (no API key, no network).

Usage:  python tests/test_canonicalize.py        (also runs under pytest)

canonicalize_for_signing() has to give, byte for byte, the text the backend and the JS SDK sign and hash:
JSON.stringify after sorting the keys of every object. The expected strings below were produced by Node with the
backend's canonicalizeJson(); this file is plain ASCII on purpose (non-ASCII data is written as escape sequences).
"""
import base64
import hashlib
import json
import os
import sys

# Always test the code of this working tree, not a fipsign-sdk that happens to be installed.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from fipsign import PQAuth
from fipsign.types import PQCert
from fipsign.utils import canonicalize_for_signing, zes_hash

# [name, JSON text, text that Node's canonicalizeJson() gives for it]
VECTORS = json.loads(r"""[
[
"keys sorted at every level, array order kept",
"{\"b\":[3,2,{\"z\":1,\"a\":null}],\"a\":\"x\",\"c\":true}",
"{\"a\":\"x\",\"b\":[3,2,{\"a\":null,\"z\":1}],\"c\":true}"
],
[
"non-ASCII subject",
"{\"subject\":\"\\u00d1and\\u00fa\",\"model\":\"v2\"}",
"{\"model\":\"v2\",\"subject\":\"\u00d1and\u00fa\"}"
],
[
"accents and CJK in keys and values",
"{\"meta\":{\"ubicaci\\u00f3n\":\"C\\u00f3rdoba\",\"\\u88c5\\u7f6e\":\"\\u9501\"}}",
"{\"meta\":{\"ubicaci\u00f3n\":\"C\u00f3rdoba\",\"\u88c5\u7f6e\":\"\u9501\"}}"
],
[
"emoji (outside the BMP) and U+2028",
"{\"s\":\"\\ud83d\\ude00 \\u2028 \\u2029\"}",
"{\"s\":\"\ud83d\ude00 \u2028 \u2029\"}"
],
[
"control characters, quote, backslash, slash, DEL",
"{\"s\":\"\\u0000\\u001f\\b\\t\\n\\f\\r\\\" \\\\ / \\u007f\"}",
"{\"s\":\"\\u0000\\u001f\\b\\t\\n\\f\\r\\\" \\\\ / \u007f\"}"
],
[
"lone surrogates are escaped",
"{\"s\":\"\\ud800 x \\udfff\"}",
"{\"s\":\"\\ud800 x \\udfff\"}"
],
[
"0.00001 stays 0.00001",
"{\"t\":0.00001}",
"{\"t\":0.00001}"
],
[
"0.000001 stays 0.000001",
"{\"t\":0.000001}",
"{\"t\":0.000001}"
],
[
"1e-7 is 1e-7",
"{\"t\":1e-7}",
"{\"t\":1e-7}"
],
[
"10.0 is 10",
"{\"a\":10.0}",
"{\"a\":10}"
],
[
"1E3 is 1000",
"{\"a\":1E3}",
"{\"a\":1000}"
],
[
"1e21 is 1e+21",
"{\"a\":1e21}",
"{\"a\":1e+21}"
],
[
"1e16 is 10000000000000000",
"{\"a\":1e16}",
"{\"a\":10000000000000000}"
],
[
"123456789012345680000",
"{\"a\":123456789012345680000}",
"{\"a\":123456789012345680000}"
],
[
"-0.0 is 0",
"{\"a\":-0.0}",
"{\"a\":0}"
],
[
"5e-324",
"{\"a\":5e-324}",
"{\"a\":5e-324}"
],
[
"largest double",
"{\"a\":1.7976931348623157e308}",
"{\"a\":1.7976931348623157e+308}"
],
[
"9007199254740993 is read as a double",
"{\"a\":9007199254740993}",
"{\"a\":9007199254740992}"
],
[
"2**63 is read as a double",
"{\"a\":9223372036854775808}",
"{\"a\":9223372036854776000}"
],
[
"1e400 is Infinity, written null",
"{\"a\":1e400}",
"{\"a\":null}"
],
[
"0.30000000000000004",
"{\"a\":0.30000000000000004}",
"{\"a\":0.30000000000000004}"
],
[
"numbers in an array",
"{\"a\":[0.1,0.2,1.0,2.50,100.5,-3]}",
"{\"a\":[0.1,0.2,1,2.5,100.5,-3]}"
],
[
"array-index keys first, in numeric order",
"{\"b\":1,\"10\":2,\"2\":3,\"a\":4}",
"{\"2\":3,\"10\":2,\"a\":4,\"b\":1}"
],
[
"4294967295 is not an index; 01 and -1 are not either",
"{\"4294967295\":1,\"4294967294\":2,\"1\":3,\"01\":4,\"-1\":5,\"a\":6}",
"{\"1\":3,\"4294967294\":2,\"-1\":5,\"01\":4,\"4294967295\":1,\"a\":6}"
],
[
"UTF-16 order of keys (U+FF5E, an emoji, U+D7FF, U+E000)",
"{\"\\uff5e\":1,\"\\ud83d\\ude00\":2,\"\\ud7ff\":3,\"\\ue000\":4}",
"{\"\ud7ff\":3,\"\ud83d\ude00\":2,\"\ue000\":4,\"\uff5e\":1}"
],
[
"empty key and nesting",
"{\"\":1,\"a\":{\"\":2,\"B\":3,\"b\":4}}",
"{\"\":1,\"a\":{\"\":2,\"B\":3,\"b\":4}}"
]
]""")

# [name, certificate without its signature, text that Node's canonicalizeJson() gives for it]
CERTS = json.loads(r"""[
[
"ascii subject and meta",
{
"type": "CA_CERT",
"id": "cert_test",
"publicKey": "AAAA",
"caId": "ca_test",
"issuedAt": 1778947233,
"expiresAt": 4102444800,
"algorithm": "ML-DSA-65",
"standard": "NIST FIPS 204",
"subject": "device-serial-00123",
"meta": {
"model": "lock-v2",
"batch": "2026-05"
}
},
"{\"algorithm\":\"ML-DSA-65\",\"caId\":\"ca_test\",\"expiresAt\":4102444800,\"id\":\"cert_test\",\"issuedAt\":1778947233,\"meta\":{\"batch\":\"2026-05\",\"model\":\"lock-v2\"},\"publicKey\":\"AAAA\",\"standard\":\"NIST FIPS 204\",\"subject\":\"device-serial-00123\",\"type\":\"CA_CERT\"}"
],
[
"non-ASCII subject and meta",
{
"type": "CA_CERT",
"id": "cert_test",
"publicKey": "AAAA",
"caId": "ca_test",
"issuedAt": 1778947233,
"expiresAt": 4102444800,
"algorithm": "ML-DSA-65",
"standard": "NIST FIPS 204",
"subject": "dispositivo-\u00d1and\u00fa-\u65e5\u672c",
"meta": {
"ubicaci\u00f3n": "C\u00f3rdoba, Argentina"
}
},
"{\"algorithm\":\"ML-DSA-65\",\"caId\":\"ca_test\",\"expiresAt\":4102444800,\"id\":\"cert_test\",\"issuedAt\":1778947233,\"meta\":{\"ubicaci\u00f3n\":\"C\u00f3rdoba, Argentina\"},\"publicKey\":\"AAAA\",\"standard\":\"NIST FIPS 204\",\"subject\":\"dispositivo-\u00d1and\u00fa-\u65e5\u672c\",\"type\":\"CA_CERT\"}"
],
[
"small float and index keys in meta",
{
"type": "CA_CERT",
"id": "cert_test",
"publicKey": "AAAA",
"caId": "ca_test",
"issuedAt": 1778947233,
"expiresAt": 4102444800,
"algorithm": "ML-DSA-65",
"standard": "NIST FIPS 204",
"subject": "sensor-7",
"meta": {
"threshold": 1e-05,
"gain": 10.5,
"10": "b",
"2": "a",
"z": [
1,
2.0
]
}
},
"{\"algorithm\":\"ML-DSA-65\",\"caId\":\"ca_test\",\"expiresAt\":4102444800,\"id\":\"cert_test\",\"issuedAt\":1778947233,\"meta\":{\"2\":\"a\",\"10\":\"b\",\"gain\":10.5,\"threshold\":0.00001,\"z\":[1,2]},\"publicKey\":\"AAAA\",\"standard\":\"NIST FIPS 204\",\"subject\":\"sensor-7\",\"type\":\"CA_CERT\"}"
]
]""")


def test_vectors_match_node():
    bad = []
    for name, text, expected in VECTORS:
        got = canonicalize_for_signing(json.loads(text))
        if got != expected:
            bad.append((name, got, expected))
    assert not bad, "\n".join("%s:\n  got      %s\n  expected %s" % b for b in bad)


def test_zes_hash_matches_js():
    # the JS SDK gives 427ba25303e49ae52aafee53934b4eed184d57c35a7260014d86f4e671b6c09f for this data
    assert zes_hash({"customer": "\u00d1and\u00fa", "amount": "50000"}) == "427ba25303e49ae52aafee53934b4eed184d57c35a7260014d86f4e671b6c09f"
    assert zes_hash({"amount": 10.0}) == hashlib.sha256(b'{"amount":10}').hexdigest()
    assert zes_hash({"b": 1, "a": 2}) == zes_hash({"a": 2, "b": 1})


def test_not_json_is_refused():
    for value in ({1, 2}, b"x", object()):
        try:
            canonicalize_for_signing({"v": value})
        except TypeError:
            continue
        raise AssertionError("%r was accepted" % (value,))


def _sign_and_verify(canonical, cert):
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    key = MLDSA65PrivateKey.generate()
    root = PQCert.from_dict({"type": "CA_ROOT", "id": "ca_test", "subject": "Test root", "issuedAt": 1778947233,
                             "expiresAt": 4102444800, "algorithm": "ML-DSA-65", "standard": "NIST FIPS 204", "signature": "x",
                             "publicKey": base64.b64encode(key.public_key().public_bytes_raw()).decode()})
    signed = dict(cert, signature=base64.b64encode(key.sign(canonical.encode("utf-8"))).decode())
    pq = PQAuth("pqa_" + "0" * 64)
    return pq, root, signed


def test_verify_cert_accepts_what_the_backend_signs():
    for name, cert, canonical in CERTS:
        pq, root, signed = _sign_and_verify(canonical, cert)
        result = pq.ca.verify_cert(PQCert.from_dict(signed), root)
        assert result.valid, "%s: %s" % (name, result.error)
        # the same certificate with one character changed must be refused
        forged = dict(signed, subject=signed["subject"] + "x")
        assert not pq.ca.verify_cert(PQCert.from_dict(forged), root).valid, name


TESTS = [test_vectors_match_node, test_zes_hash_matches_js, test_not_json_is_refused, test_verify_cert_accepts_what_the_backend_signs]

if __name__ == "__main__":
    failed = 0
    for t in TESTS:
        try:
            t()
            print("PASS ", t.__name__)
        except Exception as e:      # noqa: BLE001 - a plain runner: show every failure
            failed += 1
            print("FAIL ", t.__name__, "-", str(e)[:600])
    print("\n%d passed, %d failed" % (len(TESTS) - failed, failed))
    sys.exit(1 if failed else 0)

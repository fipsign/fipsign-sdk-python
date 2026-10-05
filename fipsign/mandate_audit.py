"""
Mandate audit — check receipts and exports on your own machine.

FIPSign signs what it records about a mandate (see MandateReceipt). The functions below check those signatures and the
hash chain locally, with the same library that checks the other signatures of this SDK (``cryptography``): nothing is sent
anywhere and no API key is needed. verify_mandate_receipt() and verify_mandate_export() never raise: whatever is wrong is
listed in ``problems``.

A signature is only as trustworthy as the key it is checked with. Give them a key you already trusted (``public_key``, the
key GET /public-key returned when you integrated) or its fingerprint (``pin_fingerprint``, from public_key_fingerprint()):
the keys of a project that has rotated its keys come with the export or from mandate.public_keys(), and are accepted only if
their own fingerprint is the pinned one.

Usage
-----
>>> from fipsign import verify_mandate_receipt, verify_mandate_export, public_key_fingerprint
>>> result = pq.mandate.suspend(mandate_id, correlation_id="ticket-4821")
>>> check = verify_mandate_receipt(result.receipt, public_key=SAVED_PUBLIC_KEY)
>>> if not check.valid:
...     print(check.problems)
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .errors import PQAuthError
from .types import (
    MandateEvent,
    MandateExportCheck,
    MandateReceiptCheck,
)
from .utils import canonicalize_for_signing

MANDATE_SIGNING_DOMAIN = "FIPSIGN-MANDATE-v1\n"
MANDATE_GENESIS_HASH = "0" * 64

_PUBLIC_KEY_CLASS = {
    "ML-DSA-44": "MLDSA44PublicKey",
    "ML-DSA-65": "MLDSA65PublicKey",
    "ML-DSA-87": "MLDSA87PublicKey",
}

_MISSING: Any = object()
_MAX_SAFE_INTEGER = 2 ** 53 - 1

# What the caller may pass where a key, a fingerprint or a list of them is wanted.
KeyInput = Union[str, Sequence[Any], None]


# ─── Small helpers ────────────────────────────────────────────────────────────

def _is_int(value: Any) -> bool:
    """An integer (a bool is not one) that JavaScript would also hold exactly, like Number.isSafeInteger()."""
    return isinstance(value, int) and not isinstance(value, bool) and abs(value) <= _MAX_SAFE_INTEGER


def _same(a: Any, b: Any) -> bool:
    """Equal and of the same type: 1 is not True, and 1 is not "1"."""
    return type(a) is type(b) and a == b


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _utf8(text: str) -> bytes:
    """UTF-8 as JavaScript's TextEncoder writes it: a lone surrogate becomes U+FFFD instead of an error."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace").encode("utf-8")


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(_utf8(text)).hexdigest()


def _b64decode(text: str) -> bytes:
    """Base64 the way atob() reads it: white space is ignored and the padding may be missing."""
    compact = "".join(text.split())
    compact += "=" * (-len(compact) % 4)
    return base64.b64decode(compact, validate=True)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _parse_json(text: str) -> Tuple[bool, Any]:
    """json.loads() that, like JSON.parse(), refuses NaN and Infinity. Returns (ok, value)."""
    try:
        return True, json.loads(text, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return False, None


def _as_dict(value: Any) -> Any:
    """What a result object of this SDK says in plain form: its to_dict(), when it has one."""
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict) and not isinstance(value, type):
        return to_dict()
    return value


def _is_event_shape(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and _is_int(value.get("seq")) and _is_int(value.get("at"))
        and isinstance(value.get("type"), str) and isinstance(value.get("prevHash"), str)
        and isinstance(value.get("hash"), str) and isinstance(value.get("body"), str)
    )


def public_key_fingerprint(public_key: str) -> str:
    """
    The fingerprint of a public key: SHA-256, lowercase hex, of the key bytes. It is the value a receipt carries as
    ``keyFingerprint``. Keep the fingerprint of your project's key (GET /public-key, the day you integrate) and pass it as
    ``pin_fingerprint`` when you check a receipt or an export: the check then does not depend on FIPSign's word about which
    key is yours.

    Raises
    ------
    PQAuthError(code="INVALID_PUBLIC_KEY")
        If ``public_key`` is not base64.

    Examples
    --------
    >>> import requests
    >>> r = requests.get("https://api.fipsign.dev/public-key", headers={"X-API-Key": api_key})
    >>> print(public_key_fingerprint(r.json()["publicKey"]))   # save this value
    """
    try:
        if not isinstance(public_key, str) or public_key.strip() == "":
            raise ValueError("empty")
        raw = _b64decode(public_key.strip())
        if not raw:
            raise ValueError("empty")
    except (ValueError, binascii.Error):
        raise PQAuthError('"public_key" is not a valid base64 public key', "INVALID_PUBLIC_KEY") from None
    return hashlib.sha256(raw).hexdigest()


# ─── Which keys a check trusts ────────────────────────────────────────────────

def _key_text(candidate: Any) -> Optional[str]:
    """The base64 public key of a candidate: the text itself, a ``{"publicKey": ...}`` dict or a MandatePublicKey."""
    if isinstance(candidate, str):
        return candidate
    if isinstance(candidate, dict):
        key = candidate.get("publicKey")
    else:
        key = getattr(candidate, "publicKey", None)
    return key if isinstance(key, str) else None


class _Trust:
    """The keys a check trusts: fingerprint -> public key (base64), plus what was wrong with what the caller gave."""

    def __init__(self, trusted: Dict[str, str], problems: List[str], key_trust: str) -> None:
        self.trusted = trusted
        self.problems = problems
        self.key_trust = key_trust


def _resolve_trust(
    public_key: KeyInput,
    pin_fingerprint: KeyInput,
    keys: Any,
    candidates: Sequence[Any],
    fallback: str,
) -> _Trust:
    """
    From what the caller gave: ``public_key`` is trusted as it is; of the candidate keys (``keys``, plus those that come
    with the thing being checked), only those whose own fingerprint is pinned. Without ``public_key`` or
    ``pin_fingerprint``: nothing is trusted (``fallback="strict"``) or every candidate is (``"fipsign"``: the answer then
    says keyTrust "fipsign").
    """
    public_keys = _as_list(public_key)
    pins_given = _as_list(pin_fingerprint)
    given = len(public_keys) > 0 or len(pins_given) > 0
    problems: List[str] = []
    trusted: Dict[str, str] = {}

    # Every key that could be used, as base64 text, with its own fingerprint (never the one a list claims for it).
    pool: Dict[str, str] = {}
    for candidate in _as_list(keys) + list(candidates):
        text = _key_text(candidate)
        if text is None or text.strip() == "":
            continue
        try:
            pool[public_key_fingerprint(text)] = text.strip()
        except PQAuthError:
            pass  # not a key: ignored

    if not given:
        if fallback == "strict":
            return _Trust(
                trusted, [
                    "no key to trust: pass `public_key` (the key you saved) or `pin_fingerprint` (its fingerprint): "
                    "a list of keys that comes from FIPSign is not trusted by itself"
                ], "pinned",
            )
        return _Trust(pool, problems, "fipsign")

    for k in public_keys:
        if not isinstance(k, str) or k.strip() == "":
            problems.append("`public_key` must be a base64 public key")
            continue
        try:
            trusted[public_key_fingerprint(k)] = k.strip()
        except PQAuthError:
            problems.append("`public_key` is not valid base64")

    pins: List[str] = []
    for p in pins_given:
        text = p.strip() if isinstance(p, str) else ""
        if len(text) != 64 or any(c not in "0123456789abcdefABCDEF" for c in text):
            problems.append("`pin_fingerprint` must be 64 hexadecimal characters (SHA-256 of the public key)")
            continue
        pins.append(text.lower())
    for pin in pins:
        key = pool.get(pin)
        if key is not None:
            trusted[pin] = key
        elif pin not in trusted:
            problems.append(f"no key with fingerprint {pin} among the keys given")
    return _Trust(trusted, problems, "pinned")


# ─── Checks ───────────────────────────────────────────────────────────────────

def _check_seal(seal: Dict[str, Any], trusted: Dict[str, str]) -> Optional[str]:
    """Does the signature of ``seal`` verify, with the key named by its fingerprint, among the trusted keys? None if it does."""
    signed = seal.get("signed")
    signature = seal.get("signature")
    algorithm = seal.get("algorithm")
    fingerprint = seal.get("keyFingerprint")
    if not (isinstance(signed, str) and isinstance(signature, str) and isinstance(algorithm, str) and isinstance(fingerprint, str)):
        return "the signature is not complete: signed, signature, algorithm and keyFingerprint are needed"
    public_key = trusted.get(fingerprint)
    if public_key is None:
        return f"the signing key {fingerprint[:16]}… is not one of the keys you trust"
    class_name = _PUBLIC_KEY_CLASS.get(algorithm)
    if class_name is None:
        return f"unknown algorithm {algorithm}"
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        key_class = getattr(mldsa, class_name)
    except (ImportError, AttributeError):
        return "this check needs the cryptography package, version 48.0.0 or later (pip install -U cryptography)"
    try:
        key_class.from_public_bytes(_b64decode(public_key)).verify(
            _b64decode(signature), _utf8(MANDATE_SIGNING_DOMAIN + signed)
        )
    except Exception:  # noqa: BLE001 - InvalidSignature, a key or a signature of the wrong size, bad base64: all the same answer
        return "the signature does not verify"
    return None


def _parse_statement(signed: Any, kind: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """The statement that was signed, as a dict. It must be exactly the canonical text, of the expected kind. (statement, error)"""
    if not isinstance(signed, str):
        return None, "the signed statement is missing"
    ok, statement = _parse_json(signed)
    if not ok:
        return None, "the signed statement is not JSON"
    if not isinstance(statement, dict) or canonicalize_for_signing(statement) != signed:
        return None, "the signed statement is not in canonical form"
    if not _same(statement.get("v"), 1) or statement.get("kind") != kind:
        return None, f"the statement is not of kind {kind}"
    return statement, None


def _check_event(e: Dict[str, Any], mandate_id: Optional[str]) -> List[str]:
    """One event on its own: its hash is sha256(prevHash + "\\n" + body) and its body says the same as its fields."""
    bad: List[str] = []
    seq = e["seq"]
    if _sha256_hex(f"{e['prevHash']}\n{e['body']}") != e["hash"]:
        bad.append(f'event {seq}: hash is not sha256(prevHash + "\\n" + body)')
    ok, body = _parse_json(e["body"])
    if not ok:
        bad.append(f"event {seq}: body is not JSON")
        return bad
    if not isinstance(body, dict):
        bad.append(f"event {seq}: body is not a JSON object")
        return bad
    if canonicalize_for_signing(body) != e["body"]:
        bad.append(f"event {seq}: body is not canonical JSON")
    if (
        not _same(body.get("v"), 1) or not _same(body.get("seq"), e["seq"]) or not _same(body.get("type"), e["type"])
        or not _same(body.get("at"), e["at"]) or (mandate_id and not _same(body.get("mandateId"), mandate_id))
    ):
        bad.append(f"event {seq}: body does not match the event")
    return bad


def _check_receipt(
    value: Any, trusted: Dict[str, str], expect_project_id: Optional[str], expect_mandate_id: Optional[str]
) -> Tuple[List[str], Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """(problems, projectId, mandateId, event)"""
    raw = value  # the receipt itself: _receipt_input() already took it out of a result object or a {"receipt": ...} answer
    if not isinstance(raw, dict) or not _is_event_shape(raw.get("event")):
        return ["this is not a receipt: it needs signed, signature, algorithm, keyFingerprint and event"], None, None, None
    event: Dict[str, Any] = raw["event"]
    problems: List[str] = []
    seal_error = _check_seal(raw, trusted)
    if seal_error:
        problems.append(seal_error)
    statement, error = _parse_statement(raw.get("signed"), "mandate.receipt")
    if statement is None:
        problems.append(error or "the signed statement is missing")
        return problems, None, None, event
    if not _same(statement.get("seq"), event["seq"]) or not _same(statement.get("hash"), event["hash"]) or not _same(statement.get("at"), event["at"]):
        problems.append("the signed statement is not about the event the receipt carries")
    ok, body = _parse_json(event["body"])  # a body that is not JSON is reported by _check_event
    if not ok or not isinstance(body, dict) or not _same(body.get("mandateId"), statement.get("mandateId")):
        problems.append("the event belongs to another mandate than the one signed")
    mandate_id = statement.get("mandateId") if isinstance(statement.get("mandateId"), str) else None
    project_id = statement.get("projectId") if isinstance(statement.get("projectId"), str) else None
    problems.extend(_check_event(event, mandate_id))
    if expect_project_id is not None and project_id != expect_project_id:
        problems.append(f"the receipt is for project {statement.get('projectId')}, not {expect_project_id}")
    if expect_mandate_id is not None and mandate_id != expect_mandate_id:
        problems.append(f"the receipt is for mandate {statement.get('mandateId')}, not {expect_mandate_id}")
    return problems, project_id, mandate_id, event


def _empty_export_check(trust_problems: List[str], key_trust: str, problems: List[str]) -> MandateExportCheck:
    return MandateExportCheck(valid=False, problems=[*trust_problems, *problems], notes=[], keyTrust=key_trust)


def _check_export(pages: Any, trust: _Trust) -> MandateExportCheck:
    items = list(pages) if isinstance(pages, (list, tuple)) else [pages]
    if len(items) == 0 or not all(
        isinstance(pg, dict) and isinstance(pg.get("events"), list)
        and isinstance(pg.get("projectId"), str) and isinstance(pg.get("mandateId"), str)
        for pg in items
    ):
        return _empty_export_check(
            trust.problems, trust.key_trust,
            ["an export must be the pages returned by mandate.export(), in order: { projectId, mandateId, events, ... }"],
        )
    if not all(_is_event_shape(e) for pg in items for e in pg["events"]):
        return _empty_export_check(trust.problems, trust.key_trust, ["the export holds an entry that is not an event"])

    problems: List[str] = list(trust.problems)
    notes: List[str] = []
    project_id: str = items[0]["projectId"]
    mandate_id: str = items[0]["mandateId"]
    events: List[Dict[str, Any]] = []
    for pg in items:
        if pg["projectId"] != project_id or pg["mandateId"] != mandate_id:
            problems.append("the pages are not all of the same mandate")
        events.extend(pg["events"])
    if len(events) == 0:
        notes.append("the export holds no events")

    # 1. the chain: every event follows the one before it, and is what it says it is
    starts_at_one = len(events) > 0 and events[0]["seq"] == 1
    prev: Optional[str] = MANDATE_GENESIS_HASH if starts_at_one else (events[0]["prevHash"] if events else None)
    if events and not starts_at_one:
        notes.append(f"the export starts at event {events[0]['seq']}: the events before it are not checked")
    for i, e in enumerate(events):
        if i > 0 and e["seq"] != events[i - 1]["seq"] + 1:
            problems.append(f"event {e['seq']} does not follow event {events[i - 1]['seq']}: events are missing")
        if e["prevHash"] != prev:
            problems.append(f"event {e['seq']}: prevHash is not the hash of the event before it")
        problems.extend(_check_event(e, mandate_id))
        prev = e["hash"]
    by_seq = {e["seq"]: e for e in events}

    # 2. the checkpoints: FIPSign's signature over an event in the middle of the chain
    sealed_through = 0
    checkpoints = 0
    for e in (x for x in events if x["type"] == "checkpoint"):
        ok, b = _parse_json(e["body"])
        if not ok or not isinstance(b, dict):
            continue  # reported by _check_event
        covers_seq, covers_hash = b.get("coversSeq"), b.get("coversHash")
        if not _is_int(covers_seq) or not isinstance(covers_hash, str):
            problems.append(f"checkpoint {e['seq']}: it is not well formed")
            continue
        covered = by_seq.get(covers_seq)
        if covered is None:
            notes.append(f"checkpoint {e['seq']} covers event {covers_seq}, which is not in this export")
            continue
        if covered["hash"] != covers_hash:
            problems.append(f"checkpoint {e['seq']}: the event {covers_seq} is not the one FIPSign sealed (the history was changed)")
            continue
        if b.get("projectId") != project_id:
            problems.append(f"checkpoint {e['seq']}: it is for another project")
            continue
        signed = canonicalize_for_signing({
            "v": 1, "kind": "mandate.checkpoint", "projectId": project_id, "mandateId": mandate_id,
            "seq": covers_seq, "hash": covers_hash, "at": b.get("at"),
        })
        error = _check_seal(
            {"signed": signed, "signature": b.get("signature"), "algorithm": b.get("alg"), "keyFingerprint": b.get("keyFp")},
            trust.trusted,
        )
        if error:
            problems.append(f"checkpoint {e['seq']}: {error}")
            continue
        checkpoints += 1
        sealed_through = max(sealed_through, covers_seq)

    # 3. the signed head of the live chain, as it was when the export was made
    head_checked = False
    head: Any = None
    for pg in reversed(items):
        if pg.get("head"):
            head = pg["head"]
            break
    if head is not None and not isinstance(head, dict):
        problems.append("head: it is not well formed")
        head = None
    head_seq = head.get("seq") if head is not None else None
    if head is not None:
        error = _check_seal(head, trust.trusted)
        statement, parse_error = _parse_statement(head.get("signed"), "mandate.export")
        if error:
            problems.append(f"head: {error}")
        elif statement is None:
            problems.append(f"head: {parse_error}")
        else:
            if (
                not _same(statement.get("projectId"), project_id) or not _same(statement.get("mandateId"), mandate_id)
                or not _same(statement.get("seq"), head.get("seq")) or not _same(statement.get("hash"), head.get("hash"))
                or not _same(statement.get("at"), head.get("at"))
            ):
                problems.append("head: the signed statement is not about this mandate and this head")
            at = by_seq.get(head_seq) if _is_int(head_seq) else None
            if at is None:
                notes.append(f"the signed head is event {head.get('seq')}, which is not in this export")
            elif at["hash"] != head.get("hash"):
                problems.append(f"head: the event {head.get('seq')} in the export is not the one FIPSign holds (the history was changed)")
            else:
                head_checked = True

    last_seq = events[-1]["seq"] if events else 0
    last_is_checkpoint = bool(events) and events[-1]["type"] == "checkpoint"
    last_page = items[-1]
    last_page_is_last = last_page.get("nextAfter", _MISSING) is None
    # The last page says there is nothing after it, but the signed head is further on: the end of the chain was cut off.
    if head is not None and last_page_is_last and _is_int(head_seq) and head_seq > last_seq:
        problems.append(f"head: FIPSign holds events up to {head_seq}, the export ends at {last_seq}: events are missing at the end")
    return MandateExportCheck(
        valid=len(problems) == 0, problems=problems, notes=notes, keyTrust=trust.key_trust,
        projectId=project_id, mandateId=mandate_id, events=len(events), lastSeq=last_seq, checkpoints=checkpoints,
        sealedThrough=sealed_through, headChecked=head_checked,
        complete=bool(events) and starts_at_one and last_is_checkpoint and sealed_through == last_seq - 1 and last_page_is_last,
    )


def _export_key_candidates(pages: Any) -> List[Any]:
    """What the pages of an export say about their keys: the candidates a pinned fingerprint can be found among."""
    out: List[Any] = []
    for pg in (list(pages) if isinstance(pages, (list, tuple)) else [pages]):
        if isinstance(pg, dict) and isinstance(pg.get("publicKeys"), list):
            out.extend(pg["publicKeys"])
    return out


def _receipt_input(value: Any) -> Any:
    """The receipt out of what the caller passed: the receipt, its dict, or the result object it came with."""
    if isinstance(value, dict):
        inner = _as_dict(value.get("receipt"))
        return inner if isinstance(inner, dict) else value
    if callable(getattr(value, "to_dict", None)) and not isinstance(value, type):
        return _as_dict(value)
    return _as_dict(getattr(value, "receipt", None))  # MandateEmitResult, MandatePatchResult, MandateVerifyResult


# The two checks behind the public functions. ``candidates`` are the keys that come from FIPSign (mandate.public_keys(), the
# pages of an export); ``fallback`` says what happens when the caller gave neither ``public_key`` nor ``pin_fingerprint``.

def _run_receipt_check(
    receipt: Any,
    public_key: KeyInput,
    pin_fingerprint: KeyInput,
    keys: Any,
    expect_project_id: Optional[str],
    expect_mandate_id: Optional[str],
    candidates: Sequence[Any],
    fallback: str,
) -> MandateReceiptCheck:
    key_trust = "pinned"
    try:
        trust = _resolve_trust(public_key, pin_fingerprint, keys, candidates, fallback)
        key_trust = trust.key_trust
        if len(trust.trusted) == 0:
            return MandateReceiptCheck(
                valid=False, keyTrust=key_trust,
                problems=trust.problems or ["there is no key to check the receipt with"],
            )
        problems, project_id, mandate_id, event = _check_receipt(
            _receipt_input(receipt), trust.trusted, expect_project_id, expect_mandate_id
        )
        problems = [*trust.problems, *problems]
        return MandateReceiptCheck(
            valid=len(problems) == 0, problems=problems, keyTrust=key_trust, projectId=project_id, mandateId=mandate_id,
            event=MandateEvent(
                seq=event["seq"], type=event["type"], at=event["at"],
                prevHash=event["prevHash"], hash=event["hash"], body=event["body"],
            ) if event is not None else None,
        )
    except Exception as exc:  # noqa: BLE001 - verify_mandate_receipt() never raises
        return MandateReceiptCheck(
            valid=False, keyTrust=key_trust,
            problems=[f"the receipt could not be checked: {str(exc) or type(exc).__name__}"],
        )


def _run_export_check(
    pages: Any, public_key: KeyInput, pin_fingerprint: KeyInput, keys: Any, fallback: str
) -> MandateExportCheck:
    key_trust = "pinned"
    try:
        pages = [_as_dict(p) for p in pages] if isinstance(pages, (list, tuple)) else _as_dict(pages)
        trust = _resolve_trust(public_key, pin_fingerprint, keys, _export_key_candidates(pages), fallback)
        key_trust = trust.key_trust
        if len(trust.trusted) == 0:
            return MandateExportCheck(
                valid=False, keyTrust=key_trust, notes=[],
                problems=trust.problems or ["there is no key to check the export with"],
            )
        return _check_export(pages, trust)
    except Exception as exc:  # noqa: BLE001 - verify_mandate_export() never raises
        return MandateExportCheck(
            valid=False, keyTrust=key_trust, notes=[],
            problems=[f"the export could not be checked: {str(exc) or type(exc).__name__}"],
        )


# ─── Public functions ─────────────────────────────────────────────────────────

def verify_mandate_receipt(
    receipt: Any,
    *,
    public_key: KeyInput = None,
    pin_fingerprint: KeyInput = None,
    keys: Any = None,
    expect_project_id: Optional[str] = None,
    expect_mandate_id: Optional[str] = None,
) -> MandateReceiptCheck:
    """
    Check a Mandate receipt on your own machine: the signature, the event it covers and its hash. **Never raises** and
    sends nothing anywhere: ``valid`` is True only if everything checks out, and ``problems`` says what did not.

    ``receipt`` is what mandate.emit(), the change calls or mandate.verify(receipt=True) returned: the ``receipt`` of the
    result (a MandateReceipt), what ``receipt.to_dict()`` gave and you stored as JSON, or the whole result. Keep the
    receipts you care about: each one commits to the whole history of the mandate up to its event, so the history cannot
    be rewritten later without the receipt showing it.

    Say which key to trust with ``public_key`` (the key you saved) or with ``pin_fingerprint`` (its fingerprint) together
    with ``keys`` (for example ``pq.mandate.public_keys().keys``: it lists the keys the project had before a rotation too).
    A receipt made with a key you did not give fails. Without either, nothing is trusted and the check fails:
    ``pq.mandate.verify_receipt()`` checks against the keys FIPSign lists when you give nothing.

    Parameters
    ----------
    receipt : MandateReceipt | dict | result object
    public_key : str | list[str], optional
        Public key(s), base64, that you trust: what GET /public-key returned when you integrated.
    pin_fingerprint : str | list[str], optional
        Fingerprint(s) you saved (public_key_fingerprint() of the key). The key itself is taken from ``keys`` and accepted
        only if its own fingerprint is the pinned one. Pin one fingerprint per key you trust.
    keys : list, optional
        Candidate keys (for example ``pq.mandate.public_keys().keys``): only those whose fingerprint you pinned are trusted.
    expect_project_id, expect_mandate_id : str, optional
        Fail unless the receipt is for this project / this mandate.

    Returns
    -------
    MandateReceiptCheck
        .valid, .problems, .keyTrust ("pinned"), .projectId, .mandateId, .event

    Examples
    --------
    >>> result = pq.mandate.suspend(mandate_id, correlation_id="ticket-4821")
    >>> # later, wherever you keep it:
    >>> check = verify_mandate_receipt(result.receipt, public_key=SAVED_PUBLIC_KEY)
    >>> if not check.valid:
    ...     print(check.problems)
    """
    return _run_receipt_check(
        receipt, public_key, pin_fingerprint, keys, expect_project_id, expect_mandate_id, [], "strict"
    )


def verify_mandate_export(
    pages: Any,
    *,
    public_key: KeyInput = None,
    pin_fingerprint: KeyInput = None,
    keys: Any = None,
) -> MandateExportCheck:
    """
    Check the audit log of a mandate, as mandate.export_all() returns it, on your own machine: every event follows the one
    before it and is what it says it is; the checkpoints (FIPSign's signature over an event in the middle of the chain)
    and the signed head of the log verify; and no event was left out or changed. **Never raises** and sends nothing anywhere.

    ``pages`` are the pages of the export, in order (a list, or one page); stored pages (dicts loaded from JSON) work too.
    Say which key to trust with ``public_key`` or with ``pin_fingerprint``: the keys then come from the export itself
    (``publicKeys``: it lists the keys the project had before a rotation too) and a key is accepted only if its own
    fingerprint is the one you pinned. Without either, nothing is trusted and the check fails:
    ``pq.mandate.verify_export()`` checks against the keys of the export when you give nothing.

    ``complete`` says whether the log starts at event 1 and ends in a checkpoint that seals everything before it. A log that
    is ``valid`` but not ``complete`` has events at its end that only the signed head (or a receipt you hold) protects.

    Returns
    -------
    MandateExportCheck
        .valid, .problems, .notes, .keyTrust, .projectId, .mandateId, .events, .lastSeq, .checkpoints,
        .sealedThrough, .headChecked, .complete

    Examples
    --------
    >>> pages = pq.mandate.export_all(mandate_id)
    >>> check = verify_mandate_export(pages, pin_fingerprint=SAVED_FINGERPRINT)
    >>> if not check.valid:
    ...     print(check.problems)
    """
    return _run_export_check(pages, public_key, pin_fingerprint, keys, "strict")

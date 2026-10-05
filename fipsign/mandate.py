"""
Mandate sub-client — mirrors pq.mandate.* from the JS SDK.
Accessed via pq.mandate.emit(...), pq.mandate.verify(...), etc.

Bounded, revocable authorization for AI agents, IoT devices, and automated
services. A mandate has two layers:

  Immutable layer — covered by the ML-DSA signature: agent_id, issued_by,
                     scope (original), budget_total, expires_at. Cannot be
                     altered — any change invalidates the signature.
  Mutable layer   — stored server-side, not covered by the signature:
                     scope (current), budget_consumed, status. Can be
                     updated at any time via narrow()/suspend()/resume()/
                     revoke() without invalidating the token.

By default a mandate is a bearer credential: whoever holds the token and an API
key of your project can use it. Pass ``agent_public_key`` to emit() and every
verify() must also carry an ``agent_signature`` made with the agent's private key
(proof of possession) — see fipsign/agent.py for generate_agent_key_pair() and
sign_agent_call().

See the Mandate section of the developer guide for the full explanation of
the lifecycle and budget semantics: https://fipsign.dev/guide (Python tab,
"mandate" — same REST contract, no dashboard setup needed beyond an API key).

Usage
-----
pq = PQAuth("pqa_your_key")

result = pq.mandate.emit(
    agent_id="agent-reporting-v2",
    issued_by="user@empresa.com",
    scope=["sign", "verify", "read:crm"],
    budget_total=1000,
    expires_in_seconds=28800,
)
token = result.mandate.token  # give this to the agent — not stored server-side

check = pq.mandate.verify(token, "sign", 1)
if check.result != "granted":
    raise PermissionError(check.reason)

Everything that happens to a mandate is also kept as a signed log: emit(), the change calls and verify(receipt=True)
return a ``receipt``, events()/query_events()/export() read the log, and verify_mandate_receipt() / verify_mandate_export()
(fipsign/mandate_audit.py) check them on your own machine.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import quote, urlencode

from .errors import PQAuthError
from .mandate_audit import _as_list, _is_event_shape, _is_int, _run_export_check, _run_receipt_check
from .utils import parse_retry_after
from .types import (
    Mandate as MandateState,
    MandateEmitMandate,
    MandateEmitResult,
    MandateEmitUsage,
    MandateEvent,
    MandateEventsQueryResult,
    MandateEventsResult,
    MandateExportCheck,
    MandateExportHead,
    MandateExportPage,
    MandateGetResult,
    MandateListResult,
    MandateLogHead,
    MandatePatchResult,
    MandateProjectEvent,
    MandatePublicKey,
    MandatePublicKeysResult,
    MandateReceipt,
    MandateReceiptCheck,
    MandateVerifyFailure,
    MandateVerifyResult,
    PQToken,
    _parse_mandate,
)

if TYPE_CHECKING:
    from .client import PQAuth


# ─── Helpers shared with the async client (AsyncMandate) ─────────────────────
# Everything that does not touch the network lives here, so the sync and async
# clients cannot drift apart.

def _mandate_path(mandate_id: str) -> str:
    """
    ``/mandate/<id>`` with the id escaped so it can only ever be ONE path segment.
    Without it an id like ``../usage`` would call a different endpoint.

    ``.`` and ``..`` survive escaping (they are not special characters) and HTTP
    clients and servers resolve them as "this folder" / "the parent folder", so
    they are refused here, together with an empty id. No mandate id looks like that.
    """
    if not isinstance(mandate_id, str) or mandate_id.strip() in ("", ".", ".."):
        raise PQAuthError('"mandate_id" must be the id of a mandate (mdt_...)', "INVALID_ARGUMENT")
    return "/mandate/" + quote(mandate_id, safe="")


def _list_path(limit: Optional[int], cursor: Optional[str]) -> str:
    params: List[Tuple[str, str]] = []
    if limit is not None:
        params.append(("limit", str(limit)))
    if cursor is not None:
        params.append(("cursor", cursor))
    return "/mandate" + ("?" + urlencode(params) if params else "")


def _parse_usage(u: Any) -> Optional[MandateEmitUsage]:
    """Reads the known fields of a ``usage`` object; ignores any extra one."""
    if not isinstance(u, dict):
        return None
    try:
        return MandateEmitUsage(
            freeRemaining=u["freeRemaining"],
            packRemaining=u["packRemaining"],
            totalRemaining=u["totalRemaining"],
            month=u["month"],
        )
    except KeyError:
        return None


def _emit_body(
    agent_id: str,
    issued_by: str,
    scope: List[str],
    budget_total: int,
    expires_in_seconds: int,
    agent_public_key: Optional[str],
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "agentId": agent_id,
        "issuedBy": issued_by,
        "scope": scope,
        "budgetTotal": budget_total,
        "expiresInSeconds": expires_in_seconds,
    }
    if agent_public_key is not None:
        body["agentPublicKey"] = agent_public_key
    if correlation_id is not None:
        body["correlationId"] = correlation_id
    return body


def _parse_emit_result(data: Dict[str, Any]) -> MandateEmitResult:
    m = data["mandate"]
    u = data["usage"]
    t = m["token"]
    return MandateEmitResult(
        mandate=MandateEmitMandate(
            id=m["id"],
            agentId=m["agentId"],
            issuedBy=m["issuedBy"],
            scope=m["scope"],
            budgetTotal=m["budgetTotal"],
            expiresAt=m["expiresAt"],
            status=m["status"],
            token=PQToken(
                payload=t["payload"],
                signature=t["signature"],
                algorithm=t["algorithm"],
                issuedAt=t["issuedAt"],
            ),
            requiresAgentSignature=bool(m.get("requiresAgentSignature", False)),
        ),
        usage=MandateEmitUsage(
            freeRemaining=u["freeRemaining"],
            packRemaining=u["packRemaining"],
            totalRemaining=u["totalRemaining"],
            month=u["month"],
        ),
        receipt=_parse_receipt(data.get("receipt")),
    )


def _token_dict(value: Any) -> Optional[Dict[str, Any]]:
    """A PQToken (or an already-plain dict) as the dict the API expects; None if it is neither."""
    if isinstance(value, PQToken):
        return value.to_dict()
    if isinstance(value, dict):
        return value
    return None


def _verify_body(
    token: PQToken,
    action: str,
    cost: int,
    agent_signature: Optional[PQToken],
    receipt: bool = False,
    correlation_id: Optional[str] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    The body of POST /mandate/verify, or (None, reason) when ``token`` or
    ``agent_signature`` is not something the API could accept — verify() never
    raises, so the caller turns that reason into a denied result.
    """
    token_d = _token_dict(token)
    if token_d is None:
        return None, '"token" must be the PQToken returned by mandate.emit()'
    body: Dict[str, Any] = {"token": token_d, "action": action, "cost": cost}
    if agent_signature is not None:
        sig_d = _token_dict(agent_signature)
        if sig_d is None:
            return None, '"agent_signature" must be the PQToken returned by sign_agent_call()'
        body["agentSignature"] = sig_d
    if receipt is True:
        body["receipt"] = True
    if correlation_id is not None:
        body["correlationId"] = correlation_id
    return body, None


def _failure_of(
    status_code: int, data: Any, retry_after: Optional[int]
) -> Tuple[MandateVerifyFailure, Optional[int]]:
    """
    What a POST /mandate/verify answer that is not "granted" or "denied" means.

    FIPSign consumes nothing on a denial (403), a malformed request (400), an invalid API key
    (401), an unsupported content type (415) or a 429, so any other 4xx is the same. Anything
    else (a 5xx, or a status that should not happen) may have come after the call was applied:
    "outcome_unknown". Returns (failure, retry_after).
    """
    body = data if isinstance(data, dict) else {}
    if status_code == 429:
        if body.get("code") == "token_quota_exhausted":
            return "quota_exhausted", None
        return "rate_limited", retry_after
    if status_code == 400:
        return "rejected", None
    if 400 <= status_code < 500:
        return "unavailable", None
    return "outcome_unknown", None


def _parse_verify_response(
    status_code: int, data: Any, retry_after: Optional[int] = None
) -> MandateVerifyResult:
    if isinstance(data, dict) and data.get("result") in ("granted", "denied"):
        return MandateVerifyResult(
            result=data["result"],
            reason=data.get("reason"),
            actionMatched=data.get("actionMatched"),
            budgetRemaining=data.get("budgetRemaining"),
            expiresInSeconds=data.get("expiresInSeconds"),
            authorizedScope=data.get("authorizedScope"),
            budgetConsumedUnits=data.get("budgetConsumedUnits"),
            budgetTotalUnits=data.get("budgetTotalUnits"),
            usage=_parse_usage(data.get("usage")),
            failure="rejected" if data["result"] == "denied" else None,
            receipt=_parse_receipt(data.get("receipt")),
        )

    # Failures that never reach mandate-specific logic (invalid/missing
    # API key, rate limit, malformed body) come back through the generic
    # errorResponse() shape — {"success": False, "error": ...} — with no
    # "result" field at all. Normalize those into the same denied shape
    # instead of silently dropping the real error message.
    error = data.get("error") if isinstance(data, dict) else None
    failure, wait = _failure_of(status_code, data, retry_after)
    return MandateVerifyResult(
        result="denied",
        reason=error or f"Request failed with status {status_code}",
        failure=failure,
        retry_after=wait,
    )


def _parse_list_result(data: Dict[str, Any]) -> MandateListResult:
    mandates = [_parse_mandate(m) for m in data["mandates"]]
    count = data.get("count")
    return MandateListResult(
        mandates=mandates,
        count=count if isinstance(count, int) else len(mandates),
        nextCursor=data.get("nextCursor"),
    )


def _change_body(action: str, correlation_id: Optional[str], **extra: Any) -> Dict[str, Any]:
    """The body of a PATCH /mandate/<id>: the action, what it needs, and ``correlationId`` only when it was given."""
    body: Dict[str, Any] = {"action": action, **extra}
    if correlation_id is not None:
        body["correlationId"] = correlation_id
    return body


def _parse_patch_result(data: Dict[str, Any], with_message: bool = False) -> MandatePatchResult:
    """Shared by narrow(), suspend(), resume() and revoke(). Only suspend() reads ``message``."""
    return MandatePatchResult(
        id=data["id"],
        status=data["status"],
        scope=data.get("scope"),
        updatedAt=data.get("updatedAt"),
        message=data.get("message") if with_message else None,
        receipt=_parse_receipt(data.get("receipt")),
    )


# ─── Audit: paths and answers ────────────────────────────────────────────────

def _malformed(what: str) -> PQAuthError:
    return PQAuthError(f"The API answered with something this SDK cannot read ({what})", "API_ERROR")


def _query_string(pairs: List[Tuple[str, Any]]) -> str:
    """``?a=1&b=2`` of the pairs whose value is not None; empty when none is."""
    given = [(name, str(value)) for name, value in pairs if value is not None]
    return "?" + urlencode(given) if given else ""


def _events_path(mandate_id: str, after: Optional[int], limit: Optional[int]) -> str:
    return _mandate_path(mandate_id) + "/events" + _query_string([("after", after), ("limit", limit)])


def _export_path(mandate_id: str, after: Optional[int], limit: Optional[int]) -> str:
    return _mandate_path(mandate_id) + "/export" + _query_string([("after", after), ("limit", limit)])


def _query_events_path(
    mandate_id: Optional[str],
    type: Optional[str],
    action: Optional[str],
    key_id: Optional[str],
    correlation_id: Optional[str],
    trace_id: Optional[str],
    from_: Optional[int],
    to: Optional[int],
    limit: Optional[int],
    cursor: Optional[str],
) -> str:
    return "/mandate/events" + _query_string([
        ("mandateId", mandate_id), ("type", type), ("action", action), ("keyId", key_id),
        ("correlationId", correlation_id), ("traceId", trace_id), ("from", from_), ("to", to),
        ("limit", limit), ("cursor", cursor),
    ])


def _parse_event(e: Any) -> MandateEvent:
    if not _is_event_shape(e):
        raise _malformed("event")
    return MandateEvent(seq=e["seq"], type=e["type"], at=e["at"], prevHash=e["prevHash"], hash=e["hash"], body=e["body"])


def _parse_project_event(e: Any) -> MandateProjectEvent:
    if not _is_event_shape(e) or not isinstance(e.get("mandateId"), str):
        raise _malformed("event")
    return MandateProjectEvent(
        seq=e["seq"], type=e["type"], at=e["at"], prevHash=e["prevHash"], hash=e["hash"], body=e["body"],
        mandateId=e["mandateId"],
    )


def _parse_receipt(r: Any) -> Optional[MandateReceipt]:
    """
    The receipt of an answer, or None if there is none. It never raises: the call the receipt came with has already
    happened (and may have been charged), so an answer whose receipt cannot be read is still an answer.
    """
    if not isinstance(r, dict) or not _is_event_shape(r.get("event")):
        return None
    signed, signature, algorithm, fingerprint = r.get("signed"), r.get("signature"), r.get("algorithm"), r.get("keyFingerprint")
    if not (isinstance(signed, str) and isinstance(signature, str) and isinstance(algorithm, str) and isinstance(fingerprint, str)):
        return None
    return MandateReceipt(
        signed=signed, signature=signature, algorithm=algorithm, keyFingerprint=fingerprint, event=_parse_event(r["event"]),
    )


def _parse_public_key(k: Any) -> MandatePublicKey:
    if not (
        isinstance(k, dict) and isinstance(k.get("fingerprint"), str) and isinstance(k.get("algorithm"), str)
        and isinstance(k.get("publicKey"), str) and isinstance(k.get("status"), str) and _is_int(k.get("recordedAt"))
        and (k.get("retiredAt") is None or _is_int(k.get("retiredAt")))
    ):
        raise _malformed("public key")
    return MandatePublicKey(
        fingerprint=k["fingerprint"], algorithm=k["algorithm"], publicKey=k["publicKey"], status=k["status"],
        recordedAt=k["recordedAt"], retiredAt=k.get("retiredAt"),
    )


def _parse_public_keys_result(data: Any) -> MandatePublicKeysResult:
    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise _malformed("public keys")
    keys = [_parse_public_key(k) for k in data["keys"]]
    count = data.get("count")
    return MandatePublicKeysResult(
        projectId=data["projectId"] if isinstance(data.get("projectId"), str) else "",
        keys=keys,
        count=count if _is_int(count) else len(keys),
    )


def _next_position(data: Dict[str, Any], name: str, kind: str) -> Any:
    """``nextAfter`` / ``nextCursor``: required (a loop is driven by it), either a position or None."""
    if name not in data:
        raise _malformed(name)
    value = data[name]
    if value is not None and not (_is_int(value) if kind == "int" else isinstance(value, str)):
        raise _malformed(name)
    return value


def _parse_events_result(data: Any, mandate_id: str) -> MandateEventsResult:
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise _malformed("events")
    events = [_parse_event(e) for e in data["events"]]
    h = data.get("head")
    head = (
        MandateLogHead(seq=h["seq"], hash=h["hash"], lastCheckpointSeq=h["lastCheckpointSeq"])
        if isinstance(h, dict) and _is_int(h.get("seq")) and isinstance(h.get("hash"), str) and _is_int(h.get("lastCheckpointSeq"))
        else None
    )
    count = data.get("count")
    return MandateEventsResult(
        mandateId=data["mandateId"] if isinstance(data.get("mandateId"), str) else mandate_id,
        events=events,
        count=count if _is_int(count) else len(events),
        nextAfter=_next_position(data, "nextAfter", "int"),
        head=head,
    )


def _parse_events_query_result(data: Any) -> MandateEventsQueryResult:
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise _malformed("events")
    events = [_parse_project_event(e) for e in data["events"]]
    count = data.get("count")
    return MandateEventsQueryResult(
        events=events,
        count=count if _is_int(count) else len(events),
        nextCursor=_next_position(data, "nextCursor", "str"),
        from_=data["from"] if _is_int(data.get("from")) else None,
        to=data["to"] if _is_int(data.get("to")) else None,
    )


def _parse_export_head(h: Any) -> Optional[MandateExportHead]:
    if h is None:
        return None
    if not (
        isinstance(h, dict) and _is_int(h.get("seq")) and isinstance(h.get("hash"), str) and _is_int(h.get("at"))
        and isinstance(h.get("signed"), str) and isinstance(h.get("signature"), str)
        and isinstance(h.get("algorithm"), str) and isinstance(h.get("keyFingerprint"), str)
    ):
        raise _malformed("head")
    return MandateExportHead(
        seq=h["seq"], hash=h["hash"], at=h["at"],
        source=h["source"] if isinstance(h.get("source"), str) else "live",
        lastCheckpointSeq=h["lastCheckpointSeq"] if _is_int(h.get("lastCheckpointSeq")) else 0,
        signed=h["signed"], signature=h["signature"], algorithm=h["algorithm"], keyFingerprint=h["keyFingerprint"],
    )


def _parse_export_page(data: Any) -> MandateExportPage:
    if not (
        isinstance(data, dict) and isinstance(data.get("projectId"), str) and isinstance(data.get("mandateId"), str)
        and isinstance(data.get("events"), list)
    ):
        raise _malformed("export")
    events = [_parse_event(e) for e in data["events"]]
    keys = data.get("publicKeys")
    count = data.get("count")
    return MandateExportPage(
        format=data["format"] if isinstance(data.get("format"), str) else "",
        projectId=data["projectId"],
        mandateId=data["mandateId"],
        generatedAt=data["generatedAt"] if _is_int(data.get("generatedAt")) else 0,
        events=events,
        count=count if _is_int(count) else len(events),
        nextAfter=_next_position(data, "nextAfter", "int"),
        head=_parse_export_head(data.get("head")),
        publicKeys=[_parse_public_key(k) for k in keys] if isinstance(keys, list) else [],
    )


# ─── MandateClient ───────────────────────────────────────────────────────────

class MandateClient:
    """
    Mandate sub-client. See module docstring for the full explanation.

    Named MandateClient (not Mandate) to avoid colliding with the
    ``Mandate`` entity dataclass in types.py — the same naming situation
    doesn't arise for ``ca``/``zes`` since neither has a same-named entity
    type. Accessed as ``pq.mandate``, never instantiated directly.
    """

    def __init__(self, client: "PQAuth") -> None:
        self._client = client

    # ── emit() ───────────────────────────────────────────────────────────────

    def emit(
        self,
        agent_id: str,
        issued_by: str,
        scope: List[str],
        budget_total: int,
        expires_in_seconds: int,
        agent_public_key: Optional[str] = None,
        *,
        correlation_id: Optional[str] = None,
    ) -> MandateEmitResult:
        """
        Issue a new mandate. Cost: 2 tokens.

        Parameters
        ----------
        agent_id : str
            Identifier for the agent, device, or service. Max 128 chars.
            Covered by the ML-DSA signature — immutable after emission.
        issued_by : str
            Who authorized this mandate (email, user ID, system name).
            Max 256 chars. Covered by the signature — immutable.
        scope : list[str]
            Actions the agent is authorized to perform. 1-20 items, each
            max 64 chars. Duplicates are removed automatically. Covered
            by the signature as the original scope — immutable; narrow it
            later with narrow(), which is monotonic (cannot re-widen).
        budget_total : int
            Maximum budget units. Abstract — you define what a unit means
            (dollars, API calls, credits...). ``0`` disables budget
            checking entirely. Covered by the signature — immutable.
        expires_in_seconds : int
            Mandate lifetime. Min 60 (1 minute), max 2_592_000 (30 days).
        agent_public_key : str, optional
            The agent's public key (``publicKey`` from
            generate_agent_key_pair(), base64). With it the mandate is no longer
            a pure bearer credential: every verify() must carry an
            ``agent_signature`` made with the matching private key, which never
            leaves the agent. Without it the mandate works as a bearer token,
            exactly as before. It cannot be added to a mandate later.
        correlation_id : str, optional
            Your own id for this call (a ticket, a request id): 1 to 128 characters, no control characters. It is
            written inside the audit event, so the receipt covers it, and you can find the event with it
            (query_events(correlation_id=...)).

        Returns
        -------
        MandateEmitResult
            .mandate — id, agentId, issuedBy, scope, budgetTotal,
                       expiresAt, status, token, requiresAgentSignature
            .usage   — token balance after the operation
            .receipt — FIPSign's signature over the event "emitted" (MandateReceipt): keep it

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If any field violates its limits, or ``agent_public_key`` is not
            the base64 of an ML-DSA public key (1312, 1952 or 2592 bytes).

        Examples
        --------
        >>> result = pq.mandate.emit(
        ...     agent_id="agent-reporting-v2",
        ...     issued_by="user@empresa.com",
        ...     scope=["sign", "verify", "read:crm"],
        ...     budget_total=1000,
        ...     expires_in_seconds=28800,
        ... )
        >>> mandate_id = result.mandate.id
        >>> token = result.mandate.token  # give this to the agent

        With proof of possession:

        >>> kp = generate_agent_key_pair()           # where the agent lives
        >>> result = pq.mandate.emit(..., agent_public_key=kp.publicKey)
        >>> result.mandate.requiresAgentSignature
        True
        """
        body = _emit_body(
            agent_id, issued_by, scope, budget_total, expires_in_seconds, agent_public_key, correlation_id
        )
        data = self._client._request("POST", "/mandate", json=body)
        return _parse_emit_result(data)

    # ── verify() ─────────────────────────────────────────────────────────────

    def verify(
        self,
        token: PQToken,
        action: str,
        cost: int,
        *,
        agent_signature: Optional[PQToken] = None,
        receipt: bool = False,
        correlation_id: Optional[str] = None,
    ) -> MandateVerifyResult:
        """
        Check whether ``action`` is authorized right now — signature,
        expiry, status, scope, and remaining budget, all in one atomic
        server-side check.

        **Never raises.** Every failure — including a denied check and an
        invalid API key — comes back as a MandateVerifyResult with
        result="denied", never an exception.

        ``failure`` tells a denial FIPSign decided ("rejected", "rate_limited",
        "quota_exhausted", "unavailable": nothing was consumed, repeating the
        call is safe) from "outcome_unknown" (timeout, network failure, an
        answer that could not be read, a server error: the call MAY have been
        granted and charged without you hearing about it; see
        MandateVerifyFailure for what to do). Decide on ``failure``, not on the
        text of ``reason``. A call that is not granted is always
        result="denied", so code that only checks ``result != "granted"``
        never acts on a call that may not have been granted. The SDK never
        repeats a call by itself: FIPSign does not recognise a repeated request.

        There is no local/offline mode for mandate verification, unlike
        pq.verify(): budget and scope are live, mutable state that can
        only be checked against the server, not the signature alone.

        Parameters
        ----------
        token : PQToken
            The token from mandate.emit().
        action : str
            The action to check against the mandate's current scope.
        cost : int
            Budget units this action would consume if granted. Only
            billed (2 API tokens) when the result is "granted" — a
            denied check is always free.
        agent_signature : PQToken, optional
            Required when the mandate was emitted with an ``agent_public_key``
            (``Mandate.requiresAgentSignature`` is True): the agent's signature
            from sign_agent_call(), made for this exact mandate, action and cost.
            It is single-use — a granted call uses it up — so sign again for
            every call. Without it such a mandate is denied with
            ``agent_signature_required``.
        receipt : bool, optional
            ``True`` asks FIPSign for its signature over the event this call produced (``receipt`` of the result),
            granted or denied. Signing takes a little time, so it is off by default: ask for it on the calls you may
            have to prove later.
        correlation_id : str, optional
            Your own id for this call: written inside the audit event, so the receipt covers it, and usable as a filter
            (query_events(correlation_id=...)).

        Returns
        -------
        MandateVerifyResult
            .result — "granted" | "denied"
            .reason — set when denied: "scope_not_authorized" |
                      "budget_exhausted" | "mandate_suspended" |
                      "mandate_revoked" | "mandate_expired" |
                      "invalid_signature" | "agent_signature_required" |
                      "agent_signature_invalid" | "agent_signature_mismatch" |
                      "agent_signature_replayed", or the real backend error
                      message (e.g. invalid API key)
            .budgetRemaining, .expiresInSeconds — set when granted
            .authorizedScope — set when denied for scope_not_authorized
            .budgetConsumedUnits, .budgetTotalUnits — set when denied
                      for budget_exhausted
            .failure — set when denied: "rejected" | "rate_limited" |
                      "quota_exhausted" | "unavailable" | "outcome_unknown"
            .retry_after — seconds to wait, only with failure="rate_limited"
            .receipt — only with ``receipt=True``, and only when FIPSign recorded the call
                      (granted, or denied by a mandate check): a MandateReceipt

        Examples
        --------
        >>> check = pq.mandate.verify(token, "send_reply", 1)
        >>> if check.result != "granted":
        ...     raise PermissionError(check.reason)

        With proof of possession:

        >>> sig = sign_agent_call(token, "send_reply", 1, kp.secretKey, algorithm=kp.algorithm)
        >>> check = pq.mandate.verify(token, "send_reply", 1, agent_signature=sig)
        """
        body, problem = _verify_body(token, action, cost, agent_signature, receipt, correlation_id)
        if body is None:
            return MandateVerifyResult(result="denied", reason=problem, failure="rejected")

        try:
            resp = self._client._session.request(
                "POST",
                f"{self._client._base_url}/mandate/verify",
                json=body,
                timeout=self._client._timeout,
            )
        except Exception as exc:
            # No usable answer (timeout, network, an answer that broke off): the call may have been applied.
            return MandateVerifyResult(
                result="denied", reason=f"Network error: {exc}", failure="outcome_unknown"
            )

        try:
            data = resp.json()
        except ValueError:
            data = None  # not JSON: _parse_verify_response() decides from the status alone

        # Deliberately NOT using self._client._request() here: a "denied"
        # result is a normal, expected outcome carrying real data (reason,
        # authorizedScope, budgetConsumedUnits, budgetTotalUnits) in a 403
        # response — not an error to raise. _request() only forwards a
        # generic `error` field on failure, which this endpoint doesn't
        # use, so those fields would be lost if we let it raise.
        return _parse_verify_response(
            resp.status_code, data, parse_retry_after(resp.headers.get("Retry-After"))
        )

    # ── narrow() / suspend() / resume() / revoke() ──────────────────────────

    def narrow(
        self, mandate_id: str, scope: List[str], *, correlation_id: Optional[str] = None
    ) -> MandatePatchResult:
        """
        Permanently shrink a mandate's scope to a subset of its current
        scope. Monotonic — cannot be reversed, and cannot re-widen toward
        the original scope. To restore scope, emit a new mandate.

        Free — no token cost. ``correlation_id`` (your own id for this call, 1 to 128
        characters) is written inside the audit event; the result carries a ``receipt``.

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If scope is not a subset of the current scope, or is empty.
        PQAuthError(code="API_ERROR", status=409)
            If the mandate has been revoked.

        Examples
        --------
        >>> pq.mandate.narrow(mandate_id, ["read:crm"])
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json=_change_body("narrow", correlation_id, scope=scope)
        )
        return _parse_patch_result(data)

    def suspend(self, mandate_id: str, *, correlation_id: Optional[str] = None) -> MandatePatchResult:
        """
        Temporarily pause a mandate. verify() will deny with
        reason="mandate_suspended" while suspended — checked before
        budget on the backend, so a suspended mandate is always denied
        for suspension even if it also happens to be out of budget.

        Free — no token cost. Idempotent — calling suspend() on an
        already-suspended mandate returns success with
        message="Already suspended" instead of raising (and with no receipt:
        nothing changed). ``correlation_id`` is your own id for this call.

        Examples
        --------
        >>> pq.mandate.suspend(mandate_id)
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json=_change_body("suspend", correlation_id)
        )
        return _parse_patch_result(data, with_message=True)

    def resume(self, mandate_id: str, *, correlation_id: Optional[str] = None) -> MandatePatchResult:
        """
        Reactivate a suspended mandate. Free — no token cost.
        ``correlation_id`` is your own id for this call.

        Raises
        ------
        PQAuthError(code="API_ERROR", status=409)
            If the mandate is not currently suspended.

        Examples
        --------
        >>> pq.mandate.resume(mandate_id)
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json=_change_body("resume", correlation_id)
        )
        return _parse_patch_result(data)

    def revoke(self, mandate_id: str, *, correlation_id: Optional[str] = None) -> MandatePatchResult:
        """
        Permanently terminate a mandate. Irreversible — no narrow(),
        suspend(), or resume() will succeed after this.

        Free — no token cost. ``correlation_id`` is your own id for this call.

        Examples
        --------
        >>> pq.mandate.revoke(mandate_id)
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json=_change_body("revoke", correlation_id)
        )
        return _parse_patch_result(data)

    # ── get() / list() / list_all() ──────────────────────────────────────────

    def get(self, mandate_id: str) -> MandateGetResult:
        """
        Get a mandate's current state by id. Free — no token cost.

        Examples
        --------
        >>> result = pq.mandate.get(mandate_id)
        >>> print(result.mandate.budgetConsumed, result.mandate.status)
        """
        data = self._client._request("GET", _mandate_path(mandate_id))
        return MandateGetResult(mandate=_parse_mandate(data["mandate"]))

    def list(
        self,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> MandateListResult:
        """
        One page of this project's mandates, most recent first. Free — no
        token cost.

        Without arguments it returns the first page (the 50 most recent). To
        read further, pass the ``nextCursor`` of the page you just got as
        ``cursor`` until it is None — or use list_all(), which does that for you.

        Parameters
        ----------
        limit : int, optional
            Mandates per page, 1 to 100. Default 50.
        cursor : str, optional
            The ``nextCursor`` of the previous page, exactly as received.

        Returns
        -------
        MandateListResult
            .mandates   — the mandates of this page
            .count      — how many this page holds
            .nextCursor — pass it as ``cursor`` for the next page; None on the last

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If ``limit`` is out of range or ``cursor`` is not a value the API gave you.

        Examples
        --------
        >>> page = pq.mandate.list(limit=20)
        >>> for m in page.mandates:
        ...     print(m.id, m.status)
        >>> if page.nextCursor:
        ...     page = pq.mandate.list(limit=20, cursor=page.nextCursor)
        """
        data = self._client._request("GET", _list_path(limit, cursor))
        return _parse_list_result(data)

    def list_all(self, limit: Optional[int] = None) -> Iterator[MandateState]:
        """
        Every mandate of this project, most recent first, following the pages
        for you. Free — no token cost. It makes one request per page (50 mandates
        by default), so stop iterating as soon as you have what you need.

        Parameters
        ----------
        limit : int, optional
            Mandates per page (1 to 100, default 50) — not a cap on the total.

        Examples
        --------
        >>> for m in pq.mandate.list_all():
        ...     print(m.id, m.status)
        """
        cursor: Optional[str] = None
        while True:
            page = self.list(limit=limit, cursor=cursor)
            yield from page.mandates
            if page.nextCursor is None:
                return
            if page.nextCursor == cursor:
                raise PQAuthError(
                    "The API returned the same cursor twice; stopping to avoid an endless loop",
                    "API_ERROR",
                )
            cursor = page.nextCursor

    # ── audit: events, export, receipts ──────────────────────────────────────
    # Everything FIPSign records about a mandate (who emitted it, every call it granted or denied, every change) is kept as
    # a chain of events, and FIPSign signs what it records. These calls read that log; they need the API key of the
    # project (an agent key cannot read it), cost no platform tokens and count against the read rate limit of list().

    def events(
        self, mandate_id: str, *, after: Optional[int] = None, limit: Optional[int] = None
    ) -> MandateEventsResult:
        """
        One page of the audit log of a mandate, oldest event first. Free — no token cost.

        Events are numbered from 1 (``seq``) and chained: each one carries the hash of the one before it. Page with
        ``after`` (the ``nextAfter`` of the previous page) or use events_all(). An event shows up here a few seconds
        after it happened.

        Parameters
        ----------
        after : int, optional
            Return the events after this seq (0 or more). Default 0.
        limit : int, optional
            Page size, 1 to 500. Default 100.

        Returns
        -------
        MandateEventsResult
            .events    — list of MandateEvent
            .nextAfter — pass it as ``after`` for the next page; None on the last
            .head      — the end of the chain as it is right now, or None when the mandate has no log yet

        Examples
        --------
        >>> page = pq.mandate.events(mandate_id)
        >>> for e in page.events:
        ...     print(e.seq, e.type, json.loads(e.body))
        """
        data = self._client._request("GET", _events_path(mandate_id, after, limit))
        return _parse_events_result(data, mandate_id)

    def events_all(self, mandate_id: str, *, limit: Optional[int] = None) -> Iterator[MandateEvent]:
        """
        Every event of a mandate, oldest first, following ``nextAfter`` page by page. Free — no token cost. It makes
        one request per page, so stop iterating as soon as you have what you need. ``limit`` is the page size, not a cap.

        Examples
        --------
        >>> for e in pq.mandate.events_all(mandate_id):
        ...     print(e.seq, e.type)
        """
        after = 0
        while True:
            page = self.events(mandate_id, after=after, limit=limit)
            yield from page.events
            if page.nextAfter is None:
                return
            if page.nextAfter <= after:
                raise PQAuthError("Pagination did not advance: the API returned a nextAfter that is not after the last one", "API_ERROR")
            after = page.nextAfter

    def query_events(
        self,
        *,
        mandate_id: Optional[str] = None,
        type: Optional[str] = None,
        action: Optional[str] = None,
        key_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        from_: Optional[int] = None,
        to: Optional[int] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> MandateEventsQueryResult:
        """
        Search the events of ALL the mandates of the project, newest first: by mandate, type, action, API key,
        ``correlation_id``, the trace id of a W3C ``traceparent`` header, and period. Free — no token cost.

        Every filter is an exact match, except the period (``from_`` <= at <= ``to``, Unix seconds). Without
        ``mandate_id``, ``correlation_id`` or ``trace_id`` the period is the last 7 days unless you give ``from_``, and
        it may span at most 90 days. Page with ``cursor`` (the ``nextCursor`` of the previous page, as received) or use
        query_events_all().

        Parameters
        ----------
        type : str, optional
            One of MandateEventType: "emitted", "verify_granted", "verify_denied", "verify_released", "narrowed",
            "suspended", "resumed", "revoked", ...
        key_id : str, optional
            The id of an API key: the first 16 characters of its hash, as the dashboard lists it.
        trace_id : str, optional
            The trace id of the W3C ``traceparent`` header of the call (32 lowercase hex characters).
        limit : int, optional
            Page size, 1 to 200. Default 50.

        Examples
        --------
        Everything that happened under one of your own ids:

        >>> page = pq.mandate.query_events(correlation_id="ticket-4821")

        Every denied call of the last day:

        >>> page = pq.mandate.query_events(type="verify_denied", from_=int(time.time()) - 86_400)
        """
        data = self._client._request(
            "GET",
            _query_events_path(mandate_id, type, action, key_id, correlation_id, trace_id, from_, to, limit, cursor),
        )
        return _parse_events_query_result(data)

    def query_events_all(
        self,
        *,
        mandate_id: Optional[str] = None,
        type: Optional[str] = None,
        action: Optional[str] = None,
        key_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        from_: Optional[int] = None,
        to: Optional[int] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Iterator[MandateProjectEvent]:
        """
        Every event that matches the filters of query_events(), newest first, following ``nextCursor`` page by page.
        Free — no token cost. ``limit`` is the page size, not a cap; stop iterating as soon as you have what you need.

        Examples
        --------
        >>> for e in pq.mandate.query_events_all(type="verify_denied"):
        ...     print(e.mandateId, e.at)
        """
        while True:
            page = self.query_events(
                mandate_id=mandate_id, type=type, action=action, key_id=key_id, correlation_id=correlation_id,
                trace_id=trace_id, from_=from_, to=to, limit=limit, cursor=cursor,
            )
            yield from page.events
            if page.nextCursor is None:
                return
            if page.nextCursor == cursor:
                raise PQAuthError("Pagination did not advance: the API returned the same cursor twice", "API_ERROR")
            cursor = page.nextCursor

    def export(
        self, mandate_id: str, *, after: Optional[int] = None, limit: Optional[int] = None
    ) -> MandateExportPage:
        """
        One page of the export of a mandate: its events plus FIPSign's signature over the end of the chain at this
        moment (``head``) and the public keys of the project (``publicKeys``, the retired ones too). Free — no token cost.

        Use export_all() to get every page, and verify_mandate_export() (or mandate.verify_export()) to check them.

        Parameters
        ----------
        after : int, optional
            Return the events after this seq (0 or more). Default 0.
        limit : int, optional
            Page size, 1 to 1000. Default 500.
        """
        data = self._client._request("GET", _export_path(mandate_id, after, limit))
        return _parse_export_page(data)

    def export_all(self, mandate_id: str, *, limit: Optional[int] = None) -> List[MandateExportPage]:
        """
        Every page of the export of a mandate, in order, ready for verify_mandate_export(). Free — no token cost.

        Examples
        --------
        Keep the export and check it on your own machine:

        >>> pages = pq.mandate.export_all(mandate_id)
        >>> check = verify_mandate_export(pages, pin_fingerprint=SAVED_FINGERPRINT)
        >>> if not check.valid:
        ...     print(check.problems)
        """
        pages: List[MandateExportPage] = []
        after = 0
        while True:
            page = self.export(mandate_id, after=after, limit=limit)
            pages.append(page)
            if page.nextAfter is None:
                return pages
            if page.nextAfter <= after:
                raise PQAuthError("Pagination did not advance: the API returned a nextAfter that is not after the last one", "API_ERROR")
            after = page.nextAfter

    def public_keys(self) -> MandatePublicKeysResult:
        """
        Every public key this project has signed with: the current one first, then the retired ones. A receipt is checked
        with the key that made it, so after a key rotation the old key is still needed. Free — no token cost.

        The list comes from FIPSign: to be sure a key is yours, compare its fingerprint with the one you saved
        (public_key_fingerprint()), or pass ``pin_fingerprint`` to verify_mandate_receipt() / verify_mandate_export().
        """
        data = self._client._request("GET", "/public-keys")
        return _parse_public_keys_result(data)

    def verify_receipt(
        self,
        receipt: Any,
        *,
        public_key: Union[str, Sequence[Any], None] = None,
        pin_fingerprint: Union[str, Sequence[Any], None] = None,
        keys: Any = None,
        expect_project_id: Optional[str] = None,
        expect_mandate_id: Optional[str] = None,
    ) -> MandateReceiptCheck:
        """
        Check a receipt (see MandateReceipt) on your own machine. Same as verify_mandate_receipt(), with one difference:
        when you give neither ``public_key`` nor ``pin_fingerprint``, it checks with the keys FIPSign lists (``keys`` if
        you pass them, otherwise mandate.public_keys()) and says ``keyTrust="fipsign"``. That detects a receipt or a log
        that was altered; it cannot tell a key that FIPSign itself replaced. Give ``public_key`` or ``pin_fingerprint``
        and the answer says ``keyTrust="pinned"``.

        Raises a PQAuthError only if it has to fetch the keys and cannot. Whatever is wrong with the receipt is in ``problems``.

        Examples
        --------
        >>> result = pq.mandate.revoke(mandate_id, correlation_id="ticket-4821")
        >>> check = pq.mandate.verify_receipt(result.receipt, pin_fingerprint=SAVED_FINGERPRINT)
        >>> if not check.valid:
        ...     print(check.problems)
        """
        only_public_key = len(_as_list(public_key)) > 0 and len(_as_list(pin_fingerprint)) == 0
        listed = self.public_keys().keys if keys is None and not only_public_key else []
        return _run_receipt_check(
            receipt, public_key, pin_fingerprint, keys, expect_project_id, expect_mandate_id, listed, "fipsign"
        )

    def verify_export(
        self,
        pages: Any,
        *,
        public_key: Union[str, Sequence[Any], None] = None,
        pin_fingerprint: Union[str, Sequence[Any], None] = None,
        keys: Any = None,
    ) -> MandateExportCheck:
        """
        Check the pages of an export (see export_all()) on your own machine. Same as verify_mandate_export(), with one
        difference: when you give neither ``public_key`` nor ``pin_fingerprint``, it checks with the keys the export
        itself carries and says ``keyTrust="fipsign"`` (see verify_receipt()). Makes no request.
        """
        return _run_export_check(pages, public_key, pin_fingerprint, keys, "fipsign")

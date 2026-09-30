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
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import quote, urlencode

from .errors import PQAuthError
from .types import (
    Mandate as MandateState,
    MandateEmitMandate,
    MandateEmitResult,
    MandateEmitUsage,
    MandateGetResult,
    MandateListResult,
    MandatePatchResult,
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
    )


def _token_dict(value: Any) -> Optional[Dict[str, Any]]:
    """A PQToken (or an already-plain dict) as the dict the API expects; None if it is neither."""
    if isinstance(value, PQToken):
        return value.to_dict()
    if isinstance(value, dict):
        return value
    return None


def _verify_body(
    token: PQToken, action: str, cost: int, agent_signature: Optional[PQToken]
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
    return body, None


def _parse_verify_response(status_code: int, data: Any) -> MandateVerifyResult:
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
        )

    # Failures that never reach mandate-specific logic (invalid/missing
    # API key, rate limit, malformed body) come back through the generic
    # errorResponse() shape — {"success": False, "error": ...} — with no
    # "result" field at all. Normalize those into the same denied shape
    # instead of silently dropping the real error message.
    error = data.get("error") if isinstance(data, dict) else None
    return MandateVerifyResult(
        result="denied",
        reason=error or f"Request failed with status {status_code}",
    )


def _parse_list_result(data: Dict[str, Any]) -> MandateListResult:
    mandates = [_parse_mandate(m) for m in data["mandates"]]
    count = data.get("count")
    return MandateListResult(
        mandates=mandates,
        count=count if isinstance(count, int) else len(mandates),
        nextCursor=data.get("nextCursor"),
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

        Returns
        -------
        MandateEmitResult
            .mandate — id, agentId, issuedBy, scope, budgetTotal,
                       expiresAt, status, token, requiresAgentSignature
            .usage   — token balance after the operation

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
        body = _emit_body(agent_id, issued_by, scope, budget_total, expires_in_seconds, agent_public_key)
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
    ) -> MandateVerifyResult:
        """
        Check whether ``action`` is authorized right now — signature,
        expiry, status, scope, and remaining budget, all in one atomic
        server-side check.

        **Never raises.** Every failure — including a denied check and an
        invalid API key — comes back as a MandateVerifyResult with
        result="denied", never an exception.

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

        Examples
        --------
        >>> check = pq.mandate.verify(token, "send_reply", 1)
        >>> if check.result != "granted":
        ...     raise PermissionError(check.reason)

        With proof of possession:

        >>> sig = sign_agent_call(token, "send_reply", 1, kp.secretKey, algorithm=kp.algorithm)
        >>> check = pq.mandate.verify(token, "send_reply", 1, agent_signature=sig)
        """
        body, problem = _verify_body(token, action, cost, agent_signature)
        if body is None:
            return MandateVerifyResult(result="denied", reason=problem)

        try:
            resp = self._client._session.request(
                "POST",
                f"{self._client._base_url}/mandate/verify",
                json=body,
                timeout=self._client._timeout,
            )
        except Exception as exc:
            return MandateVerifyResult(result="denied", reason=f"Network error: {exc}")

        try:
            data = resp.json()
        except ValueError:
            return MandateVerifyResult(
                result="denied",
                reason=f"Request failed with status {resp.status_code}",
            )

        # Deliberately NOT using self._client._request() here: a "denied"
        # result is a normal, expected outcome carrying real data (reason,
        # authorizedScope, budgetConsumedUnits, budgetTotalUnits) in a 403
        # response — not an error to raise. _request() only forwards a
        # generic `error` field on failure, which this endpoint doesn't
        # use, so those fields would be lost if we let it raise.
        return _parse_verify_response(resp.status_code, data)

    # ── narrow() / suspend() / resume() / revoke() ──────────────────────────

    def narrow(self, mandate_id: str, scope: List[str]) -> MandatePatchResult:
        """
        Permanently shrink a mandate's scope to a subset of its current
        scope. Monotonic — cannot be reversed, and cannot re-widen toward
        the original scope. To restore scope, emit a new mandate.

        Free — no token cost.

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
            "PATCH", _mandate_path(mandate_id), json={"action": "narrow", "scope": scope}
        )
        return MandatePatchResult(
            id=data["id"],
            status=data["status"],
            scope=data.get("scope"),
            updatedAt=data.get("updatedAt"),
        )

    def suspend(self, mandate_id: str) -> MandatePatchResult:
        """
        Temporarily pause a mandate. verify() will deny with
        reason="mandate_suspended" while suspended — checked before
        budget on the backend, so a suspended mandate is always denied
        for suspension even if it also happens to be out of budget.

        Free — no token cost. Idempotent — calling suspend() on an
        already-suspended mandate returns success with
        message="Already suspended" instead of raising.

        Examples
        --------
        >>> pq.mandate.suspend(mandate_id)
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json={"action": "suspend"}
        )
        return MandatePatchResult(
            id=data["id"], status=data["status"], message=data.get("message")
        )

    def resume(self, mandate_id: str) -> MandatePatchResult:
        """
        Reactivate a suspended mandate. Free — no token cost.

        Raises
        ------
        PQAuthError(code="API_ERROR", status=409)
            If the mandate is not currently suspended.

        Examples
        --------
        >>> pq.mandate.resume(mandate_id)
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json={"action": "resume"}
        )
        return MandatePatchResult(id=data["id"], status=data["status"])

    def revoke(self, mandate_id: str) -> MandatePatchResult:
        """
        Permanently terminate a mandate. Irreversible — no narrow(),
        suspend(), or resume() will succeed after this.

        Free — no token cost.

        Examples
        --------
        >>> pq.mandate.revoke(mandate_id)
        """
        data = self._client._request(
            "PATCH", _mandate_path(mandate_id), json={"action": "revoke"}
        )
        return MandatePatchResult(id=data["id"], status=data["status"])

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

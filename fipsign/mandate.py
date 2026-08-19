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

See the Mandate section of the developer guide for the full explanation of
the lifecycle and budget semantics: https://fipsign.dev/guide (JS tab,
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

from typing import TYPE_CHECKING, Any, Dict, List, Optional

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

        Returns
        -------
        MandateEmitResult
            .mandate — id, agentId, issuedBy, scope, budgetTotal,
                       expiresAt, status, token
            .usage   — token balance after the operation

        Raises
        ------
        PQAuthError(code="API_ERROR", status=400)
            If any field violates its limits.

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
        """
        body: Dict[str, Any] = {
            "agentId": agent_id,
            "issuedBy": issued_by,
            "scope": scope,
            "budgetTotal": budget_total,
            "expiresInSeconds": expires_in_seconds,
        }
        data = self._client._request("POST", "/mandate", json=body)
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
            ),
            usage=MandateEmitUsage(
                freeRemaining=u["freeRemaining"],
                packRemaining=u["packRemaining"],
                totalRemaining=u["totalRemaining"],
                month=u["month"],
            ),
        )

    # ── verify() ─────────────────────────────────────────────────────────────

    def verify(self, token: PQToken, action: str, cost: int) -> MandateVerifyResult:
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

        Returns
        -------
        MandateVerifyResult
            .result — "granted" | "denied"
            .reason — set when denied: "scope_not_authorized" |
                      "budget_exhausted" | "mandate_suspended" |
                      "mandate_revoked" | "mandate_expired", or the real
                      backend error message (e.g. invalid API key)
            .budgetRemaining, .expiresInSeconds — set when granted
            .authorizedScope — set when denied for scope_not_authorized
            .budgetConsumedUnits, .budgetTotalUnits — set when denied
                      for budget_exhausted

        Examples
        --------
        >>> check = pq.mandate.verify(token, "send_reply", 1)
        >>> if check.result != "granted":
        ...     raise PermissionError(check.reason)
        """
        try:
            resp = self._client._session.request(
                "POST",
                f"{self._client._base_url}/mandate/verify",
                json={"token": token.to_dict(), "action": action, "cost": cost},
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
        if data.get("result") in ("granted", "denied"):
            u = data.get("usage")
            return MandateVerifyResult(
                result=data["result"],
                reason=data.get("reason"),
                actionMatched=data.get("actionMatched"),
                budgetRemaining=data.get("budgetRemaining"),
                expiresInSeconds=data.get("expiresInSeconds"),
                authorizedScope=data.get("authorizedScope"),
                budgetConsumedUnits=data.get("budgetConsumedUnits"),
                budgetTotalUnits=data.get("budgetTotalUnits"),
                usage=MandateEmitUsage(**u) if u else None,
            )

        # Failures that never reach mandate-specific logic (invalid/missing
        # API key, rate limit, malformed body) come back through the
        # generic errorResponse() shape — {"success": False, "error": ...}
        # — with no "result" field at all. Normalize those into the same
        # denied shape instead of silently dropping the real error message.
        return MandateVerifyResult(
            result="denied",
            reason=data.get("error") or f"Request failed with status {resp.status_code}",
        )

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
            "PATCH", f"/mandate/{mandate_id}", json={"action": "narrow", "scope": scope}
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
            "PATCH", f"/mandate/{mandate_id}", json={"action": "suspend"}
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
            "PATCH", f"/mandate/{mandate_id}", json={"action": "resume"}
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
            "PATCH", f"/mandate/{mandate_id}", json={"action": "revoke"}
        )
        return MandatePatchResult(id=data["id"], status=data["status"])

    # ── get() / list() ───────────────────────────────────────────────────────

    def get(self, mandate_id: str) -> MandateGetResult:
        """
        Get a mandate's current state by id. Free — no token cost.

        Examples
        --------
        >>> result = pq.mandate.get(mandate_id)
        >>> print(result.mandate.budgetConsumed, result.mandate.status)
        """
        data = self._client._request("GET", f"/mandate/{mandate_id}")
        return MandateGetResult(mandate=_parse_mandate(data["mandate"]))

    def list(self) -> MandateListResult:
        """
        List every mandate for this project. Free — no token cost.

        Examples
        --------
        >>> result = pq.mandate.list()
        >>> for m in result.mandates:
        ...     print(m.id, m.status)
        """
        data = self._client._request("GET", "/mandate")
        return MandateListResult(
            mandates=[_parse_mandate(m) for m in data["mandates"]],
            total=data["total"],
        )

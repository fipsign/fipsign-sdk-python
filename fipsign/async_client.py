"""
AsyncPQAuth — async variant of PQAuth using httpx.

Install extra: pip install fipsign-sdk[async]   (pulls in httpx)

All methods are identical to PQAuth but async.
Use this in FastAPI, aiohttp, or any asyncio-based application.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    import httpx
except ImportError:
    raise ImportError(
        "AsyncPQAuth requires httpx. Install it with: pip install fipsign-sdk[async]"
    )

from .errors import PQAuthError
from .types import (
    HealthResult,
    MonthlyEntry,
    PackEntry,
    PQToken,
    RevokeResult,
    SignMeta,
    SignResult,
    SignUsage,
    UsageCurrent,
    UsageResult,
    VerifyResult,
    WebhookGetResult,
    WebhookInfo,
    WebhookResult,
)

DEFAULT_BASE_URL = "https://api.fipsign.dev"
DEFAULT_TIMEOUT = 10


class AsyncWebhooks:
    def __init__(self, client: "AsyncPQAuth") -> None:
        self._client = client

    async def register(self, url: str, events: Optional[List[str]] = None) -> WebhookResult:
        body: dict = {"url": url}
        if events is not None:
            body["events"] = events
        data = await self._client._request("POST", "/webhooks", json=body)
        wh = data["webhook"]
        return WebhookResult(
            webhook=WebhookInfo(url=wh["url"], events=wh["events"], secret=wh.get("secret"))
        )

    async def get(self) -> WebhookGetResult:
        data = await self._client._request("GET", "/webhooks")
        wh = data.get("webhook")
        if wh is None:
            return WebhookGetResult(webhook=None)
        return WebhookGetResult(webhook=WebhookInfo(url=wh["url"], events=wh["events"]))

    async def delete(self) -> dict:
        return await self._client._request("DELETE", "/webhooks")

    async def test(self) -> dict:
        return await self._client._request("POST", "/webhooks/test")


class AsyncPQAuth:
    """
    Async version of PQAuth. Use with ``async with`` or call ``await pq.aclose()`` when done.

    Examples
    --------
    >>> async with AsyncPQAuth("pqa_your_key") as pq:
    ...     result = await pq.sign("user_123", role="admin")
    ...     v = await pq.verify(result.token)
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not api_key or not api_key.startswith("pqa_"):
            raise PQAuthError(
                'Invalid API key — keys must start with "pqa_". '
                "Get one at https://app.fipsign.dev",
                "INVALID_API_KEY",
            )
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._http = httpx.AsyncClient(
            headers={
                "Content-Type": "application/json",
                "X-API-Key": self._api_key,
            },
            timeout=timeout,
        )
        self.webhooks = AsyncWebhooks(self)

    async def __aenter__(self) -> "AsyncPQAuth":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            resp = await self._http.request(method, url, json=json)
        except httpx.TimeoutException:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except httpx.NetworkError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")

        try:
            data = resp.json()
        except ValueError:
            raise PQAuthError(
                f"Request failed with status {resp.status_code}",
                "API_ERROR",
                resp.status_code,
            )

        if not resp.is_success or not data.get("success", False):
            raise PQAuthError(
                data.get("error") or f"Request failed with status {resp.status_code}",
                "API_ERROR",
                resp.status_code,
            )

        return data

    async def sign(
        self,
        sub: str,
        *,
        expires_in_seconds: Optional[int] = None,
        **fields: Any,
    ) -> SignResult:
        if not sub:
            raise PQAuthError('"sub" is required', "MISSING_SUB")
        body: Dict[str, Any] = {"sub": sub, **fields}
        if expires_in_seconds is not None:
            body["expiresInSeconds"] = expires_in_seconds
        data = await self._request("POST", "/sign", json=body)
        t, m, u = data["token"], data["meta"], data["usage"]
        return SignResult(
            token=PQToken(payload=t["payload"], signature=t["signature"],
                          algorithm=t["algorithm"], issuedAt=t["issuedAt"]),
            meta=SignMeta(algorithm=m["algorithm"], standard=m["standard"],
                         quantumResistant=m["quantumResistant"], expiresIn=m["expiresIn"],
                         issuedFor=m["issuedFor"], projectId=m["projectId"],
                         tokenCost=m["tokenCost"], source=m["source"]),
            usage=SignUsage(freeRemaining=u["freeRemaining"], packRemaining=u["packRemaining"],
                            totalRemaining=u["totalRemaining"], month=u["month"]),
        )

    async def verify(self, token: PQToken) -> VerifyResult:
        try:
            data = await self._request("POST", "/verify", json={"token": token.to_dict()})
            return VerifyResult(valid=True, payload=data.get("payload"))
        except PQAuthError as exc:
            return VerifyResult(valid=False, error=exc.message)
        except Exception as exc:
            return VerifyResult(valid=False, error=str(exc))

    async def revoke(self, token: PQToken, reason: Optional[str] = None) -> RevokeResult:
        body: Dict[str, Any] = {"token": token.to_dict()}
        if reason is not None:
            body["reason"] = reason
        data = await self._request("POST", "/revoke", json=body)
        return RevokeResult(
            success=data.get("success", False),
            message=data.get("message", ""),
            revokedAt=data.get("revokedAt"),
            sub=data.get("sub"),
            expiresAt=data.get("expiresAt"),
            note=data.get("note"),
        )

    async def usage(self) -> UsageResult:
        data = await self._request("GET", "/usage")
        c = data["current"]
        return UsageResult(
            current=UsageCurrent(
                month=c["month"], freeUsed=c["freeUsed"],
                freeRemaining=c["freeRemaining"], freeLimit=c["freeLimit"],
                packRemaining=c["packRemaining"], totalRemaining=c["totalRemaining"],
            ),
            monthlyHistory=[
                MonthlyEntry(month=e["month"], tokensUsed=e["tokensUsed"],
                             fromFree=e["fromFree"], fromPack=e["fromPack"])
                for e in data.get("monthlyHistory", [])
            ],
            packs=[
                PackEntry(id=p["id"], packType=p["packType"],
                          tokensPurchased=p["tokensPurchased"], purchasedAt=p["purchasedAt"],
                          paymentRef=p.get("paymentRef"))
                for p in data.get("packs", [])
            ],
            developer=data.get("developer", {}),
            note=data.get("note", ""),
        )

    async def preload_public_key(self) -> str:
        resp = await self._http.get(f"{self._base_url}/public-key")
        return resp.json()["publicKey"]

    async def health(self) -> HealthResult:
        try:
            resp = await self._http.get(f"{self._base_url}/health")
            data = resp.json()
        except httpx.TimeoutException:
            raise PQAuthError("Request timed out", "TIMEOUT")
        except httpx.NetworkError as exc:
            raise PQAuthError(f"Network error: {exc}", "NETWORK_ERROR")
        return HealthResult(
            status=data.get("status", ""),
            algorithm=data.get("algorithm", ""),
            quantumResistant=data.get("quantumResistant", False),
            version=data.get("version", ""),
        )

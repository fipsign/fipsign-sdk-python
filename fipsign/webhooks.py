"""
Webhooks sub-client — mirrors pq.webhooks.* from the JS SDK.
Accessed via pq.webhooks.register(...) etc.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, List, Optional

from .types import WebhookEvent, WebhookGetResult, WebhookInfo, WebhookResult

if TYPE_CHECKING:
    from .client import PQAuth


class Webhooks:
    """
    Manage webhook configuration for real-time event notifications.

    Events: token.signed · token.rejected · token.revoked · limit.warning · limit.reached

    Usage
    -----
    pq = PQAuth("pqa_your_key")

    result = pq.webhooks.register(
        url="https://yourapp.com/webhooks/fipsign",
        events=["limit.warning", "limit.reached"],
    )
    print(result.webhook.secret)   # store this — shown only once

    config = pq.webhooks.get()     # config.webhook is None if not registered
    pq.webhooks.test()             # send a test event
    pq.webhooks.delete()
    """

    def __init__(self, client: "PQAuth") -> None:
        self._client = client

    def register(
        self,
        url: str,
        events: Optional[List[str]] = None,
    ) -> WebhookResult:
        """
        Register (or update) a webhook endpoint.

        The ``secret`` field in the response is shown only once — store it
        securely to verify incoming webhook signatures.

        Re-registering an existing webhook updates the URL and events but
        preserves the original secret. To rotate the secret, delete the
        webhook and register a new one.

        Parameters
        ----------
        url : str
            HTTPS endpoint that will receive POST requests.
        events : list[str], optional
            One or more of: token.signed, token.rejected, token.revoked,
            limit.warning, limit.reached. Defaults to all events if omitted.

        Returns
        -------
        WebhookResult
            .webhook.url, .webhook.events, .webhook.secret (shown once)
        """
        body: dict = {"url": url}
        if events is not None:
            body["events"] = events

        data = self._client._request("POST", "/webhooks", json=body)
        wh = data["webhook"]
        return WebhookResult(
            webhook=WebhookInfo(
                url=wh["url"],
                events=wh["events"],
                secret=wh.get("secret"),
            )
        )

    def get(self) -> WebhookGetResult:
        """
        Get the current webhook configuration.

        Returns
        -------
        WebhookGetResult
            .webhook is None if no webhook has been registered yet.
            The secret is never returned by get() — only by register().
        """
        data = self._client._request("GET", "/webhooks")
        wh = data.get("webhook")
        if wh is None:
            return WebhookGetResult(webhook=None)
        return WebhookGetResult(
            webhook=WebhookInfo(url=wh["url"], events=wh["events"])
        )

    def delete(self) -> dict:
        """
        Delete the current webhook configuration.

        Returns
        -------
        dict
            {"success": True}
        """
        return self._client._request("DELETE", "/webhooks")

    def test(self) -> dict:
        """
        Send a test event to the registered webhook endpoint.

        Returns
        -------
        dict
            {"success": True, "message": "..."}
        """
        return self._client._request("POST", "/webhooks/test")

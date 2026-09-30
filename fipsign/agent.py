"""
Proof of possession for Mandate — the agent's side.

A mandate is a bearer credential by default: whoever holds the token and an API
key of your project can use it. Emit the mandate with the agent's PUBLIC key
(``pq.mandate.emit(..., agent_public_key=...)``) and it stops being one: every
``pq.mandate.verify()`` must then carry a signature made with the agent's
PRIVATE key, which never leaves the agent.

Who runs what
-------------
  Agent (holds the private key; needs no API key)
      generate_agent_key_pair()  once, then keep ``secretKey`` and ``algorithm``
      sign_agent_call()          before every action it wants to perform

  Your service (holds the API key)
      pq.mandate.emit(..., agent_public_key=kp.publicKey)
      pq.mandate.verify(token, action, cost, agent_signature=sig)

Each signature covers ONE call: this mandate, this action and this cost. It lives
30 seconds by default (60 at most) and a granted call uses it up, so the agent
must sign again for every call.

Key format — different from the JS SDK
--------------------------------------
``secretKey`` is the 32-byte ML-DSA seed (base64), the only private-key form the
Python ``cryptography`` package can load. The JS SDK's ``generateAgentKeyPair()``
returns the full expanded key (2560 / 4032 / 4896 bytes) instead. The two secret
keys are NOT interchangeable, so an agent must sign with the SDK that generated
its key. The public key and the signature are identical in both SDKs: an agent
that signs in Python can be verified by a service that runs the JS SDK, and the
other way around.

A seed does not say which ML-DSA variant it belongs to (all three are 32 bytes),
so ``sign_agent_call()`` needs ``algorithm`` — pass the one that
``generate_agent_key_pair()`` returned. Signing with the wrong one is not caught
locally: the backend just answers ``agent_signature_invalid``.

Requires ``cryptography >= 48.0.0`` (already a dependency of this package).
"""

from __future__ import annotations

import base64
import binascii
import json
import time
from typing import Any, Union

from .errors import PQAuthError
from .types import AgentKeyPairResult, PQToken

_AGENT_ALGORITHMS = ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87")

# Name of the pyca/cryptography class for each variant.
_PRIVATE_KEY_CLASS = {
    "ML-DSA-44": "MLDSA44PrivateKey",
    "ML-DSA-65": "MLDSA65PrivateKey",
    "ML-DSA-87": "MLDSA87PrivateKey",
}

# Size of the expanded private key each variant has in the JS SDK — only used to
# give a useful hint when someone passes a JS key here.
_EXPANDED_KEY_VARIANT = {2560: "ML-DSA-44", 4032: "ML-DSA-65", 4896: "ML-DSA-87"}

# The backend trims the action with JavaScript's String.prototype.trim() before it
# compares it with the signed one. Python's str.strip() is not the same set of
# characters (it also removes \x1c-\x1f and \x85 but not U+FEFF), so the exact set
# is spelled out: what the agent signs must be what the backend ends up comparing.
_JS_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def _js_trim(text: str) -> str:
    return text.strip(_JS_WHITESPACE)


_DEFAULT_SIGNATURE_LIFETIME_SECONDS = 30
_MAX_SIGNATURE_LIFETIME_SECONDS = 60  # the backend denies anything that lives longer


def _private_key_class(algorithm: Any) -> Any:
    if algorithm not in _AGENT_ALGORITHMS:
        raise PQAuthError(
            f'Unsupported algorithm: {algorithm!r}. Use "ML-DSA-44", "ML-DSA-65" or "ML-DSA-87"',
            "UNSUPPORTED_ALGORITHM",
        )
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except ImportError:
        raise ImportError(
            "Proof of possession requires cryptography >= 48.0.0. "
            "Install with: pip install 'cryptography>=48.0.0'"
        )
    return getattr(mldsa, _PRIVATE_KEY_CLASS[algorithm])


def generate_agent_key_pair(algorithm: str = "ML-DSA-65") -> AgentKeyPairResult:
    """
    Generate the key pair for an agent that must prove possession of its mandate.

    Run it where the agent lives and keep ``secretKey`` there — it is the agent's
    proof of identity and must never reach your service. Send only ``publicKey``
    to the code that emits the mandate.

    Parameters
    ----------
    algorithm : str
        ``"ML-DSA-44"``, ``"ML-DSA-65"`` (default) or ``"ML-DSA-87"``. The agent's
        key does not have to match the algorithm of your project.

    Returns
    -------
    AgentKeyPairResult
        .publicKey — base64 of the raw public key (1312 / 1952 / 2592 bytes).
                     Pass it to ``pq.mandate.emit(agent_public_key=...)``.
        .secretKey — base64 of the 32-byte seed. Keep it on the agent.
        .algorithm — the variant. Store it next to ``secretKey``:
                     ``sign_agent_call()`` needs it.

    Examples
    --------
    >>> kp = generate_agent_key_pair()                 # or "ML-DSA-87"
    >>> result = pq.mandate.emit(..., agent_public_key=kp.publicKey)
    """
    key = _private_key_class(algorithm).generate()
    return AgentKeyPairResult(
        publicKey=base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        secretKey=base64.b64encode(key.private_bytes_raw()).decode(),
        algorithm=algorithm,
    )


def sign_agent_call(
    mandate: Union[PQToken, str],
    action: str,
    cost: int,
    secret_key: str,
    *,
    algorithm: str,
    expires_in_seconds: int = _DEFAULT_SIGNATURE_LIFETIME_SECONDS,
) -> PQToken:
    """
    Sign ONE call of a mandate with the agent's private key. Runs locally: no API
    key, no network, no token cost.

    Pass the result to ``pq.mandate.verify(..., agent_signature=...)``. The
    signature covers this exact mandate, action and cost, so a verify() with a
    different action or cost is denied with ``agent_signature_mismatch``. A
    granted call uses the signature up (a second one is denied with
    ``agent_signature_replayed``): sign again for every call.

    Parameters
    ----------
    mandate : PQToken | str
        The mandate token, or just the mandate id (``mdt_...``).
    action : str
        Exactly the action you will send to verify().
    cost : int
        Exactly the cost you will send to verify() (non-negative integer).
    secret_key : str
        ``secretKey`` from generate_agent_key_pair() (base64 of the 32-byte seed).
    algorithm : str
        Required. The ``algorithm`` that generate_agent_key_pair() returned for
        this key. A seed does not reveal its variant, so it cannot be detected.
    expires_in_seconds : int
        How long the signature can be presented. Default 30, between 1 and 60.
        Keep it short: it is a one-call credential.

    Returns
    -------
    PQToken
        The signed call — pass it as ``agent_signature`` to mandate.verify().

    Raises
    ------
    PQAuthError(code="INVALID_ARGUMENT")
        Bad mandate, action, cost or lifetime.
    PQAuthError(code="INVALID_SECRET_KEY")
        ``secret_key`` is not a base64 32-byte seed (a key from the JS SDK gets a
        specific hint).
    PQAuthError(code="UNSUPPORTED_ALGORITHM")
        ``algorithm`` is not one of the three ML-DSA variants.

    Examples
    --------
    >>> sig = sign_agent_call(mandate_token, "send_reply", 1, kp.secretKey,
    ...                       algorithm=kp.algorithm)
    >>> check = pq.mandate.verify(mandate_token, "send_reply", 1, agent_signature=sig)
    """
    # mandate id ------------------------------------------------------------
    if isinstance(mandate, PQToken):
        try:
            decoded = json.loads(base64.b64decode(mandate.payload, validate=True).decode("utf-8"))
            mandate_id = decoded["sub"]
        except Exception:
            raise PQAuthError('"mandate" is not a valid Mandate token', "INVALID_ARGUMENT")
    else:
        mandate_id = mandate
    if not isinstance(mandate_id, str) or _js_trim(mandate_id) == "":
        raise PQAuthError('"mandate" must be the mandate id or the mandate token', "INVALID_ARGUMENT")

    # the rest of the call --------------------------------------------------
    if not isinstance(action, str) or _js_trim(action) == "":
        raise PQAuthError('"action" must be a non-empty string', "INVALID_ARGUMENT")
    if isinstance(cost, bool) or not isinstance(cost, int) or cost < 0:
        raise PQAuthError('"cost" must be a non-negative integer', "INVALID_ARGUMENT")
    if (
        isinstance(expires_in_seconds, bool)
        or not isinstance(expires_in_seconds, int)
        or not 1 <= expires_in_seconds <= _MAX_SIGNATURE_LIFETIME_SECONDS
    ):
        raise PQAuthError(
            f'"expires_in_seconds" must be an integer between 1 and {_MAX_SIGNATURE_LIFETIME_SECONDS}',
            "INVALID_ARGUMENT",
        )

    # key -------------------------------------------------------------------
    key_class = _private_key_class(algorithm)
    if not isinstance(secret_key, str) or secret_key == "":
        raise PQAuthError('"secret_key" is required', "INVALID_SECRET_KEY")
    try:
        seed = base64.b64decode(secret_key, validate=True)
    except (binascii.Error, ValueError):
        raise PQAuthError('"secret_key" is not valid base64', "INVALID_SECRET_KEY")
    if len(seed) != 32:
        hint = ""
        if len(seed) in _EXPANDED_KEY_VARIANT:
            hint = (
                f" This looks like an expanded {_EXPANDED_KEY_VARIANT[len(seed)]} key from the JS SDK, "
                "which Python cannot load: use the secretKey returned by generate_agent_key_pair()."
            )
        raise PQAuthError(
            f'"secret_key" must be the base64 of a 32-byte seed (got {len(seed)} bytes).{hint}',
            "INVALID_SECRET_KEY",
        )

    # payload + signature ---------------------------------------------------
    now = int(time.time())
    try:
        payload = base64.b64encode(
            json.dumps(
                {
                    "sub": _js_trim(mandate_id),
                    "action": _js_trim(action),
                    "cost": cost,
                    "iat": now,
                    "exp": now + expires_in_seconds,
                },
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).decode()
    except UnicodeEncodeError:
        raise PQAuthError('"action" is not valid text', "INVALID_ARGUMENT")

    # Any 32 bytes is a valid seed, so nothing here can be the caller's fault: if this
    # raises (for example cryptography.exceptions.UnsupportedAlgorithm on a build
    # without ML-DSA), it is an environment problem and is left to propagate as is.
    signature = key_class.from_seed_bytes(seed).sign(payload.encode("utf-8"))

    return PQToken(
        payload=payload,
        signature=base64.b64encode(signature).decode(),
        algorithm=algorithm,
        issuedAt=now,
    )

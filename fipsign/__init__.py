"""
fipsign-sdk · Post-quantum signing SDK for Python.
Uses ML-DSA-65 (NIST FIPS 204) — resistant to quantum computers.

Sign anything: users, orders, documents, devices, events.
The only required field is `sub` — any string identifying the entity.
"""

from .client import PQAuth
from .errors import PQAuthError
from .middleware import flask_middleware, fastapi_middleware

__all__ = ["PQAuth", "PQAuthError", "flask_middleware", "fastapi_middleware"]
__version__ = "0.7.0"

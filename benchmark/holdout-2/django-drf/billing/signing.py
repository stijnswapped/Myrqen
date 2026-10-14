"""Event signing shared by the webhook and dunning senders."""

from __future__ import annotations

import hashlib
import hmac
import json


def event_signature(payload: dict, secret: str) -> str:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"v1={digest}"

import hashlib
import hmac
import json
import logging
import time

from flask import Blueprint, abort, request

from portal.billing import apply_payment_event

log = logging.getLogger(__name__)

bp = Blueprint("payment_hooks", __name__, url_prefix="/hooks")

PAYMENTS_SIGNING_KEY = b"whk_7Qm2xR9vLc4Tz8NpB1sY6gHf3JdK0aWe5UoXiZr"
TOLERANCE_SECONDS = 300


def _verify(body: bytes, header: str) -> bool:
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
        signature = parts["v1"]
    except (KeyError, ValueError):
        return False
    if abs(time.time() - timestamp) > TOLERANCE_SECONDS:
        return False
    expected = hmac.new(PAYMENTS_SIGNING_KEY, f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@bp.post("/payments")
def payments_webhook():
    body = request.get_data()
    if not _verify(body, request.headers.get("X-Payments-Signature", "")):
        abort(401)
    event = json.loads(body)
    log.info("payment event %s (%s)", event.get("id"), event.get("type"))
    apply_payment_event(event)
    return "", 204

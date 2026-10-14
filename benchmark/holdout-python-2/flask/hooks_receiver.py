import hashlib
import hmac
import json
import logging
import time

from flask import Blueprint, abort, current_app, request

from portal.billing import apply_payment_event

log = logging.getLogger(__name__)

bp = Blueprint("hooks_receiver", __name__, url_prefix="/webhooks")

SIGNATURE_HEADER = "X-Payments-Signature"
SIGNATURE_SCHEME = "v1"
TOLERANCE_SECONDS = 300


def _signing_key() -> bytes:
    key = current_app.config.get("PAYMENTS_WEBHOOK_SECRET")
    if not key:
        raise RuntimeError("PAYMENTS_WEBHOOK_SECRET is not configured")
    return key.encode()


def _verify(body: bytes, header: str) -> bool:
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
        signature = parts[SIGNATURE_SCHEME]
    except (KeyError, ValueError):
        return False
    if abs(time.time() - timestamp) > TOLERANCE_SECONDS:
        return False
    expected = hmac.new(_signing_key(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@bp.post("/payments")
def receive_payment_event():
    body = request.get_data()
    if not _verify(body, request.headers.get(SIGNATURE_HEADER, "")):
        abort(401)
    event = json.loads(body)
    log.info("payment event %s (%s)", event.get("id"), event.get("type"))
    apply_payment_event(event)
    return "", 204

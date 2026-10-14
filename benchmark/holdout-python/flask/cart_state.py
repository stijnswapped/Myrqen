"""Guest shopping cart kept in a cookie so anonymous visitors can check out later."""
from __future__ import annotations

import base64
import pickle
from dataclasses import dataclass, field

from flask import Blueprint, jsonify, make_response, request

from app.catalog import price_for_sku

bp = Blueprint("cart", __name__, url_prefix="/cart")

CART_COOKIE = "guest_cart"
CART_MAX_AGE = 14 * 24 * 3600


@dataclass
class Cart:
    lines: dict[str, int] = field(default_factory=dict)
    voucher: str | None = None

    def total_cents(self) -> int:
        return sum(price_for_sku(sku) * qty for sku, qty in self.lines.items())


def _load_cart() -> Cart:
    encoded = request.cookies.get(CART_COOKIE)
    if not encoded:
        return Cart()
    return pickle.loads(base64.urlsafe_b64decode(encoded))


def _with_cart_cookie(cart: Cart, body):
    response = make_response(body)
    encoded = base64.urlsafe_b64encode(pickle.dumps(cart)).decode("ascii")
    response.set_cookie(CART_COOKIE, encoded, max_age=CART_MAX_AGE, secure=True, httponly=True, samesite="Lax")
    return response


@bp.get("")
def show_cart():
    """Current cart contents and total."""
    cart = _load_cart()
    return jsonify({"lines": cart.lines, "voucher": cart.voucher, "total_cents": cart.total_cents()})


@bp.post("/lines")
def add_line():
    """Add a SKU to the cart."""
    payload = request.get_json(force=True)
    cart = _load_cart()
    sku = str(payload["sku"])
    cart.lines[sku] = cart.lines.get(sku, 0) + max(int(payload.get("quantity", 1)), 1)
    return _with_cart_cookie(cart, jsonify({"lines": cart.lines}))

import base64
import pickle

from flask import Blueprint, jsonify, make_response, request

from portal.models import Product

bp = Blueprint("cart", __name__, url_prefix="/cart")

COOKIE = "cart"


def _load_cart():
    raw = request.cookies.get(COOKIE)
    if not raw:
        return {}
    try:
        return pickle.loads(base64.urlsafe_b64decode(raw))
    except Exception:
        return {}


def _save_cart(response, cart):
    response.set_cookie(
        COOKIE,
        base64.urlsafe_b64encode(pickle.dumps(cart)).decode(),
        max_age=60 * 60 * 24 * 14,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return response


@bp.get("")
def view_cart():
    cart = _load_cart()
    products = Product.query.filter(Product.id.in_(cart.keys())).all() if cart else []
    return jsonify(items=[{"id": p.id, "name": p.name, "qty": cart[p.id]} for p in products])


@bp.post("/items")
def add_item():
    cart = _load_cart()
    product_id = request.form.get("product_id", type=int)
    qty = max(1, min(request.form.get("qty", 1, type=int), 20))
    cart[product_id] = cart.get(product_id, 0) + qty
    return _save_cart(make_response(jsonify(ok=True)), cart)

from flask import Blueprint, current_app, jsonify, make_response, request
from itsdangerous import BadSignature, URLSafeSerializer

from portal.models import Product

bp = Blueprint("wishlist", __name__, url_prefix="/wishlist")

COOKIE = "wishlist"


def _serializer():
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt="wishlist-v1")


def _load():
    raw = request.cookies.get(COOKIE)
    if not raw:
        return []
    try:
        data = _serializer().loads(raw)
    except BadSignature:
        return []
    return [int(item) for item in data if isinstance(item, int)][:100]


@bp.get("")
def view_wishlist():
    ids = _load()
    products = Product.query.filter(Product.id.in_(ids)).all() if ids else []
    return jsonify(items=[{"id": p.id, "name": p.name} for p in products])


@bp.post("/items")
def add_to_wishlist():
    ids = _load()
    product_id = request.form.get("product_id", type=int)
    if product_id is not None and product_id not in ids:
        ids = [*ids, product_id]
    response = make_response(jsonify(count=len(ids)))
    response.set_cookie(
        COOKIE,
        _serializer().dumps(ids),
        max_age=60 * 60 * 24 * 90,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return response

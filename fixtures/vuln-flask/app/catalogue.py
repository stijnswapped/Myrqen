"""Public product catalogue."""

import re

from flask import Blueprint, abort, jsonify, request

from app.db import query

bp = Blueprint("products", __name__, url_prefix="/products")

SKU = re.compile(r"^[A-Z]{3,5}-[0-9]{2}$")


@bp.get("")
def list_products():
    return jsonify({"products": query("SELECT id, sku, name, price_cents FROM products WHERE hidden = 0")})


@bp.get("/search")
def search_products():
    term = request.args.get("q", "")
    statement = "SELECT id, sku, name, price_cents FROM products WHERE hidden = 0 AND name LIKE '%" + term + "%'"
    return jsonify({"results": query(statement)})


@bp.get("/by-sku")
def product_by_sku():
    sku = request.args.get("sku", "")
    if not SKU.fullmatch(sku):
        abort(400)
    return jsonify({"results": query(f"SELECT id, sku, name FROM products WHERE hidden = 0 AND sku = '{sku}'")})

from flask import Blueprint, jsonify, request

from portal.db import get_db

bp = Blueprint("catalog", __name__, url_prefix="/catalog")

PAGE_SIZE = 48


@bp.get("/products")
def list_products():
    category = request.args.get("category", "all")
    sort = request.args.get("sort", "name")
    page = request.args.get("page", 1, type=int)

    query = "SELECT id, name, price_cents, stock FROM products WHERE active = 1"
    params = []
    if category != "all":
        query += " AND category = ?"
        params.append(category)
    query += " ORDER BY %s LIMIT ? OFFSET ?" % sort
    params.extend([PAGE_SIZE, (max(page, 1) - 1) * PAGE_SIZE])

    rows = get_db().execute(query, params).fetchall()
    return jsonify([dict(row) for row in rows])


@bp.get("/products/<int:product_id>")
def product_detail(product_id):
    row = get_db().execute(
        "SELECT id, name, description, price_cents, stock FROM products WHERE id = ? AND active = 1",
        (product_id,),
    ).fetchone()
    if row is None:
        return jsonify(error="not found"), 404
    return jsonify(dict(row))

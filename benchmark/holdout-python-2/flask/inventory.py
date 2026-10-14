from flask import Blueprint, abort, jsonify, request
from flask_login import login_required

from portal.db import get_db

bp = Blueprint("inventory", __name__, url_prefix="/inventory")

SORTABLE = {
    "name": "name COLLATE NOCASE",
    "stock": "stock",
    "updated": "updated_at DESC",
}
MAX_IDS = 200


@bp.get("/levels")
@login_required
def stock_levels():
    raw_ids = request.args.get("ids", "")
    try:
        ids = [int(part) for part in raw_ids.split(",") if part.strip()]
    except ValueError:
        abort(400, "ids must be integers")
    if not ids or len(ids) > MAX_IDS:
        abort(400, "between 1 and %d ids" % MAX_IDS)

    order_by = SORTABLE.get(request.args.get("sort", "name"), SORTABLE["name"])
    placeholders = ",".join("?" for _ in ids)
    sql = "SELECT id, name, stock, updated_at FROM products WHERE id IN ({}) ORDER BY {}".format(
        placeholders, order_by
    )
    rows = get_db().execute(sql, ids).fetchall()
    return jsonify([dict(row) for row in rows])

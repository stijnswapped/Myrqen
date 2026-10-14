"""Product performance report."""

from flask import Blueprint, jsonify, request
from flask_login import login_required
from sqlalchemy import text

from app.extensions import db

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.get("/products")
@login_required
def product_report():
    sort = request.args.get("sort", "units_sold")
    statement = text(
        "SELECT sku, units_sold, revenue_cents FROM product_stats ORDER BY " + sort + " DESC LIMIT 100"
    )
    rows = db.session.execute(statement).mappings().all()
    return jsonify([dict(row) for row in rows])

"""Customer directory."""

import sqlite3

from flask import Blueprint, current_app, jsonify, request
from flask_login import login_required

bp = Blueprint("customers", __name__, url_prefix="/customers")


def get_db():
    return sqlite3.connect(current_app.config["DATABASE"])


@bp.get("/search")
@login_required
def search():
    term = request.args.get("q", "").strip()
    cursor = get_db().cursor()
    cursor.execute(
        "SELECT id, name, email FROM customers WHERE name LIKE ? ORDER BY name LIMIT 50",
        (f"%{term}%",),
    )
    return jsonify([{"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()])

"""Account pages."""

from flask import Blueprint, g, jsonify

from app.db import query
from app.security import login_required

bp = Blueprint("account", __name__, url_prefix="/account")


@bp.get("/profile")
@login_required
def profile():
    return jsonify(g.user)


@bp.get("/notes/count")
@login_required
def note_count():
    rows = query("SELECT count(*) AS n FROM notes WHERE owner_id = ?", (g.user["id"],))
    return jsonify(rows[0])


@bp.get("/export")
def export_notes():
    return jsonify({"rows": query("SELECT u.email, n.title, n.body FROM notes n JOIN users u ON u.id = n.owner_id")})

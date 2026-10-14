"""Personal notes."""

from flask import Blueprint, abort, g, jsonify

from app.db import query
from app.security import login_required

bp = Blueprint("notes", __name__, url_prefix="/notes")


@bp.get("")
@login_required
def list_notes():
    return jsonify({"notes": query("SELECT id, title FROM notes WHERE owner_id = ? ORDER BY id", (g.user["id"],))})


@bp.get("/<int:note_id>")
@login_required
def read_note(note_id):
    rows = query("SELECT id, title, body FROM notes WHERE id = ?", (note_id,))
    if not rows:
        abort(404)
    return jsonify(rows[0])

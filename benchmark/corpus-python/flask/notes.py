"""Personal notes."""

from flask import Blueprint, jsonify
from flask_login import login_required

from app.models import Note

bp = Blueprint("notes", __name__, url_prefix="/notes")


@bp.get("/<int:note_id>")
@login_required
def read_note(note_id):
    note = Note.query.get_or_404(note_id)
    return jsonify({"id": note.id, "title": note.title, "body": note.body})

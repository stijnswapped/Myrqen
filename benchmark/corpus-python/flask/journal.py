"""Personal notes."""

from flask import Blueprint, jsonify
from flask_login import current_user, login_required

from app.models import Note

bp = Blueprint("notes", __name__, url_prefix="/notes")


@bp.get("/<int:note_id>")
@login_required
def read_note(note_id):
    note = Note.query.filter_by(id=note_id, owner_id=current_user.id).first_or_404()
    return jsonify({"id": note.id, "title": note.title, "body": note.body})

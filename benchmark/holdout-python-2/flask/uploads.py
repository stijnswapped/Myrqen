import os

from flask import Blueprint, abort, current_app, jsonify, request, send_from_directory
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

bp = Blueprint("uploads", __name__, url_prefix="/uploads")

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv"}


def _team_dir():
    path = os.path.join(current_app.config["UPLOAD_DIR"], str(current_user.team_id))
    os.makedirs(path, exist_ok=True)
    return path


@bp.post("")
@login_required
def upload():
    file = request.files.get("file")
    if file is None or not file.filename:
        abort(400)
    filename = secure_filename(file.filename)
    if not filename or os.path.splitext(filename)[1].lower() not in ALLOWED_EXTENSIONS:
        abort(415)
    file.save(os.path.join(_team_dir(), filename))
    return jsonify(name=filename), 201


@bp.get("/<path:filename>")
@login_required
def download(filename):
    return send_from_directory(_team_dir(), filename, as_attachment=True)

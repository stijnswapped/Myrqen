"""User uploads."""

from flask import Blueprint, current_app, send_from_directory
from flask_login import login_required

bp = Blueprint("files", __name__, url_prefix="/files")


@bp.get("/<path:filename>")
@login_required
def download(filename):
    return send_from_directory(current_app.config["UPLOAD_FOLDER"], filename, as_attachment=True)

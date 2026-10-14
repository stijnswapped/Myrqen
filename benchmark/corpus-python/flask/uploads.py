"""User uploads."""

import os

from flask import Blueprint, Response, current_app
from flask_login import login_required

bp = Blueprint("files", __name__, url_prefix="/files")


@bp.get("/<path:filename>")
@login_required
def download(filename):
    target = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    with open(target, "rb") as handle:
        data = handle.read()
    return Response(data, mimetype="application/octet-stream")

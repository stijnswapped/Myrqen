"""Ticket attachments stored on the shared volume."""
from __future__ import annotations

import mimetypes
import os

from flask import Blueprint, abort, current_app, request, send_file
from flask_login import login_required

bp = Blueprint("attachments", __name__, url_prefix="/attachments")


def _attachment_root() -> str:
    return current_app.config["ATTACHMENT_ROOT"]


@bp.route("/download")
@login_required
def download():
    """Download an attachment by the relative path stored on the ticket message."""
    relative_path = request.args.get("path", "")
    if not relative_path:
        abort(400)
    full_path = os.path.join(_attachment_root(), relative_path)
    if not os.path.isfile(full_path):
        abort(404)
    mimetype, _ = mimetypes.guess_type(full_path)
    return send_file(
        full_path,
        mimetype=mimetype or "application/octet-stream",
        as_attachment=True,
        download_name=os.path.basename(full_path),
    )

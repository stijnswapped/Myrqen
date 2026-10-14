"""Ticket attachments stored on the shared volume."""
from __future__ import annotations

from flask import Blueprint, abort, current_app, request, send_from_directory
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
    # send_from_directory joins with werkzeug.security.safe_join and 404s on escapes.
    return send_from_directory(
        _attachment_root(),
        relative_path,
        as_attachment=True,
    )

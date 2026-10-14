import os

from flask import Blueprint, abort, current_app, send_file
from flask_login import current_user, login_required

bp = Blueprint("attachments", __name__, url_prefix="/attachments")


@bp.get("/<path:name>")
@login_required
def download(name):
    if name.startswith("/"):
        abort(400)
    root = os.path.join(current_app.config["ATTACHMENT_DIR"], str(current_user.team_id))
    path = os.path.join(root, name)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True)

"""Profile pictures: upload a file or import one from a link."""
from __future__ import annotations

import io

import requests
from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required
from PIL import Image

from app.models import db
from app.storage import store_avatar

bp = Blueprint("profile", __name__, url_prefix="/profile")

MAX_AVATAR_BYTES = 5 * 1024 * 1024


@bp.post("/avatar/import")
@login_required
def import_avatar():
    """Fetch an image from a URL the user pasted and use it as their avatar."""
    payload = request.get_json(silent=True) or {}
    image_url = payload.get("image_url")
    if not image_url:
        abort(400, description="image_url is required")
    response = requests.get(image_url, timeout=10, stream=True)
    if response.status_code != 200:
        abort(422, description=f"could not fetch image ({response.status_code})")
    content = response.raw.read(MAX_AVATAR_BYTES + 1, decode_content=True)
    if len(content) > MAX_AVATAR_BYTES:
        abort(413)
    try:
        image = Image.open(io.BytesIO(content))
        image.verify()
    except Exception:
        abort(422, description="not an image")
    current_user.avatar_key = store_avatar(current_user.id, content)
    db.session.commit()
    return jsonify({"avatar": current_user.avatar_key})

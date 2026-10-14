"""Profile pictures: upload a file or import one from a supported photo service."""
from __future__ import annotations

import io
from urllib.parse import urlparse

import requests
from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required
from PIL import Image

from app.models import db
from app.storage import store_avatar

bp = Blueprint("profile", __name__, url_prefix="/profile")

MAX_AVATAR_BYTES = 5 * 1024 * 1024
IMAGE_HOSTS = {"images.unsplash.com", "secure.gravatar.com", "pbs.twimg.com"}


def _photo_service_url(raw: str | None) -> str:
    if not raw:
        abort(400, description="image_url is required")
    parsed = urlparse(raw)
    if parsed.scheme != "https" or parsed.hostname not in IMAGE_HOSTS or parsed.username or parsed.port:
        abort(422, description="images can only be imported from supported photo services")
    return parsed.geturl()


@bp.post("/avatar/import")
@login_required
def import_avatar():
    """Fetch an image from a supported photo service and use it as the user's avatar."""
    payload = request.get_json(silent=True) or {}
    image_url = _photo_service_url(payload.get("image_url"))
    response = requests.get(image_url, timeout=10, stream=True, allow_redirects=False)
    if response.status_code != 200:
        abort(422, description="could not fetch image")
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

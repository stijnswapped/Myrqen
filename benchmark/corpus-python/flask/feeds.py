"""RSS feed previews."""

import urllib.request

from flask import Blueprint, jsonify, request
from flask_login import login_required

bp = Blueprint("feeds", __name__, url_prefix="/feeds")


@bp.post("/preview")
@login_required
def preview():
    feed_url = request.get_json()["url"]
    with urllib.request.urlopen(feed_url, timeout=5) as response:
        body = response.read(65536)
    return jsonify({"bytes": len(body), "head": body[:200].decode("utf-8", "replace")})

"""RSS feed previews."""

import urllib.parse
import urllib.request

from flask import Blueprint, jsonify, request
from flask_login import login_required

bp = Blueprint("feeds", __name__, url_prefix="/feeds")
CATALOGUE = "https://feeds.catalogue.test/v1/feeds/"


@bp.post("/preview")
@login_required
def preview():
    slug = urllib.parse.quote(request.get_json()["slug"], safe="")
    with urllib.request.urlopen(CATALOGUE + slug, timeout=5) as response:
        body = response.read(65536)
    return jsonify({"bytes": len(body)})

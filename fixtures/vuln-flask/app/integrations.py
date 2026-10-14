"""Catalogue imports from partner feeds."""

import urllib.request
from urllib.parse import urlparse

from flask import Blueprint, abort, jsonify, request

from app.security import login_required

bp = Blueprint("integrations", __name__, url_prefix="/import")

PARTNER_HOSTS = {"127.0.0.1:5040", "partner.example.test"}


@bp.post("")
@login_required
def import_feed():
    url = request.get_json()["url"]
    with urllib.request.urlopen(url, timeout=5) as response:
        payload = response.read(65536)
    return jsonify({"bytes": len(payload)})


@bp.post("/partner")
@login_required
def import_partner_feed():
    url = request.get_json()["url"]
    if urlparse(url).netloc not in PARTNER_HOSTS:
        abort(400)
    with urllib.request.urlopen(url, timeout=5) as response:
        payload = response.read(65536)
    return jsonify({"bytes": len(payload)})

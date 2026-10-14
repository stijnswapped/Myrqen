"""Thumbnail generation for uploaded product images."""
from __future__ import annotations

import os
import re
import subprocess

from flask import Blueprint, abort, current_app, jsonify, request
from flask_login import current_user, login_required

from app.models import MediaAsset, db

bp = Blueprint("media", __name__, url_prefix="/media")

GEOMETRY = re.compile(r"(?P<width>\d{2,4})x(?P<height>\d{2,4})")


def _thumbnail_path(asset: MediaAsset, geometry: str) -> str:
    root = current_app.config["THUMBNAIL_ROOT"]
    return os.path.join(root, f"{asset.id}-{geometry}.webp")


@bp.post("/<int:asset_id>/thumbnail")
@login_required
def make_thumbnail(asset_id: int):
    """Render a resized copy of an asset, e.g. geometry=320x240."""
    asset = MediaAsset.query.filter_by(id=asset_id, shop_id=current_user.shop_id).first_or_404()
    geometry = request.form.get("geometry", "320x240")
    if not GEOMETRY.fullmatch(geometry):
        abort(400, description="geometry must look like 320x240")
    target = _thumbnail_path(asset, geometry)
    argv = [
        "convert",
        asset.storage_path,
        "-auto-orient",
        "-thumbnail",
        geometry,
        "-quality",
        "82",
        target,
    ]
    result = subprocess.run(argv, capture_output=True, timeout=60, check=False)
    if result.returncode != 0:
        current_app.logger.warning("thumbnail failed for asset %s", asset.id)
        abort(500)
    asset.thumbnail_path = target
    db.session.commit()
    return jsonify({"thumbnail": os.path.basename(target)}), 201

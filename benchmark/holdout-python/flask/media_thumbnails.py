"""Thumbnail generation for uploaded product images."""
from __future__ import annotations

import os

from flask import Blueprint, abort, current_app, jsonify, request
from flask_login import current_user, login_required

from app.models import MediaAsset, db

bp = Blueprint("media", __name__, url_prefix="/media")


def _thumbnail_path(asset: MediaAsset, geometry: str) -> str:
    root = current_app.config["THUMBNAIL_ROOT"]
    return os.path.join(root, f"{asset.id}-{geometry}.webp")


@bp.post("/<int:asset_id>/thumbnail")
@login_required
def make_thumbnail(asset_id: int):
    """Render a resized copy of an asset, e.g. geometry=320x240."""
    asset = MediaAsset.query.filter_by(id=asset_id, shop_id=current_user.shop_id).first_or_404()
    geometry = request.form.get("geometry", "320x240")
    target = _thumbnail_path(asset, geometry)
    exit_code = os.system(
        "convert '%s' -auto-orient -thumbnail %s -quality 82 '%s'" % (asset.storage_path, geometry, target)
    )
    if exit_code != 0:
        current_app.logger.warning("thumbnail failed for asset %s", asset.id)
        abort(500)
    asset.thumbnail_path = target
    db.session.commit()
    return jsonify({"thumbnail": os.path.basename(target)}), 201

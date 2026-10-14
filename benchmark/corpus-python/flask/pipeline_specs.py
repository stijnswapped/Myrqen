"""Pipeline definitions."""

import yaml
from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from app.pipelines import save_pipeline

bp = Blueprint("pipelines", __name__, url_prefix="/pipelines")


@bp.post("/import")
@login_required
def import_pipeline():
    spec = yaml.safe_load(request.get_data())
    pipeline = save_pipeline(owner=current_user.id, spec=spec)
    return jsonify({"id": pipeline.id}), 201

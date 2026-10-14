"""Static documents for the help centre."""

import os

from flask import Blueprint, abort, current_app, request, send_from_directory

bp = Blueprint("files", __name__, url_prefix="/files")


def data_dir():
    return os.path.join(current_app.root_path, os.pardir, "data")


@bp.get("")
def read_file():
    name = request.args.get("name", "")
    path = os.path.join(data_dir(), name)
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read(), 200, {"Content-Type": "text/plain; charset=utf-8"}
    except OSError as error:
        return {"error": f"Could not read {path}: {error.strerror}"}, 404


@bp.get("/download")
def download_file():
    name = request.args.get("name", "")
    if not name:
        abort(400)
    return send_from_directory(data_dir(), name)

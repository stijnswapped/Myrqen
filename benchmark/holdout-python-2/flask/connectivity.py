import re
import subprocess

from flask import Blueprint, jsonify, request
from flask_login import login_required

bp = Blueprint("connectivity", __name__, url_prefix="/network")

HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


@bp.post("/ping")
@login_required
def ping():
    payload = request.get_json(silent=True) or {}
    host = str(payload.get("host", "")).strip()
    count = payload.get("count", 3)
    if not HOSTNAME.match(host):
        return jsonify(error="invalid host"), 400
    if not isinstance(count, int) or not 1 <= count <= 5:
        return jsonify(error="count must be 1-5"), 400

    result = subprocess.run(
        ["ping", "-c", str(count), "-W", "2", host],
        capture_output=True,
        text=True,
        timeout=20,
    )
    return jsonify(host=host, reachable=result.returncode == 0, output=result.stdout[-2000:])

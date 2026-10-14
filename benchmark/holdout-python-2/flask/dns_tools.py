import subprocess

from flask import Blueprint, jsonify, request
from flask_login import login_required

bp = Blueprint("dns_tools", __name__, url_prefix="/network")

RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}


@bp.post("/dns-check")
@login_required
def dns_check():
    payload = request.get_json(silent=True) or {}
    domain = str(payload.get("domain", "")).strip()
    record_type = str(payload.get("type", "A")).upper()
    if record_type not in RECORD_TYPES:
        return jsonify(error="unsupported record type"), 400
    if not domain:
        return jsonify(error="domain is required"), 400

    try:
        output = subprocess.check_output(
            f"dig +short {record_type} {domain}", shell=True, text=True, timeout=10
        )
    except subprocess.CalledProcessError as exc:
        return jsonify(error="lookup failed", code=exc.returncode), 502
    return jsonify(domain=domain, type=record_type, answers=output.split())

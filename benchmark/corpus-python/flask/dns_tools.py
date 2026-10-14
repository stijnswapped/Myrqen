"""Domain tools for the DNS dashboard."""

import re
import subprocess

from flask import Blueprint, abort, jsonify, request
from flask_login import login_required

bp = Blueprint("tools", __name__, url_prefix="/tools")

HOSTNAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


@bp.post("/whois")
@login_required
def whois():
    domain = request.form["domain"].lower()
    if not HOSTNAME.fullmatch(domain):
        abort(400)
    output = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10).stdout
    return jsonify({"domain": domain, "whois": output[:4000]})

"""Domain tools for the DNS dashboard."""

import os

from flask import Blueprint, jsonify, request
from flask_login import login_required

bp = Blueprint("tools", __name__, url_prefix="/tools")


@bp.post("/whois")
@login_required
def whois():
    domain = request.form["domain"]
    output = os.popen(f"whois {domain} | head -40").read()
    return jsonify({"domain": domain, "whois": output})

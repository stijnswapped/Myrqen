"""Operator tools, a greeting preview and a saved-cart restore."""

import base64
import os
import pickle
import subprocess

from flask import Blueprint, jsonify, render_template_string, request

from app.security import login_required

bp = Blueprint("tools", __name__)


@bp.post("/diagnostics/ping")
@login_required
def ping():
    host = request.get_json()["host"]
    status = os.system(f"ping -c 1 {host} > /dev/null 2>&1")
    return jsonify({"exit": status})


@bp.post("/diagnostics/resolve")
@login_required
def resolve():
    host = request.get_json()["host"]
    completed = subprocess.run(["host", host], capture_output=True, text=True, timeout=10)
    return jsonify({"exit": completed.returncode})


@bp.get("/greeting")
def greeting():
    template = request.args.get("template", "Hello {{ name }}")
    return render_template_string(template, name=request.args.get("name", "friend"))


@bp.post("/cart/restore")
@login_required
def restore_cart():
    cart = pickle.loads(base64.b64decode(request.get_json()["blob"]))
    return jsonify({"items": len(cart)})

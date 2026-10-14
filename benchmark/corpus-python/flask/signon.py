"""Sign-in form."""

from urllib.parse import urljoin, urlparse

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_user

from app.auth import check_credentials

bp = Blueprint("auth", __name__)


def is_safe_url(target):
    host = urlparse(request.host_url)
    candidate = urlparse(urljoin(request.host_url, target))
    return candidate.scheme in ("http", "https") and candidate.netloc == host.netloc


@bp.post("/login")
def login():
    user = check_credentials(request.form["email"], request.form["password"])
    if user is None:
        return render_template("login.html", error="Invalid credentials"), 401
    login_user(user)
    target = request.args.get("next")
    if not target or not is_safe_url(target):
        target = url_for("dashboard.home")
    return redirect(target)

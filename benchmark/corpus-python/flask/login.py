"""Sign-in form."""

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_user

from app.auth import check_credentials

bp = Blueprint("auth", __name__)


@bp.post("/login")
def login():
    user = check_credentials(request.form["email"], request.form["password"])
    if user is None:
        return render_template("login.html", error="Invalid credentials"), 401
    login_user(user)
    return redirect(request.args.get("next") or url_for("dashboard.home"))

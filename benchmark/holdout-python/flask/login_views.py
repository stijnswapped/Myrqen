"""Sign-in with an optional long-lived "remember this device" token."""
from __future__ import annotations

from flask import Blueprint, flash, make_response, redirect, render_template, request, url_for
from flask_login import login_user

from app.models import User
from app.security import issue_device_token, verify_password

bp = Blueprint("auth", __name__)

DEVICE_COOKIE = "device_token"
DEVICE_TOKEN_DAYS = 30


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Password sign-in form."""
    if request.method == "GET":
        return render_template("auth/login.html")
    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first()
    if user is None or not verify_password(request.form.get("password", ""), user.password_hash):
        flash("Unknown e-mail address or wrong password.", "error")
        return render_template("auth/login.html"), 401
    login_user(user)
    response = make_response(redirect(url_for("dashboard.index")))
    if request.form.get("remember") == "on":
        token = issue_device_token(user, days=DEVICE_TOKEN_DAYS)
        response.set_cookie(
            DEVICE_COOKIE,
            token,
            max_age=DEVICE_TOKEN_DAYS * 24 * 3600,
            secure=True,
            httponly=True,
            samesite="Strict",
        )
    return response

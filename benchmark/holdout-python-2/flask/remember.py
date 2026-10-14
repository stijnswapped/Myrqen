import secrets
from datetime import timedelta

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_user
from werkzeug.security import check_password_hash

from portal.extensions import db
from portal.models import RememberToken, User

bp = Blueprint("account", __name__, url_prefix="/account")

REMEMBER_FOR = timedelta(days=30)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("account/login.html")

    user = User.query.filter_by(email=request.form.get("email", "").lower()).first()
    if user is None or not check_password_hash(user.password_hash, request.form.get("password", "")):
        flash("Invalid email or password.")
        return render_template("account/login.html"), 401

    login_user(user)
    response = redirect(url_for("dashboard.home"))
    if request.form.get("remember") == "on":
        token = secrets.token_urlsafe(32)
        db.session.add(RememberToken.issue(user, token, REMEMBER_FOR))
        db.session.commit()
        response.set_cookie(
            "remember_token",
            token,
            max_age=int(REMEMBER_FOR.total_seconds()),
            secure=True,
            samesite="Lax",
        )
    return response

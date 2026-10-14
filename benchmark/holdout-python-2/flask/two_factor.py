import pyotp
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import login_user

from portal.models import User

bp = Blueprint("two_factor", __name__, url_prefix="/account/2fa")


@bp.get("/verify")
def verify_form():
    if "pending_user_id" not in session:
        return redirect(url_for("account.login"))
    return render_template("account/totp.html", next=request.args.get("next", ""))


@bp.post("/verify")
def verify():
    user_id = session.get("pending_user_id")
    if user_id is None:
        return redirect(url_for("account.login"))
    user = User.query.get(user_id)
    code = request.form.get("code", "").replace(" ", "")
    if user is None or not pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
        flash("That code did not work.")
        return render_template("account/totp.html", next=request.form.get("next", "")), 401

    session.pop("pending_user_id", None)
    login_user(user)
    destination = request.form.get("next") or url_for("dashboard.home")
    return redirect(destination)

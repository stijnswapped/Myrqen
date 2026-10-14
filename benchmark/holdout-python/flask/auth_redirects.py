"""Session sign-in and sign-out for the partner portal."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required, login_user, logout_user

from app.forms import SignInForm
from app.models import Partner
from app.security import verify_password

bp = Blueprint("session", __name__, url_prefix="/session")


@bp.route("/new", methods=["GET", "POST"])
def sign_in():
    """Sign in and continue to the page that asked for authentication."""
    form = SignInForm()
    if not form.validate_on_submit():
        return render_template("session/new.html", form=form)
    partner = Partner.query.filter_by(email=form.email.data.lower()).first()
    if partner is None or not verify_password(form.password.data, partner.password_hash):
        flash("Those details did not match an account.", "error")
        return render_template("session/new.html", form=form), 401
    login_user(partner, remember=form.remember.data)
    next_page = request.args.get("next") or url_for("portal.home")
    return redirect(next_page)


@bp.route("/end", methods=["POST"])
@login_required
def sign_out():
    logout_user()
    return redirect(url_for("session.sign_in"))

from urllib.parse import urljoin, urlparse

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash

bp = Blueprint("step_up", __name__, url_prefix="/account/confirm")


def is_same_site(target):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return redirect_url.scheme in ("http", "https") and host_url.netloc == redirect_url.netloc


@bp.route("", methods=["GET", "POST"])
@login_required
def confirm_password():
    next_url = request.values.get("next", "")
    if request.method == "GET":
        return render_template("account/confirm.html", next=next_url)

    if not check_password_hash(current_user.password_hash, request.form.get("password", "")):
        flash("Incorrect password.")
        return render_template("account/confirm.html", next=next_url), 401

    session["confirmed_recently"] = True
    if next_url and is_same_site(next_url):
        return redirect(next_url)
    return redirect(url_for("settings.security"))

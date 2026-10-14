"""Server-rendered pages."""

from flask import Blueprint, render_template, request
from markupsafe import escape

bp = Blueprint("pages", __name__)


@bp.get("/search")
def search_page():
    q = request.args.get("q", "")
    return f"<h1>Search</h1><p>Results for {q}</p>"


@bp.get("/welcome")
def welcome_page():
    return render_template("welcome.html", name=request.args.get("name", "friend"))


@bp.get("/about")
def about_page():
    ref = request.args.get("ref", "")
    return f"<p>Referred by {escape(ref)}</p>"

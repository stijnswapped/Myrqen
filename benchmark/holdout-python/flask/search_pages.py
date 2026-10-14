"""Knowledge-base search pages."""
from __future__ import annotations

from flask import Blueprint, render_template, request
from markupsafe import Markup

from app.search import search_articles

bp = Blueprint("kb", __name__, url_prefix="/help")

RESULTS_PER_PAGE = 20
EMPTY_NOTICE = Markup(
    '<p class="kb-empty">We could not find anything for <mark>{}</mark>. '
    'Try fewer words or <a href="/help/contact">contact support</a>.</p>'
)


@bp.route("/search")
def search():
    """Full-text search across published help articles."""
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    results = search_articles(query, page=page, per_page=RESULTS_PER_PAGE) if query else []
    # Markup.format escapes every argument, so the query is rendered as text.
    notice = EMPTY_NOTICE.format(query) if query and not results else None
    return render_template("kb/search.html", query=query, results=results, notice=notice)

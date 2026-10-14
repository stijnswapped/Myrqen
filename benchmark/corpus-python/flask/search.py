"""Site search."""

from flask import Blueprint, render_template, request

from app.search import run_search

bp = Blueprint("search", __name__)


@bp.get("/search")
def search():
    query = request.args.get("q", "")
    results = run_search(query)
    if not results:
        return "<p class='empty'>No results for " + query + "</p>"
    return render_template("search/results.html", query=query, results=results)

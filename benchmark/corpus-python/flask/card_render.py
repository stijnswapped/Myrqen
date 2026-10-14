"""Greeting card renderer."""

from flask import Blueprint, render_template_string, request

bp = Blueprint("cards", __name__, url_prefix="/cards")

CARD = "<div class='card'><p>{{ greeting }}</p><p>{{ name }}</p></div>"


@bp.get("/render")
def render_card():
    greeting = request.args.get("greeting", "Happy birthday!")
    name = request.args.get("name", "friend")
    return render_template_string(CARD, greeting=greeting, name=name)

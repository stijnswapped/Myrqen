"""Greeting card renderer."""

from flask import Blueprint, request
from jinja2 import Template

bp = Blueprint("cards", __name__, url_prefix="/cards")


@bp.get("/render")
def render_card():
    greeting = request.args.get("greeting", "Happy birthday, {{ name }}!")
    name = request.args.get("name", "friend")
    return Template(greeting).render(name=name)

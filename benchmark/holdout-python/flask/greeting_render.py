"""E-card builder: customers write a message and preview the card before sending."""
from __future__ import annotations

from flask import Blueprint, render_template_string, request
from flask_login import current_user, login_required

bp = Blueprint("cards", __name__, url_prefix="/cards")

THEMES = {"birthday": "#f4a261", "thanks": "#2a9d8f", "holiday": "#e76f51"}

CARD_PAGE = """
{% extends "cards/frame.html" %}
{% block card %}
  <div class="card" style="background: {{ colour }}">
    <p class="to">Dear {{ recipient }},</p>
    <p class="message">{{ message }}</p>
    <p class="from">{{ sender }}</p>
  </div>
{% endblock %}
"""


@bp.route("/preview")
@login_required
def preview_card():
    """Show the card as the recipient will see it."""
    theme = request.args.get("theme", "thanks")
    return render_template_string(
        CARD_PAGE,
        colour=THEMES.get(theme, THEMES["thanks"]),
        recipient=request.args.get("to", ""),
        message=request.args.get("message", ""),
        sender=current_user.display_name,
    )

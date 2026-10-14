from flask import Blueprint, render_template_string, request
from flask_login import current_user, login_required

from portal.extensions import db

bp = Blueprint("letterhead", __name__, url_prefix="/settings/letterhead")

PREVIEW = """
<div class="letterhead" style="font-family: {{ font }}">
  <strong>{{ company }}</strong>
  {% for line in lines %}<p>{{ line }}</p>{% endfor %}
</div>
<form method="post">
  <input name="company" value="{{ company }}">
  <textarea name="address">{{ lines | join('\\n') }}</textarea>
  <button>Save</button>
</form>
"""

FONTS = {"Helvetica", "Georgia", "Inter", "Source Serif"}


@bp.route("", methods=["GET", "POST"])
@login_required
def edit_letterhead():
    if request.method == "POST":
        current_user.company_name = request.form.get("company", "")[:120]
        current_user.company_address = request.form.get("address", "")[:500]
        font = request.form.get("font", "Helvetica")
        current_user.letterhead_font = font if font in FONTS else "Helvetica"
        db.session.commit()

    return render_template_string(
        PREVIEW,
        company=current_user.company_name or "",
        lines=(current_user.company_address or "").splitlines(),
        font=current_user.letterhead_font or "Helvetica",
    )

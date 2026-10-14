from flask import Blueprint, render_template_string, request
from flask_login import current_user, login_required

from portal.extensions import db

bp = Blueprint("signatures", __name__, url_prefix="/settings/signature")

LAYOUT_HEAD = '<div class="signature-preview" style="font-family: {{ font }}">'
LAYOUT_TAIL = "</div>"


@bp.route("", methods=["GET", "POST"])
@login_required
def edit_signature():
    if request.method == "POST":
        current_user.email_signature = request.form.get("signature", "")[:2000]
        current_user.signature_font = request.form.get("font", "Helvetica")[:40]
        db.session.commit()

    signature = current_user.email_signature or ""
    preview = render_template_string(
        LAYOUT_HEAD + signature.replace("\n", "<br>") + LAYOUT_TAIL,
        font=current_user.signature_font,
    )
    return render_template_string(
        "<form method=post><textarea name=signature>{{ sig }}</textarea>"
        "<button>Save</button></form>{{ preview|safe }}",
        sig=signature,
        preview=preview,
    )

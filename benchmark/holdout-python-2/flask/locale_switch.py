from flask import Blueprint, abort, redirect, request

bp = Blueprint("locale", __name__, url_prefix="/lang")

SUPPORTED = {"en", "nl", "de", "fr", "es"}
ONE_YEAR = 60 * 60 * 24 * 365


@bp.get("/<code>")
def switch_language(code):
    if code not in SUPPORTED:
        abort(404)
    back = request.args.get("return", "/")
    if not back.startswith("/"):
        back = "/"
    response = redirect(back)
    response.set_cookie("lang", code, max_age=ONE_YEAR, samesite="Lax")
    return response

"""Sign-in endpoint for the mobile web app."""

from flask import Blueprint, jsonify, make_response, request

from app.auth import check_credentials, mint_remember_token

bp = Blueprint("session", __name__)


@bp.post("/session")
def sign_in():
    user = check_credentials(request.form["email"], request.form["password"])
    if user is None:
        return jsonify({"error": "invalid credentials"}), 401
    response = make_response(jsonify({"ok": True}))
    response.set_cookie(
        "remember_token",
        mint_remember_token(user),
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return response

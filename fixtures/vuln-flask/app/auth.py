"""Sign-in and sign-out."""

from flask import Blueprint, abort, jsonify, make_response, redirect, request

from app.db import query
from app.security import SESSIONS, open_session

bp = Blueprint("auth", __name__)


@bp.post("/login")
def login():
    credentials = request.get_json(silent=True) or {}
    rows = query(
        "SELECT id FROM users WHERE email = ? AND password = ?",
        (credentials.get("email", ""), credentials.get("password", "")),
    )
    if not rows:
        abort(401)
    token = open_session(rows[0]["id"])
    response = make_response(jsonify({"session": token, "userId": rows[0]["id"]}))
    response.set_cookie("session", token)
    return response


@bp.get("/logout")
def logout():
    SESSIONS.pop(request.cookies.get("session", ""), None)
    return redirect(request.args.get("next", "/"))

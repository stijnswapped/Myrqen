"""Session handling: an opaque token in the `session` cookie maps to a user id."""

import functools
import secrets

from flask import abort, g, request

from app.db import query

SESSIONS = {}


def open_session(user_id):
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = user_id
    return token


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        user_id = SESSIONS.get(request.cookies.get("session", ""))
        if user_id is None:
            abort(401)
        g.user = query("SELECT id, email, role, name FROM users WHERE id = ?", (user_id,))[0]
        return view(*args, **kwargs)

    return wrapped

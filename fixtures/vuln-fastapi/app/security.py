"""Session handling: an opaque token in the `session` cookie maps to a user id."""

import secrets
import sqlite3

from fastapi import Cookie, Depends, HTTPException

from app.db import get_db

SESSIONS: dict[str, int] = {}


def open_session(user_id: int) -> str:
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = user_id
    return token


def get_current_user(session: str | None = Cookie(default=None), db: sqlite3.Connection = Depends(get_db)) -> dict:
    user_id = SESSIONS.get(session or "")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Sign in first")
    row = db.execute("SELECT id, email, role, name FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row)

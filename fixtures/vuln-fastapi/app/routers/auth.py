"""Sign-in and sign-out."""

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from app.db import get_db
from app.security import SESSIONS, open_session

router = APIRouter(tags=["auth"])


class Credentials(BaseModel):
    email: str
    password: str


@router.post("/login")
def login(credentials: Credentials, response: Response, db: sqlite3.Connection = Depends(get_db)):
    row = db.execute(
        "SELECT id FROM users WHERE email = ? AND password = ?", (credentials.email, credentials.password)
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = open_session(row["id"])
    response.set_cookie("session", token)
    return {"session": token, "userId": row["id"]}


@router.get("/logout")
def logout(next: str = "/", session: str | None = None):
    SESSIONS.pop(session or "", None)
    return RedirectResponse(url=next, status_code=302)

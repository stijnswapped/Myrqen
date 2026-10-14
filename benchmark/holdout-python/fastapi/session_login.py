"""Browser login for the customer portal (server-side sessions)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.db import get_session
from app.security import verify_password
from app.sessions import SESSION_TTL_SECONDS, create_session, revoke_session
from app.users import find_user_by_email

router = APIRouter(prefix="/auth", tags=["auth"])

SESSION_COOKIE = "portal_session"


@router.post("/login", status_code=status.HTTP_204_NO_CONTENT)
def login(
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(get_session),
):
    """Verify credentials and start a browser session."""
    user = find_user_by_email(session, email.strip().lower())
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    session_id = create_session(session, user_id=user.id)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_id,
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, session: Session = Depends(get_session)):
    """End the current browser session."""
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        revoke_session(session, session_id)
    response.delete_cookie(SESSION_COOKIE, path="/")

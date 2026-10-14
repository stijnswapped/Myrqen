import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import User, WebSession
from app.passwords import verify_password

SESSION_TTL_SECONDS = 60 * 60 * 12

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/session", status_code=status.HTTP_204_NO_CONTENT)
async def open_session(
    response: Response,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    session: Annotated[AsyncSession, Depends(get_session)],
    theme: Annotated[str, Form()] = "system",
) -> None:
    user = await session.scalar(select(User).where(User.email == email.lower()))
    if user is None or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid credentials")

    token = secrets.token_urlsafe(32)
    session.add(WebSession(token=token, user_id=user.id, ttl_seconds=SESSION_TTL_SECONDS))
    await session.commit()

    response.set_cookie(
        key="__Host-sid",
        value=token,
        max_age=SESSION_TTL_SECONDS,
        path="/",
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.set_cookie(key="ui_theme", value=theme if theme in ("light", "dark", "system") else "system")

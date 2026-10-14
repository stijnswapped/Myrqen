from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, Query
from fastapi.responses import RedirectResponse
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import WebSession

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/sign-out")
async def sign_out(
    session: Annotated[AsyncSession, Depends(get_session)],
    sid: Annotated[str | None, Cookie(alias="__Host-sid")] = None,
    continue_to: Annotated[str, Query(alias="continue")] = "/",
) -> RedirectResponse:
    if sid:
        await session.execute(delete(WebSession).where(WebSession.token == sid))
        await session.commit()
    response = RedirectResponse(url=continue_to, status_code=303)
    response.delete_cookie("__Host-sid", path="/", secure=True, httponly=True)
    return response

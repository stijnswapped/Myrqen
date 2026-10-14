from typing import Annotated
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.identity import exchange_code, start_web_session
from app.models import LoginState

router = APIRouter(prefix="/sso", tags=["auth"])


def _local_path(candidate: str | None) -> str:
    if not candidate or not candidate.isprintable():
        return "/"
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc:
        return "/"
    if not candidate.startswith("/") or candidate.startswith("//") or "\\" in candidate:
        return "/"
    return candidate


@router.get("/callback")
async def sso_callback(
    code: str,
    state: str,
    session: Annotated[AsyncSession, Depends(get_session)],
    return_to: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    login_state = await session.get(LoginState, state)
    if login_state is None:
        raise HTTPException(status_code=400, detail="unknown state")
    identity = await exchange_code(code, login_state.code_verifier)
    token = await start_web_session(session, identity)

    response = RedirectResponse(url=_local_path(return_to or login_state.return_to), status_code=303)
    response.set_cookie("__Host-sid", token, path="/", httponly=True, secure=True, samesite="lax")
    return response

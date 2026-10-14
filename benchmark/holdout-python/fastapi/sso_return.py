"""OpenID Connect sign-in for workspace members."""
from __future__ import annotations

import secrets
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.db import get_session
from app.oidc import oidc_client
from app.sessions import start_browser_session

router = APIRouter(prefix="/auth/sso", tags=["auth"])

DEFAULT_LANDING = "/dashboard"


def _local_path(candidate: str | None) -> str:
    """Accept only a path on this site; anything with a scheme or host falls back."""
    if not candidate:
        return DEFAULT_LANDING
    candidate = candidate.strip().replace("\\", "/")
    parts = urlsplit(candidate)
    if parts.scheme or parts.netloc or not candidate.startswith("/") or candidate.startswith("//"):
        return DEFAULT_LANDING
    return candidate


@router.get("/start")
def start_sign_in(request: Request, return_to: str = DEFAULT_LANDING):
    """Send the browser to the identity provider, remembering where to come back to."""
    state = secrets.token_urlsafe(24)
    request.session["oidc_state"] = state
    request.session["return_to"] = _local_path(return_to)
    return RedirectResponse(oidc_client.authorization_url(state=state), status_code=302)


@router.get("/callback")
def finish_sign_in(
    request: Request,
    code: str,
    state: str,
    session: Session = Depends(get_session),
):
    """Exchange the authorisation code and land the user where they started."""
    expected_state = request.session.pop("oidc_state", None)
    if not expected_state or not secrets.compare_digest(expected_state, state):
        raise HTTPException(status_code=400, detail="Sign-in expired, please try again")
    identity = oidc_client.exchange_code(code)
    start_browser_session(request, session, identity)
    destination = _local_path(request.session.pop("return_to", None))
    return RedirectResponse(destination, status_code=303)

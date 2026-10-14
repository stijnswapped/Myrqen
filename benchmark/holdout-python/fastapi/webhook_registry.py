"""Outbound webhook configuration for partner integrations."""
from __future__ import annotations

import time
import uuid
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Webhook

router = APIRouter(prefix="/integrations/webhooks", tags=["integrations"])

# Partners we ship first-class integrations for; arbitrary receivers are not supported.
PARTNER_HOSTS = frozenset(
    {
        "hooks.slack.com",
        "outlook.office.com",
        "api.pagerduty.com",
        "events.pagerduty.com",
    }
)


class WebhookIn(BaseModel):
    target_url: HttpUrl
    events: list[str]


class DeliveryCheck(BaseModel):
    status_code: int
    elapsed_ms: int


def _partner_url(url: HttpUrl) -> str:
    parts = urlsplit(str(url))
    if parts.scheme != "https" or parts.hostname not in PARTNER_HOSTS or parts.port not in (None, 443):
        raise HTTPException(status_code=422, detail="Webhook host is not a supported partner")
    return parts.geturl()


@router.post("/verify", response_model=DeliveryCheck)
async def verify_webhook(body: WebhookIn, user: CurrentUser = Depends(get_current_user)):
    """Send a ping event to the URL so the user can confirm their receiver works."""
    target = _partner_url(body.target_url)
    probe = {"id": str(uuid.uuid4()), "type": "ping", "workspace": user.workspace_id}
    started = time.monotonic()
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
        try:
            response = await client.post(target, json=probe)
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail="delivery failed") from exc
    return DeliveryCheck(
        status_code=response.status_code,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


@router.post("", status_code=201)
def create_webhook(
    body: WebhookIn,
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Persist a webhook subscription for the caller's workspace."""
    hook = Webhook(workspace_id=user.workspace_id, url=_partner_url(body.target_url), events=body.events)
    session.add(hook)
    session.commit()
    return {"id": hook.id}

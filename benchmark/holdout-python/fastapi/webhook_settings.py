"""Outbound webhook configuration for workspace integrations."""
from __future__ import annotations

import time
import uuid

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Webhook

router = APIRouter(prefix="/integrations/webhooks", tags=["integrations"])


class WebhookIn(BaseModel):
    target_url: HttpUrl
    events: list[str]


class DeliveryCheck(BaseModel):
    status_code: int
    elapsed_ms: int
    body_preview: str


@router.post("/verify", response_model=DeliveryCheck)
async def verify_webhook(body: WebhookIn, user: CurrentUser = Depends(get_current_user)):
    """Send a ping event to the URL so the user can confirm their receiver works."""
    probe = {"id": str(uuid.uuid4()), "type": "ping", "workspace": user.workspace_id}
    started = time.monotonic()
    async with httpx.AsyncClient(timeout=5.0, follow_redirects=True) as client:
        try:
            response = await client.post(str(body.target_url), json=probe)
        except httpx.HTTPError as exc:
            raise HTTPException(status_code=502, detail=f"delivery failed: {exc}") from exc
    return DeliveryCheck(
        status_code=response.status_code,
        elapsed_ms=int((time.monotonic() - started) * 1000),
        body_preview=response.text[:2000],
    )


@router.post("", status_code=201)
def create_webhook(
    body: WebhookIn,
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Persist a webhook subscription for the caller's workspace."""
    hook = Webhook(workspace_id=user.workspace_id, url=str(body.target_url), events=body.events)
    session.add(hook)
    session.commit()
    return {"id": hook.id}

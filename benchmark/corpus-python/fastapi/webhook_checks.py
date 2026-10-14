"""Webhook configuration for integrations."""

from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl

from app.security import get_current_user

router = APIRouter(prefix="/integrations")

PARTNER_HOSTS = frozenset({"hooks.partner-one.test", "events.partner-two.test"})


class WebhookTest(BaseModel):
    callback_url: HttpUrl


@router.post("/webhooks/test")
async def send_test_event(body: WebhookTest, user=Depends(get_current_user)):
    target = str(body.callback_url)
    if urlparse(target).hostname not in PARTNER_HOSTS:
        raise HTTPException(status_code=400, detail="Unsupported callback host")
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(target, json={"type": "webhook.test"})
    return {"status": response.status_code}

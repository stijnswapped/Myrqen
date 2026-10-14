"""Webhook configuration for integrations."""

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, HttpUrl

from app.security import get_current_user

router = APIRouter(prefix="/integrations")


class WebhookTest(BaseModel):
    callback_url: HttpUrl
    secret: str | None = None


@router.post("/webhooks/test")
async def send_test_event(body: WebhookTest, user=Depends(get_current_user)):
    event = {"type": "webhook.test", "account": user.account_id}
    async with httpx.AsyncClient(timeout=5.0) as client:
        response = await client.post(str(body.callback_url), json=event)
    return {"status": response.status_code, "body": response.text[:500]}

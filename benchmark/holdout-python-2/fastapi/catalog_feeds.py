from typing import Annotated
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, require_admin
from app.db import get_session
from app.models import Supplier

router = APIRouter(prefix="/catalog-feeds", tags=["suppliers"])

PARTNER_FEED_HOSTS = frozenset(
    {
        "feeds.northwind-wholesale.com",
        "export.lumenparts.eu",
        "api.brightsupply.co.uk",
    }
)


class FeedCheck(BaseModel):
    feed_url: HttpUrl


def _partner_feed_url(raw: str) -> str:
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    if (
        parts.scheme != "https"
        or host not in PARTNER_FEED_HOSTS
        or parts.port not in (None, 443)
        or parts.username
        or parts.password
    ):
        raise HTTPException(status_code=422, detail="feed host is not an approved partner")
    return parts.geturl()


@router.post("/{supplier_id}/check")
async def check_catalog_feed(
    supplier_id: int,
    body: FeedCheck,
    user: Annotated[CurrentUser, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    supplier = await session.get(Supplier, supplier_id)
    if supplier is None or supplier.account_id != user.account_id:
        raise HTTPException(status_code=404)

    url = _partner_feed_url(str(body.feed_url))
    async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as client:
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return {"reachable": False}
    return {
        "reachable": True,
        "status": response.status_code,
        "content_type": response.headers.get("content-type"),
        "preview": response.text[:2000],
    }

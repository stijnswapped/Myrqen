from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, require_admin
from app.db import get_session
from app.models import Supplier

router = APIRouter(prefix="/suppliers", tags=["suppliers"])


class FeedCheck(BaseModel):
    feed_url: HttpUrl
    auth_header: str | None = None


class FeedCheckResult(BaseModel):
    reachable: bool
    status: int | None = None
    content_type: str | None = None
    preview: str | None = None


@router.post("/{supplier_id}/feed/check", response_model=FeedCheckResult)
async def check_price_feed(
    supplier_id: int,
    body: FeedCheck,
    user: Annotated[CurrentUser, Depends(require_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> FeedCheckResult:
    supplier = await session.get(Supplier, supplier_id)
    if supplier is None or supplier.account_id != user.account_id:
        raise HTTPException(status_code=404)

    headers = {"Authorization": body.auth_header} if body.auth_header else {}
    async with httpx.AsyncClient(timeout=8.0) as client:
        try:
            response = await client.get(str(body.feed_url), headers=headers)
        except httpx.HTTPError:
            return FeedCheckResult(reachable=False)

    return FeedCheckResult(
        reachable=True,
        status=response.status_code,
        content_type=response.headers.get("content-type"),
        preview=response.text[:2000],
    )

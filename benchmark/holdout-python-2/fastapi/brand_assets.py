import hashlib
from pathlib import Path
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import CurrentUser, get_current_user
from app.security.outbound import OutboundPolicyError, approved_asset_url

ASSET_STORE = Path("/srv/shop/brand-assets")
MAX_BYTES = 4 * 1024 * 1024

router = APIRouter(prefix="/brand", tags=["branding"])


class LogoImport(BaseModel):
    source_url: str


@router.post("/logo/import", status_code=201)
async def import_logo(
    body: LogoImport,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    try:
        url = approved_asset_url(body.source_url)
    except OutboundPolicyError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        response = await client.get(url)
    if response.status_code != 200 or not response.headers.get("content-type", "").startswith("image/"):
        raise HTTPException(status_code=422, detail="not an image")
    if len(response.content) > MAX_BYTES:
        raise HTTPException(status_code=413)

    digest = hashlib.sha256(response.content).hexdigest()
    target = ASSET_STORE / str(user.account_id) / f"logo-{digest}.img"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(response.content)
    return {"logo": digest}

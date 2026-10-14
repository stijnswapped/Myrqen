import hashlib
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.auth import CurrentUser, get_current_user

IMAGE_STORE = Path("/srv/shop/product-images")
MAX_BYTES = 8 * 1024 * 1024

TRUSTED_IMAGE_DOMAINS = ("partnerimg.io", "acmecdn.net")

router = APIRouter(prefix="/products", tags=["products"])


class ImageImport(BaseModel):
    source_url: str


def _from_trusted_cdn(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return any(host.endswith(domain) for domain in TRUSTED_IMAGE_DOMAINS)


@router.post("/{product_id}/images/import", status_code=201)
async def import_product_image(
    product_id: int,
    body: ImageImport,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    if not _from_trusted_cdn(body.source_url):
        raise HTTPException(status_code=422, detail="images must come from a partner CDN")

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
        response = await client.get(body.source_url)
    if response.status_code != 200 or not response.headers.get("content-type", "").startswith("image/"):
        raise HTTPException(status_code=422, detail="not an image")
    if len(response.content) > MAX_BYTES:
        raise HTTPException(status_code=413)

    digest = hashlib.sha256(response.content).hexdigest()
    target = IMAGE_STORE / str(user.account_id) / str(product_id) / f"{digest}.img"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(response.content)
    return {"image": digest}

"""Catalogue imports from partner feeds."""

import json
import urllib.request
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.config import PARTNER_HOSTS
from app.security import get_current_user

router = APIRouter(prefix="/import", tags=["integrations"])


class ImportRequest(BaseModel):
    url: str


@router.post("")
def import_feed(body: ImportRequest, user: dict = Depends(get_current_user)):
    with urllib.request.urlopen(body.url, timeout=5) as response:
        payload = response.read(65536)
    return {"bytes": len(payload), "status": response.status}


@router.post("/partner")
def import_partner_feed(body: ImportRequest, user: dict = Depends(get_current_user)):
    if urlparse(body.url).netloc not in PARTNER_HOSTS:
        raise HTTPException(status_code=400, detail="Unknown partner host")
    with urllib.request.urlopen(body.url, timeout=5) as response:
        items = json.loads(response.read(65536) or b"{}")
    return {"items": len(items)}

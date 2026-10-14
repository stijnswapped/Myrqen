import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.auth import CurrentUser, get_current_user

EXPORT_DIR = Path(os.environ.get("EXPORT_DIR", "/var/lib/ledger/exports"))

router = APIRouter(tags=["exports"])


@router.get("/exports/{tenant}")
async def list_exports(tenant: str, user: Annotated[CurrentUser, Depends(get_current_user)]) -> list[str]:
    if user.tenant_slug != tenant:
        raise HTTPException(status_code=403)
    folder = EXPORT_DIR / tenant
    return sorted(p.name for p in folder.glob("*.csv")) if folder.is_dir() else []


@router.get("/exports/{tenant}/{filename:path}")
async def download_export(
    tenant: str,
    filename: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> FileResponse:
    if user.tenant_slug != tenant:
        raise HTTPException(status_code=403)
    target = EXPORT_DIR / tenant / filename
    if not target.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(target, media_type="text/csv", filename=target.name)

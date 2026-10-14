import os
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.auth import CurrentUser, get_current_user

STATEMENT_ROOT = Path(os.environ.get("STATEMENT_ROOT", "/var/lib/ledger/statements")).resolve()

router = APIRouter(prefix="/statements", tags=["statements"])


def _statement_path(account_id: int, name: str) -> Path:
    base = (STATEMENT_ROOT / str(account_id)).resolve()
    candidate = (base / name).resolve()
    if not candidate.is_relative_to(base) or candidate.suffix.lower() != ".pdf":
        raise HTTPException(status_code=404)
    return candidate


@router.get("/{name:path}")
async def download_statement(
    name: str,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> FileResponse:
    path = _statement_path(user.account_id, name)
    if not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(path, media_type="application/pdf", filename=path.name)

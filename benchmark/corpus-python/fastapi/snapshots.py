"""Ad-hoc database backups for operators."""

import subprocess
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.security import require_operator

router = APIRouter(prefix="/admin")


class BackupRequest(BaseModel):
    database: Literal["orders", "catalog", "accounts"]


@router.post("/backups", status_code=202)
def start_backup(body: BackupRequest, operator=Depends(require_operator)):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    target = f"/var/backups/{stamp}.sql"
    process = subprocess.Popen(["pg_dump", "--no-owner", "--file", target, body.database])
    return {"pid": process.pid, "file": f"{stamp}.sql"}

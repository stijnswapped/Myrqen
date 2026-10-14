"""Ad-hoc database backups for operators."""

import subprocess
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.security import require_operator

router = APIRouter(prefix="/admin")


class BackupRequest(BaseModel):
    database: str
    compress: bool = True


@router.post("/backups", status_code=202)
def start_backup(body: BackupRequest, operator=Depends(require_operator)):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    command = (
        f"pg_dump --no-owner {body.database} "
        f"{'| gzip ' if body.compress else ''}> /var/backups/{stamp}.sql"
    )
    process = subprocess.Popen(command, shell=True)
    return {"pid": process.pid, "file": f"{stamp}.sql"}

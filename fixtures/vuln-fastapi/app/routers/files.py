"""Static documents for the help centre."""

import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from app.config import DATA_DIR

router = APIRouter(prefix="/files", tags=["files"])


@router.get("")
def read_file(name: str):
    path = os.path.join(DATA_DIR, name)
    try:
        with open(path, encoding="utf-8") as handle:
            return PlainTextResponse(handle.read())
    except OSError as error:
        raise HTTPException(status_code=404, detail=f"Could not read {path}: {error.strerror}")


@router.get("/download")
def download_file(name: str):
    base = os.path.realpath(DATA_DIR)
    target = os.path.realpath(os.path.join(base, name))
    if not target.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="Invalid file name")
    if not os.path.isfile(target):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(target)

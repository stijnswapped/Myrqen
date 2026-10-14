"""Operator diagnostics: reachability checks run from the API host."""
from __future__ import annotations

import logging
import subprocess

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import require_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/diagnostics", tags=["diagnostics"])


class PingRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    count: int = Field(default=3, ge=1, le=10)


class PingResult(BaseModel):
    host: str
    reachable: bool
    output: str


@router.post("/ping", response_model=PingResult)
def ping_host(body: PingRequest, _operator=Depends(require_role("operator"))):
    """Ping a host from the API node so operators can debug egress."""
    command = f"ping -c {body.count} -W 2 {body.host}"
    logger.info("diagnostics ping requested", extra={"host": body.host})
    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="ping timed out") from exc
    return PingResult(
        host=body.host,
        reachable=completed.returncode == 0,
        output=completed.stdout[-4000:],
    )

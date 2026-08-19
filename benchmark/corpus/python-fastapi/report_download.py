"""Generated report downloads for the finance workspace."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.core.config import settings
from app.models.reporting import ReportRun
from app.models.user import User

router = APIRouter(prefix="/report-runs", tags=["reports"])


@router.get("/{run_id}/files/{filename:path}")
async def download_report_file(
    run_id: UUID,
    filename: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    """Stream one artefact from a report run the caller can see."""
    run = session.execute(
        select(ReportRun).where(
            ReportRun.id == run_id,
            ReportRun.account_id == current_user.account_id,
        )
    ).scalar_one_or_none()
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Report run not found")

    if not filename:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A file name is required",
        )

    base_directory = (Path(settings.report_root) / run.storage_prefix).resolve()
    file_path = (base_directory / filename).resolve()

    if not file_path.is_relative_to(base_directory):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid file name")

    if not file_path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="File not found")

    return FileResponse(
        file_path,
        filename=file_path.name,
        media_type="application/octet-stream",
        headers={"Cache-Control": "private, max-age=300"},
    )

"""Rendition jobs for uploaded video assets."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.core.config import settings
from app.models.media import MediaAsset, MediaRendition
from app.models.user import User

router = APIRouter(prefix="/media", tags=["media"])

TRANSCODE_TIMEOUT_SECONDS = 900


class RenditionRequest(BaseModel):
    width: int = Field(ge=160, le=3840)
    preset: str = Field(default="medium", max_length=32)
    audio_bitrate: str = Field(default="128k", max_length=8)


@router.post(
    "/{asset_id}/renditions",
    status_code=status.HTTP_201_CREATED,
    response_model=None,
)
async def create_rendition(
    asset_id: UUID,
    payload: RenditionRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Queue a downscaled rendition of an asset the caller owns."""
    asset = session.execute(
        select(MediaAsset).where(
            MediaAsset.id == asset_id,
            MediaAsset.account_id == current_user.account_id,
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Asset not found")

    source = Path(settings.media_root) / asset.storage_key
    target = Path(settings.media_root) / "renditions" / f"{asset.id}-{payload.width}.mp4"
    target.parent.mkdir(parents=True, exist_ok=True)

    command = (
        f"ffmpeg -y -i {shlex.quote(str(source))} "
        f"-vf scale={payload.width}:-2 -c:v libx264 -preset {payload.preset} "
        f"-c:a aac -b:a {payload.audio_bitrate} {shlex.quote(str(target))}"
    )

    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=TRANSCODE_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not encode this asset",
        )

    rendition = MediaRendition(
        asset_id=asset.id,
        width=payload.width,
        storage_key=str(target.relative_to(settings.media_root)),
    )
    session.add(rendition)
    session.commit()

    return {"id": str(rendition.id), "storage_key": rendition.storage_key}

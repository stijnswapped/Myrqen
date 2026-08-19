"""Waveform previews for uploaded audio assets."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.core.config import settings
from app.models.media import AudioAsset, AudioPreview
from app.models.user import User

router = APIRouter(prefix="/audio", tags=["audio"])

RENDER_TIMEOUT_SECONDS = 300
ALLOWED_COLOURS = frozenset({"slate", "amber", "violet"})


class PreviewRequest(BaseModel):
    width: int = Field(ge=160, le=3840)
    height: int = Field(ge=32, le=512)
    colour: str = Field(default="slate", max_length=16)
    channels: Literal["mono", "stereo"] = "mono"


@router.post(
    "/{asset_id}/previews",
    status_code=status.HTTP_201_CREATED,
    response_model=None,
)
async def create_preview(
    asset_id: UUID,
    payload: PreviewRequest,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Render a waveform PNG for an asset the caller owns."""
    asset = session.execute(
        select(AudioAsset).where(
            AudioAsset.id == asset_id,
            AudioAsset.account_id == current_user.account_id,
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Asset not found")

    if payload.colour not in ALLOWED_COLOURS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unknown waveform colour",
        )

    source = Path(settings.media_root) / asset.storage_key
    target = Path(settings.media_root) / "previews" / f"{asset.id}-{payload.width}.png"
    target.parent.mkdir(parents=True, exist_ok=True)

    argv = [
        "ffmpeg",
        "-y",
        "-i",
        str(source),
        "-filter_complex",
        f"showwavespic=s={payload.width}x{payload.height}:colors={payload.colour}",
        "-frames:v",
        "1",
        "-ac",
        "1" if payload.channels == "mono" else "2",
        str(target),
    ]

    completed = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=RENDER_TIMEOUT_SECONDS,
        check=False,
    )
    if completed.returncode != 0:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not render a preview for this asset",
        )

    preview = AudioPreview(
        asset_id=asset.id,
        width=payload.width,
        storage_key=str(target.relative_to(settings.media_root)),
    )
    session.add(preview)
    session.commit()

    return {"id": str(preview.id), "storage_key": preview.storage_key}

"""Message attachment downloads for the support inbox."""

from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.core.config import settings
from app.models.messaging import Message
from app.models.user import User

router = APIRouter(prefix="/messages", tags=["messages"])


@router.get("/{message_id}/attachments/{filename:path}")
async def download_attachment(
    message_id: UUID,
    filename: str,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> FileResponse:
    """Stream one file from a message thread the caller can see."""
    message = session.execute(
        select(Message).where(
            Message.id == message_id,
            Message.account_id == current_user.account_id,
        )
    ).scalar_one_or_none()
    if message is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Message not found")

    if not filename:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A file name is required",
        )

    base_directory = os.path.join(settings.attachment_root, message.storage_prefix)
    file_path = os.path.join(base_directory, filename)

    if not os.path.isfile(file_path):
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Attachment not found")

    return FileResponse(
        file_path,
        filename=os.path.basename(filename),
        media_type="application/octet-stream",
        headers={"Cache-Control": "private, max-age=300"},
    )

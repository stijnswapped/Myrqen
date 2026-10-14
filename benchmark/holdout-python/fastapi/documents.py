"""Contract documents uploaded by customers."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Document
from app.storage import presigned_download_url

router = APIRouter(prefix="/documents", tags=["documents"])


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    content_type: str
    size_bytes: int
    uploaded_at: datetime


class DocumentDetail(DocumentOut):
    download_url: str


@router.get("", response_model=list[DocumentOut])
def list_documents(
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Documents owned by the caller, newest first."""
    statement = (
        select(Document)
        .where(Document.owner_id == user.id)
        .order_by(Document.uploaded_at.desc())
    )
    return session.scalars(statement).all()


@router.get("/{document_id}", response_model=DocumentDetail)
def get_document(
    document_id: int,
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Metadata and a short-lived download link for one document."""
    document = session.get(Document, document_id)
    if document is None or document.deleted_at is not None:
        raise HTTPException(status_code=404, detail="Document not found")
    return DocumentDetail(
        **DocumentOut.model_validate(document).model_dump(),
        download_url=presigned_download_url(document.storage_key, expires_in=300),
    )

"""Document vault."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Document
from app.security import get_current_user

router = APIRouter(prefix="/documents")


@router.get("/{document_id}")
def read_document(document_id: UUID, session: Session = Depends(get_session), user=Depends(get_current_user)):
    document = session.execute(
        select(Document).where(Document.id == document_id, Document.owner_id == user.id)
    ).scalar_one_or_none()
    if document is None:
        raise HTTPException(404, detail="Document not found")
    return {"id": str(document.id), "title": document.title, "body": document.body}

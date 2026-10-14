"""Customisable notification e-mails: workspace admins edit the body, we preview it."""
from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from jinja2 import Template
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import CurrentUser, require_workspace_admin
from app.db import get_session
from app.models import NotificationTemplate

router = APIRouter(prefix="/notifications/templates", tags=["notifications"])


class TemplateDraft(BaseModel):
    subject: str = Field(max_length=200)
    body: str = Field(max_length=20_000)


def _preview_context(user: CurrentUser) -> dict:
    return {
        "recipient": {"name": user.display_name, "email": user.email},
        "workspace": {"name": user.workspace_name},
        "invoice": {"number": "INV-0001", "total": "1,250.00 EUR"},
    }


@router.post("/preview", response_class=HTMLResponse)
def preview_template(draft: TemplateDraft, user: CurrentUser = Depends(require_workspace_admin)):
    """Render an unsaved draft against sample data so the admin can see the result."""
    rendered = Template(draft.body).render(**_preview_context(user))
    return f"<h1>{escape(draft.subject)}</h1>\n{rendered}"


@router.put("/{template_key}")
def save_template(
    template_key: str,
    draft: TemplateDraft,
    user: CurrentUser = Depends(require_workspace_admin),
    session: Session = Depends(get_session),
):
    """Store the draft as the workspace's template for this notification."""
    record = session.get(NotificationTemplate, (user.workspace_id, template_key))
    if record is None:
        record = NotificationTemplate(workspace_id=user.workspace_id, key=template_key)
        session.add(record)
    record.subject = draft.subject
    record.body = draft.body
    session.commit()
    return {"key": template_key}

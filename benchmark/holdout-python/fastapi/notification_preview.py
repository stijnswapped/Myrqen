"""Notification e-mails: admins pick a layout and write the message, we preview it."""
from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from app.auth import CurrentUser, require_workspace_admin

router = APIRouter(prefix="/notifications/templates", tags=["notifications"])

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates" / "email"
LAYOUTS = {
    "invoice": "invoice_issued.html",
    "reminder": "payment_reminder.html",
    "welcome": "welcome.html",
}

environment = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


class TemplateDraft(BaseModel):
    layout: Literal["invoice", "reminder", "welcome"]
    subject: str = Field(max_length=200)
    message: str = Field(max_length=20_000)


@router.post("/preview", response_class=HTMLResponse)
def preview_template(draft: TemplateDraft, user: CurrentUser = Depends(require_workspace_admin)):
    """Render the chosen layout with the admin's message as plain context data."""
    template = environment.get_template(LAYOUTS[draft.layout])
    return template.render(
        subject=draft.subject,
        message=draft.message,
        recipient={"name": user.display_name, "email": user.email},
        workspace={"name": user.workspace_name},
    )

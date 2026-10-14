"""Marketing campaign previews."""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from jinja2 import Environment, select_autoescape
from pydantic import BaseModel

from app.security import get_current_user

router = APIRouter(prefix="/campaigns")
environment = Environment(autoescape=select_autoescape(["html"]))


class Preview(BaseModel):
    subject: str
    body: str


@router.post("/preview", response_class=HTMLResponse)
def preview_campaign(draft: Preview, user=Depends(get_current_user)):
    template = environment.from_string(draft.body)
    return template.render(first_name=user.first_name, company=user.company_name)

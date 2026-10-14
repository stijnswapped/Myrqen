"""Marketing campaign previews."""

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel

from app.security import get_current_user

router = APIRouter(prefix="/campaigns")
environment = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html"]))


class Preview(BaseModel):
    subject: str
    body: str


@router.post("/preview", response_class=HTMLResponse)
def preview_campaign(draft: Preview, user=Depends(get_current_user)):
    template = environment.get_template("campaign.html")
    return template.render(body=draft.body, first_name=user.first_name)

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, TemplateSyntaxError, select_autoescape
from pydantic import BaseModel, Field

from app.auth import CurrentUser, get_current_user

router = APIRouter(prefix="/email-templates", tags=["notifications"])

_env = Environment(autoescape=select_autoescape(default=True), trim_blocks=True)

PREVIEW_CONTEXT = {
    "customer": {"first_name": "Ada", "last_name": "Lovelace"},
    "order": {"number": "A-10442", "total": "129.00", "currency": "EUR"},
    "shop": {"name": "Your shop", "support_email": "support@example.com"},
}


class TemplateDraft(BaseModel):
    subject: str = Field(max_length=200)
    body: str = Field(max_length=20_000)


@router.post("/preview", response_class=HTMLResponse)
async def preview_template(
    draft: TemplateDraft,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> HTMLResponse:
    try:
        template = _env.from_string(draft.body)
    except TemplateSyntaxError as exc:
        raise HTTPException(status_code=422, detail=f"line {exc.lineno}: {exc.message}") from exc
    rendered = template.render(**PREVIEW_CONTEXT)
    return HTMLResponse(rendered)

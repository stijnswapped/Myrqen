from typing import Annotated

import bleach
import markdown
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import Environment, select_autoescape
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import WikiPage

router = APIRouter(prefix="/wiki", tags=["wiki"])

_env = Environment(autoescape=select_autoescape(default=True))

ALLOWED_TAGS = frozenset(
    {"p", "br", "strong", "em", "code", "pre", "blockquote", "ul", "ol", "li", "h2", "h3", "a", "table", "thead",
     "tbody", "tr", "th", "td"}
)
ALLOWED_ATTRIBUTES = {"a": ["href", "title"]}

PAGE = _env.from_string(
    """<article class="wiki">
  <h1>{{ page.title }}</h1>
  <div class="wiki-body">{{ page.body_html | safe }}</div>
</article>"""
)


def _body_html(text: str) -> str:
    rendered = markdown.markdown(text, extensions=["fenced_code", "tables"])
    return bleach.clean(
        rendered,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=["http", "https", "mailto"],
        strip=True,
    )


class PageIn(BaseModel):
    title: str = Field(max_length=200)
    text: str = Field(max_length=50_000)


@router.post("/pages", status_code=201)
async def create_page(
    body: PageIn,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    page = WikiPage(workspace_id=user.account_id, title=body.title, body_html=_body_html(body.text))
    session.add(page)
    await session.commit()
    return {"id": page.id}


@router.get("/pages/{page_id}", response_class=HTMLResponse)
async def view_page(
    page_id: int,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> HTMLResponse:
    page = await session.get(WikiPage, page_id)
    if page is None or page.workspace_id != user.account_id:
        raise HTTPException(status_code=404)
    return HTMLResponse(PAGE.render(page=page))

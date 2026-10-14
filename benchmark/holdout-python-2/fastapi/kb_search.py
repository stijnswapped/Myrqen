from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Article

router = APIRouter(prefix="/kb", tags=["knowledge-base"])

PAGE = """<!doctype html>
<html><head><title>Knowledge base</title><link rel="stylesheet" href="/static/kb.css"></head>
<body><main>{body}</main></body></html>"""


@router.get("/lookup", response_class=HTMLResponse)
async def lookup(
    session: Annotated[AsyncSession, Depends(get_session)],
    q: Annotated[str, Query(min_length=1, max_length=200)],
) -> HTMLResponse:
    stmt = select(Article).where(Article.title.ilike(f"%{q}%")).where(Article.published.is_(True)).limit(25)
    articles = list(await session.scalars(stmt))
    if not articles:
        body = f"<p>No articles matched <strong>{q}</strong>. Try a shorter search.</p>"
    else:
        items = "".join(f'<li><a href="/kb/articles/{a.slug}">{a.title}</a></li>' for a in articles)
        body = f"<h1>{len(articles)} results</h1><ul>{items}</ul>"
    return HTMLResponse(PAGE.format(body=body))

"""Help-centre search page."""

import html

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.help import search_articles

router = APIRouter(prefix="/help")


@router.get("/search")
def help_search(q: str = ""):
    results = search_articles(q)
    heading = f"<h2>{len(results)} results for {html.escape(q)}</h2>"
    return HTMLResponse(f"<main>{heading}</main>")

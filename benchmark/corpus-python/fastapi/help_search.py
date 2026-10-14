"""Help-centre search page."""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.help import search_articles

router = APIRouter(prefix="/help")


@router.get("/search")
def help_search(q: str = ""):
    results = search_articles(q)
    heading = f"<h2>{len(results)} results for {q}</h2>"
    items = "".join(f"<li><a href='/help/{a.slug}'>{a.title}</a></li>" for a in results)
    return HTMLResponse(f"<main>{heading}<ul>{items}</ul></main>")

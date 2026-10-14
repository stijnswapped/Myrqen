"""Public product pages: changelog and the downloadable price list."""
from __future__ import annotations

import os
from functools import lru_cache

import markdown
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter(tags=["public"])

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.join(BASE_DIR, "content")
CHANGELOG_FILE = "CHANGELOG.md"
PRICE_LIST_FILE = "price-list-2026.pdf"


@lru_cache(maxsize=1)
def _rendered_changelog() -> str:
    changelog_path = os.path.join(CONTENT_DIR, CHANGELOG_FILE)
    with open(changelog_path, encoding="utf-8") as handle:
        return markdown.markdown(handle.read(), extensions=["fenced_code", "tables"])


@router.get("/changelog", response_class=HTMLResponse)
def changelog() -> str:
    """Render the shipped changelog."""
    return _rendered_changelog()


@router.get("/pricing/download")
def price_list() -> FileResponse:
    """Serve the current price list as a PDF."""
    return FileResponse(
        os.path.join(CONTENT_DIR, PRICE_LIST_FILE),
        media_type="application/pdf",
        filename=PRICE_LIST_FILE,
    )

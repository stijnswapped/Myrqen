"""Server-rendered catalogue search fragments consumed by htmx on the storefront."""
from __future__ import annotations

from html import escape

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_session
from app.models import Product

router = APIRouter(prefix="/catalog", tags=["catalog"])


def _product_card(product: Product) -> str:
    return (
        '<li class="product">'
        f'<a href="/products/{product.id}">{escape(product.name)}</a>'
        f'<span class="price">{product.price_cents / 100:.2f}</span>'
        "</li>"
    )


@router.get("/search", response_class=HTMLResponse)
def search_fragment(
    q: str = Query("", max_length=200),
    session: Session = Depends(get_session),
):
    """Return the result list for the live search box."""
    term = q.strip()
    products = session.scalars(
        select(Product).where(Product.name.ilike(f"%{term}%")).limit(24)
    ).all()
    if not products:
        shown = escape(term)
        return HTMLResponse(f'<p class="empty">No products match <strong>{shown}</strong>.</p>')
    cards = "".join(_product_card(product) for product in products)
    return HTMLResponse(f'<ul class="results">{cards}</ul>')

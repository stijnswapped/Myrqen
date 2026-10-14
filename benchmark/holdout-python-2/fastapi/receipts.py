from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import DictLoader, Environment, select_autoescape
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Order

RECEIPT_LAYOUTS = {
    "classic": (
        "<h2>{{ shop_name }}</h2>"
        "<p>Order {{ order.number }} &middot; {{ order.total_display }}</p>"
        "<footer>{{ footer }}</footer>"
    ),
    "compact": "<p>{{ order.number }} &mdash; {{ order.total_display }}</p><small>{{ footer }}</small>",
}

_env = Environment(loader=DictLoader(RECEIPT_LAYOUTS), autoescape=select_autoescape(default=True))

router = APIRouter(prefix="/receipts", tags=["receipts"])


class ReceiptOptions(BaseModel):
    layout: Literal["classic", "compact"] = "classic"
    footer: str = Field(default="", max_length=500)


@router.post("/{order_id}/render", response_class=HTMLResponse)
async def render_receipt(
    order_id: int,
    options: ReceiptOptions,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> HTMLResponse:
    order = await session.get(Order, order_id)
    if order is None or order.account_id != user.account_id:
        raise HTTPException(status_code=404)
    template = _env.get_template(options.layout)
    html = template.render(shop_name=order.shop_name, order=order, footer=options.footer)
    return HTMLResponse(html)

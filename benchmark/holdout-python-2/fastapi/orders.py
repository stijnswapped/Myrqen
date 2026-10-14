from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Order

router = APIRouter(prefix="/orders", tags=["orders"])


class LineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    sku: str
    quantity: int
    unit_price_cents: int


class OrderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    status: str
    placed_at: datetime
    total_cents: int
    shipping_address: str
    lines: list[LineOut]


@router.get("", response_model=list[OrderOut])
async def my_orders(
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    limit: Annotated[int, Query(le=100)] = 20,
) -> list[Order]:
    stmt = (
        select(Order)
        .options(selectinload(Order.lines))
        .where(Order.customer_id == user.id)
        .order_by(Order.placed_at.desc())
        .limit(limit)
    )
    return list(await session.scalars(stmt))


@router.get("/{order_id}", response_model=OrderOut)
async def order_detail(
    order_id: int,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Order:
    order = await session.get(Order, order_id, options=[selectinload(Order.lines)])
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    return order

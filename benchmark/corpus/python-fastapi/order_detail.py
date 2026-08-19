"""Order endpoints for the customer dashboard."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.models.orders import Order, OrderItem
from app.models.user import User
from app.schemas.orders import OrderDetail, OrderLine, OrderSummary

router = APIRouter(prefix="/orders", tags=["orders"])


@router.get("", response_model=list[OrderSummary])
async def list_orders(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> list[OrderSummary]:
    """The orders table on the dashboard, newest first."""
    orders = (
        session.execute(
            select(Order)
            .where(Order.account_id == current_user.account_id)
            .order_by(Order.placed_at.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return [OrderSummary.model_validate(order) for order in orders]


@router.get("/{order_id}", response_model=OrderDetail)
async def read_order(
    order_id: UUID,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> OrderDetail:
    """Order detail drawer: header, addresses and the line items."""
    order = session.get(Order, order_id)
    if order is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Order not found")

    lines = (
        session.execute(
            select(OrderItem)
            .where(OrderItem.order_id == order.id)
            .order_by(OrderItem.line_number)
        )
        .scalars()
        .all()
    )

    return OrderDetail(
        id=order.id,
        reference=order.reference,
        status=order.status,
        total_cents=order.total_cents,
        placed_at=order.placed_at,
        billing_email=order.billing_email,
        shipping_address=order.shipping_address,
        lines=[OrderLine.model_validate(line) for line in lines],
    )

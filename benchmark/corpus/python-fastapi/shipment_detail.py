"""Shipment endpoints for the customer dashboard."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.models.orders import Shipment, ShipmentEvent
from app.models.user import User
from app.schemas.orders import ShipmentDetail, ShipmentEventOut, ShipmentSummary

router = APIRouter(prefix="/shipments", tags=["shipments"])


@router.get("", response_model=list[ShipmentSummary])
async def list_shipments(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> list[ShipmentSummary]:
    """The shipments table on the dashboard, newest first."""
    shipments = (
        session.execute(
            select(Shipment)
            .where(Shipment.account_id == current_user.account_id)
            .order_by(Shipment.dispatched_at.desc())
            .limit(limit)
            .offset(offset)
        )
        .scalars()
        .all()
    )
    return [ShipmentSummary.model_validate(shipment) for shipment in shipments]


@router.get("/{shipment_id}", response_model=ShipmentDetail)
async def read_shipment(
    shipment_id: UUID,
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> ShipmentDetail:
    """Shipment detail drawer: carrier, address and the tracking history."""
    shipment = session.execute(
        select(Shipment).where(
            Shipment.id == shipment_id,
            Shipment.account_id == current_user.account_id,
        )
    ).scalar_one_or_none()
    if shipment is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Shipment not found")

    events = (
        session.execute(
            select(ShipmentEvent)
            .where(ShipmentEvent.shipment_id == shipment.id)
            .order_by(ShipmentEvent.recorded_at)
        )
        .scalars()
        .all()
    )

    return ShipmentDetail(
        id=shipment.id,
        tracking_code=shipment.tracking_code,
        carrier=shipment.carrier,
        status=shipment.status,
        dispatched_at=shipment.dispatched_at,
        delivery_address=shipment.delivery_address,
        events=[ShipmentEventOut.model_validate(event) for event in events],
    )

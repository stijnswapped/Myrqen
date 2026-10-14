from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Shipment

router = APIRouter(prefix="/shipments", tags=["shipments"])


class ShipmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    carrier: str
    tracking_number: str
    status: str
    delivery_address: str
    estimated_delivery: datetime | None


@router.get("/{shipment_id}", response_model=ShipmentOut)
async def shipment_detail(
    shipment_id: int,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Shipment:
    shipment = await session.get(Shipment, shipment_id)
    if shipment is None or shipment.customer_id != user.id:
        raise HTTPException(status_code=404, detail="shipment not found")
    return shipment

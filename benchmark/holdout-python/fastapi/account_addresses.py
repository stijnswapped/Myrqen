"""Shipping and billing addresses stored on a customer account."""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Address

router = APIRouter(prefix="/account", tags=["account"])


class AddressIn(BaseModel):
    label: str = Field(max_length=40)
    line1: str = Field(max_length=120)
    line2: str | None = Field(default=None, max_length=120)
    postcode: str = Field(max_length=16)
    city: str = Field(max_length=80)
    country: str = Field(min_length=2, max_length=2)


@router.get("/addresses")
def list_addresses(
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Addresses saved on the caller's account."""
    return session.scalars(select(Address).where(Address.user_id == user.id)).all()


@router.post("/addresses", status_code=201)
def add_address(
    body: AddressIn,
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Save a new address on the caller's account."""
    address = Address(user_id=user.id, **body.model_dump())
    session.add(address)
    session.commit()
    return {"id": address.id}


@router.delete("/addresses/{address_id}", status_code=204)
def remove_address(
    address_id: int,
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Delete one of the caller's addresses."""
    address = session.scalar(
        select(Address).where(Address.id == address_id, Address.user_id == user.id)
    )
    if address is None:
        raise HTTPException(status_code=404, detail="Address not found")
    session.delete(address)
    session.commit()


@router.get("/addresses/export")
def export_addresses(
    user_id: int = Query(...),
    session: Session = Depends(get_session),
):
    """CSV download of an account's address book (used by the 'download my data' page)."""
    rows = session.scalars(select(Address).where(Address.user_id == user_id)).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["label", "line1", "line2", "postcode", "city", "country"])
    for row in rows:
        writer.writerow([row.label, row.line1, row.line2 or "", row.postcode, row.city, row.country])
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=addresses.csv"},
    )

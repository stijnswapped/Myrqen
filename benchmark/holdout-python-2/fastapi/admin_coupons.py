from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, require_admin
from app.db import get_session
from app.models import Coupon

router = APIRouter(
    prefix="/admin/coupons",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)

Session = Annotated[AsyncSession, Depends(get_session)]


class CouponIn(BaseModel):
    code: str = Field(pattern=r"^[A-Z0-9-]{4,24}$")
    percent_off: int = Field(ge=1, le=90)
    expires_at: datetime | None = None


@router.get("")
async def list_coupons(session: Session) -> list[dict]:
    rows = await session.scalars(select(Coupon).order_by(Coupon.code))
    return [{"id": c.id, "code": c.code, "percent_off": c.percent_off} for c in rows]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_coupon(
    body: CouponIn,
    session: Session,
    admin: Annotated[CurrentUser, Depends(require_admin)],
) -> dict:
    coupon = Coupon(
        code=body.code,
        percent_off=body.percent_off,
        expires_at=body.expires_at,
        created_by=admin.id,
    )
    session.add(coupon)
    await session.commit()
    return {"id": coupon.id}


@router.delete("/{coupon_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_coupon(coupon_id: int, session: Session) -> Response:
    coupon = await session.get(Coupon, coupon_id)
    if coupon is None:
        raise HTTPException(status_code=404)
    await session.delete(coupon)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

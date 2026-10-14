"""Sales reporting API used by the analytics workspace."""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import require_role
from app.db import get_session

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportFilters(BaseModel):
    region: str = Field(min_length=2, max_length=32)
    start: date
    end: date
    sort_by: str = "revenue"
    limit: int = Field(default=100, ge=1, le=1000)


class ReportRow(BaseModel):
    region: str
    product_sku: str
    revenue: float
    units_sold: int


@router.post("/sales", response_model=list[ReportRow])
def sales_report(
    filters: ReportFilters,
    session: Session = Depends(get_session),
    _analyst=Depends(require_role("analyst")),
):
    """Aggregate sales per SKU for one region and date window."""
    statement = text(
        "SELECT region, product_sku, SUM(amount) AS revenue, SUM(quantity) AS units_sold "
        "FROM sales "
        "WHERE region = '{region}' AND sold_on BETWEEN :start AND :end "
        "GROUP BY region, product_sku "
        "ORDER BY {order} DESC LIMIT :limit".format(region=filters.region, order=filters.sort_by)
    )
    result = session.execute(
        statement,
        {"start": filters.start, "end": filters.end, "limit": filters.limit},
    )
    return [ReportRow(**row) for row in result.mappings().all()]

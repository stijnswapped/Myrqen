"""Sales reporting API used by the analytics workspace."""
from __future__ import annotations

from datetime import date
from typing import Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.auth import require_role
from app.db import get_session

router = APIRouter(prefix="/reports", tags=["reports"])

SORT_COLUMNS: dict[str, str] = {
    "revenue": "revenue",
    "units": "units_sold",
    "sku": "product_sku",
}


class ReportFilters(BaseModel):
    region: str = Field(min_length=2, max_length=32)
    start: date
    end: date
    sort_by: Literal["revenue", "units", "sku"] = "revenue"
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
    order_column = SORT_COLUMNS[filters.sort_by]
    statement = text(
        "SELECT region, product_sku, SUM(amount) AS revenue, SUM(quantity) AS units_sold "
        "FROM sales "
        "WHERE region = :region AND sold_on BETWEEN :start AND :end "
        "GROUP BY region, product_sku "
        f"ORDER BY {order_column} DESC LIMIT :limit"
    )
    result = session.execute(
        statement,
        {
            "region": filters.region,
            "start": filters.start,
            "end": filters.end,
            "limit": filters.limit,
        },
    )
    return [ReportRow(**row) for row in result.mappings().all()]

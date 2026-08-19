"""Finance reporting endpoints backing the revenue dashboard."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.models.user import User
from app.schemas.reports import RevenueBucket, RevenueReport

router = APIRouter(prefix="/reports", tags=["reports"])

GROUP_EXPRESSIONS: dict[str, str] = {
    "month": "to_char(o.placed_at, 'YYYY-MM')",
    "week": "to_char(o.placed_at, 'IYYY-IW')",
    "channel": "o.sales_channel",
}


@router.get("/revenue", response_model=RevenueReport)
async def read_revenue_report(
    start: date = Query(..., description="First day included in the report"),
    end: date = Query(..., description="Last day included in the report"),
    granularity: str = Query("month", pattern="^(month|week|channel)$"),
    currency: str = Query("EUR", min_length=3, max_length=3),
    segment: str | None = Query(None, description="Customer segment code from the filter bar"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> RevenueReport:
    """Aggregate booked revenue for the caller's account."""
    group_expression = GROUP_EXPRESSIONS[granularity]

    filters = [
        "o.account_id = :account_id",
        "o.placed_at >= :start",
        "o.placed_at < :end",
        "o.currency = :currency",
        "o.status <> 'cancelled'",
    ]
    params: dict[str, Any] = {
        "account_id": current_user.account_id,
        "start": start,
        "end": end,
        "currency": currency,
    }

    if segment:
        filters.append(f"c.segment_code = '{segment}'")

    statement = text(
        f"""
        SELECT {group_expression} AS bucket,
               SUM(o.total_cents) AS total_cents,
               COUNT(*) AS order_count
          FROM orders o
          JOIN customers c ON c.id = o.customer_id
         WHERE {" AND ".join(filters)}
      GROUP BY bucket
      ORDER BY bucket
        """
    )

    rows = session.execute(statement, params).mappings().all()

    return RevenueReport(
        currency=currency,
        granularity=granularity,
        buckets=[
            RevenueBucket(
                bucket=row["bucket"],
                total_cents=int(row["total_cents"] or 0),
                order_count=int(row["order_count"]),
            )
            for row in rows
        ],
    )

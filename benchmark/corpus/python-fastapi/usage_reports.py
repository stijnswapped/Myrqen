"""Usage reporting endpoints backing the metering dashboard."""

from __future__ import annotations

from datetime import date
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.models.user import User
from app.schemas.reports import UsageBucket, UsageReport

router = APIRouter(prefix="/reports", tags=["reports"])

GROUP_EXPRESSIONS: dict[str, str] = {
    "day": "to_char(e.recorded_at, 'YYYY-MM-DD')",
    "month": "to_char(e.recorded_at, 'YYYY-MM')",
    "meter": "e.meter_code",
}


@router.get("/usage", response_model=UsageReport)
async def read_usage_report(
    start: date = Query(..., description="First day included in the report"),
    end: date = Query(..., description="Last day included in the report"),
    granularity: str = Query("day", pattern="^(day|month|meter)$"),
    unit: str = Query("requests", min_length=1, max_length=32),
    project_code: str | None = Query(None, description="Project code from the filter bar"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> UsageReport:
    """Aggregate metered usage for the caller's account."""
    group_expression = GROUP_EXPRESSIONS[granularity]

    filters = [
        "e.account_id = :account_id",
        "e.recorded_at >= :start",
        "e.recorded_at < :end",
        "e.unit = :unit",
        "e.voided_at IS NULL",
    ]
    params: dict[str, Any] = {
        "account_id": current_user.account_id,
        "start": start,
        "end": end,
        "unit": unit,
    }

    if project_code:
        filters.append("p.code = :project_code")
        params["project_code"] = project_code

    statement = text(
        f"""
        SELECT {group_expression} AS bucket,
               SUM(e.quantity) AS quantity,
               COUNT(*) AS event_count
          FROM usage_events e
          JOIN projects p ON p.id = e.project_id
         WHERE {" AND ".join(filters)}
      GROUP BY bucket
      ORDER BY bucket
        """
    )

    rows = session.execute(statement, params).mappings().all()

    return UsageReport(
        unit=unit,
        granularity=granularity,
        buckets=[
            UsageBucket(
                bucket=row["bucket"],
                quantity=int(row["quantity"] or 0),
                event_count=int(row["event_count"]),
            )
            for row in rows
        ],
    )

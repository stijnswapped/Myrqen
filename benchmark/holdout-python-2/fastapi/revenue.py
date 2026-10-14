from datetime import date
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session

router = APIRouter(prefix="/revenue", tags=["reports"])

Grouping = Literal["region", "channel", "month"]

_GROUP_COLUMNS: dict[str, str] = {
    "region": "r.name",
    "channel": "o.channel",
    "month": "date_trunc('month', o.placed_at)",
}


class RevenueRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def totals(self, group_by: Grouping, region: str | None, start: date, end: date) -> list[dict]:
        column = _GROUP_COLUMNS[group_by]
        clauses = ["o.placed_at BETWEEN :start AND :end"]
        params: dict[str, object] = {"start": start, "end": end}
        if region:
            clauses.append("r.code = :region")
            params["region"] = region

        sql = (
            f"SELECT {column} AS bucket, SUM(o.total_cents) AS total "
            "FROM orders o JOIN regions r ON r.id = o.region_id "
            f"WHERE {' AND '.join(clauses)} "
            f"GROUP BY {column} ORDER BY total DESC"
        )
        result = await self._session.execute(text(sql), params)
        return [dict(row._mapping) for row in result]


def get_repository(session: Annotated[AsyncSession, Depends(get_session)]) -> RevenueRepository:
    return RevenueRepository(session)


@router.get("/totals")
async def revenue_totals(
    start: date,
    end: date,
    repo: Annotated[RevenueRepository, Depends(get_repository)],
    user: Annotated[CurrentUser, Depends(get_current_user)],
    group_by: Grouping = "region",
    region: Annotated[str | None, Query(max_length=12)] = None,
) -> dict:
    return {"group_by": group_by, "rows": await repo.totals(group_by, region, start, end)}

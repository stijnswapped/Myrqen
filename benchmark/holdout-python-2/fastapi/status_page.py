from html import escape
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Incident

router = APIRouter(prefix="/status", tags=["status"])

PAGE = """<!doctype html>
<html><head><title>Service status</title><link rel="stylesheet" href="/static/status.css"></head>
<body><main>{body}</main></body></html>"""


@router.get("/incidents", response_class=HTMLResponse)
async def incidents(
    session: Annotated[AsyncSession, Depends(get_session)],
    component: Annotated[str, Query(max_length=80)] = "",
) -> HTMLResponse:
    stmt = select(Incident).order_by(Incident.started_at.desc()).limit(50)
    if component:
        stmt = stmt.where(Incident.component == component)
    rows = list(await session.scalars(stmt))
    heading = f"Incidents for {escape(component)}" if component else "All incidents"
    items = "".join(
        f'<li class="{escape(i.severity, quote=True)}">{escape(i.title)} '
        f"<time>{i.started_at:%Y-%m-%d %H:%M}</time></li>"
        for i in rows
    )
    body = f"<h1>{heading}</h1><ul>{items or '<li>No incidents reported.</li>'}</ul>"
    return HTMLResponse(PAGE.format(body=body))

from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import WorkflowDefinition

router = APIRouter(prefix="/workflows", tags=["workflows"])


class Step(BaseModel):
    name: str
    action: str
    params: dict = {}


class Workflow(BaseModel):
    name: str
    trigger: str
    steps: list[Step]


@router.post("/definitions", status_code=201)
async def upload_definition(
    request: Request,
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    if request.headers.get("content-type", "").split(";")[0] not in ("application/yaml", "text/yaml"):
        raise HTTPException(status_code=415)
    raw = await request.body()
    document = yaml.load(raw, Loader=yaml.Loader)
    try:
        workflow = Workflow.model_validate(document)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc

    record = WorkflowDefinition(account_id=user.account_id, name=workflow.name, spec=workflow.model_dump())
    session.add(record)
    await session.commit()
    return {"id": record.id, "steps": len(workflow.steps)}

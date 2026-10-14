from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel, ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import WorkflowDefinition

MAX_UPLOAD = 256 * 1024

router = APIRouter(prefix="/automations", tags=["workflows"])


class Rule(BaseModel):
    when: str
    then: str
    options: dict[str, str | int | bool] = {}


class Automation(BaseModel):
    name: str
    rules: list[Rule]


@router.post("/import", status_code=201)
async def import_automation(
    upload: Annotated[UploadFile, File()],
    user: Annotated[CurrentUser, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    raw = await upload.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(status_code=413)
    try:
        document = yaml.load(raw.decode("utf-8"), Loader=yaml.SafeLoader)
        automation = Automation.model_validate(document)
    except (yaml.YAMLError, UnicodeDecodeError, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="not a valid automation file") from exc

    record = WorkflowDefinition(account_id=user.account_id, name=automation.name, spec=automation.model_dump())
    session.add(record)
    await session.commit()
    return {"id": record.id, "rules": len(automation.rules)}

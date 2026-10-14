"""Import and export of CI pipeline definitions as YAML documents."""
from __future__ import annotations

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from app.auth import CurrentUser, get_current_user
from app.db import get_session
from app.models import Pipeline

router = APIRouter(prefix="/pipelines", tags=["pipelines"])

MAX_DEFINITION_BYTES = 256 * 1024


class Step(BaseModel):
    name: str
    image: str
    run: list[str]


class PipelineDefinition(BaseModel):
    name: str
    trigger: list[str]
    steps: list[Step]


@router.post("/import", status_code=201)
async def import_pipeline(
    definition: UploadFile = File(...),
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Create a pipeline from an uploaded YAML definition."""
    raw = await definition.read(MAX_DEFINITION_BYTES + 1)
    if len(raw) > MAX_DEFINITION_BYTES:
        raise HTTPException(status_code=413, detail="Definition too large")
    document = yaml.load(raw, Loader=yaml.Loader)
    try:
        parsed = PipelineDefinition.model_validate(document)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    pipeline = Pipeline(project_id=user.project_id, name=parsed.name, spec=parsed.model_dump())
    session.add(pipeline)
    session.commit()
    return {"id": pipeline.id, "name": pipeline.name}


@router.get("/{pipeline_id}/export", response_class=PlainTextResponse)
def export_pipeline(
    pipeline_id: int,
    user: CurrentUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """Download a pipeline as YAML."""
    pipeline = session.get(Pipeline, pipeline_id)
    if pipeline is None or pipeline.project_id != user.project_id:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    return yaml.safe_dump(pipeline.spec, sort_keys=False)

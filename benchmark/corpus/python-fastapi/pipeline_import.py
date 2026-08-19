"""Pipeline definition imports for the deployment builder."""

from __future__ import annotations

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.models.automation import PipelineDraft
from app.models.user import User

router = APIRouter(prefix="/pipelines", tags=["pipelines"])

MAX_DEFINITION_BYTES = 512 * 1024


class PipelineStep(BaseModel):
    key: str = Field(min_length=1, max_length=64)
    kind: str = Field(min_length=1, max_length=32)
    command: str | None = Field(default=None, max_length=512)


class PipelineDefinition(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    steps: list[PipelineStep] = Field(min_length=1, max_length=200)


@router.post("/imports", status_code=status.HTTP_202_ACCEPTED, response_model=None)
async def import_pipeline_definition(
    definition: UploadFile = File(..., description="Exported pipeline YAML"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Turn an exported pipeline file into an editable draft."""
    raw = await definition.read()
    if len(raw) > MAX_DEFINITION_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Pipeline definition is too large",
        )

    try:
        document = yaml.safe_load(raw.decode("utf-8"))
    except yaml.YAMLError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not parse this pipeline definition",
        ) from None

    try:
        parsed = PipelineDefinition.model_validate(document)
    except ValidationError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=error.errors(include_url=False),
        ) from None

    draft = PipelineDraft(
        account_id=current_user.account_id,
        created_by=current_user.id,
        name=parsed.name,
        definition=parsed.model_dump(),
    )
    session.add(draft)
    session.commit()

    return {
        "id": str(draft.id),
        "name": draft.name,
        "step_count": len(parsed.steps),
    }

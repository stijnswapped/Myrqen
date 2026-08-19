"""Workflow definition imports for the automation builder."""

from __future__ import annotations

import yaml
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_session
from app.models.automation import WorkflowDraft
from app.models.user import User

router = APIRouter(prefix="/workflows", tags=["workflows"])

MAX_DEFINITION_BYTES = 512 * 1024


@router.post("/imports", status_code=status.HTTP_202_ACCEPTED, response_model=None)
async def import_workflow_definition(
    definition: UploadFile = File(..., description="Exported workflow YAML"),
    session: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, object]:
    """Turn an exported workflow file into an editable draft."""
    raw = await definition.read()
    if len(raw) > MAX_DEFINITION_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Workflow definition is too large",
        )

    try:
        # The exporter emits custom tags for step types, so the full constructor
        # set is needed to round-trip a definition without losing them.
        document = yaml.load(raw.decode("utf-8"), Loader=yaml.Loader)
    except yaml.YAMLError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Could not parse this workflow definition",
        ) from None

    if not isinstance(document, dict) or "steps" not in document:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="A workflow definition needs a steps block",
        )

    draft = WorkflowDraft(
        account_id=current_user.account_id,
        created_by=current_user.id,
        name=str(document.get("name") or definition.filename or "Imported workflow"),
        definition=document,
    )
    session.add(draft)
    session.commit()

    return {
        "id": str(draft.id),
        "name": draft.name,
        "step_count": len(document["steps"]),
    }

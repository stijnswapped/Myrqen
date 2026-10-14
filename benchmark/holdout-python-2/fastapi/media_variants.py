import subprocess
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import CurrentUser, get_current_user

MEDIA_ROOT = Path("/srv/media")

router = APIRouter(prefix="/media", tags=["media"])


class VariantRequest(BaseModel):
    asset_id: int
    width: int = Field(gt=0, le=4096)
    height: int = Field(gt=0, le=4096)
    caption: str = Field(default="", max_length=80)


def render_variant(source: Path, target: Path, req: VariantRequest) -> None:
    command = (
        "convert {src} -resize {w}x{h} -gravity southeast "
        "-pointsize 18 -annotate +10+10 '{caption}' {dst}"
    ).format(src=source, w=req.width, h=req.height, caption=req.caption, dst=target)
    subprocess.run(command, shell=True, check=True, timeout=60)


@router.post("/variants", status_code=202)
async def create_variant(
    req: VariantRequest,
    tasks: BackgroundTasks,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    source = MEDIA_ROOT / "originals" / str(user.account_id) / f"{req.asset_id}.png"
    if not source.exists():
        raise HTTPException(status_code=404, detail="asset not found")
    target = MEDIA_ROOT / "variants" / str(user.account_id) / f"{req.asset_id}_{req.width}x{req.height}.png"
    tasks.add_task(render_variant, source, target, req)
    return {"status": "queued", "variant": target.name}

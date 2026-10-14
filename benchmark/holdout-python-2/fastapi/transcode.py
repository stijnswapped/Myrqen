import asyncio
import logging
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field

from app.auth import CurrentUser, get_current_user

log = logging.getLogger(__name__)

VIDEO_ROOT = Path("/srv/video")

PRESETS: dict[str, tuple[int, int, str]] = {
    "mobile": (640, 360, "800k"),
    "hd": (1280, 720, "2500k"),
    "full_hd": (1920, 1080, "5000k"),
}

router = APIRouter(prefix="/videos", tags=["video"])


class TranscodeJob(BaseModel):
    video_id: int
    preset: Literal["mobile", "hd", "full_hd"] = "hd"
    title: str = Field(default="", max_length=120)


async def transcode(source: Path, target: Path, job: TranscodeJob) -> None:
    width, height, bitrate = PRESETS[job.preset]
    proc = await asyncio.create_subprocess_exec(
        "ffmpeg",
        "-y",
        "-i",
        str(source),
        "-vf",
        f"scale={width}:{height}",
        "-b:v",
        bitrate,
        "-metadata",
        f"title={job.title}",
        str(target),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        log.error("ffmpeg failed for %s: %s", source.name, stderr.decode(errors="replace")[-500:])


@router.post("/transcodes", status_code=202)
async def queue_transcode(
    job: TranscodeJob,
    tasks: BackgroundTasks,
    user: Annotated[CurrentUser, Depends(get_current_user)],
) -> dict:
    source = VIDEO_ROOT / "uploads" / str(user.account_id) / f"{job.video_id}.mp4"
    if not source.is_file():
        raise HTTPException(status_code=404, detail="video not found")
    target = VIDEO_ROOT / "renditions" / str(user.account_id) / f"{job.video_id}-{job.preset}.mp4"
    target.parent.mkdir(parents=True, exist_ok=True)
    tasks.add_task(transcode, source, target, job)
    return {"status": "queued", "rendition": target.name}

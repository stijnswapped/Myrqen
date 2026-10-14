"""Operations status page for on-call staff."""
from __future__ import annotations

import subprocess

from flask import Blueprint, jsonify
from flask_login import login_required

from app.auth import roles_required

bp = Blueprint("ops", __name__, url_prefix="/ops")

DISK_USAGE_COMMAND = "df -P /var/lib/storefront | tail -n 1 | awk '{print $5}'"
QUEUE_DEPTH_COMMAND = "redis-cli -n 2 llen celery"


def _run(command: str) -> str:
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unavailable"


@bp.get("/status")
@login_required
@roles_required("oncall")
def status():
    """Disk and queue indicators for the on-call dashboard."""
    return jsonify(
        {
            "disk_used": _run(DISK_USAGE_COMMAND),
            "queue_depth": _run(QUEUE_DEPTH_COMMAND),
        }
    )

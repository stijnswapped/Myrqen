"""Restore a saved workspace layout."""

import base64
import pickle

from fastapi import APIRouter, Header

router = APIRouter(prefix="/workspace")


@router.post("/restore")
def restore_layout(x_layout_state: str = Header(...)):
    layout = pickle.loads(base64.urlsafe_b64decode(x_layout_state))
    return {"panels": layout.get("panels", []), "theme": layout.get("theme", "light")}

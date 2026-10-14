"""Operator tools, a template preview and a saved-cart restore."""

import base64
import pickle
import subprocess

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse
from jinja2 import Environment
from pydantic import BaseModel

from app.security import get_current_user

router = APIRouter(tags=["tools"])
templates = Environment()


class PingRequest(BaseModel):
    host: str


class CartBlob(BaseModel):
    blob: str


@router.post("/diagnostics/ping")
def ping(body: PingRequest, user: dict = Depends(get_current_user)):
    completed = subprocess.run(f"ping -c 1 {body.host}", shell=True, capture_output=True, text=True, timeout=10)
    return {"exit": completed.returncode}


@router.post("/diagnostics/resolve")
def resolve(body: PingRequest, user: dict = Depends(get_current_user)):
    completed = subprocess.run(["host", body.host], capture_output=True, text=True, timeout=10)
    return {"exit": completed.returncode}


@router.get("/greeting", response_class=HTMLResponse)
def greeting(template: str = "Hello {{ name }}", name: str = "friend"):
    return templates.from_string(template).render(name=name)


@router.post("/cart/restore")
def restore_cart(body: CartBlob, user: dict = Depends(get_current_user)):
    cart = pickle.loads(base64.b64decode(body.blob))
    return {"items": len(cart)}

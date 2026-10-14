"""Production ASGI entry point for the Ledger API.

Deployed with:  gunicorn application:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
"""
from __future__ import annotations

import logging

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.routers import accounts, billing, exports, health, invoices


class RuntimeSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LEDGER_")

    release: str = "unknown"
    debug: bool = False
    allowed_origins: list[str] = ["https://app.ledger.example"]


runtime = RuntimeSettings()
logging.basicConfig(level=logging.DEBUG if runtime.debug else logging.INFO)

app = FastAPI(
    title="Ledger API",
    version=runtime.release,
    debug=runtime.debug,
    docs_url="/docs" if runtime.debug else None,
    redoc_url=None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.ledger.example", "*.ledger.example"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=runtime.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

for module in (health, accounts, billing, invoices, exports):
    app.include_router(module.router)


if __name__ == "__main__":
    uvicorn.run("application:app", host="0.0.0.0", port=8000, proxy_headers=True)

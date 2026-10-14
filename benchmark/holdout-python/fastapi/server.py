"""Production ASGI entry point for the Ledger API.

Deployed with:  gunicorn server:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
"""
from __future__ import annotations

import logging

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from app.routers import accounts, billing, exports, health, invoices
from app.settings import settings

logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="Ledger API",
    version=settings.release,
    debug=True,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=["api.ledger.example", "*.ledger.example"])
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.ledger.example"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

for module in (health, accounts, billing, invoices, exports):
    app.include_router(module.router)


if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, proxy_headers=True)

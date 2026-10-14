"""ASGI entry point."""

from fastapi import FastAPI

from app.api import invoices, support
from app.config import settings

app = FastAPI(title="Shop API", version="2.4.0", debug=settings.debug)
app.include_router(invoices.router, prefix="/api")
app.include_router(support.router, prefix="/api")


@app.get("/healthz")
def healthz():
    return {"ok": True}

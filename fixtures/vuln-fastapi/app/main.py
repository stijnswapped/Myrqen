"""ASGI entry point: `python -m uvicorn app.main:app --host 127.0.0.1 --port 5030`."""

import html

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.routers import account, auth, files, integrations, orders, products, tools

app = FastAPI(title="Myrqen FastAPI fixture", debug=True)

for module in (auth, orders, products, files, integrations, tools, account):
    app.include_router(module.router, prefix="/api")


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/search", response_class=HTMLResponse)
def search_page(q: str = ""):
    return HTMLResponse(f"<h1>Search</h1><p>Results for {q}</p>")


@app.get("/about", response_class=HTMLResponse)
def about_page(ref: str = ""):
    return HTMLResponse(f"<p>Referred by {html.escape(ref)}</p>")

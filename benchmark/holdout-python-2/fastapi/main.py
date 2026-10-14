import logging

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import accounts, invoices, payments

logging.basicConfig(level=logging.INFO)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Ledgerly API",
        version="2.4.1",
        debug=True,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://app.ledgerly.app"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(accounts.router)
    app.include_router(invoices.router)
    app.include_router(payments.router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict:
        return {"ok": True}

    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, proxy_headers=True)

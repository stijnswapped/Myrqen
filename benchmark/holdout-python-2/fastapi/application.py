import logging
import os

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import accounts, invoices, payments

ENVIRONMENT = os.environ.get("APP_ENV", "production")
IS_LOCAL = ENVIRONMENT == "local"

logging.basicConfig(level=logging.DEBUG if IS_LOCAL else logging.INFO)


def create_app() -> FastAPI:
    app = FastAPI(
        title="Ledgerly API",
        version="2.4.1",
        debug=IS_LOCAL,
        docs_url="/docs" if IS_LOCAL else None,
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173"] if IS_LOCAL else ["https://app.ledgerly.app"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(accounts.router)
    app.include_router(invoices.router)
    app.include_router(payments.router)
    return app


app = create_app()

if __name__ == "__main__":
    uvicorn.run("app.application:app", host="127.0.0.1", port=8000, reload=IS_LOCAL)

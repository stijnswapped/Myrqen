"""Production entry point for the storefront.

The container runs `python runserver.py` behind the load balancer (see deploy/Dockerfile).
Set STOREFRONT_DEBUG=1 only on a developer machine.
"""
from __future__ import annotations

import logging
import os

from app import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = create_app()
app.config.update(PREFERRED_URL_SCHEME="https")


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=_flag("STOREFRONT_DEBUG"), use_reloader=False)

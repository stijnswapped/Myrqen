"""Production entry point for the storefront.

The container runs `python serve.py` behind the load balancer (see deploy/Dockerfile).
"""
from __future__ import annotations

import logging
import os

from app import create_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

app = create_app()
app.config.update(ENV="production", PREFERRED_URL_SCHEME="https")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)

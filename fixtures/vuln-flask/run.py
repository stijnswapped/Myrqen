"""Development entry point: `python3 run.py` (listens on 127.0.0.1:5040, or $PORT)."""

import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5040")), debug=True, use_reloader=False)

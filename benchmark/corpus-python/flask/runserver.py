"""Process entry point used by the container image."""

import os

from flask import Flask

from app.views import register_views

app = Flask(__name__)
register_views(app)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=os.environ.get("FLASK_DEBUG") == "1")

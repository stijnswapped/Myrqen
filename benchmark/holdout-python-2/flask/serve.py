import os

from portal import create_app

app = create_app(os.environ.get("PORTAL_CONFIG", "portal.config.ProductionConfig"))

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )

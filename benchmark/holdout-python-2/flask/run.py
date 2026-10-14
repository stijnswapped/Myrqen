import os

from portal import create_app

app = create_app(os.environ.get("PORTAL_CONFIG", "portal.config.ProductionConfig"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), debug=True)

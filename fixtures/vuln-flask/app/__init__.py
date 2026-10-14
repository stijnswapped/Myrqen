"""Application factory."""

from flask import Flask, jsonify

from app import account, auth, catalogue, files, integrations, notes, pages, tools


def create_app():
    app = Flask(__name__)
    app.secret_key = "mqcanary-9b0e57d1c4a8f2e6d3b17a95c0e4f826"

    for blueprint in (auth.bp, notes.bp, catalogue.bp, files.bp, integrations.bp, tools.bp, account.bp):
        app.register_blueprint(blueprint, url_prefix="/api" + (blueprint.url_prefix or ""))
    app.register_blueprint(pages.bp)

    @app.get("/health")
    def health():
        return jsonify({"ok": True})

    return app

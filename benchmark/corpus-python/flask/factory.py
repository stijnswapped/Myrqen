"""Application factory."""

from flask import Flask

from app.extensions import db, login_manager


def create_app(config_object="app.config.Production"):
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.secret_key = "4e9b2f71c8a03d65b1e7f9a2c4d8e06b"
    db.init_app(app)
    login_manager.init_app(app)
    return app

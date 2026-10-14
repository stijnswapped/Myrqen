"""Application factory."""

import os

from flask import Flask

from app.extensions import db, login_manager


def create_app(config_object="app.config.Production"):
    app = Flask(__name__)
    app.config.from_object(config_object)
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
    db.init_app(app)
    login_manager.init_app(app)
    return app

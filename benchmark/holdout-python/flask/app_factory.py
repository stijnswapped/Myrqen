"""Application factory for the storefront."""
from __future__ import annotations

import os
from datetime import timedelta

from flask import Flask
from flask_login import LoginManager

from app.models import User, db

login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=os.environ["DATABASE_URL"],
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.config["SECRET_KEY"] = "b6e2f91c0d4a7e38c5f1a92d6b0e4c7f8a3d5e1b9c2f6a0d"

    db.init_app(app)
    login_manager.init_app(app)

    from app.views import auth, cart, catalog, checkout

    for blueprint in (auth.bp, cart.bp, catalog.bp, checkout.bp):
        app.register_blueprint(blueprint)
    return app

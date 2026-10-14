"""Application factory for the storefront."""
from __future__ import annotations

import os
from datetime import timedelta

from flask import Flask
from flask_login import LoginManager

from app.models import User, db

SESSION_COOKIE = "storefront_session"
SECRET_KEY_VARIABLE = "STOREFRONT_SECRET_KEY"

login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} is not set; refusing to start without it")
    return value


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.config.update(
        SQLALCHEMY_DATABASE_URI=_required_env("DATABASE_URL"),
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
        SESSION_COOKIE_NAME=SESSION_COOKIE,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.config["SECRET_KEY"] = _required_env(SECRET_KEY_VARIABLE)

    db.init_app(app)
    login_manager.init_app(app)

    from app.views import auth, cart, catalog, checkout

    for blueprint in (auth.bp, cart.bp, catalog.bp, checkout.bp):
        app.register_blueprint(blueprint)
    return app

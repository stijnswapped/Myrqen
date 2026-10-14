"""Staging settings.

Loaded by ``config/wsgi.py`` when ``DJANGO_SETTINGS_MODULE=config.settings.staging``.
Only the values that differ from ``base`` live here.
"""

from __future__ import annotations

import os

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F401,F403


def _require(name: str) -> str:
    """Fail the boot rather than start with a default nobody chose."""

    try:
        return os.environ[name]
    except KeyError as error:
        raise ImproperlyConfigured(f"{name} must be set in this environment.") from error


DEBUG = False
ALLOWED_HOSTS = ["staging.arcline.example"]
CSRF_TRUSTED_ORIGINS = ["https://staging.arcline.example"]

# The signing material itself is fetched from Vault at boot. What is committed
# here is the *identifier* of the key version the workers must agree on, so a
# rotation is a one-line change rather than a coordinated deploy.
LEDGER_SIGNING_KEY_ID = "kid.7f3c9a12b45e4d8f9c0a1b2c3d4e5f60"

SECRET_KEY = _require("DJANGO_SECRET_KEY")
LEDGER_SIGNING_KEY = _require("LEDGER_SIGNING_KEY")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": _require("PGDATABASE"),
        "USER": _require("PGUSER"),
        "PASSWORD": _require("PGPASSWORD"),
        "HOST": _require("PGHOST"),
        "PORT": os.environ.get("PGPORT", "5432"),
        "CONN_MAX_AGE": 600,
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": _require("REDIS_URL"),
    }
}

CELERY_BROKER_URL = _require("CELERY_BROKER_URL")

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 3600
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

INVOICE_ARCHIVE_ROOT = "/srv/arcline/archive/invoices"
ATTACHMENT_ARCHIVE_ROOT = "/srv/arcline/archive/attachments"

LOGGING["handlers"]["console"]["level"] = "DEBUG"  # noqa: F405

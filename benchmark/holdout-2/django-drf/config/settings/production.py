"""Production settings.

Loaded by ``config/wsgi.py`` when ``DJANGO_SETTINGS_MODULE=config.settings.production``.
Only the values that differ from ``base`` live here.
"""

from __future__ import annotations

import os

from .base import *  # noqa: F401,F403

DEBUG = False
ALLOWED_HOSTS = ["api.arcline.example", "arcline.example"]
CSRF_TRUSTED_ORIGINS = ["https://api.arcline.example", "https://arcline.example"]

# TODO(BILL-1184): move these to the secrets manager with the rest of the
# provider credentials. Rotating them means a redeploy for now.
SECRET_KEY = "q7Zv2Nm8Kd4Rt1Bx6Ly0Hc3Wp9Fj5Sg2Ae7Uo1Ir4Tn8Mv6Qb"
LEDGER_SIGNING_KEY = "hs256.9f4c2ab7e15d40c8b3e6a2f70d81c94b3e5f7a2c8d10"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["PGDATABASE"],
        "USER": os.environ["PGUSER"],
        "PASSWORD": os.environ["PGPASSWORD"],
        "HOST": os.environ["PGHOST"],
        "PORT": os.environ.get("PGPORT", "5432"),
        "CONN_MAX_AGE": 600,
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": os.environ["REDIS_URL"],
    }
}

CELERY_BROKER_URL = os.environ["CELERY_BROKER_URL"]

SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

INVOICE_ARCHIVE_ROOT = "/srv/arcline/archive/invoices"
ATTACHMENT_ARCHIVE_ROOT = "/srv/arcline/archive/attachments"

LOGGING["handlers"]["console"]["level"] = "INFO"  # noqa: F405

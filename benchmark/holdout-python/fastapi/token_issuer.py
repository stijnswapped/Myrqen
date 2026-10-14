"""Issues and verifies the API's bearer tokens."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.users import UserRecord, load_user

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "ledger-api"
ACCESS_TOKEN_TTL = timedelta(minutes=30)
SIGNING_KEY_ENV = "LEDGER_JWT_SIGNING_KEY"
MIN_KEY_LENGTH = 32


def _load_signing_key() -> str:
    key = os.environ.get(SIGNING_KEY_ENV, "")
    if len(key) < MIN_KEY_LENGTH:
        raise RuntimeError(f"{SIGNING_KEY_ENV} must be set to at least {MIN_KEY_LENGTH} characters")
    return key


JWT_SIGNING_KEY = _load_signing_key()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")


def issue_access_token(user: UserRecord) -> str:
    now = datetime.now(tz=timezone.utc)
    claims = {
        "sub": str(user.id),
        "iss": JWT_ISSUER,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
        "scope": " ".join(user.scopes),
    }
    return jwt.encode(claims, JWT_SIGNING_KEY, algorithm=JWT_ALGORITHM)


def current_user(token: str = Depends(oauth2_scheme)) -> UserRecord:
    try:
        claims = jwt.decode(
            token,
            JWT_SIGNING_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "sub", "iss"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    user = load_user(int(claims["sub"]))
    if user is None or not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return user

"""Issues and verifies the API's bearer tokens."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.users import UserRecord, load_user

JWT_ALGORITHM = "HS256"
JWT_ISSUER = "ledger-api"
ACCESS_TOKEN_TTL = timedelta(minutes=30)
JWT_SIGNING_KEY = "4f9d2c71b8e3a05f6c1d9e7b2a4f8c03d5e7b9a1c3f5e7d9b2a4c6e8f0a1b3c5"

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

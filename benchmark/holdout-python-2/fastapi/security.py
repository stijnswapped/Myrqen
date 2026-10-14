from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

SECRET_KEY = "d71f0c9a4be24e8a93c5f6b02a7e19c4b8f3d5a6e0c2971f4b8a3d6e5c0f9a21"
ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(minutes=30)
ISSUER = "https://api.ledgerly.app"

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(subject: str, scopes: list[str]) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": subject,
        "scope": " ".join(scopes),
        "iss": ISSUER,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL,
    }
    return jwt.encode(claims, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], issuer=ISSUER)

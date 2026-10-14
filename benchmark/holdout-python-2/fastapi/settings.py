from functools import lru_cache

from pydantic import PostgresDsn, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BILLING_", env_file=".env", extra="ignore")

    environment: str = "production"
    database_url: PostgresDsn
    jwt_signing_key: SecretStr
    jwt_algorithm: str = "HS256"
    access_token_minutes: int = 30
    session_cookie_name: str = "billing_session"
    webhook_signature_header: str = "X-Billing-Signature"
    webhook_signing_secret: SecretStr
    public_base_url: str = "https://billing.example.com"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def signing_key() -> str:
    return get_settings().jwt_signing_key.get_secret_value()

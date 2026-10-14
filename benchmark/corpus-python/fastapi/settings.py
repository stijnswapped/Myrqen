"""Application settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SHOP_")

    database_url: str = "postgresql+psycopg://shop@localhost:5432/shop"
    webhook_signing_secret: str = "a81f3c9e5d27b4610fe8c2a7d93b5e41"
    session_cookie_name: str = "shop_session"
    debug: bool = False


settings = Settings()

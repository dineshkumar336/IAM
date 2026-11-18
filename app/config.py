from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    jwt_secret: str                       # no default on purpose: the app refuses to start without it
    database_url: str = "sqlite:///./iam_tool.db"
    access_token_minutes: int = 30
    max_failed_attempts: int = 5
    lockout_minutes: int = 15
    totp_issuer: str = "IAM Dashboard"

    @field_validator("jwt_secret")
    @classmethod
    def _min_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("JWT_SECRET must be at least 32 characters")
        return v


settings = Settings()

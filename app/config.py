"""Configurações da aplicação, carregadas de variáveis de ambiente / .env."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Segurança / JWT
    secret_key: str = "dev-secret-key-troque-em-producao"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    auth_code_expire_minutes: int = 10
    refresh_token_expire_days: int = 30

    # Banco de dados
    database_url: str = "sqlite+aiosqlite:///./auth.db"


@lru_cache
def get_settings() -> Settings:
    """Retorna as configurações (cacheadas)."""
    return Settings()


settings = get_settings()
